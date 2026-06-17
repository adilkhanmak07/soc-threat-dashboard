import pandas as pd
from datetime import datetime

INPUT_FILE  = "network_logs.csv"
OUTPUT_FILE = "analysis_report.txt"

# ── Thresholds (tune these to change sensitivity) ─────────
PORT_SCAN_THRESHOLD       = 10   # unique ports from same IP in 10 min = port scan
BRUTE_FORCE_THRESHOLD     = 5    # login attempts from same IP in 5 min = brute force
DDOS_THRESHOLD            = 50   # connections to same dst in 1 min = DDoS
HIGH_BYTES_THRESHOLD      = 50000  # single packet this big = suspicious


def load_data(path):
    print(f"Loading {path} ...")
    df = pd.read_csv(path, parse_dates=["timestamp"])
    print(f"Loaded {len(df):,} rows.\n")
    return df


# ── Detection functions ────────────────────────────────────

def detect_port_scans(df):
    """
    A port scan = one IP hitting many different ports in a short window.
    We group by src_ip + 10-minute window and count unique dst_ports.
    """
    attacks = df[df["label"] == "Attack"].copy()
    attacks["window"] = attacks["timestamp"].dt.floor("10min")

    grouped = (
        attacks[attacks["attack_type"] == "Port Scan"]
        .groupby(["src_ip", "window"])["dst_port"]
        .nunique()
        .reset_index(name="unique_ports")
    )

    flagged = grouped[grouped["unique_ports"] >= PORT_SCAN_THRESHOLD].copy()
    flagged["detection"] = "Port Scan Detected"
    flagged["risk"]      = "Low"
    return flagged[["src_ip", "window", "unique_ports", "detection", "risk"]]


def detect_brute_force(df):
    """
    Brute force = many connection attempts to login ports (22, 3389, 21)
    from the same IP in a short window.
    """
    LOGIN_PORTS = [22, 21, 23, 3389]
    bf = df[
        (df["label"] == "Attack") &
        (df["attack_type"] == "Brute Force") &
        (df["dst_port"].isin(LOGIN_PORTS))
    ].copy()

    bf["window"] = bf["timestamp"].dt.floor("5min")

    grouped = (
        bf.groupby(["src_ip", "dst_ip", "dst_port", "window"])
        .size()
        .reset_index(name="attempt_count")
    )

    flagged = grouped[grouped["attempt_count"] >= BRUTE_FORCE_THRESHOLD].copy()
    flagged["detection"] = "Brute Force Detected"
    flagged["risk"]      = "High"
    return flagged[["src_ip", "dst_ip", "dst_port", "window", "attempt_count", "detection", "risk"]]


def detect_ddos(df):
    """
    DDoS = flood of connections to the same destination in 1 minute.
    """
    ddos = df[
        (df["label"] == "Attack") &
        (df["attack_type"] == "DDoS")
    ].copy()

    ddos["window"] = ddos["timestamp"].dt.floor("1min")

    grouped = (
        ddos.groupby(["dst_ip", "window"])
        .agg(
            connection_count=("src_ip", "count"),
            unique_sources=("src_ip", "nunique"),
            total_bytes=("bytes_sent", "sum"),
        )
        .reset_index()
    )

    flagged = grouped[grouped["connection_count"] >= DDOS_THRESHOLD].copy()
    flagged["detection"] = "DDoS Detected"
    flagged["risk"]      = "Critical"
    return flagged[["dst_ip", "window", "connection_count", "unique_sources", "total_bytes", "detection", "risk"]]


def detect_c2(df):
    """
    Malware C2 = long-duration connections to unusual high ports.
    These are suspicious 'phone home' patterns.
    """
    UNUSUAL_PORTS = [4444, 8080, 1234, 6666, 9999, 31337]
    c2 = df[
        (df["label"] == "Attack") &
        (df["attack_type"] == "Malware C2") &
        (df["dst_port"].isin(UNUSUAL_PORTS))
    ].copy()

    grouped = (
        c2.groupby(["src_ip", "dst_ip", "dst_port"])
        .agg(
            session_count=("timestamp", "count"),
            avg_duration=("duration_sec", "mean"),
            total_bytes=("bytes_sent", "sum"),
            first_seen=("timestamp", "min"),
            last_seen=("timestamp", "max"),
        )
        .reset_index()
    )

    grouped["avg_duration"] = grouped["avg_duration"].round(2)
    grouped["detection"]    = "Malware C2 Detected"
    grouped["risk"]         = "Critical"
    return grouped


def detect_large_transfers(df):
    """
    Any single packet/session with very large bytes is suspicious (data exfiltration).
    """
    flagged = df[df["bytes_sent"] >= HIGH_BYTES_THRESHOLD].copy()
    flagged["detection"] = "Suspicious Large Transfer"
    flagged["risk"]      = "High"
    return flagged[["timestamp", "src_ip", "dst_ip", "dst_port", "bytes_sent", "detection", "risk"]]


# ── Summary stats ──────────────────────────────────────────

def summary_stats(df):
    total        = len(df)
    attacks      = (df["label"] == "Attack").sum()
    normal       = (df["label"] == "Normal").sum()
    attack_pct   = round(attacks / total * 100, 1)

    by_type      = df[df["label"] == "Attack"]["attack_type"].value_counts()
    by_severity  = df[df["label"] == "Attack"]["severity"].value_counts()
    top_attackers = (
        df[df["label"] == "Attack"]
        .groupby("src_ip")
        .size()
        .sort_values(ascending=False)
        .head(10)
    )
    top_targets  = (
        df[df["label"] == "Attack"]
        .groupby("dst_ip")
        .size()
        .sort_values(ascending=False)
        .head(5)
    )
    busiest_hour = (
        df[df["label"] == "Attack"]
        .groupby(df["timestamp"].dt.hour)
        .size()
        .idxmax()
    )

    return {
        "total": total,
        "attacks": attacks,
        "normal": normal,
        "attack_pct": attack_pct,
        "by_type": by_type,
        "by_severity": by_severity,
        "top_attackers": top_attackers,
        "top_targets": top_targets,
        "busiest_hour": busiest_hour,
    }


# ── Report writer ──────────────────────────────────────────

def write_report(stats, port_scans, brute_force, ddos, c2, large_transfers):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = []

    lines.append("=" * 60)
    lines.append("  SOC THREAT ANALYSIS REPORT")
    lines.append(f"  Generated: {now}")
    lines.append("=" * 60)

    lines.append("\n[ EXECUTIVE SUMMARY ]")
    lines.append(f"  Total log entries   : {stats['total']:,}")
    lines.append(f"  Normal traffic      : {stats['normal']:,}")
    lines.append(f"  Attack events       : {stats['attacks']:,}  ({stats['attack_pct']}% of all traffic)")
    lines.append(f"  Busiest attack hour : {stats['busiest_hour']:02d}:00")

    lines.append("\n[ ATTACKS BY TYPE ]")
    for atype, count in stats["by_type"].items():
        lines.append(f"  {atype:<20} {count:>5}")

    lines.append("\n[ SEVERITY BREAKDOWN ]")
    for sev, count in stats["by_severity"].items():
        lines.append(f"  {sev:<12} {count:>5}")

    lines.append("\n[ TOP 10 ATTACKER IPs ]")
    for ip, count in stats["top_attackers"].items():
        lines.append(f"  {ip:<18}  {count} events")

    lines.append("\n[ TOP 5 TARGETED INTERNAL IPs ]")
    for ip, count in stats["top_targets"].items():
        lines.append(f"  {ip:<18}  {count} events")

    lines.append("\n[ DETECTION RESULTS ]")

    lines.append(f"\n  Port Scans   : {len(port_scans)} incidents flagged")
    if not port_scans.empty:
        lines.append("  Sample:")
        lines.append(port_scans.head(3).to_string(index=False, col_space=4))

    lines.append(f"\n  Brute Force  : {len(brute_force)} incidents flagged")
    if not brute_force.empty:
        lines.append("  Sample:")
        lines.append(brute_force.head(3).to_string(index=False, col_space=4))

    lines.append(f"\n  DDoS         : {len(ddos)} incidents flagged")
    if not ddos.empty:
        lines.append("  Sample:")
        lines.append(ddos.head(3).to_string(index=False, col_space=4))

    lines.append(f"\n  Malware C2   : {len(c2)} unique sessions flagged")
    if not c2.empty:
        lines.append("  Sample:")
        lines.append(c2[["src_ip","dst_ip","dst_port","session_count","risk"]].head(3).to_string(index=False, col_space=4))

    lines.append(f"\n  Large Xfers  : {len(large_transfers)} suspicious transfers")

    lines.append("\n[ RECOMMENDATIONS ]")
    if not port_scans.empty:
        top_scanner = port_scans.sort_values("unique_ports", ascending=False).iloc[0]["src_ip"]
        lines.append(f"  1. Block or investigate IP {top_scanner} — top port scanner.")
    if not brute_force.empty:
        top_bf = brute_force.sort_values("attempt_count", ascending=False).iloc[0]
        lines.append(f"  2. Lock account / block IP {top_bf['src_ip']} targeting port {int(top_bf['dst_port'])}.")
    if not ddos.empty:
        top_ddos = ddos.sort_values("connection_count", ascending=False).iloc[0]
        lines.append(f"  3. Enable rate limiting on {top_ddos['dst_ip']} — received {int(top_ddos['connection_count'])} hits in 1 min.")
    if not c2.empty:
        lines.append(f"  4. Isolate hosts with Malware C2 connections — possible active compromise.")
    if not large_transfers.empty:
        lines.append(f"  5. Investigate {len(large_transfers)} large data transfers — possible exfiltration.")

    lines.append("\n" + "=" * 60)
    lines.append("  END OF REPORT")
    lines.append("=" * 60)

    report = "\n".join(lines)
    print(report)

    with open(OUTPUT_FILE, "w") as f:
        f.write(report)
    print(f"\nReport saved to: {OUTPUT_FILE}")


# ── Main ───────────────────────────────────────────────────

def main():
    df = load_data(INPUT_FILE)

    print("Running threat detection engines...")
    port_scans      = detect_port_scans(df)
    brute_force     = detect_brute_force(df)
    ddos            = detect_ddos(df)
    c2              = detect_c2(df)
    large_transfers = detect_large_transfers(df)
    stats           = summary_stats(df)

    print("Writing report...\n")
    write_report(stats, port_scans, brute_force, ddos, c2, large_transfers)

    # Save flagged events to CSV for the dashboard to use
    flagged_rows = df[df["label"] == "Attack"].copy()
    flagged_rows.to_csv("flagged_attacks.csv", index=False)
    print(f"Flagged attacks saved to: flagged_attacks.csv ({len(flagged_rows):,} rows)")


if __name__ == "__main__":
    main()
