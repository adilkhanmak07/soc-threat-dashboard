import pandas as pd
import random
from datetime import datetime, timedelta
from faker import Faker

fake = Faker()
random.seed(42)

# ── Settings ──────────────────────────────────────────────
TOTAL_ROWS    = 5000
ATTACK_RATIO  = 0.30   # 30% of traffic will be attacks
OUTPUT_FILE   = "network_logs.csv"

# Common ports
NORMAL_PORTS  = [80, 443, 53, 22, 25, 110, 143, 3306, 5432]
ATTACK_PORTS  = [22, 23, 3389, 445, 139, 21, 8080, 4444, 1433]

# Attack types and their patterns
ATTACK_TYPES = {
    "Port Scan": {
        "ports": list(range(1, 1024)),   # scans many ports
        "bytes_range": (40, 120),         # small packets
        "duration_range": (0.001, 0.05),
        "protocol": ["TCP", "UDP"],
    },
    "Brute Force": {
        "ports": [22, 3389, 21, 23],      # targets login services
        "bytes_range": (200, 600),
        "duration_range": (0.1, 2.0),
        "protocol": ["TCP"],
    },
    "DDoS": {
        "ports": [80, 443, 53],           # floods web/DNS
        "bytes_range": (1000, 65000),
        "duration_range": (0.001, 0.01),
        "protocol": ["TCP", "UDP"],
    },
    "SQL Injection": {
        "ports": [80, 443, 3306, 5432],
        "bytes_range": (300, 2000),
        "duration_range": (0.05, 0.5),
        "protocol": ["TCP"],
    },
    "Malware C2": {
        "ports": [4444, 8080, 1234, 6666],
        "bytes_range": (500, 5000),
        "duration_range": (1.0, 30.0),
        "protocol": ["TCP"],
    },
}

# Fixed attacker IPs (so the same IPs appear multiple times — realistic)
ATTACKER_IPS = [fake.ipv4() for _ in range(15)]

# Internal network IPs (victims / normal users)
INTERNAL_IPS = [f"192.168.1.{i}" for i in range(10, 60)]
INTERNAL_IPS += [f"10.0.0.{i}" for i in range(1, 30)]


def random_timestamp(start_days_ago=7):
    """Return a random timestamp within the last N days."""
    start = datetime.now() - timedelta(days=start_days_ago)
    random_seconds = random.randint(0, start_days_ago * 24 * 3600)
    return start + timedelta(seconds=random_seconds)


def generate_normal_row(ts):
    src = random.choice(INTERNAL_IPS)
    dst_ip = fake.ipv4_public()
    port = random.choice(NORMAL_PORTS)
    protocol = random.choice(["TCP", "UDP"])
    bytes_sent = random.randint(200, 15000)
    duration = round(random.uniform(0.1, 5.0), 4)
    return {
        "timestamp":     ts.strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip":        src,
        "dst_ip":        dst_ip,
        "src_port":      random.randint(1024, 65535),
        "dst_port":      port,
        "protocol":      protocol,
        "bytes_sent":    bytes_sent,
        "duration_sec":  duration,
        "attack_type":   "Normal",
        "severity":      "None",
        "label":         "Normal",
    }


def generate_attack_row(ts):
    attack_name = random.choice(list(ATTACK_TYPES.keys()))
    attack      = ATTACK_TYPES[attack_name]

    src_ip      = random.choice(ATTACKER_IPS)
    dst_ip      = random.choice(INTERNAL_IPS)
    dst_port    = random.choice(attack["ports"])
    protocol    = random.choice(attack["protocol"])
    bytes_sent  = random.randint(*attack["bytes_range"])
    duration    = round(random.uniform(*attack["duration_range"]), 4)

    # Severity based on attack type
    severity_map = {
        "Port Scan":      "Low",
        "Brute Force":    "High",
        "DDoS":           "Critical",
        "SQL Injection":  "High",
        "Malware C2":     "Critical",
    }

    return {
        "timestamp":    ts.strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip":       src_ip,
        "dst_ip":       dst_ip,
        "src_port":     random.randint(1024, 65535),
        "dst_port":     dst_port,
        "protocol":     protocol,
        "bytes_sent":   bytes_sent,
        "duration_sec": duration,
        "attack_type":  attack_name,
        "severity":     severity_map[attack_name],
        "label":        "Attack",
    }


def main():
    print("Generating network logs...")
    rows = []

    attack_count = int(TOTAL_ROWS * ATTACK_RATIO)
    normal_count = TOTAL_ROWS - attack_count

    for _ in range(normal_count):
        ts = random_timestamp()
        rows.append(generate_normal_row(ts))

    for _ in range(attack_count):
        ts = random_timestamp()
        rows.append(generate_attack_row(ts))

    # Shuffle so attacks are mixed throughout, not all at the end
    random.shuffle(rows)

    df = pd.DataFrame(rows)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values("timestamp").reset_index(drop=True)

    df.to_csv(OUTPUT_FILE, index=False)

    # ── Summary ───────────────────────────────────────────
    print(f"\nDone! Saved to: {OUTPUT_FILE}")
    print(f"Total rows    : {len(df):,}")
    print(f"Normal traffic: {(df['label']=='Normal').sum():,}")
    print(f"Attacks       : {(df['label']=='Attack').sum():,}")
    print("\nAttack breakdown:")
    attack_df = df[df["label"] == "Attack"]
    print(attack_df["attack_type"].value_counts().to_string())
    print("\nSeverity breakdown:")
    print(attack_df["severity"].value_counts().to_string())
    print(f"\nUnique attacker IPs : {attack_df['src_ip'].nunique()}")
    print(f"Date range          : {df['timestamp'].min()} → {df['timestamp'].max()}")


if __name__ == "__main__":
    main()