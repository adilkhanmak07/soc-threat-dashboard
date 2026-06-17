import pandas as pd
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta

# ── Page config ────────────────────────────────────────────
st.set_page_config(
    page_title="SOC Threat Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ─────────────────────────────────────────────
st.markdown("""
<style>
    .metric-card {
        background: #0e1117;
        border: 1px solid #262730;
        border-radius: 8px;
        padding: 16px 20px;
        margin-bottom: 8px;
    }
    .critical { border-left: 4px solid #ff4b4b; }
    .high     { border-left: 4px solid #ffa500; }
    .low      { border-left: 4px solid #00d4aa; }
    .normal   { border-left: 4px solid #4a9eff; }
    .stMetric label { font-size: 13px !important; color: #a0a0a0 !important; }
</style>
""", unsafe_allow_html=True)


# ── Load data ──────────────────────────────────────────────
@st.cache_data
def load_logs():
    try:
        df = pd.read_csv("network_logs.csv", parse_dates=["timestamp"])
        return df
    except FileNotFoundError:
        st.error("network_logs.csv not found. Run generate_logs.py first.")
        st.stop()

@st.cache_data
def load_flagged():
    try:
        df = pd.read_csv("flagged_attacks.csv", parse_dates=["timestamp"])
        return df
    except FileNotFoundError:
        return pd.DataFrame()


df      = load_logs()
flagged = load_flagged()


# ── Sidebar ────────────────────────────────────────────────
with st.sidebar:
    st.image("https://img.icons8.com/color/96/shield.png", width=60)
    st.title("SOC Dashboard")
    st.caption("Security Operations Center · Live View")
    st.divider()

    st.subheader("Filters")

    min_date = df["timestamp"].min().date()
    max_date = df["timestamp"].max().date()
    date_range = st.date_input(
        "Date range",
        value=(min_date, max_date),
        min_value=min_date,
        max_value=max_date,
    )

    attack_types = ["All"] + sorted(df[df["label"] == "Attack"]["attack_type"].unique().tolist())
    selected_attack = st.selectbox("Attack type", attack_types)

    severities = ["All", "Critical", "High", "Low"]
    selected_severity = st.selectbox("Severity", severities)

    protocols = ["All"] + sorted(df["protocol"].unique().tolist())
    selected_protocol = st.selectbox("Protocol", protocols)

    st.subheader("IP Search")
    ip_search = st.text_input("Search source IP", placeholder="e.g. 192.168.1.10")

    st.divider()
    st.caption(f"Data range: {min_date} to {max_date}")
    st.caption(f"Total events: {len(df):,}")


# ── Apply filters ──────────────────────────────────────────
filtered = df.copy()

if len(date_range) == 2:
    start_dt = datetime.combine(date_range[0], datetime.min.time())
    end_dt   = datetime.combine(date_range[1], datetime.max.time())
    filtered = filtered[(filtered["timestamp"] >= start_dt) & (filtered["timestamp"] <= end_dt)]

if selected_attack != "All":
    filtered = filtered[
        (filtered["label"] == "Normal") | (filtered["attack_type"] == selected_attack)
    ]

if selected_severity != "All":
    filtered = filtered[
        (filtered["severity"] == "None") | (filtered["severity"] == selected_severity)
    ]

if selected_protocol != "All":
    filtered = filtered[filtered["protocol"] == selected_protocol]

if ip_search:
    filtered = filtered[filtered["src_ip"].str.contains(ip_search, na=False)]

attacks_filtered = filtered[filtered["label"] == "Attack"]


# ── Header ─────────────────────────────────────────────────
st.markdown("## SOC Threat Dashboard")
st.caption(f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  |  Showing {len(filtered):,} events")
st.divider()


# ── KPI Metric Cards ───────────────────────────────────────
col1, col2, col3, col4, col5 = st.columns(5)

total_events     = len(filtered)
total_attacks    = len(attacks_filtered)
attack_pct       = round(total_attacks / total_events * 100, 1) if total_events > 0 else 0
unique_attackers = attacks_filtered["src_ip"].nunique()
critical_count   = (attacks_filtered["severity"] == "Critical").sum()
high_count       = (attacks_filtered["severity"] == "High").sum()

with col1:
    st.metric("Total events", f"{total_events:,}")
with col2:
    st.metric("Attacks detected", f"{total_attacks:,}", delta=f"{attack_pct}% of traffic", delta_color="inverse")
with col3:
    st.metric("Critical alerts", f"{critical_count:,}")
with col4:
    st.metric("High alerts", f"{high_count:,}")
with col5:
    st.metric("Unique attacker IPs", f"{unique_attackers:,}")

st.divider()


# ── Row 1: Attack timeline + Attack type breakdown ─────────
col_left, col_right = st.columns([2, 1])

with col_left:
    st.subheader("Attack timeline")
    if not attacks_filtered.empty:
        timeline = (
            attacks_filtered
            .set_index("timestamp")
            .resample("1h")
            .size()
            .reset_index(name="count")
        )
        fig_timeline = px.area(
            timeline, x="timestamp", y="count",
            labels={"timestamp": "", "count": "Attacks per hour"},
            color_discrete_sequence=["#ff4b4b"],
        )
        fig_timeline.update_layout(
            plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
            margin=dict(l=0, r=0, t=10, b=0), height=260, showlegend=False,
            xaxis=dict(showgrid=False),
            yaxis=dict(showgrid=True, gridcolor="#262730"),
        )
        fig_timeline.update_traces(fillcolor="rgba(255,75,75,0.15)", line_width=2)
        st.plotly_chart(fig_timeline, use_container_width=True)
    else:
        st.info("No attacks in selected range.")

with col_right:
    st.subheader("Attack types")
    if not attacks_filtered.empty:
        type_counts = attacks_filtered["attack_type"].value_counts().reset_index()
        type_counts.columns = ["attack_type", "count"]
        color_map = {
            "Port Scan":     "#4a9eff",
            "Brute Force":   "#ffa500",
            "DDoS":          "#ff4b4b",
            "SQL Injection": "#a855f7",
            "Malware C2":    "#ff6b6b",
        }
        colors = [color_map.get(t, "#888") for t in type_counts["attack_type"]]
        fig_types = go.Figure(go.Bar(
            x=type_counts["count"], y=type_counts["attack_type"],
            orientation="h", marker_color=colors,
            text=type_counts["count"], textposition="outside",
        ))
        fig_types.update_layout(
            plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
            margin=dict(l=0, r=40, t=10, b=0), height=260,
            xaxis=dict(showgrid=False, showticklabels=False),
            yaxis=dict(showgrid=False),
        )
        st.plotly_chart(fig_types, use_container_width=True)


# ── Row 2: Severity donut + Top attacker IPs + Protocol ───
col_a, col_b, col_c = st.columns(3)

with col_a:
    st.subheader("Severity split")
    if not attacks_filtered.empty:
        sev_counts = attacks_filtered["severity"].value_counts().reset_index()
        sev_counts.columns = ["severity", "count"]
        sev_colors = {"Critical": "#ff4b4b", "High": "#ffa500", "Low": "#00d4aa"}
        colors_sev = [sev_colors.get(s, "#888") for s in sev_counts["severity"]]
        fig_sev = go.Figure(go.Pie(
            labels=sev_counts["severity"], values=sev_counts["count"],
            hole=0.6, marker=dict(colors=colors_sev),
            textinfo="label+percent", textfont_size=12,
        ))
        fig_sev.update_layout(
            plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
            margin=dict(l=0, r=0, t=10, b=0), height=240, showlegend=False,
        )
        st.plotly_chart(fig_sev, use_container_width=True)

with col_b:
    st.subheader("Top attacker IPs")
    if not attacks_filtered.empty:
        top_ips = (
            attacks_filtered.groupby("src_ip")
            .agg(events=("timestamp", "count"))
            .sort_values("events", ascending=False)
            .head(8).reset_index()
        )
        fig_ips = go.Figure(go.Bar(
            x=top_ips["events"], y=top_ips["src_ip"],
            orientation="h", marker_color="#ff4b4b",
            text=top_ips["events"], textposition="outside",
        ))
        fig_ips.update_layout(
            plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
            margin=dict(l=0, r=40, t=10, b=0), height=240,
            xaxis=dict(showgrid=False, showticklabels=False),
            yaxis=dict(showgrid=False, autorange="reversed"),
        )
        st.plotly_chart(fig_ips, use_container_width=True)

with col_c:
    st.subheader("Attack by protocol")
    if not attacks_filtered.empty:
        proto_counts = attacks_filtered["protocol"].value_counts().reset_index()
        proto_counts.columns = ["protocol", "count"]
        fig_proto = go.Figure(go.Pie(
            labels=proto_counts["protocol"], values=proto_counts["count"],
            hole=0.55, marker=dict(colors=["#4a9eff", "#a855f7"]),
            textinfo="label+percent", textfont_size=13,
        ))
        fig_proto.update_layout(
            plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
            margin=dict(l=0, r=0, t=10, b=0), height=240, showlegend=False,
        )
        st.plotly_chart(fig_proto, use_container_width=True)


# ── Row 3: Top targeted ports ──────────────────────────────
st.subheader("Most targeted ports")
if not attacks_filtered.empty:
    port_counts = (
        attacks_filtered.groupby(["dst_port", "attack_type"])
        .size().reset_index(name="count")
        .sort_values("count", ascending=False).head(12)
    )
    fig_ports = px.bar(
        port_counts, x="dst_port", y="count", color="attack_type",
        labels={"dst_port": "Destination port", "count": "Hit count", "attack_type": "Attack type"},
        color_discrete_map={
            "Port Scan":     "#4a9eff",
            "Brute Force":   "#ffa500",
            "DDoS":          "#ff4b4b",
            "SQL Injection": "#a855f7",
            "Malware C2":    "#ff6b6b",
        },
    )
    fig_ports.update_layout(
        plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=0, r=0, t=10, b=0), height=240,
        legend=dict(orientation="h", yanchor="bottom", y=1.02),
        xaxis=dict(type="category", showgrid=False),
        yaxis=dict(showgrid=True, gridcolor="#262730"),
    )
    st.plotly_chart(fig_ports, use_container_width=True)

st.divider()


# ── Row 4: Live alert feed ─────────────────────────────────
st.subheader("Live alert feed — last 50 threats")

severity_emoji = {"Critical": "CRIT", "High": "HIGH", "Low": "LOW", "None": "OK"}

if not attacks_filtered.empty:
    recent = (
        attacks_filtered
        .sort_values("timestamp", ascending=False)
        .head(50)
        [["timestamp", "src_ip", "dst_ip", "dst_port", "attack_type", "severity", "bytes_sent", "protocol"]]
        .reset_index(drop=True)
    )
    recent["timestamp"] = recent["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
    st.dataframe(
        recent,
        use_container_width=True,
        height=380,
        column_config={
            "timestamp":   st.column_config.TextColumn("Timestamp", width=160),
            "src_ip":      st.column_config.TextColumn("Source IP", width=130),
            "dst_ip":      st.column_config.TextColumn("Target IP", width=130),
            "dst_port":    st.column_config.NumberColumn("Port", width=70),
            "attack_type": st.column_config.TextColumn("Attack type", width=130),
            "severity":    st.column_config.TextColumn("Severity", width=90),
            "bytes_sent":  st.column_config.NumberColumn("Bytes", width=80, format="%d"),
            "protocol":    st.column_config.TextColumn("Proto", width=70),
        },
        hide_index=True,
    )
else:
    st.success("No attacks match current filters.")


# ── Row 5: Attacker IP deep-dive ───────────────────────────
st.divider()
st.subheader("Attacker IP investigation")

if not attacks_filtered.empty:
    all_attacker_ips = sorted(attacks_filtered["src_ip"].unique().tolist())
    selected_ip = st.selectbox("Select an attacker IP to investigate", all_attacker_ips)

    ip_data = attacks_filtered[attacks_filtered["src_ip"] == selected_ip]

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total events",     len(ip_data))
    c2.metric("Attack types",     ip_data["attack_type"].nunique())
    c3.metric("Unique targets",   ip_data["dst_ip"].nunique())
    c4.metric("Total bytes sent", f"{ip_data['bytes_sent'].sum():,}")

    col_i1, col_i2 = st.columns(2)

    with col_i1:
        st.caption("Attack types used by this IP")
        type_breakdown = ip_data["attack_type"].value_counts().reset_index()
        type_breakdown.columns = ["Attack type", "Count"]
        st.dataframe(type_breakdown, use_container_width=True, hide_index=True, height=180)

    with col_i2:
        st.caption("Ports targeted by this IP")
        port_breakdown = ip_data["dst_port"].value_counts().head(10).reset_index()
        port_breakdown.columns = ["Port", "Hit count"]
        st.dataframe(port_breakdown, use_container_width=True, hide_index=True, height=180)

    st.caption("Activity timeline for this IP (30-min buckets)")
    ip_timeline = (
        ip_data.set_index("timestamp").resample("30min").size().reset_index(name="count")
    )
    fig_ip = px.bar(
        ip_timeline, x="timestamp", y="count",
        labels={"timestamp": "", "count": "Events per 30 min"},
        color_discrete_sequence=["#ff4b4b"],
    )
    fig_ip.update_layout(
        plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=0, r=0, t=10, b=0), height=200, showlegend=False,
        xaxis=dict(showgrid=False),
        yaxis=dict(showgrid=True, gridcolor="#262730"),
    )
    st.plotly_chart(fig_ip, use_container_width=True)


# ── Footer ─────────────────────────────────────────────────
st.divider()
st.caption("SOC Threat Dashboard  |  Built with Python + Streamlit + Plotly  |  Portfolio project")
