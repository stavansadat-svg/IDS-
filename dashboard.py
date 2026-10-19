import streamlit as st
import pandas as pd
import altair as alt
import time
import os
from datetime import datetime

LOG_PATH = os.path.expanduser("~/ids_project/live_log.csv")

st.set_page_config(page_title="IoT IDS Dashboard", page_icon="🛡️", layout="wide")

CHART_HEIGHT = 380

# ---------- Custom styling ----------
st.markdown(f"""
<style>
    .main {{ background-color: #0e1117; }}
    .metric-card {{
        background-color: #1a1d24;
        border: 1px solid #2d3139;
        border-radius: 10px;
        padding: 18px 24px;
        text-align: center;
    }}
    .metric-label {{
        font-size: 13px;
        color: #8b949e;
        text-transform: uppercase;
        letter-spacing: 1px;
        margin-bottom: 6px;
    }}
    .metric-value {{
        font-size: 36px;
        font-weight: 700;
    }}
    .metric-benign .metric-value {{ color: #3fb950; }}
    .metric-malicious .metric-value {{ color: #f85149; }}
    .metric-total .metric-value {{ color: #ffffff; }}
    .status-bar {{
        display: flex;
        align-items: center;
        gap: 8px;
        font-size: 13px;
        color: #8b949e;
        margin-bottom: 18px;
    }}
    .dot {{
        height: 9px;
        width: 9px;
        border-radius: 50%;
        background-color: #3fb950;
        display: inline-block;
        animation: pulse 2s infinite;
    }}
    @keyframes pulse {{
        0% {{ opacity: 1; }}
        50% {{ opacity: 0.3; }}
        100% {{ opacity: 1; }}
    }}
    .verdict-badge {{
        padding: 3px 10px;
        border-radius: 12px;
        font-size: 12px;
        font-weight: 600;
        display: inline-block;
    }}
    .badge-benign {{ background-color: #3fb95030; color: #3fb950; border: 1px solid #3fb95060; }}
    .badge-scan {{ background-color: #f8514930; color: #f85149; border: 1px solid #f8514960; }}
    .badge-bruteforce {{ background-color: #f0883e30; color: #f0883e; border: 1px solid #f0883e60; }}
    .badge-flood {{ background-color: #a371f730; color: #a371f7; border: 1px solid #a371f760; }}
    table {{ font-size: 13px; }}

    /* Keep all three column headings at the same baseline */
    div[data-testid="column"] {{
        display: flex;
        flex-direction: column;
    }}

    /* Wrapper matches the chart area height; the box inside is centered vertically */
    .feed-wrapper {{
        min-height: {CHART_HEIGHT + 40}px;
        display: flex;
        align-items: center;
        justify-content: center;
    }}
    .feed-box {{
        width: 100%;
        max-height: {CHART_HEIGHT}px;
        overflow-y: auto;
        border: 1px solid #2d3139;
        border-radius: 8px;
        padding: 6px 10px;
    }}
    .feed-box table {{
        width: 100%;
        margin: 0;
    }}
</style>
""", unsafe_allow_html=True)

# ---------- Header ----------
st.markdown("## 🛡️ AI-Based IoT Intrusion Detection System")
st.markdown("**Live Monitoring Dashboard** — MQTT sensor traffic, flow-based detection (Random Forest + Isolation Forest)")

BADGE_MAP = {
    "benign": "badge-benign",
    "scan": "badge-scan",
    "bruteforce": "badge-bruteforce",
    "mqtt_flood": "badge-flood",
}

placeholder = st.empty()

while True:
    if os.path.exists(LOG_PATH):
        df = pd.read_csv(LOG_PATH)
    else:
        df = pd.DataFrame()

    with placeholder.container():
        now = datetime.now().strftime("%H:%M:%S")
        st.markdown(
            f'<div class="status-bar"><span class="dot"></span> Live — monitoring enp0s8 — last refresh {now}</div>',
            unsafe_allow_html=True
        )

        total = len(df)
        malicious = len(df[df["final_verdict"] == "MALICIOUS"]) if not df.empty else 0
        benign = total - malicious
        mal_pct = f"{(malicious/total*100):.1f}%" if total else "—"

        col1, col2, col3 = st.columns(3)
        with col1:
            st.markdown(f'<div class="metric-card metric-total"><div class="metric-label">Total Flows</div>'
                        f'<div class="metric-value">{total}</div></div>', unsafe_allow_html=True)
        with col2:
            st.markdown(f'<div class="metric-card metric-malicious"><div class="metric-label">Malicious ({mal_pct})</div>'
                        f'<div class="metric-value">{malicious}</div></div>', unsafe_allow_html=True)
        with col3:
            st.markdown(f'<div class="metric-card metric-benign"><div class="metric-label">Benign</div>'
                        f'<div class="metric-value">{benign}</div></div>', unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        if not df.empty:
            colA, colB, colC = st.columns([1.1, 2, 1.1])

            with colA:
                st.markdown("#### Verdict Breakdown")
                chart_df = df["final_verdict"].value_counts().reset_index()
                chart_df.columns = ["verdict", "count"]
                color_scale = alt.Scale(domain=["BENIGN", "MALICIOUS"], range=["#3fb950", "#f85149"])
                chart = alt.Chart(chart_df).mark_bar().encode(
                    x=alt.X("verdict", sort=None, title=None),
                    y=alt.Y("count", title=None),
                    color=alt.Color("verdict", scale=color_scale, legend=None)
                ).properties(height=CHART_HEIGHT)
                st.altair_chart(chart, use_container_width=True)

            with colB:
                st.markdown("#### Live Event Feed")
                recent = df.iloc[::-1].head(8).copy()

                def badge(row):
                    label = str(row["rf_verdict"])
                    cls = BADGE_MAP.get(label, "badge-scan")
                    return f'<span class="verdict-badge {cls}">{label.upper()}</span>'

                recent["Verdict"] = recent.apply(badge, axis=1)
                display_cols = ["time", "src", "dst", "packet_count", "Verdict"]
                display_df = recent[display_cols].rename(columns={
                    "time": "Time", "src": "Source", "dst": "Destination",
                    "packet_count": "Packets"
                })

                st.markdown(
                    f'<div class="feed-wrapper">'
                    f'<div class="feed-box">'
                    f'{display_df.to_html(escape=False, index=False)}'
                    f'</div>'
                    f'</div>',
                    unsafe_allow_html=True
                )

            with colC:
                st.markdown("#### By Attack Type")
                type_df = df["rf_verdict"].value_counts().reset_index()
                type_df.columns = ["type", "count"]
                type_colors = {"benign": "#3fb950", "scan": "#f85149",
                               "bruteforce": "#f0883e", "mqtt_flood": "#a371f7"}
                type_scale = alt.Scale(domain=list(type_colors.keys()), range=list(type_colors.values()))
                type_chart = alt.Chart(type_df).mark_bar().encode(
                    x=alt.X("type", sort=None, title=None),
                    y=alt.Y("count", title=None),
                    color=alt.Color("type", scale=type_scale, legend=None)
                ).properties(height=CHART_HEIGHT)
                st.altair_chart(type_chart, use_container_width=True)
        else:
            st.info("Waiting for traffic... make sure live_agent.py is running.")

    time.sleep(3)
