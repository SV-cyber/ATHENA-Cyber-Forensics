from __future__ import annotations

import math
import sys
from pathlib import Path
from typing import List

import pandas as pd
import plotly.graph_objects as go
import streamlit as st
import streamlit.components.v1 as components

sys.path.append(str(Path(__file__).resolve().parents[1]))

from components.sidebar import setup_sidebar
from utils.api_client import AthenaAPIClient


TIME_RANGE_OPTIONS = {"Last Hour": "1h", "24 Hours": "24h", "7 Days": "7d"}
SEVERITY_COLORS = {"critical": "#ff3b30", "high": "#ff9500", "medium": "#ffd60a"}


def _auto_refresh() -> None:
    components.html(
        """
        <script>
        setTimeout(function() {
            window.parent.location.reload();
        }, 10000);
        </script>
        """,
        height=0,
    )


def _arc_points(source_lat: float, source_lon: float, target_lat: float, target_lon: float, steps: int = 24) -> tuple[list[float], list[float]]:
    lats: List[float] = []
    lons: List[float] = []
    for index in range(steps + 1):
        t = index / steps
        lat = source_lat + (target_lat - source_lat) * t
        lon = source_lon + (target_lon - source_lon) * t
        lat += math.sin(math.pi * t) * max(3.0, abs(target_lat - source_lat) * 0.15)
        lats.append(lat)
        lons.append(lon)
    return lats, lons


def _build_map(flows: pd.DataFrame) -> go.Figure:
    fig = go.Figure()
    if flows.empty:
        fig.update_geos(projection_type="natural earth", showframe=False, showcoastlines=True, bgcolor="#06111d")
        fig.update_layout(height=690, paper_bgcolor="#06111d", plot_bgcolor="#06111d")
        return fig

    animation_phases = [0.0, 0.35, 0.7, 1.0]
    base_traces: List[go.Scattergeo] = []
    frames: List[go.Frame] = []

    for _, row in flows.iterrows():
        lats, lons = _arc_points(
            float(row["source_latitude"]),
            float(row["source_longitude"]),
            float(row["target_latitude"]),
            float(row["target_longitude"]),
        )
        hover = (
            f"<b>{row['source_country']} -> {row['target_country']}</b><br>"
            f"Threat: {row['threat_name']}<br>"
            f"Severity: {row['severity']}<br>"
            f"Volume: {int(row['count'])}<br>"
            f"Latest: {row['latest_timestamp']}<extra></extra>"
        )
        color = SEVERITY_COLORS.get(str(row["severity"]), "#7dd3fc")
        base_traces.append(
            go.Scattergeo(
                lat=lats,
                lon=lons,
                mode="lines",
                line=dict(width=float(row["line_width"]), color=color),
                opacity=0.35 if row["severity"] == "medium" else 0.58,
                hovertemplate=hover,
                showlegend=False,
            )
        )

    for phase in animation_phases:
        frame_traces: List[go.Scattergeo] = []
        for _, row in flows.iterrows():
            pulse = 6 + phase * 8
            color = SEVERITY_COLORS.get(str(row["severity"]), "#7dd3fc")
            frame_traces.extend(
                [
                    go.Scattergeo(
                        lat=[row["source_latitude"]],
                        lon=[row["source_longitude"]],
                        mode="markers",
                        marker=dict(size=pulse, color=color, opacity=0.55),
                        hovertemplate=(
                            f"<b>{row['source_country']}</b><br>"
                            f"Source City: {row['source_city']}<br>"
                            f"Count: {int(row['count'])}<extra></extra>"
                        ),
                        showlegend=False,
                    ),
                    go.Scattergeo(
                        lat=[row["target_latitude"]],
                        lon=[row["target_longitude"]],
                        mode="markers",
                        marker=dict(size=pulse + 2, color=color, opacity=0.78),
                        hovertemplate=(
                            f"<b>{row['target_country']}</b><br>"
                            f"Target City: {row['target_city']}<br>"
                            f"Industry: {row['industry']}<extra></extra>"
                        ),
                        showlegend=False,
                    ),
                ]
            )
        frames.append(go.Frame(data=base_traces + frame_traces, name=f"pulse-{phase:.2f}"))

    fig = go.Figure(data=frames[0].data, frames=frames)
    fig.update_geos(
        projection_type="natural earth",
        showland=True,
        landcolor="#0f2f47",
        showcountries=True,
        countrycolor="#1f4f6a",
        showocean=True,
        oceancolor="#06111d",
        showcoastlines=True,
        coastlinecolor="#386b87",
        bgcolor="#06111d",
    )
    fig.update_layout(
        height=690,
        margin=dict(l=0, r=0, t=40, b=0),
        paper_bgcolor="#06111d",
        plot_bgcolor="#06111d",
        font=dict(color="#e8f2ff"),
        title="Global Attack Flow Map",
        updatemenus=[
            {
                "type": "buttons",
                "showactive": False,
                "x": 0.01,
                "y": 1.02,
                "buttons": [
                    {
                        "label": "Play",
                        "method": "animate",
                        "args": [None, {"frame": {"duration": 500, "redraw": True}, "transition": {"duration": 0}, "fromcurrent": True}],
                    }
                ],
            }
        ],
    )
    return fig


def _metric_card(title: str, value: str) -> None:
    st.markdown(
        f"""
        <div style="background:#0b1f33;border:1px solid #173b57;border-radius:12px;padding:12px 14px;margin-bottom:10px;">
            <div style="font-size:12px;color:#8fb6d5;text-transform:uppercase;letter-spacing:0.08em;">{title}</div>
            <div style="font-size:24px;color:#f4fbff;font-weight:700;">{value}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _scrolling_feed(feed: pd.DataFrame) -> None:
    if feed.empty:
        st.info("No live attacks available.")
        return
    items = []
    for _, row in feed.head(20).iterrows():
        items.append(
            f"""
            <div style="padding:8px 0;border-bottom:1px solid #173b57;">
                <div style="color:#f4fbff;font-size:13px;font-weight:600;">{row['threat_name']}</div>
                <div style="color:#9dc0db;font-size:12px;">{row['source_country']} -> {row['target_country']} | {row['industry']}</div>
                <div style="color:#7ea6c7;font-size:11px;">{row['timestamp']} | {row['severity'].upper()} | Volume {int(row['count'])}</div>
            </div>
            """
        )
    st.markdown(
        f"""
        <div style="max-height:320px;overflow-y:auto;background:#071726;border:1px solid #173b57;border-radius:12px;padding:10px;">
            {''.join(items)}
        </div>
        """,
        unsafe_allow_html=True,
    )


def _simple_table(df: pd.DataFrame, columns: List[str]) -> None:
    if df.empty:
        st.info("No data available.")
        return
    st.dataframe(df[columns], use_container_width=True, hide_index=True, height=min(320, 40 + len(df) * 35))


def main() -> None:
    setup_sidebar()
    _auto_refresh()

    st.title("Threat Map")
    st.caption("Flat 2D global threat map with animated attack flows. Click-to-filter is approximated with the country filter below because current Streamlit plot events are limited.")

    controls = st.columns([1, 1, 2])
    with controls[0]:
        selected_label = st.selectbox("Time Range", list(TIME_RANGE_OPTIONS.keys()), index=1)
    time_range = TIME_RANGE_OPTIONS[selected_label]

    flows_payload = AthenaAPIClient.get_threat_map_attack_flows(time_range=time_range)
    stats_payload = AthenaAPIClient.get_threat_map_stats(time_range=time_range)
    threats_payload = AthenaAPIClient.get_threat_map_top_threats(time_range=time_range)
    industries_payload = AthenaAPIClient.get_threat_map_top_industries(time_range=time_range)
    feed_payload = AthenaAPIClient.get_threat_map_live_feed(time_range=time_range)
    timeline_payload = AthenaAPIClient.get_threat_map_timeline(time_range=time_range)

    leaderboard = pd.DataFrame(flows_payload.get("leaderboard", [])) if isinstance(flows_payload, dict) else pd.DataFrame()
    country_options = ["All Countries"] + leaderboard["country"].tolist() if not leaderboard.empty else ["All Countries"]
    with controls[1]:
        selected_country = st.selectbox("Country Filter", country_options)
    country_filter = None if selected_country == "All Countries" else selected_country

    if country_filter:
        flows_payload = AthenaAPIClient.get_threat_map_attack_flows(time_range=time_range, country=country_filter)
        stats_payload = AthenaAPIClient.get_threat_map_stats(time_range=time_range, country=country_filter)
        threats_payload = AthenaAPIClient.get_threat_map_top_threats(time_range=time_range, country=country_filter)
        industries_payload = AthenaAPIClient.get_threat_map_top_industries(time_range=time_range, country=country_filter)
        feed_payload = AthenaAPIClient.get_threat_map_live_feed(time_range=time_range, country=country_filter)
        timeline_payload = AthenaAPIClient.get_threat_map_timeline(time_range=time_range, country=country_filter)
        leaderboard = pd.DataFrame(flows_payload.get("leaderboard", [])) if isinstance(flows_payload, dict) else pd.DataFrame()

    if "error" in flows_payload:
        st.error(flows_payload["error"])
        return

    flows = pd.DataFrame(flows_payload.get("data", []))
    threats = pd.DataFrame(threats_payload.get("data", [])) if isinstance(threats_payload, dict) else pd.DataFrame()
    industries = pd.DataFrame(industries_payload.get("data", [])) if isinstance(industries_payload, dict) else pd.DataFrame()
    feed = pd.DataFrame(feed_payload.get("data", [])) if isinstance(feed_payload, dict) else pd.DataFrame()
    timeline = pd.DataFrame(timeline_payload.get("data", [])) if isinstance(timeline_payload, dict) else pd.DataFrame()
    top_sources = pd.DataFrame(stats_payload.get("top_sources", [])) if isinstance(stats_payload, dict) else pd.DataFrame()
    top_targets = pd.DataFrame(stats_payload.get("top_targets", [])) if isinstance(stats_payload, dict) else pd.DataFrame()

    left, right = st.columns([3, 2])
    with left:
        metric_cols = st.columns(3)
        with metric_cols[0]:
            _metric_card("Total Attacks", f"{int(stats_payload.get('total_attacks', 0)):,}")
        with metric_cols[1]:
            _metric_card("Countries Affected", f"{int(stats_payload.get('countries_affected', 0)):,}")
        with metric_cols[2]:
            _metric_card("Critical Alerts", f"{int(stats_payload.get('critical_alerts', 0)):,}")

        st.plotly_chart(_build_map(flows), use_container_width=True, config={"displayModeBar": False})

        st.markdown("**Country Leaderboard**")
        _simple_table(leaderboard.head(15), ["country", "count"])

        if not timeline.empty:
            timeline["timestamp"] = pd.to_datetime(timeline["timestamp"], errors="coerce", utc=True)
            timeline_chart = go.Figure()
            for severity in ["critical", "high", "medium"]:
                subset = timeline[timeline["severity"] == severity]
                if subset.empty:
                    continue
                timeline_chart.add_trace(
                    go.Scatter(
                        x=subset["timestamp"],
                        y=subset["target_country"],
                        mode="markers",
                        marker=dict(size=10, color=SEVERITY_COLORS.get(severity, "#7dd3fc")),
                        name=severity.title(),
                        customdata=subset[["threat_name", "source_country", "count"]],
                        hovertemplate="<b>%{y}</b><br>%{customdata[0]}<br>From %{customdata[1]}<br>Volume %{customdata[2]}<extra></extra>",
                    )
                )
            timeline_chart.update_layout(
                title="Attack Timeline",
                height=300,
                paper_bgcolor="#06111d",
                plot_bgcolor="#06111d",
                font=dict(color="#e8f2ff"),
                margin=dict(l=10, r=10, t=40, b=10),
            )
            st.plotly_chart(timeline_chart, use_container_width=True, config={"displayModeBar": False})

    with right:
        st.markdown("**Top Threats**")
        _simple_table(threats.head(8), ["threat_name", "count"])

        st.markdown("**IPS Source / Target Countries**")
        src_col, dst_col = st.columns(2)
        with src_col:
            st.caption("Sources")
            _simple_table(top_sources.head(8), ["country", "count"])
        with dst_col:
            st.caption("Targets")
            _simple_table(top_targets.head(8), ["country", "count"])

        st.markdown("**Most Attacks**")
        if not leaderboard.empty:
            top_counts = leaderboard.head(8)
            bar = go.Figure(
                data=[
                    go.Bar(
                        x=top_counts["count"],
                        y=top_counts["country"],
                        orientation="h",
                        marker=dict(color="#2dd4bf"),
                    )
                ]
            )
            bar.update_layout(
                height=260,
                paper_bgcolor="#06111d",
                plot_bgcolor="#06111d",
                font=dict(color="#e8f2ff"),
                margin=dict(l=10, r=10, t=20, b=10),
            )
            st.plotly_chart(bar, use_container_width=True, config={"displayModeBar": False})

        st.markdown("**Top Targeted Industries**")
        _simple_table(industries.head(8), ["industry", "count"])

        st.markdown("**Real-Time Attacks**")
        _scrolling_feed(feed)


if __name__ == "__main__":
    main()
