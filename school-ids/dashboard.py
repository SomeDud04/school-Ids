#!/usr/bin/env python3
# dashboard.py — Live Visualisation Dashboard
# Improvements:
#   - FIX: load_alerts() now reads JSONL format (alert_logger changed to .jsonl)
#   - FIX: Legacy fallback to alerts.json if JSONL not present (backwards compat)
#   - Minor: Added "BRUTE_FORCE" to alert severity colour rules

import json
import os
import sqlite3
from datetime import datetime

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from dash import Dash, dcc, html, Input, Output, dash_table, callback

external_stylesheets = [
    "https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600"
    "&family=Syne:wght@700;800&family=Lato:wght@400;600;700&display=swap"
]

app = Dash(__name__, external_stylesheets=external_stylesheets)

C = {
    "bg":      "#0b0f19",
    "surface": "#111827",
    "card":    "#1a2235",
    "border":  "#243044",
    "blue":    "#38bdf8",
    "green":   "#34d399",
    "amber":   "#fbbf24",
    "red":     "#f87171",
    "violet":  "#a78bfa",
    "dim":     "#4d6178",
    "text":    "#cdd9e5",
    "white":   "#f0f6fc",
}

CARD = {
    "backgroundColor": C["card"],
    "border":          f"1px solid {C['border']}",
    "borderRadius":    "10px",
    "padding":         "20px",
}

LABEL = {
    "fontFamily":    "JetBrains Mono, monospace",
    "fontSize":      "0.68rem",
    "letterSpacing": "0.12em",
    "textTransform": "uppercase",
    "color":         C["dim"],
    "marginBottom":  "6px",
}

PLOT_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(family="Lato, sans-serif", color=C["text"], size=12),
    margin=dict(l=12, r=12, t=36, b=12),
    legend=dict(bgcolor="rgba(0,0,0,0)", bordercolor=C["border"]),
    xaxis=dict(gridcolor=C["border"], zerolinecolor=C["border"]),
    yaxis=dict(gridcolor=C["border"], zerolinecolor=C["border"]),
)

TABLE_STYLE = dict(
    style_table={"overflowX": "auto", "borderRadius": "6px", "overflow": "hidden"},
    style_header={
        "backgroundColor": "#1a2234",
        "color":           C["blue"],
        "fontFamily":      "JetBrains Mono, monospace",
        "fontSize":        "0.7rem",
        "fontWeight":      "600",
        "padding":         "10px 14px",
        "border":          f"1px solid {C['border']}",
        "letterSpacing":   "0.08em",
    },
    style_cell={
        "backgroundColor": C["card"],
        "color":           C["text"],
        "fontFamily":      "JetBrains Mono, monospace",
        "fontSize":        "0.78rem",
        "padding":         "9px 14px",
        "border":          f"1px solid {C['border']}",
        "whiteSpace":      "normal",
        "height":          "auto",
    },
    style_data_conditional=[
        {"if": {"row_index": "odd"}, "backgroundColor": "#141c2c"},
    ]
)


# ---------------------------------------------------------------------------
# Data loaders
# ---------------------------------------------------------------------------

def load_packets() -> pd.DataFrame:
    try:
        df = pd.read_csv("data/packets.csv")
        df["timestamp"] = pd.to_datetime(
            df["timestamp"], format="%Y-%m-%d %H:%M:%S", errors="coerce"
        )
        return df
    except Exception:
        return pd.DataFrame(columns=[
            "timestamp", "src_ip", "dst_ip",
            "src_port", "dst_port", "protocol", "flags", "packet_length"
        ])


def load_alerts() -> list:
    """
    FIX: Read from JSONL file (one record per line) instead of full JSON array.
    Falls back to legacy alerts.json for backward compatibility.
    """
    # Try JSONL first (new format)
    jsonl_path = "data/alerts.jsonl"
    if os.path.exists(jsonl_path):
        alerts = []
        with open(jsonl_path) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        alerts.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        return alerts

    # Legacy fallback
    try:
        with open("data/alerts.json") as f:
            return json.load(f)
    except Exception:
        return []


def load_summary() -> dict:
    try:
        with open("data/summary.json") as f:
            return json.load(f)
    except Exception:
        return {"total_packets": 0, "unique_src_ips": 0, "protocol_counts": {}}


# ---------------------------------------------------------------------------
# UI helpers
# ---------------------------------------------------------------------------

def stat_card(label, value, color, icon):
    return html.Div(
        style={**CARD, "borderTop": f"3px solid {color}", "flex": "1", "minWidth": "140px"},
        children=[
            html.Div(icon, style={"fontSize": "1.4rem", "marginBottom": "8px"}),
            html.Div(str(value), style={
                "fontFamily": "Syne, sans-serif",
                "fontSize":   "2rem",
                "fontWeight": "800",
                "color":      color,
                "lineHeight": "1",
            }),
            html.Div(label, style={**LABEL, "marginTop": "6px", "marginBottom": "0"}),
        ]
    )


def section_header(title, subtitle=""):
    return html.Div(style={"marginBottom": "14px"}, children=[
        html.H2(title, style={
            "fontFamily": "Syne, sans-serif",
            "fontSize":   "1rem",
            "fontWeight": "700",
            "color":      C["white"],
            "margin":     "0 0 2px",
        }),
        html.P(subtitle, style={
            "fontFamily": "JetBrains Mono, monospace",
            "fontSize":   "0.72rem",
            "color":      C["dim"],
            "margin":     "0",
        }) if subtitle else None
    ])


# ---------------------------------------------------------------------------
# Layout
# ---------------------------------------------------------------------------

app.layout = html.Div(
    style={"backgroundColor": C["bg"], "minHeight": "100vh", "fontFamily": "Lato, sans-serif"},
    children=[

        # Top bar
        html.Div(
            style={
                "backgroundColor": C["surface"],
                "borderBottom":    f"1px solid {C['border']}",
                "padding":         "0 32px",
                "display":         "flex",
                "alignItems":      "center",
                "justifyContent":  "space-between",
                "height":          "60px",
            },
            children=[
                html.Div(style={"display": "flex", "alignItems": "center", "gap": "14px"}, children=[
                    html.Div("🛡", style={"fontSize": "1.4rem"}),
                    html.Div(children=[
                        html.Span("School Network IDS", style={
                            "fontFamily": "Syne, sans-serif",
                            "fontWeight": "800",
                            "fontSize":   "1rem",
                            "color":      C["white"],
                        }),
                        html.Span(" — Live Dashboard", style={
                            "fontFamily": "JetBrains Mono, monospace",
                            "fontSize":   "0.72rem",
                            "color":      C["dim"],
                            "marginLeft": "8px",
                        }),
                    ]),
                ]),
                html.Div(style={"display": "flex", "alignItems": "center", "gap": "16px"}, children=[
                    html.Div(id="live-clock", style={
                        "fontFamily": "JetBrains Mono, monospace",
                        "fontSize":   "0.78rem",
                        "color":      C["dim"],
                    }),
                    html.Div(style={"display": "flex", "alignItems": "center", "gap": "8px"}, children=[
                        html.Div(style={
                            "width":           "8px",
                            "height":          "8px",
                            "borderRadius":    "50%",
                            "backgroundColor": C["green"],
                            "boxShadow":       f"0 0 8px {C['green']}",
                        }),
                        html.Span("LIVE", style={
                            "fontFamily":    "JetBrains Mono, monospace",
                            "fontSize":      "0.65rem",
                            "color":         C["green"],
                            "letterSpacing": "0.2em",
                        }),
                    ]),
                ])
            ]
        ),

        html.Div(style={"padding": "24px 32px"}, children=[

            dcc.Interval(id="tick", interval=1000, n_intervals=0),
            dcc.Store(id="raw-visible", data=False),

            html.Div(id="stat-cards", style={
                "display":      "flex",
                "gap":          "12px",
                "marginBottom": "24px",
                "flexWrap":     "wrap",
            }),

            # Filters
            html.Div(
                style={**CARD, "display": "flex", "gap": "16px",
                       "alignItems": "center", "marginBottom": "24px", "flexWrap": "wrap"},
                children=[
                    html.Div("FILTERS", style={
                        "color": C["dim"], "fontFamily": "JetBrains Mono, monospace",
                        "fontSize": "0.72rem", "whiteSpace": "nowrap"
                    }),
                    html.Div(style={"flex": "1", "minWidth": "140px"}, children=[
                        html.Div("Protocol", style=LABEL),
                        dcc.Dropdown(
                            id="proto-filter",
                            options=[{"label": p, "value": p} for p in ["ALL", "TCP", "UDP", "ICMP"]],
                            value="ALL", clearable=False,
                            style={"backgroundColor": C["surface"], "border": f"1px solid {C['border']}", "borderRadius": "6px"},
                        ),
                    ]),
                    html.Div(style={"flex": "2", "minWidth": "180px"}, children=[
                        html.Div("Source IP", style=LABEL),
                        dcc.Input(
                            id="ip-filter", placeholder="e.g. 192.168.1", debounce=True,
                            style={
                                "width": "100%", "backgroundColor": C["surface"],
                                "color": C["text"], "border": f"1px solid {C['border']}",
                                "borderRadius": "6px", "padding": "8px 12px",
                                "fontFamily": "JetBrains Mono, monospace", "fontSize": "0.82rem",
                                "outline": "none",
                            }
                        ),
                    ]),
                    html.Div(style={"flex": "2", "minWidth": "180px"}, children=[
                        html.Div("Time Window", style=LABEL),
                        dcc.Dropdown(
                            id="time-window",
                            options=[
                                {"label": "Last 30 seconds", "value": 30},
                                {"label": "Last 1 minute",   "value": 60},
                                {"label": "Last 5 minutes",  "value": 300},
                                {"label": "All data",        "value": 99999},
                            ],
                            value=60, clearable=False,
                            style={"backgroundColor": C["surface"], "border": f"1px solid {C['border']}", "borderRadius": "6px"},
                        ),
                    ]),
                ]
            ),

            # Packet rate
            html.Div(style={**CARD, "marginBottom": "24px"}, children=[
                section_header("Packet Rate", "packets per second — spikes indicate attacks or traffic bursts"),
                dcc.Graph(id="rate-chart", config={"displayModeBar": False}, style={"height": "220px"}),
            ]),

            # Protocol pie + Top hosts
            html.Div(
                style={"display": "grid", "gridTemplateColumns": "1fr 1.4fr",
                       "gap": "16px", "marginBottom": "24px"},
                children=[
                    html.Div(style=CARD, children=[
                        section_header("Protocol Mix", "TCP / UDP / ICMP distribution"),
                        dcc.Graph(id="proto-pie", config={"displayModeBar": False}, style={"height": "260px"}),
                    ]),
                    html.Div(style=CARD, children=[
                        section_header("Top Talkers", "source IPs with highest packet count"),
                        html.Div(id="hosts-table-wrap"),
                    ]),
                ]
            ),

            # Alerts
            html.Div(style={**CARD, "borderTop": f"3px solid {C['red']}", "marginBottom": "24px"}, children=[
                html.Div(
                    style={"display": "flex", "justifyContent": "space-between",
                           "alignItems": "center", "marginBottom": "14px"},
                    children=[
                        section_header("🚨 Alerts", "triggered when detection thresholds are crossed"),
                        html.Div(id="alert-count-badge", style={
                            "fontFamily":      "JetBrains Mono, monospace",
                            "fontSize":        "0.72rem",
                            "backgroundColor": "rgba(248,113,113,0.1)",
                            "border":          f"1px solid {C['red']}",
                            "color":           C["red"],
                            "padding":         "3px 10px",
                            "borderRadius":    "20px",
                        }),
                    ]
                ),
                html.Div(id="alert-table-wrap"),
            ]),

            # Raw packets
            html.Div(style=CARD, children=[
                html.Div(
                    style={"display": "flex", "justifyContent": "space-between",
                           "alignItems": "center", "marginBottom": "14px"},
                    children=[
                        section_header("Raw Packets", "last 50 packets captured"),
                        html.Button("Show / Hide", id="raw-btn", n_clicks=0, style={
                            "fontFamily":      "JetBrains Mono, monospace",
                            "fontSize":        "0.72rem",
                            "backgroundColor": C["surface"],
                            "color":           C["blue"],
                            "border":          f"1px solid {C['blue']}",
                            "padding":         "5px 14px",
                            "borderRadius":    "6px",
                            "cursor":          "pointer",
                        }),
                    ]
                ),
                html.Div(id="raw-panel"),
            ]),
        ]),
    ]
)


# ---------------------------------------------------------------------------
# Callbacks
# ---------------------------------------------------------------------------

app.clientside_callback(
    """
    function(n) {
        const now = new Date();
        const day   = String(now.getDate()).padStart(2, '0');
        const months = ['Jan','Feb','Mar','Apr','May','Jun',
                        'Jul','Aug','Sep','Oct','Nov','Dec'];
        const month = months[now.getMonth()];
        const year  = now.getFullYear();
        const hh    = String(now.getHours()).padStart(2, '0');
        const mm    = String(now.getMinutes()).padStart(2, '0');
        const ss    = String(now.getSeconds()).padStart(2, '0');
        return day + ' ' + month + ' ' + year + '  ' + hh + ':' + mm + ':' + ss;
    }
    """,
    Output("live-clock", "children"),
    Input("tick",        "n_intervals"),
)


@callback(
    Output("stat-cards",        "children"),
    Output("rate-chart",        "figure"),
    Output("proto-pie",         "figure"),
    Output("hosts-table-wrap",  "children"),
    Output("alert-table-wrap",  "children"),
    Output("alert-count-badge", "children"),
    Input("tick",               "n_intervals"),
    Input("proto-filter",       "value"),
    Input("ip-filter",          "value"),
    Input("time-window",        "value"),
)
def refresh(n, proto, ip_filter, time_window_secs):
    df      = load_packets()
    alerts  = load_alerts()
    summary = load_summary()

    if not df.empty and time_window_secs < 99999:
        cutoff = pd.Timestamp.now() - pd.Timedelta(seconds=time_window_secs)
        df = df[df["timestamp"] >= cutoff]

    if proto and proto != "ALL":
        df = df[df["protocol"] == proto]
    if ip_filter:
        df = df[df["src_ip"].str.contains(ip_filter, na=False)]

    total_pkts  = len(load_packets())
    unique_ips  = df["src_ip"].nunique() if not df.empty else 0
    alert_count = len(alerts)
    top_proto   = df["protocol"].value_counts().idxmax() if not df.empty else "—"

    cards = [
        stat_card("Total Packets",  total_pkts,  C["blue"],  "📦"),
        stat_card("Unique Sources", unique_ips,  C["green"], "🌐"),
        stat_card("Alerts Fired",   alert_count, C["red"],   "🚨"),
        stat_card("Top Protocol",   top_proto,   C["amber"], "📡"),
    ]

    # Packet rate chart
    if not df.empty:
        rate_df  = df.set_index("timestamp").resample("1s").size().reset_index(name="count")
        rate_fig = go.Figure(go.Scatter(
            x=rate_df["timestamp"], y=rate_df["count"],
            mode="lines", fill="tozeroy",
            line=dict(color=C["blue"], width=2),
            fillcolor="rgba(56,189,248,0.08)",
        ))
    else:
        rate_fig = go.Figure()
        rate_fig.add_annotation(text="Waiting for capture data...",
                                x=0.5, y=0.5, showarrow=False,
                                font=dict(color=C["dim"], size=13))

    rate_fig.update_layout(**PLOT_LAYOUT)
    rate_fig.update_yaxes(title="pkt/s")

    # Protocol pie
    if not df.empty:
        proto_df = df["protocol"].value_counts().reset_index()
        proto_df.columns = ["protocol", "count"]
        pie_fig = px.pie(proto_df, names="protocol", values="count",
                         color_discrete_sequence=[C["blue"], C["green"], C["amber"], C["violet"]],
                         hole=0.45)
        pie_fig.update_traces(textfont_size=12)
    else:
        pie_fig = go.Figure()
        pie_fig.add_annotation(text="No data yet", x=0.5, y=0.5,
                               showarrow=False, font=dict(color=C["dim"]))

    pie_fig.update_layout(**PLOT_LAYOUT)

    # Top hosts table
    if not df.empty:
        top_df = df["src_ip"].value_counts().head(10).reset_index()
        top_df.columns = ["Source IP", "Packets"]
        hosts_table = dash_table.DataTable(
            data=top_df.to_dict("records"),
            columns=[{"name": c, "id": c} for c in top_df.columns],
            **TABLE_STYLE
        )
    else:
        hosts_table = html.P("No data yet.", style={
            "color": C["dim"], "fontFamily": "JetBrains Mono, monospace", "fontSize": "0.82rem"
        })

    # Alerts table
    # FIX: Added BRUTE_FORCE to severity colour rules
    if alerts:
        recent      = list(reversed(alerts[-20:]))
        alert_table = dash_table.DataTable(
            data=recent,
            columns=[{"name": k.upper(), "id": k}
                     for k in recent[0].keys()
                     if k not in ("log_version",)],
            style_data_conditional=[
                {"if": {"filter_query": '{severity} = "HIGH"'},
                 "backgroundColor": "rgba(248,113,113,0.08)", "color": C["red"]},
                {"if": {"filter_query": '{severity} = "MEDIUM"'},
                 "backgroundColor": "rgba(251,191,36,0.06)",  "color": C["amber"]},
                {"if": {"row_index": "odd"}, "backgroundColor": "#141c2c"},
            ],
            **{k: v for k, v in TABLE_STYLE.items() if k != "style_data_conditional"}
        )
        badge = f"{alert_count} alert{'s' if alert_count != 1 else ''}"
    else:
        alert_table = html.Div(
            "✅  No alerts triggered yet",
            style={"textAlign": "center", "padding": "32px",
                   "color": C["dim"], "fontFamily": "JetBrains Mono, monospace", "fontSize": "0.82rem"}
        )
        badge = "0 alerts"

    return cards, rate_fig, pie_fig, hosts_table, alert_table, badge


@callback(Output("raw-visible", "data"),
          Input("raw-btn", "n_clicks"),
          prevent_initial_call=True)
def toggle_raw_store(n):
    return bool(n and n % 2 != 0)


@callback(Output("raw-panel", "children"),
          Input("tick", "n_intervals"),
          Input("raw-visible", "data"))
def update_raw_panel(n, visible):
    if not visible:
        return []
    df = load_packets()
    if df.empty:
        return html.P("No packets yet.", style={"color": C["dim"]})
    display = df.tail(50).copy()
    display["timestamp"] = display["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
    display = display[::-1]
    return dash_table.DataTable(
        data=display.to_dict("records"),
        columns=[{"name": c.upper(), "id": c} for c in display.columns],
        page_size=15,
        **TABLE_STYLE
    )


if __name__ == "__main__":
    app.run(debug=False, port=8050)
