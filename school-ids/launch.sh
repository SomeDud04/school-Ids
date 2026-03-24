#!/usr/bin/env bash
# =============================================================================
#  School Network IDS — Launcher Script
#  BMCS3413 Project II | TAR UMT
#  Usage: bash launch.sh
# =============================================================================

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m';  GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m';  BOLD='\033[1m';  RESET='\033[0m'

ok()   { echo -e "${GREEN}[+]${RESET} $*"; }
info() { echo -e "${CYAN}[*]${RESET} $*"; }
warn() { echo -e "${YELLOW}[!]${RESET} $*"; }
err()  { echo -e "${RED}[x]${RESET} $*"; }
hdr()  { echo -e "\n${BOLD}${BLUE}$*${RESET}"; }

# ── Paths ─────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_DIR="$SCRIPT_DIR/.pids"
LOG_DIR="$SCRIPT_DIR/logs"

mkdir -p "$PID_DIR" "$LOG_DIR" \
         "$SCRIPT_DIR/data" \
         "$SCRIPT_DIR/reports" \
         "$SCRIPT_DIR/captures"

DASHBOARD_PID="$PID_DIR/dashboard.pid"
CAPTURE_PID="$PID_DIR/capture.pid"
LEARNING_PID="$PID_DIR/learning.pid"
API_PID="$PID_DIR/api.pid"

# =============================================================================
#  HELPERS
# =============================================================================

check_root() {
    if [[ $EUID -ne 0 ]]; then
        err "This action requires root privileges."
        echo -e "    Run:  ${BOLD}sudo bash launch.sh${RESET}"
        exit 1
    fi
}

get_interface() {
    local iface
    iface=$(ip route get 8.8.8.8 2>/dev/null | awk '/dev/{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}')
    if [[ -z "$iface" ]]; then
        iface=$(ip -o link show | awk -F': ' '!/lo/{print $2; exit}')
    fi
    echo "$iface"
}

get_lan_ip() {
    ip route get 8.8.8.8 2>/dev/null | awk '/src/{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}'
}

is_running() {
    local pidfile="$1"
    [[ -f "$pidfile" ]] && kill -0 "$(cat "$pidfile")" 2>/dev/null
}

stop_pid() {
    local pidfile="$1"
    local label="$2"
    if is_running "$pidfile"; then
        kill "$(cat "$pidfile")" 2>/dev/null && ok "Stopped $label"
        rm -f "$pidfile"
    else
        warn "$label is not running."
        rm -f "$pidfile"
    fi
}

check_python_deps() {
    hdr "── Checking Python dependencies ──────────────────────────────"
    local missing=()
    for pkg in scapy dash plotly pandas jinja2 flask flask_cors; do
        if python3 -c "import $pkg" 2>/dev/null; then
            ok "$pkg"
        else
            err "$pkg  (missing)"
            missing+=("$pkg")
        fi
    done

    if python3 -c "import weasyprint" 2>/dev/null; then
        ok "weasyprint (optional — PDF reports)"
    else
        warn "weasyprint not installed (HTML reports will still work)"
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        echo ""
        warn "Missing packages detected. Run option [I] to install them."
        return 1
    fi
    ok "All required packages present."
    return 0
}

# =============================================================================
#  ACTIONS
# =============================================================================

action_install() {
    hdr "── Installing dependencies ────────────────────────────────────"
    info "Updating apt..."
    sudo apt-get update -qq
    info "Installing system packages..."
    sudo apt-get install -y python3 python3-pip nmap hping3 \
         libpango-1.0-0 libpangoft2-1.0-0 -qq
    info "Installing Python packages..."
    sudo pip3 install scapy dash plotly pandas jinja2 weasyprint flask flask-cors \
         --break-system-packages --quiet
    ok "Installation complete."
}

action_start_dashboard() {
    hdr "── Starting Dashboard ────────────────────────────────────────"
    if is_running "$DASHBOARD_PID"; then
        warn "Dashboard is already running (PID $(cat "$DASHBOARD_PID"))."
        info "Open: http://localhost:8050"
        return
    fi
    python3 "$SCRIPT_DIR/main.py" --dashboard \
        > "$LOG_DIR/dashboard.log" 2>&1 &
    echo $! > "$DASHBOARD_PID"
    sleep 1
    if is_running "$DASHBOARD_PID"; then
        ok "Dashboard started (PID $(cat "$DASHBOARD_PID"))"
        ok "Open in browser: http://localhost:8050"
        info "Log: $LOG_DIR/dashboard.log"
    else
        err "Dashboard failed to start. Check $LOG_DIR/dashboard.log"
    fi
}

action_stop_dashboard() {
    hdr "── Stopping Dashboard ────────────────────────────────────────"
    stop_pid "$DASHBOARD_PID" "Dashboard"
}

action_start_capture() {
    hdr "── Starting Packet Capture ───────────────────────────────────"
    check_root

    if is_running "$CAPTURE_PID"; then
        warn "Capture is already running (PID $(cat "$CAPTURE_PID"))."
        return
    fi

    local iface duration protocol
    iface=$(get_interface)

    echo ""
    echo -e "  Detected interface: ${BOLD}${iface}${RESET}"
    echo -e "  Available interfaces:"
    ip -o link show | awk -F': ' '{printf "    %s\n", $2}'
    echo ""
    read -rp "  Interface to capture on [${iface}]: " input
    iface="${input:-$iface}"

    read -rp "  Protocol filter (TCP/UDP/ICMP/all) [all]: " protocol
    protocol="${protocol:-all}"

    read -rp "  Capture duration in seconds [120]: " duration
    duration="${duration:-120}"

    echo ""
    info "Starting capture on '$iface' | protocol=$protocol | duration=${duration}s"
    info "Alerts will appear in real time below."
    info "Dashboard: http://localhost:8050"
    echo ""

    sudo python3 "$SCRIPT_DIR/main.py" \
        --interface "$iface" \
        --protocol  "$protocol" \
        --duration  "$duration" \
        --start &
    echo $! > "$CAPTURE_PID"

    wait "$(cat "$CAPTURE_PID")" 2>/dev/null || true
    rm -f "$CAPTURE_PID"
    ok "Capture session complete."
    info "Run option [R] to generate a report."
}

action_stop_capture() {
    hdr "── Stopping Capture ──────────────────────────────────────────"
    if is_running "$CAPTURE_PID"; then
        sudo kill "$(cat "$CAPTURE_PID")" 2>/dev/null
        rm -f "$CAPTURE_PID"
        ok "Capture stopped."
    else
        warn "No active capture process found."
    fi
}

action_flood_test() {
    hdr "── Attack Simulator ──────────────────────────────────────────"
    check_root

    local target iface
    target=$(get_lan_ip)
    iface=$(get_interface)

    echo ""
    info "Auto-detected LAN IP : $target"
    info "Auto-detected iface  : $iface"
    echo ""
    read -rp "  Target IP  [${target}]: " input_t
    target="${input_t:-$target}"
    read -rp "  Interface  [${iface}]: " input_i
    iface="${input_i:-$iface}"
    echo ""

    sudo python3 "$SCRIPT_DIR/flood_test.py" \
        --target    "$target" \
        --interface "$iface"
}

action_cli() {
    hdr "── Interactive CLI ───────────────────────────────────────────"
    python3 "$SCRIPT_DIR/cli.py"
}

action_learning_platform() {
    hdr "── Learning Platform ─────────────────────────────────────────"

    # ── Gemini API Key Setup ──────────────────────────────────────
    if [[ -z "${GEMINI_API_KEY:-}" ]]; then
        # Check if a key was saved from a previous run
        local key_file="$SCRIPT_DIR/.gemini_key"
        if [[ -f "$key_file" ]]; then
            GEMINI_API_KEY=$(cat "$key_file")
            ok "Loaded saved Gemini API key."
        else
            # Pre-configured key
            GEMINI_API_KEY="AIzaSyD27kdrdnbOgcvNLdeSlqqnhq755LU1geM"
            echo "$GEMINI_API_KEY" > "$key_file"
            chmod 600 "$key_file"
            ok "Gemini API key loaded."
        fi
    else
        ok "Gemini API key already set in environment."
    fi
    export GEMINI_API_KEY

    # Start API if not already running
    if is_running "$API_PID"; then
        info "IDS API already running (PID $(cat "$API_PID"))"
    else
        info "Starting IDS API on port 5000..."
        GEMINI_API_KEY="AIzaSyD27kdrdnbOgcvNLdeSlqqnhq755LU1geM" \
        python3 "$SCRIPT_DIR/api.py" \
            > "$LOG_DIR/api.log" 2>&1 &
        echo $! > "$API_PID"
        sleep 1
        if is_running "$API_PID"; then
            ok "IDS API started (PID $(cat "$API_PID"))  -> http://localhost:5000"
        else
            err "IDS API failed to start. Check $LOG_DIR/api.log"
            warn "Learning platform will run without live alert data."
        fi
    fi

    # Start HTTP server for the learning website
    if is_running "$LEARNING_PID"; then
        warn "Learning platform already running (PID $(cat "$LEARNING_PID"))."
        ok "Open in browser: http://localhost:8080/ids_learning.html"
        return
    fi

    info "Starting Learning Platform web server on port 8080..."
    python3 -m http.server 8080 \
        --directory "$SCRIPT_DIR" \
        > "$LOG_DIR/learning.log" 2>&1 &
    echo $! > "$LEARNING_PID"
    sleep 1

    if is_running "$LEARNING_PID"; then
        ok "Learning Platform started (PID $(cat "$LEARNING_PID"))"
        ok "Open in browser: http://localhost:8080/ids_learning.html"
        echo ""
        info "Tip: Start Packet Capture [2] first so Live Alerts shows real data!"
        xdg-open "http://localhost:8080/ids_learning.html" 2>/dev/null || true
    else
        err "Failed to start web server. Check $LOG_DIR/learning.log"
    fi
}

action_set_gemini_key() {
    hdr "── Set Gemini API Key ────────────────────────────────────────"
    local key_file="$SCRIPT_DIR/.gemini_key"
    echo ""
    echo -e "  Get a FREE key at: ${CYAN}https://aistudio.google.com/app/apikey${RESET}"
    echo ""
    if [[ -f "$key_file" ]]; then
        warn "A saved key already exists. Entering a new one will replace it."
    fi
    read -rp "  Paste your Gemini API key: " input_key
    if [[ -n "$input_key" ]]; then
        echo "$input_key" > "$key_file"
        chmod 600 "$key_file"
        export GEMINI_API_KEY="$input_key"
        ok "Key saved to .gemini_key and exported for this session."
    else
        warn "No key entered. Existing key unchanged."
    fi
}

action_report() {
    hdr "── Generating Report ─────────────────────────────────────────"
    echo ""
    echo "  [1] HTML report only"
    echo "  [2] HTML + PDF report"
    echo ""
    read -rp "  Choose [1]: " choice
    choice="${choice:-1}"

    if [[ "$choice" == "2" ]]; then
        python3 - <<'PYEOF'
from reporter import generate_pdf_report
generate_pdf_report()
PYEOF
    else
        python3 - <<'PYEOF'
from reporter import generate_html_report
generate_html_report()
PYEOF
    fi

    local html_path="$SCRIPT_DIR/reports/session_report.html"
    if [[ -f "$html_path" ]]; then
        ok "Report ready: $html_path"
        read -rp "  Open in browser now? (y/n) [y]: " open_it
        open_it="${open_it:-y}"
        [[ "$open_it" == "y" ]] && xdg-open "$html_path" 2>/dev/null || true
    fi
}

action_status() {
    hdr "── System Status ─────────────────────────────────────────────"
    echo ""

    if is_running "$DASHBOARD_PID"; then
        echo -e "  Dashboard   ${GREEN}RUNNING${RESET}  (PID $(cat "$DASHBOARD_PID"))  http://localhost:8050"
    else
        echo -e "  Dashboard   ${RED}STOPPED${RESET}"
    fi

    if is_running "$CAPTURE_PID"; then
        echo -e "  Capture     ${GREEN}RUNNING${RESET}  (PID $(cat "$CAPTURE_PID"))"
    else
        echo -e "  Capture     ${RED}STOPPED${RESET}"
    fi

    if is_running "$LEARNING_PID"; then
        echo -e "  Learning    ${GREEN}RUNNING${RESET}  (PID $(cat "$LEARNING_PID"))  http://localhost:8080/ids_learning.html"
    else
        echo -e "  Learning    ${RED}STOPPED${RESET}"
    fi

    if is_running "$API_PID"; then
        echo -e "  IDS API     ${GREEN}RUNNING${RESET}  (PID $(cat "$API_PID"))  http://localhost:5000"
    else
        echo -e "  IDS API     ${RED}STOPPED${RESET}"
    fi

    local key_file="$SCRIPT_DIR/.gemini_key"
    if [[ -n "${GEMINI_API_KEY:-}" ]]; then
        echo -e "  Gemini Key  ${GREEN}SET${RESET}  (from environment)"
    elif [[ -f "$key_file" ]]; then
        echo -e "  Gemini Key  ${GREEN}SAVED${RESET}  (from .gemini_key file)"
    else
        echo -e "  Gemini Key  ${YELLOW}NOT SET${RESET}  — AI Tutor will not work (press K to set)"
    fi

    echo ""
    echo -e "  ${BOLD}Network:${RESET}"
    echo -e "    Interface : $(get_interface)"
    echo -e "    LAN IP    : $(get_lan_ip)"

    echo ""
    echo -e "  ${BOLD}Data files:${RESET}"
    for f in data/packets.csv data/alerts.jsonl data/alerts.db data/summary.json; do
        local full="$SCRIPT_DIR/$f"
        if [[ -f "$full" ]]; then
            local size
            size=$(du -sh "$full" 2>/dev/null | cut -f1)
            echo -e "    ${GREEN}OK${RESET}  $f  ($size)"
        else
            echo -e "    ${YELLOW}--${RESET}  $f  (not created yet)"
        fi
    done

    local alert_count=0
    if [[ -f "$SCRIPT_DIR/data/alerts.jsonl" ]]; then
        alert_count=$(wc -l < "$SCRIPT_DIR/data/alerts.jsonl")
    fi
    echo ""
    echo -e "  Alerts logged: ${BOLD}${alert_count}${RESET}"
    echo ""
}

action_reset() {
    hdr "── Reset Session Data ────────────────────────────────────────"
    warn "This will delete all captured packets, alerts, and reports."
    read -rp "  Are you sure? (yes/no): " confirm
    if [[ "$confirm" != "yes" ]]; then
        info "Reset cancelled."
        return
    fi

    stop_pid "$DASHBOARD_PID" "Dashboard"        2>/dev/null || true
    stop_pid "$CAPTURE_PID"   "Capture"          2>/dev/null || true
    stop_pid "$LEARNING_PID"  "Learning Platform" 2>/dev/null || true
    stop_pid "$API_PID"       "IDS API"          2>/dev/null || true

    rm -f "$SCRIPT_DIR/data/packets.csv" \
          "$SCRIPT_DIR/data/alerts.jsonl" \
          "$SCRIPT_DIR/data/alerts.json" \
          "$SCRIPT_DIR/data/alerts.db" \
          "$SCRIPT_DIR/data/summary.json" \
          "$SCRIPT_DIR/logs/capture.log" \
          "$SCRIPT_DIR/captures/"*.pcap \
          "$SCRIPT_DIR/reports/"*.html \
          "$SCRIPT_DIR/reports/"*.pdf 2>/dev/null || true

    local key_file="$SCRIPT_DIR/.gemini_key"
    if [[ -f "$key_file" ]]; then
        read -rp "  Also delete saved Gemini API key? (y/n) [n]: " del_key
        del_key="${del_key:-n}"
        [[ "$del_key" == "y" ]] && rm -f "$key_file" && warn "Gemini key removed."
    fi

    ok "All session data cleared. Ready for a fresh run."
}

action_stop_all() {
    hdr "── Stopping All Services ─────────────────────────────────────"
    stop_pid "$DASHBOARD_PID" "Dashboard"
    stop_pid "$CAPTURE_PID"   "Capture"
    stop_pid "$LEARNING_PID"  "Learning Platform"
    stop_pid "$API_PID"       "IDS API"
    ok "All services stopped."
}

# =============================================================================
#  BANNER + MENU
# =============================================================================

print_banner() {
    clear
    echo -e "${BOLD}${BLUE}"
    echo "  ╔══════════════════════════════════════════════════════════════╗"
    echo "  ║   School Network Intrusion Detection System                  ║"
    echo "  ║   Detection Engine  •  Alert Logging  •  CLI                ║"
    echo "  ║   BMCS3413 Project II  |  TAR UMT                           ║"
    echo "  ╚══════════════════════════════════════════════════════════════╝"
    echo -e "${RESET}"

    local dash_status cap_status learn_status
    is_running "$DASHBOARD_PID" \
        && dash_status="${GREEN}RUNNING${RESET}" \
        || dash_status="${RED}STOPPED${RESET}"
    is_running "$CAPTURE_PID" \
        && cap_status="${GREEN}RUNNING${RESET}" \
        || cap_status="${RED}STOPPED${RESET}"
    is_running "$LEARNING_PID" \
        && learn_status="${GREEN}RUNNING${RESET}" \
        || learn_status="${RED}STOPPED${RESET}"

    echo -e "  Dashboard: $dash_status    Capture: $cap_status    Learning: $learn_status"
    echo -e "  Interface: $(get_interface)    LAN IP: $(get_lan_ip)"
    echo ""
}

main_menu() {
    print_banner
    echo -e "  ${BOLD}Setup${RESET}"
    echo    "  [I]  Install dependencies"
    echo    "  [C]  Check dependencies"
    echo ""
    echo -e "  ${BOLD}Run${RESET}"
    echo    "  [1]  Start Dashboard          (open http://localhost:8050)"
    echo    "  [2]  Start Packet Capture     (needs sudo)"
    echo    "  [3]  Run Attack Simulator     (needs sudo)"
    echo    "  [4]  Open Interactive CLI     (view logs, summary, export)"
    echo    "  [5]  Start Learning Platform  (open http://localhost:8080/ids_learning.html)"
    echo    "  [R]  Generate Report          (HTML / PDF)"
    echo ""
    echo -e "  ${BOLD}Manage${RESET}"
    echo    "  [S]  Show Status"
    echo    "  [K]  Set / Change Gemini API Key"
    echo    "  [X]  Stop All Services"
    echo    "  [Z]  Reset / Clear Session Data"
    echo    "  [Q]  Quit"
    echo ""
    read -rp "  Choose: " choice

    case "${choice^^}" in
        I)  action_install ;;
        C)  check_python_deps ;;
        1)  action_start_dashboard ;;
        2)  action_start_capture ;;
        3)  action_flood_test ;;
        4)  action_cli ;;
        5)  action_learning_platform ;;
        R)  action_report ;;
        K)  action_set_gemini_key ;;
        S)  action_status ;;
        X)  action_stop_all ;;
        Z)  action_reset ;;
        Q)  echo "Goodbye."; exit 0 ;;
        *)  warn "Invalid option." ;;
    esac

    echo ""
    read -rp "  Press Enter to return to menu..." _
}

# =============================================================================
#  ENTRY POINT
# =============================================================================

trap 'echo -e "\n${YELLOW}Interrupted. Returning to menu...${RESET}"' INT

while true; do
    main_menu
done