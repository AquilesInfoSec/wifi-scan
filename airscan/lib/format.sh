#!/system/bin/sh

# format.sh - Output formatting for airscan

# --- ANSI Colors ---
R='\033[0;31m'
G='\033[0;32m'
Y='\033[1;33m'
B='\033[0;34m'
M='\033[0;35m'
C='\033[0;36m'
W='\033[1;37m'
D='\033[2;37m'
N='\033[0m'

# Security colors
CRIT='\033[41m\033[1;37m'
WARN='\033[43m\033[1;30m'
SAFE='\033[42m\033[1;30m'
INFO='\033[44m\033[1;37m'

BOLD='\033[1m'
DIM='\033[2m'
BLINK='\033[5m'

BAR_CHAR='#'
BAR_EMPTY='.'

colorize() {
  local color="$1" text="$2"
  echo -e "${color}${text}${N}"
}

security_badge() {
  local enc="$1"
  case "$enc" in
    *WPA3*|*SAE*)     echo -e "${SAFE} WPA3 ${N}" ;;
    *WPA2*|*CCMP*)    echo -e "${SAFE}WPA2${N}" ;;
    *WPA*|*TKIP*)     echo -e "${WARN} WPA ${N}" ;;
    *WEP*)            echo -e "${CRIT} WEP ${N}" ;;
    *OPEN*|*NONE*)    echo -e "${CRIT}OPEN${N}" ;;
    *WPS*)            echo -e "${WARN} WPS ${N}" ;;
    *OWE*)            echo -e "${SAFE} OWE ${N}" ;;
    *)                echo -e "${WARN} ??  ${N}" ;;
  esac
}

signal_bar() {
  local rssi="$1" width="${2:-10}"
  local level
  if [ "$rssi" -ge -50 ]; then
    level=$((width * 4 / 4))
  elif [ "$rssi" -ge -60 ]; then
    level=$((width * 3 / 4))
  elif [ "$rssi" -ge -70 ]; then
    level=$((width * 2 / 4))
  elif [ "$rssi" -ge -80 ]; then
    level=$((width * 1 / 4))
  else
    level=0
  fi

  local filled=""; local empty=""
  for i in $(seq 1 $level); do filled="${filled}${BAR_CHAR}"; done
  for i in $(seq 1 $((width - level))); do empty="${empty}${BAR_EMPTY}"; done

  if [ "$rssi" -ge -50 ]; then
    echo -e "${G}${filled}${D}${empty}${N}"
  elif [ "$rssi" -ge -70 ]; then
    echo -e "${Y}${filled}${D}${empty}${N}"
  else
    echo -e "${R}${filled}${D}${empty}${N}"
  fi
}

print_banner() {
  local tool_name="${1:-airscan}"
  local version="${2:-1.0}"
  clear 2>/dev/null || true
  echo -e "${M}"
  echo "  ╔══════════════════════════════════════════╗"
  echo "  ║          ${W}airscan v${version}${M}                ║"
  echo "  ║     ${D}Wi-Fi Reconnaissance Scanner${M}        ║"
  echo "  ║     ${D}for Termux / Android${M}                 ║"
  echo "  ╚══════════════════════════════════════════╝"
  echo -e "${N}"
}

print_separator() {
  local char="${1:-─}"
  printf '%*s' 56 '' | tr ' ' "${char:0:1}"
}

print_header() {
  local title="$1"
  echo
  echo -e "${BOLD}${C}:: ${title}${N}"
  print_separator
}

print_key_value() {
  local key="$1" value="$2" color_key="${3:-$W}" color_val="${4:-$N}"
  printf "${color_key}%-20s${N} : ${color_val}%s${N}\n" "$key" "$value"
}

print_row() {
  printf "  ${W}%-22s${N} ${G}%-6s${N} ${Y}%-5s${N} ${C}%-4s${N} ${B}%-18s${N} %s\n" "$@"
}

print_network_compact() {
  local ssid="$1" bssid="$2" chan="$3" rssi="$4" enc="$5" freq="$6"
  local enc_badge; enc_badge=$(security_badge "$enc")
  local sbar; sbar=$(signal_bar "$rssi" 8)
  local ssid_trunc="${ssid:0:22}"
  printf "  ${W}%-22s${N} ${G}%-6s${N} ${Y}ch%-3s${N} ${C}%+4d${N} %s %s\n" \
    "$ssid_trunc" "$bssid" "$chan" "$rssi" "$enc_badge" "$sbar"
}

print_section() {
  local title="$1"
  echo
  echo -e "${BOLD}${C}┌─ ${title}${N}"
  echo -e "${BOLD}${C}│${N}"
}

print_end_section() {
  echo -e "${BOLD}${C}│${N}"
  echo -e "${BOLD}${C}└─${N}"
}

# --- Full network details display ---
show_networks() {
  local data="${1:-$NETWORKS}"
  local total
  total=$(echo "$data" | jq 'length' 2>/dev/null || echo 0)
  [ "$total" -eq 0 ] && {
    echo -e "  ${Y}No networks found.${N}"
    return
  }

  print_header "Scan Results"
  echo -e "  ${D}Scanner:${N} $(get_scanner_info)     ${D}Networks:${N} ${W}$total${N}"
  echo -e "  ${D}Time:${N}    $LAST_SCAN_TIME"
  echo

  local idx=0
  echo "$data" | jq -c '.[]' 2>/dev/null | while read -r net; do
    idx=$((idx + 1))

    local ssid bssid freq level caps
    ssid=$(echo "$net" | jq -r '.ssid // "(hidden)"')
    bssid=$(echo "$net" | jq -r '.bssid // "00:00:00:00:00:00"')
    freq=$(echo "$net" | jq -r '.frequency // "0"')
    level=$(echo "$net" | jq -r '.level // "0"')
    caps=$(echo "$net" | jq -r '.capabilities // ""')

    local chan band enc vendor qual pct dist width wps
    chan=$(freq_to_channel "$freq")
    band=$(freq_to_band "$freq")
    enc=$(parse_encryption "$caps")
    wps=$(echo "$caps" | tr ',' ' ' | grep -qi "WPS" && echo "WPS" || echo "")
    vendor=$(oui_vendor "$bssid")
    qual=$(signal_quality "$level")
    pct=$(rssi_to_percent "$level")
    dist=$(estimate_distance "$level")
    width=$(detect_channel_width "$freq" "$chan")
    ntype=$(guess_network_type "$ssid" "$enc")

    echo -e "  ${BOLD}${W}[${idx}]${N} ${BOLD}${G}$ssid${N}"
    echo "      ${D}BSSID:${N}      $bssid"
    echo "      ${D}Vendor:${N}     ${vendor:-Unknown}"
    echo "      ${D}Channel:${N}    $chan ($band, $width)"
    echo "      ${D}Freq:${N}       ${freq}MHz"
    echo "      ${D}Signal:${N}     ${level}dBm ($qual, ${pct}%)  $(signal_bar "$level" 12)"
    echo "      ${D}Distance:${N}   $dist"
    echo "      ${D}Encryption:${N} $(security_badge "$enc")  ${wps:+${WARN}WPS${N} }"
    echo "      ${D}Type:${N}       $ntype"

    if [ -n "$vendor" ] && [ "$vendor" != "Unknown" ]; then
      echo "      ${D}Risk:${N}       $(assess_risk "$enc" "$wps" | cut -d'|' -f1)"
    fi
    echo
  done
}

# --- Compact summary display ---
show_summary() {
  local data="${1:-$NETWORKS}"
  local total
  total=$(echo "$data" | jq 'length' 2>/dev/null || echo 0)
  [ "$total" -eq 0 ] && {
    echo -e "  ${Y}No networks found.${N}"
    return
  }

  print_header "Networks Summary"
  echo -e "  ${D}Total:${N} ${W}$total${N}  |  ${D}Scanner:${N} $(get_scanner_info)  |  ${D}Time:${N} $LAST_SCAN_TIME"
  echo
  echo "$data" | jq -c '.[]' 2>/dev/null | while read -r net; do
    local ssid bssid freq level caps
    ssid=$(echo "$net" | jq -r '.ssid // "(hidden)"')
    bssid=$(echo "$net" | jq -r '.bssid // "00:00:00:00:00:00"')
    freq=$(echo "$net" | jq -r '.frequency // "0"')
    level=$(echo "$net" | jq -r '.level // "0"')
    caps=$(echo "$net" | jq -r '.capabilities // ""')
    local chan enc
    chan=$(freq_to_channel "$freq")
    enc=$(parse_encryption "$caps")
    print_network_compact "$ssid" "$bssid" "$chan" "$level" "$enc" "$freq"
  done
}
