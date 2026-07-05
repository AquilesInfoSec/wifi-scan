#!/system/bin/sh

# scanner.sh - Wi-Fi scanning module for airscan

SCAN_RESULTS=""
SCAN_COUNT=0
SCAN_TIMESTAMP=""
SCANNER_TYPE=""

# --- Source detection ---
detect_scanner() {
  # Priority: termux-wifi-scaninfo → iw → nmcli
  if command -v termux-wifi-scaninfo >/dev/null 2>&1; then
    echo "termux"
  elif command -v iw >/dev/null 2>&1 && iw dev 2>/dev/null | grep -q "Interface"; then
    echo "iw"
  elif command -v nmcli >/dev/null 2>&1; then
    echo "nmcli"
  elif [ -f /proc/net/wireless ] && grep -q ":" /proc/net/wireless 2>/dev/null; then
    echo "proc"
  else
    echo "none"
  fi
}

# --- Scan using termux-wifi-scaninfo ---
scan_termux() {
  termux-wifi-scaninfo 2>/dev/null
}

# --- Scan using iw ---
scan_iw() {
  local iface devs results
  devs=$(iw dev 2>/dev/null | awk '/Interface/ {print $2}')
  [ -z "$devs" ] && return 1

  results="["
  local first=true
  for iface in $devs; do
    local scan_out
    scan_out=$(iw dev "$iface" scan 2>/dev/null) || continue

    local bssid="" ssid="" freq="" signal="" caps="" ts=""
    local entry=""
    IFS=';'  # temporary

    echo "$scan_out" | while IFS= read -r line; do
      line=$(echo "$line" | sed 's/^[[:space:]]*//')

      case "$line" in
        BSS\ *)
          [ -n "$bssid" ] && {
            entry=$(termux_entry "$bssid" "$ssid" "$freq" "$signal" "$caps" "$ts")
            echo "$entry"
          }
          bssid=$(echo "$line" | awk '{print $2}' | tr '[:upper:]' '[:lower:]')
          ssid=""; freq=""; signal=""; caps=""; ts=$(date +%s%N)
          ;;
        *SSID:*)
          ssid=$(echo "$line" | sed 's/.*SSID: //')
          ;;
        *freq:*)
          freq=$(echo "$line" | sed 's/.*freq: //')
          ;;
        *signal:*)
          signal=$(echo "$line" | sed 's/.*signal: //' | awk '{print $1}')
          ;;
        *capabilities:*)
          # skip; not useful
          ;;
        *RSN:*|*WPA:*)
          caps="$caps [WPA2]"
          ;;
        *WPA1:*|*WPA:*)
          caps="$caps [WPA]"
          ;;
        *WEP:*)
          caps="$caps [WEP]"
          ;;
        *Group\ cipher:*)
          ciph=$(echo "$line" | awk '{print $3}')
          caps="$caps $ciph"
          ;;
        *Pairwise\ cipher:*)
          ciph=$(echo "$line" | awk '{print $3}')
          caps="$caps $ciph"
          ;;
        *Authentication\ suites:*)
          auth=$(echo "$line" | awk '{print $3}')
          caps="$caps $auth"
          ;;
        *WPS:*)
          caps="$caps [WPS]"
          ;;
      esac
    done

    [ -n "$bssid" ] && {
      entry=$(termux_entry "$bssid" "$ssid" "$freq" "$signal" "$caps" "$ts")
      echo "$entry"
    }
  done | jq -s '.' 2>/dev/null
}

# --- Build a JSON entry (termux-compatible format) ---
termux_entry() {
  local bssid="$1" ssid="$2" freq="$3" level="$4" caps="$5" ts="$6"
  [ -z "$ssid" ] && ssid=""
  [ -z "$freq" ] && freq="0"
  [ -z "$level" ] && level="0"
  [ -z "$caps" ] && caps=""
  [ -z "$ts" ] && ts="0"

  jq -n \
    --arg ssid "$ssid" \
    --arg bssid "$bssid" \
    --arg frequency "$freq" \
    --arg level "$level" \
    --arg capabilities "$caps" \
    --argjson timestamp "$ts" \
    '{ssid: $ssid, bssid: $bssid, frequency: $frequency, level: ($level|tonumber), capabilities: $capabilities, timestamp: $timestamp}' 2>/dev/null
}

# --- Scan using nmcli ---
scan_nmcli() {
  nmcli -t -f SSID,BSSID,CHAN,FREQ,RATE,SIGNAL,SECURITY device wifi list 2>/dev/null | while IFS=':' read -r ssid bssid chan freq rate signal sec; do
    [ -z "$ssid" ] && ssid=""
    [ -z "$sec" ] && sec="[ESS]"
    [ -z "$freq" ] && freq=0
    [ -z "$signal" ] && signal=0
    echo "$(termux_entry "$ssid" "$bssid" "$freq" "$signal" "$sec" "$(date +%s%N)")"
  done | jq -s '.' 2>/dev/null
}

# --- Scan using /proc/net/wireless (very basic) ---
scan_proc() {
  local results="[]"
  local iface

  if [ ! -f /proc/net/wireless ]; then
    echo "$results"; return
  fi

  iface=$(awk 'NR==3 {print $1}' /proc/net/wireless 2>/dev/null | tr -d ':')
  [ -z "$iface" ] && echo "$results" && return

  # ssid?? not available from /proc/net/wireless, need iw
  if command -v iw >/dev/null 2>&1; then
    scan_iw
  else
    echo "$results"
  fi
}

# --- Main scanning function ---
do_scan() {
  local scanner
  scanner=$(detect_scanner)
  SCANNER_TYPE="$scanner"

  if [ "$scanner" = "none" ]; then
    echo '[]'
    return 1
  fi

  local raw=""
  case "$scanner" in
    termux) raw=$(scan_termux) ;;
    iw)     raw=$(scan_iw) ;;
    nmcli)  raw=$(scan_nmcli) ;;
    proc)   raw=$(scan_proc) ;;
  esac

  # Validate JSON
  echo "$raw" | jq '.' >/dev/null 2>&1 || raw='[]'
  SCAN_RESULTS="$raw"
  SCAN_COUNT=$(echo "$raw" | jq 'length' 2>/dev/null || echo 0)
  SCAN_TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
  echo "$raw"
}

# --- Get unique networks (by BSSID, keep strongest) ---
deduplicate() {
  local data="${1:-$SCAN_RESULTS}"
  echo "$data" | jq -s '
    map(. | {bssid} | unique) as $bssids |
    reduce .[] as $item ({}; .[$item.bssid] = $item) |
    [.[]] | sort_by(.level | tonumber) | reverse
  ' 2>/dev/null || echo "$data"
}

# --- Sort results ---
sort_results() {
  local data="${1:-$SCAN_RESULTS}"
  local by="${2:-level}"
  case "$by" in
    level|signal) echo "$data" | jq 'sort_by(.level | tonumber) | reverse' 2>/dev/null ;;
    freq|channel) echo "$data" | jq 'sort_by(.frequency | tonumber)' 2>/dev/null ;;
    ssid|name)    echo "$data" | jq 'sort_by(.ssid // "")' 2>/dev/null ;;
    bssid)        echo "$data" | jq 'sort_by(.bssid // "")' 2>/dev/null ;;
    *)            echo "$data" ;;
  esac
}

# --- Filter by band ---
filter_band() {
  local data="${1:-$SCAN_RESULTS}"
  local band="$2"
  case "$band" in
    2.4|2) data=$(echo "$data" | jq '[.[] | select(.frequency | tonumber >= 2412 and .frequency | tonumber <= 2484)]') ;;
    5)    data=$(echo "$data" | jq '[.[] | select(.frequency | tonumber >= 5180 and .frequency | tonumber <= 5865)]') ;;
    6)    data=$(echo "$data" | jq '[.[] | select(.frequency | tonumber >= 5955 and .frequency | tonumber <= 7115)]') ;;
  esac
  echo "$data"
}

# --- Filter by minimum signal ---
filter_min_signal() {
  local data="${1:-$SCAN_RESULTS}"
  local min="$2"
  echo "$data" | jq "[.[] | select(.level | tonumber >= $min)]" 2>/dev/null
}

# --- Search SSID ---
search_ssid() {
  local data="${1:-$SCAN_RESULTS}"
  local term="$2"
  echo "$data" | jq "[.[] | select(.ssid // \"\" | test(\"$term\"; \"i\"))]" 2>/dev/null
}

# --- Get scanner info string ---
get_scanner_info() {
  local stype="${1:-$SCANNER_TYPE}"
  case "$stype" in
    termux) echo "termux-wifi-scaninfo (Termux API)" ;;
    iw)     echo "iw (kernel nl80211)" ;;
    nmcli)  echo "nmcli (NetworkManager)" ;;
    proc)   echo "/proc/net/wireless" ;;
    none)   echo "No scanner found" ;;
    *)      echo "$stype" ;;
  esac
}

# --- Check required dependencies ---
check_deps() {
  local missing=""
  for cmd in jq; do
    command -v "$cmd" >/dev/null 2>&1 || missing="$missing $cmd"
  done
  echo "$missing"
}
