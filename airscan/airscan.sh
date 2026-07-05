#!/system/bin/sh
#
# airscan - Wi-Fi Reconnaissance Scanner for Termux/Android
# A non-intrusive network information gathering tool
#
# Usage: airscan [options]
#

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LIB_DIR="$SCRIPT_DIR/lib"
VERSION="1.0.0"

for lib in format scanner analyze; do
  . "$LIB_DIR/$lib.sh"
done

# --- Global state ---
RAW_JSON=""
NETWORKS="[]"
TOTAL_NETWORKS=0
LAST_SCAN_TIME=""

# --- Help ---
show_help() {
  echo -e "${W}airscan v${VERSION}${N} - Wi-Fi Reconnaissance Scanner (read-only)"
  echo
  echo -e "${D}Usage:${N}"
  echo "  airscan [options]"
  echo
  echo -e "${D}Options:${N}"
  echo "  -s, --scan         Perform a single scan and display results"
  echo "  -w, --watch        Continuous monitoring mode (refresh every N seconds)"
  echo "  -j, --json         Output raw JSON data"
  echo "  -b, --band <b>     Filter by band: 2.4, 5, or 6"
  echo "  -m, --min-signal <n>  Filter by minimum RSSI (e.g., -65)"
  echo "  -q, --quiet        Minimal output (list only)"
  echo "  -f, --find <name>  Search networks by SSID"
  echo "  -o, --oui <mac>    Lookup MAC vendor OUI"
  echo "  -c, --color        Force color output"
  echo "  -C, --no-color     Disable color output"
  echo "  -h, --help         Show this help"
  echo "  -v, --version      Show version"
  echo
  echo -e "${D}Examples:${N}"
  echo "  airscan -s              Single scan, all networks"
  echo "  airscan -w 5            Continuous scan, refresh every 5s"
  echo "  airscan -s -b 5         Scan only 5 GHz networks"
  echo "  airscan -s -m -70       Show only networks with signal >= -70 dBm"
  echo "  airscan -s -f \"Home\"   Search for networks containing \"Home\""
  echo "  airscan -j              Scan and output JSON"
  echo "  airscan -o AA:BB:CC:DD:EE:FF  Lookup MAC vendor"
  echo
  echo -e "${D}Note:${N} Requires Termux:API (termux-wifi-scaninfo) or root (iw)."
  echo "       Install: pkg install termux-api jq"
}

# --- Show version ---
show_version() {
  echo "airscan v$VERSION"
  echo "Wi-Fi Reconnaissance Scanner (read-only)"
  echo "For Termux / Android"
  echo "License: MIT"
}

# --- Scan and parse ---
perform_scan() {
  local raw
  raw=$(do_scan 2>/dev/null)
  [ $? -ne 0 ] || [ -z "$raw" ] || [ "$raw" = "[]" ] && return 1

  RAW_JSON="$raw"
  NETWORKS=$(deduplicate "$raw")
  TOTAL_NETWORKS=$(echo "$NETWORKS" | jq 'length' 2>/dev/null || echo 0)
  LAST_SCAN_TIME=$(date '+%Y-%m-%d %H:%M:%S')
  return 0
}

# --- Watch mode (continuous) ---
watch_mode() {
  local interval="${1:-5}"
  print_banner "airscan" "$VERSION"
  echo -e "  ${D}Continuous monitoring mode (refresh every ${interval}s)${N}"
  echo -e "  ${D}Press Ctrl+C to stop${N}"
  echo

  while true; do
    if perform_scan; then
      local now; now=$(date '+%H:%M:%S')
      echo -e "  ${BOLD}[${now}]${N} ${G}Scan complete: ${W}$TOTAL_NETWORKS${N}${G} networks found${N}"
      show_summary
    else
      echo -e "  ${R}[${now}] Scan failed or no networks found${N}"
    fi
    echo -e "  ${D}Next scan in ${interval}s...${N}"
    sleep "$interval"
  done
}

# --- CLI option parsing ---
main() {
  local mode="interactive"
  local watch_interval=5
  local band=""
  local min_signal=""
  local search_term=""
  local json_output=false
  local quiet=false

  [ $# -eq 0 ] && mode="interactive"

  while [ $# -gt 0 ]; do
    case "$1" in
      -s|--scan)        mode="scan" ;;
      -w|--watch)       mode="watch"; watch_interval="${2:-5}"; [ $# -gt 1 ] && shift ;;
      -j|--json)        json_output=true; mode="scan" ;;
      -b|--band)        band="$2"; shift ;;
      -m|--min-signal)  min_signal="$2"; shift ;;
      -q|--quiet)       quiet=true ;;
      -f|--find)        search_term="$2"; shift ;;
      -o|--oui)         echo "$(oui_vendor "$2")"; exit 0; shift ;;
      -c|--color)        : ;;  # color is default
      -C|--no-color)    N=''; R=''; G=''; Y=''; B=''; M=''; C=''; W=''; D=''; BOLD=''; DIM=''; CRIT=''; WARN=''; SAFE=''; INFO=''; BAR_CHAR='#'; BAR_EMPTY='.' ;;
      -h|--help)        show_help; exit 0 ;;
      -v|--version)     show_version; exit 0 ;;
      *)                echo -e "${R}Unknown option:${N} $1"; show_help; exit 1 ;;
    esac
    shift
  done

  # Check deps
  local deps
  deps=$(check_deps)
  [ -n "$deps" ] && {
    echo -e "${R}Error: Missing required tool(s):${N}${deps}"
    echo "Install with: pkg install$deps"
    exit 1
  }

  # Check scanner availability
  local scanner
  scanner=$(detect_scanner)
  [ "$scanner" = "none" ] && {
    echo -e "${R}Error: No Wi-Fi scanner found!${N}"
    echo "  Install Termux:API (termux-wifi-scaninfo) or run as root (iw)."
    echo "  pkg install termux-api"
    exit 1
  }

  case "$mode" in
    interactive)
      print_banner "airscan" "$VERSION"
      echo -e "  ${D}Scanner detected:${N} $(get_scanner_info)"
      echo
      echo -e "  [${W}1${N}] ${G}Quick Scan${N}     - List all networks"
      echo -e "  [${W}2${N}] ${G}Detailed Scan${N}  - Full information per network"
      echo -e "  [${W}3${N}] ${G}Watch Mode${N}     - Continuous monitoring"
      echo -e "  [${W}4${N}] ${G}Band Filter${N}    - Filter by frequency band"
      echo -e "  [${W}5${N}] ${G}Search SSID${N}    - Find network by name"
      echo -e "  [${W}6${N}] ${G}JSON Output${N}    - Raw JSON data"
      echo -e "  [${W}0${N}] ${R}Exit${N}"
      echo
      printf "  ${G}Choose an option:${N} "
      read -r opt
      echo

      case "$opt" in
        1) mode="scan"; quiet=true ;;
        2) mode="scan"; quiet=false ;;
        3) mode="watch" ;;
        4)
          printf "  Band (2.4/5/6): "; read -r band
          mode="scan"; quiet=true ;;
        5)
          printf "  Search term: "; read -r search_term
          mode="scan"; quiet=true ;;
        6) mode="scan"; json_output=true ;;
        0) exit 0 ;;
        *) echo -e "  ${R}Invalid option${N}"; exit 1 ;;
      esac
      ;;
  esac

  # Execute
  case "$mode" in
    scan)
      if ! perform_scan; then
        echo -e "${R}Scan failed or no networks found.${N}"
        echo "  Make sure Wi-Fi is enabled."
        exit 1
      fi

      # Apply filters
      local data="$NETWORKS"

      # Apply minimum signal filter
      if [ -n "$min_signal" ]; then
        data=$(filter_min_signal "$data" "$min_signal")
        local new_count
        new_count=$(echo "$data" | jq 'length' 2>/dev/null || echo 0)
        echo -e "  ${D}Filtered by signal ≥ ${min_signal}dBm: ${W}${new_count}${N}${D} networks${N}" >&2
      fi

      # Apply band filter
      if [ -n "$band" ]; then
        data=$(filter_band "$data" "$band")
        local new_count
        new_count=$(echo "$data" | jq 'length' 2>/dev/null || echo 0)
        echo -e "  ${D}Band ${band}GHz: ${W}${new_count}${N}${D} networks${N}" >&2
      fi

      # Apply search term
      if [ -n "$search_term" ]; then
        data=$(search_ssid "$data" "$search_term")
        local new_count
        new_count=$(echo "$data" | jq 'length' 2>/dev/null || echo 0)
        echo -e "  ${D}Search '${search_term}': ${W}${new_count}${N}${D} matches${N}" >&2
      fi

      # Output
      if [ "$json_output" = true ]; then
        echo "$data" | jq '.'
      elif [ "$quiet" = true ]; then
        print_banner "airscan" "$VERSION"
        show_summary "$data"
      else
        print_banner "airscan" "$VERSION"
        show_networks "$data"
      fi

      # Summary line
      if [ "$json_output" = false ]; then
        local final_count
        final_count=$(echo "$data" | jq 'length' 2>/dev/null || echo 0)
        echo -e "  ${D}Total displayed: ${W}$final_count${N}${D} networks${N}"
      fi
      ;;

    watch)
      watch_mode "$watch_interval"
      ;;
  esac
}

main "$@"
