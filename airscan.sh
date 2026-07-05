#!/system/bin/sh
#
# airscan - Scanner de Redes Wi-Fi (somente leitura)
# Estilo aircrack-ng para Termux/Android
# Uso: airscan [opcoes]
#

VERSION="1.0.0"

# ============================================================
# scanner.sh - Modulo de varredura
# ============================================================

SCAN_RESULTS=""
SCAN_COUNT=0
SCAN_TIMESTAMP=""
SCANNER_TYPE=""

detect_scanner() {
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

scan_termux() {
  termux-wifi-scaninfo 2>/dev/null
}

scan_iw() {
  local iface devs
  devs=$(iw dev 2>/dev/null | awk '/Interface/ {print $2}')
  [ -z "$devs" ] && return 1

  for iface in $devs; do
    local scan_out
    scan_out=$(iw dev "$iface" scan 2>/dev/null) || continue

    local bssid="" ssid="" freq="" signal="" caps="" ts=""
    echo "$scan_out" | while IFS= read -r line; do
      line=$(echo "$line" | sed 's/^[[:space:]]*//')
      case "$line" in
        BSS\ *)
          [ -n "$bssid" ] && echo "$(termux_entry "$bssid" "$ssid" "$freq" "$signal" "$caps" "$ts")"
          bssid=$(echo "$line" | awk '{print $2}' | tr '[:upper:]' '[:lower:]')
          ssid=""; freq=""; signal=""; caps=""; ts=$(date +%s%N) ;;
        *SSID:*)  ssid=$(echo "$line" | sed 's/.*SSID: //') ;;
        *freq:*)  freq=$(echo "$line" | sed 's/.*freq: //') ;;
        *signal:*) signal=$(echo "$line" | sed 's/.*signal: //' | awk '{print $1}') ;;
        *RSN:*|*WPA:*) caps="$caps [WPA2]" ;;
        *WPA1:*|*WPA:*) caps="$caps [WPA]" ;;
        *WEP:*)  caps="$caps [WEP]" ;;
        *Group\ cipher:*) caps="$caps $(echo "$line" | awk '{print $3}')" ;;
        *Pairwise\ cipher:*) caps="$caps $(echo "$line" | awk '{print $3}')" ;;
        *Authentication\ suites:*) caps="$caps $(echo "$line" | awk '{print $3}')" ;;
        *WPS:*)  caps="$caps [WPS]" ;;
      esac
    done
    [ -n "$bssid" ] && echo "$(termux_entry "$bssid" "$ssid" "$freq" "$signal" "$caps" "$ts")"
  done | jq -s '.' 2>/dev/null
}

termux_entry() {
  local bssid="$1" ssid="$2" freq="$3" level="$4" caps="$5" ts="$6"
  [ -z "$ssid" ] && ssid=""; [ -z "$freq" ] && freq="0"
  [ -z "$level" ] && level="0"; [ -z "$caps" ] && caps=""; [ -z "$ts" ] && ts="0"
  jq -n --arg ssid "$ssid" --arg bssid "$bssid" --arg frequency "$freq" \
    --arg level "$level" --arg capabilities "$caps" --argjson timestamp "$ts" \
    '{ssid: $ssid, bssid: $bssid, frequency: $frequency, level: ($level|tonumber), capabilities: $capabilities, timestamp: $timestamp}' 2>/dev/null
}

scan_nmcli() {
  nmcli -t -f SSID,BSSID,CHAN,FREQ,RATE,SIGNAL,SECURITY device wifi list 2>/dev/null | \
  while IFS=':' read -r ssid bssid chan freq rate signal sec; do
    [ -z "$ssid" ] && ssid=""; [ -z "$sec" ] && sec="[ESS]"
    [ -z "$freq" ] && freq=0; [ -z "$signal" ] && signal=0
    echo "$(termux_entry "$ssid" "$bssid" "$freq" "$signal" "$sec" "$(date +%s%N)")"
  done | jq -s '.' 2>/dev/null
}

scan_proc() {
  local results="[]"; local iface
  [ ! -f /proc/net/wireless ] && echo "$results" && return
  iface=$(awk 'NR==3 {print $1}' /proc/net/wireless 2>/dev/null | tr -d ':')
  [ -z "$iface" ] && echo "$results" && return
  if command -v iw >/dev/null 2>&1; then scan_iw; else echo "$results"; fi
}

do_scan() {
  local scanner; scanner=$(detect_scanner); SCANNER_TYPE="$scanner"
  [ "$scanner" = "none" ] && echo '[]' && return 1
  local raw=""
  case "$scanner" in
    termux) raw=$(scan_termux) ;;
    iw)     raw=$(scan_iw) ;;
    nmcli)  raw=$(scan_nmcli) ;;
    proc)   raw=$(scan_proc) ;;
  esac
  echo "$raw" | jq '.' >/dev/null 2>&1 || raw='[]'
  SCAN_RESULTS="$raw"
  SCAN_COUNT=$(echo "$raw" | jq 'length' 2>/dev/null || echo 0)
  SCAN_TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
  echo "$raw"
}

deduplicate() {
  local data="${1:-$SCAN_RESULTS}"
  echo "$data" | jq -s '
    map(. | {bssid} | unique) as $bssids |
    reduce .[] as $item ({}; .[$item.bssid] = $item) |
    [.[]] | sort_by(.level | tonumber) | reverse
  ' 2>/dev/null || echo "$data"
}

sort_results() {
  local data="${1:-$SCAN_RESULTS}" by="${2:-level}"
  case "$by" in
    level|signal) echo "$data" | jq 'sort_by(.level | tonumber) | reverse' 2>/dev/null ;;
    freq|channel) echo "$data" | jq 'sort_by(.frequency | tonumber)' 2>/dev/null ;;
    ssid|name)    echo "$data" | jq 'sort_by(.ssid // "")' 2>/dev/null ;;
    bssid)        echo "$data" | jq 'sort_by(.bssid // "")' 2>/dev/null ;;
    *)            echo "$data" ;;
  esac
}

filter_band() {
  local data="${1:-$SCAN_RESULTS}" band="$2"
  case "$band" in
    2.4|2) echo "$data" | jq '[.[] | select(.frequency | tonumber >= 2412 and .frequency | tonumber <= 2484)]' ;;
    5)     echo "$data" | jq '[.[] | select(.frequency | tonumber >= 5180 and .frequency | tonumber <= 5865)]' ;;
    6)     echo "$data" | jq '[.[] | select(.frequency | tonumber >= 5955 and .frequency | tonumber <= 7115)]' ;;
    *)     echo "$data" ;;
  esac
}

filter_min_signal() {
  local data="${1:-$SCAN_RESULTS}" min="$2"
  echo "$data" | jq "[.[] | select(.level | tonumber >= $min)]" 2>/dev/null || echo "$data"
}

search_ssid() {
  local data="${1:-$SCAN_RESULTS}" term="$2"
  echo "$data" | jq "[.[] | select(.ssid // \"\" | test(\"$term\"; \"i\"))]" 2>/dev/null || echo "$data"
}

get_scanner_info() {
  local stype="${1:-$SCANNER_TYPE}"
  case "$stype" in
    termux) echo "termux-wifi-scaninfo (Termux API)" ;;
    iw)     echo "iw (kernel nl80211)" ;;
    nmcli)  echo "nmcli (NetworkManager)" ;;
    proc)   echo "/proc/net/wireless" ;;
    none)   echo "Nenhum scanner encontrado" ;;
    *)      echo "$stype" ;;
  esac
}

check_deps() {
  local missing=""
  command -v jq >/dev/null 2>&1 || missing="$missing jq"
  echo "$missing"
}

# ============================================================
# analyze.sh - Modulo de analise
# ============================================================

freq_to_channel() {
  local freq="$1" ch="?"
  [ -z "$freq" ] || [ "$freq" = "null" ] && echo "?" && return
  freq="${freq%.*}"
  case "$freq" in
    2412) ch=1;;  2417) ch=2;;  2422) ch=3;;  2427) ch=4;;
    2432) ch=5;;  2437) ch=6;;  2442) ch=7;;  2447) ch=8;;
    2452) ch=9;;  2457) ch=10;; 2462) ch=11;; 2467) ch=12;;
    2472) ch=13;; 2484) ch=14;;
    5180) ch=36;; 5200) ch=40;; 5220) ch=44;; 5240) ch=48;;
    5260) ch=52;; 5280) ch=56;; 5300) ch=60;; 5320) ch=64;;
    5500) ch=100;; 5520) ch=104;; 5540) ch=108;; 5560) ch=112;;
    5580) ch=116;; 5600) ch=120;; 5620) ch=124;; 5640) ch=128;;
    5660) ch=132;; 5680) ch=136;; 5700) ch=140;; 5720) ch=144;;
    5745) ch=149;; 5765) ch=153;; 5785) ch=157;; 5805) ch=161;;
    5825) ch=165;; 5845) ch=169;; 5865) ch=173;;
    5955) ch=1;; 5975) ch=5;; 5995) ch=9;; 6015) ch=13;;
    6035) ch=17;; 6055) ch=21;; 6075) ch=25;; 6095) ch=29;;
    6115) ch=33;; 6135) ch=37;; 6155) ch=41;; 6175) ch=45;;
    6195) ch=49;; 6215) ch=53;; 6235) ch=57;; 6255) ch=61;;
    6275) ch=65;; 6295) ch=69;; 6315) ch=73;; 6335) ch=77;;
    6355) ch=81;; 6375) ch=85;; 6395) ch=89;; 6415) ch=93;;
    6435) ch=97;; 6455) ch=101;; 6475) ch=105;; 6495) ch=109;;
    6515) ch=113;; 6535) ch=117;; 6555) ch=121;; 6575) ch=125;;
    6595) ch=129;; 6615) ch=133;; 6635) ch=137;; 6655) ch=141;;
    6675) ch=145;; 6695) ch=149;; 6715) ch=153;; 6735) ch=157;;
    6755) ch=161;; 6775) ch=165;; 6795) ch=169;; 6815) ch=173;;
    6835) ch=177;; 6855) ch=181;; 6875) ch=185;; 6895) ch=189;;
    6915) ch=193;; 6935) ch=197;; 6955) ch=201;; 6975) ch=205;;
    6995) ch=209;; 7015) ch=213;; 7035) ch=217;; 7055) ch=221;;
    7075) ch=225;; 7095) ch=229;; 7115) ch=233;;
    *)
      if [ "$freq" -ge 2412 ] && [ "$freq" -le 2484 ]; then ch=$(( (freq - 2412) / 5 + 1 ))
      elif [ "$freq" -ge 5180 ] && [ "$freq" -le 5865 ]; then ch=$(( (freq - 5000) / 5 ))
      elif [ "$freq" -ge 5955 ] && [ "$freq" -le 7115 ]; then ch=$(( (freq - 5950) / 5 )); fi ;;
  esac
  echo "$ch"
}

freq_to_band() {
  local freq="$1"
  [ -z "$freq" ] || [ "$freq" = "null" ] && echo "?" && return
  freq="${freq%.*}"
  if [ "$freq" -ge 2412 ] && [ "$freq" -le 2484 ]; then echo "2.4GHz"
  elif [ "$freq" -ge 5180 ] && [ "$freq" -le 5865 ]; then echo "5GHz"
  elif [ "$freq" -ge 5955 ] && [ "$freq" -le 7115 ]; then echo "6GHz"
  else echo "${freq}MHz"; fi
}

parse_encryption() {
  local caps="$1"
  [ -z "$caps" ] && echo "ABERTA" && return
  caps=$(echo "$caps" | tr ',' ' ' | tr '][' '\n' | grep -v '^$' | tr -d '"')
  local enc_type="ABERTA"
  echo "$caps" | grep -qi "WPA3-SAE\|SAE" && enc_type="WPA3"
  echo "$caps" | grep -qi "WPA2\|RSN\|CCMP" && {
    [ "$enc_type" = "WPA3" ] && enc_type="WPA3/WPA2" || enc_type="WPA2"
  }
  echo "$caps" | grep -qi "WPA-PSK\|WPA1\|TKIP" && {
    case "$enc_type" in
      WPA2) enc_type="WPA2/WPA" ;;
      WPA3/WPA2) enc_type="WPA3/WPA2/WPA" ;;
      WPA3) enc_type="WPA3/WPA2/WPA" ;;
      *) enc_type="WPA" ;;
    esac
  }
  echo "$caps" | grep -qi "WEP" && enc_type="WEP"
  echo "$caps" | grep -qi "OWE" && enc_type="OWE"
  echo "$caps" | grep -qi "EAP\|802.1X\|WPA-EAP" && enc_type="${enc_type}-Empresarial"
  echo "$caps" | grep -qi "WPS" && enc_type="${enc_type}+WPS"
  echo "$enc_type"
}

rssi_to_percent() {
  local rssi="$1"
  [ -z "$rssi" ] || [ "$rssi" = "null" ] && echo 0 && return
  if [ "$rssi" -ge -30 ]; then echo 100
  elif [ "$rssi" -le -100 ]; then echo 0
  else echo $(( (rssi + 100) * 100 / 70 )); fi
}

estimate_distance() {
  local rssi="$1"
  [ -z "$rssi" ] || [ "$rssi" = "null" ] && echo "?m" && return
  if [ "$rssi" -ge -40 ]; then echo "< 5m"
  elif [ "$rssi" -ge -55 ]; then echo "5-15m"
  elif [ "$rssi" -ge -65 ]; then echo "15-30m"
  elif [ "$rssi" -ge -75 ]; then echo "30-50m"
  elif [ "$rssi" -ge -85 ]; then echo "50-100m"
  else echo "> 100m"; fi
}

signal_quality() {
  local rssi="$1"
  [ -z "$rssi" ] || [ "$rssi" = "null" ] && echo "???" && return
  if [ "$rssi" -ge -40 ]; then echo "Excelente"
  elif [ "$rssi" -ge -60 ]; then echo "Bom"
  elif [ "$rssi" -ge -70 ]; then echo "Regular"
  elif [ "$rssi" -ge -80 ]; then echo "Fraco"
  else echo "Muito Fraco"; fi
}

oui_vendor() {
  local bssid="$1"
  [ -z "$bssid" ] && echo "Desconhecido" && return
  local oui
  oui=$(echo "$bssid" | tr '[:lower:]' '[:upper:]' | sed 's/[^A-F0-9]//g' | cut -c1-6)
  [ ${#oui} -ne 6 ] && echo "Desconhecido" && return
  case "$oui" in
    00037F|AC853D|A080C5) echo "TP-Link" ;;
    00137B|001F33|00C0CA) echo "Intel" ;;
    001B2F|001E52|002511) echo "Apple" ;;
    0027C8|ACB920|3891D5) echo "Samsung" ;;
    1430C6|E0B9BA|18A6F7) echo "Xiaomi" ;;
    B8DBA0|582CF1|20B5C6) echo "Huawei" ;;
    000B6B|000C84|00904C) echo "Cisco" ;;
    0414E4|0432F4|00A0F8) echo "D-Link" ;;
    8863DF|E8DE27|B44B2F) echo "Netgear" ;;
    90F652|2C3783|1C5C55) echo "Asus" ;;
    F01DBC|C8750F|987BF3) echo "MikroTik" ;;
    00156D|38AA3C|2C36F8) echo "Ubiquiti" ;;
    0C8268|78318B|A4530E) echo "Ruckus" ;;
    44D9E8|B0C559|6C3C8C) echo "Zyxel" ;;
    1CBDB9|101F74|1848D8) echo "Tenda" ;;
    001EE7|080046|080020) echo "Sony" ;;
    18D6C7|88C36E|60D9C7) echo "LG" ;;
    B8B7F1|FC7326|D85D4C) echo "ZTE" ;;
    E0ACCB|28E3A2|9C28BF) echo "Raspberry Pi" ;;
    001788|0021E1|207B85) echo "Broadcom" ;;
    00049F|000625|000FE8) echo "Atheros" ;;
    0021D1|00A050|000C41) echo "MediaTek" ;;
    001405|00E0A6|00906A) echo "Qualcomm" ;;
    001B11|00E07C|B0487A) echo "Marvell" ;;
    00037B|001A2F|E0B9A5) echo "Realtek" ;;
    F8E7A5|4C57CA|5CF9DD) echo "Roku" ;;
    00247A|B0791C|08ED02) echo "Amazon" ;;
    A887ED|F86ABF|3054B4) echo "Google" ;;
    10AE66|6051BE|3C75D5) echo "Aruba" ;;
    D46D6D|C8B5B6|B03A2D) echo "Motorola" ;;
    001D7D|000FF5|00E0B0) echo "Nokia" ;;
    00254B|B8A9A2|C875F1) echo "AVM/Fritz!" ;;
    *) echo "" ;;
  esac
}

detect_channel_width() {
  local freq="$1"
  [ -z "$freq" ] && echo "20MHz" && return
  freq="${freq%.*}"
  if [ "$freq" -ge 2412 ] && [ "$freq" -le 2484 ]; then echo "20MHz"
  elif [ "$freq" -ge 5180 ] && [ "$freq" -le 5865 ]; then
    local m40=$((freq % 40)) m80=$((freq % 80))
    [ "$m80" -eq 0 ] && echo "80MHz" || [ "$m40" -eq 0 ] && echo "40MHz" || echo "20MHz"
  else echo "20MHz"; fi
}

assess_risk() {
  local enc="$1" caps="$2"
  case "$enc" in
    *WPA3*) echo "BAIXO|WPA3 e a opcao mais segura disponivel" ;;
    *WPA2*)
      echo "$caps" | grep -qi "WPS" && \
        echo "MEDIO|WPA2 com WPS ativo - vulneravel a PIN attack" || \
        echo "BAIXO|WPA2 e seguro se usar senha forte" ;;
    *WPA*PSK*|*WPA1*|*WPA*-WPA*) echo "MEDIO|WPA-PSK vulneravel a ataques de dicionario" ;;
    *WEP*)  echo "ALTO|WEP obsoleto e trivialmente quebravel" ;;
    *ABERTA*) echo "ALTO|Sem criptografia - todo trafego visivel" ;;
    *OWE*)  echo "BAIXO|OWE fornece criptografia em redes abertas" ;;
    *)      echo "DESCONHECIDO|Nivel de seguranca indeterminado" ;;
  esac
}

guess_network_type() {
  local ssid="$1"
  [ -z "$ssid" ] || [ "$ssid" = "null" ] && echo "Rede Oculta" && return
  local s; s=$(echo "$ssid" | tr '[:lower:]' '[:upper:]')
  case "$s" in
    *FREE*|*PUBLIC*|*HOTSPOT*|*STARBUCKS*|*MCDONALDS*) echo "Hotspot Publico" ;;
    *GUEST*)    echo "Rede de Convidados" ;;
    *IOT*|*SMART*) echo "IoT/Casa Inteligente" ;;
    *CORP*|*ENTERPRISE*|*EMPLOYEE*) echo "Corporativa" ;;
    *STUDENT*|*UNIVERSITY*|*CAMPUS*) echo "Educacional" ;;
    *5G*|*DUAL*) echo "Roteador Dupla Banda" ;;
    *MESH*)     echo "Rede Mesh" ;;
    *)          echo "Roteador Particular" ;;
  esac
}

# ============================================================
# format.sh - Modulo de formatacao estilo aircrack-ng
# ============================================================

BOLD='\033[1m'
DIM='\033[2m'
R='\033[0;31m'
G='\033[0;32m'
Y='\033[1;33m'
N='\033[0m'

print_banner() {
  clear 2>/dev/null || true
  echo
  echo "    airscan v${VERSION}"
  echo "    Scanner de Redes Wi-Fi (somente leitura)"
  echo "    para Termux / Android"
  echo
}

msg_info()   { echo -e "  ${BOLD}[+]${N} $1"; }
msg_warn()   { echo -e "  ${BOLD}[!]${N} $1"; }
msg_error()  { echo -e "  ${BOLD}[-]${N} $1"; }
msg_status() { echo -e "     ${DIM}$1${N}"; }

print_header() {
  local title="$1"
  echo
  echo "  ${BOLD}${title}${N}"
  printf '%*s\n' 56 '' | tr ' ' '-'
}

sec_label() {
  local caps="$1"
  [ -z "$caps" ] && echo "ABERTA" && return
  local u; u=$(echo "$caps" | tr '[:lower:]' '[:upper:]')
  echo "$u" | grep -q "WPA3" && echo "WPA3" && return
  echo "$u" | grep -q "WPA2\|RSN\|CCMP" && echo "WPA2" && return
  echo "$u" | grep -q "WPA1\|WPAPSK\|TKIP" && echo "WPA" && return
  echo "$u" | grep -q "WEP" && echo "WEP" && return
  echo "$u" | grep -q "OWE" && echo "OWE" && return
  echo "$u" | grep -q "ESS\|WPS" && echo "ABERTA" && return
  echo "????"
}

show_summary() {
  local data="${1:-$NETWORKS}"
  local total
  total=$(echo "$data" | jq 'length' 2>/dev/null || echo 0)
  [ "$total" -eq 0 ] && { msg_error "Nenhuma rede encontrada."; return; }
  print_header "Redes Encontradas: $total"
  echo
  printf "  %-2s %-32s %-17s %-3s %-5s %s\n" "N" "SSID" "BSSID" "CH" "SINAL" "SEGURANCA"
  printf "  %-2s %-32s %-17s %-3s %-5s %s\n" "--" "--------------------------------" "-----------------" "---" "-----" "---------"
  local idx=0
  echo "$data" | jq -c '.[]' 2>/dev/null | while read -r net; do
    idx=$((idx + 1))
    local ssid bssid freq level caps
    ssid=$(echo "$net" | jq -r '.ssid // "(oculta)"')
    bssid=$(echo "$net" | jq -r '.bssid // "00:00:00:00:00:00"')
    freq=$(echo "$net" | jq -r '.frequency // "0"')
    level=$(echo "$net" | jq -r '.level // "0"')
    caps=$(echo "$net" | jq -r '.capabilities // ""')
    local chan enc; chan=$(freq_to_channel "$freq"); enc=$(sec_label "$caps")
    printf "  %-2d %-32s %-17s %-3s %+4d  %s\n" "$idx" "${ssid:0:32}" "$bssid" "$chan" "$level" "$enc"
  done
}

show_network_detail() {
  local net="$1"
  [ -z "$net" ] && return
  local ssid bssid freq level caps
  ssid=$(echo "$net" | jq -r '.ssid // "(oculta)"')
  bssid=$(echo "$net" | jq -r '.bssid // "00:00:00:00:00:00"')
  freq=$(echo "$net" | jq -r '.frequency // "0"')
  level=$(echo "$net" | jq -r '.level // "0"')
  caps=$(echo "$net" | jq -r '.capabilities // ""')

  local chan band enc vendor qual pct dist width
  chan=$(freq_to_channel "$freq"); band=$(freq_to_band "$freq")
  enc=$(parse_encryption "$caps"); vendor=$(oui_vendor "$bssid")
  qual=$(signal_quality "$level"); pct=$(rssi_to_percent "$level")
  dist=$(estimate_distance "$level"); width=$(detect_channel_width "$freq")

  local risk risk_level risk_desc
  risk=$(assess_risk "$enc" "$caps"); risk_level="${risk%%|*}"; risk_desc="${risk#*|}"

  echo
  echo "  ${BOLD}SSID:${N}         $ssid"
  echo "  ${BOLD}BSSID:${N}        $bssid"
  echo "  ${BOLD}Fabricante:${N}   ${vendor:-Desconhecido}"
  echo "  ${BOLD}Canal:${N}        $chan ($band, $width)"
  echo "  ${BOLD}Frequencia:${N}   ${freq}MHz"
  echo "  ${BOLD}Sinal:${N}        ${level}dBm ($qual, ${pct}%)"
  echo "  ${BOLD}Distancia:${N}    $dist"
  echo "  ${BOLD}Cripto:${N}       $enc"
  echo "  ${BOLD}Tipo:${N}         $(guess_network_type "$ssid")"
  echo "  ${BOLD}Risco:${N}        $risk_level - $risk_desc"
  echo
}

show_networks() {
  local data="${1:-$NETWORKS}"
  local total
  total=$(echo "$data" | jq 'length' 2>/dev/null || echo 0)
  [ "$total" -eq 0 ] && { msg_error "Nenhuma rede encontrada."; return; }
  print_header "Varredura Completa: $total redes encontradas"
  echo "  Scanner: $(get_scanner_info)  |  Horario: $LAST_SCAN_TIME"
  echo
  local idx=0
  echo "$data" | jq -c '.[]' 2>/dev/null | while read -r net; do
    idx=$((idx + 1))
    echo "  ${BOLD}[${idx}]${N} ----------------------------------------------------"
    show_network_detail "$net"
  done
}

# ============================================================
# Variaveis globais
# ============================================================

RAW_JSON=""
NETWORKS="[]"
TOTAL_NETWORKS=0
LAST_SCAN_TIME=""

# ============================================================
# Funcoes principais
# ============================================================

perform_scan() {
  local raw; raw=$(do_scan 2>/dev/null)
  [ $? -ne 0 ] || [ -z "$raw" ] || [ "$raw" = "[]" ] && return 1
  RAW_JSON="$raw"
  NETWORKS=$(deduplicate "$raw")
  TOTAL_NETWORKS=$(echo "$NETWORKS" | jq 'length' 2>/dev/null || echo 0)
  LAST_SCAN_TIME=$(date '+%d/%m/%Y %H:%M:%S')
  return 0
}

watch_mode() {
  local interval="${1:-5}"
  print_banner
  echo "  Modo monitoramento continuo (intervalo: ${interval}s)"
  echo "  Pressione Ctrl+C para parar"
  echo
  while true; do
    if perform_scan; then
      local agora; agora=$(date '+%H:%M:%S')
      msg_info "[$agora] Varredura concluida: $TOTAL_NETWORKS redes encontradas"
      show_summary
    fi
    echo; echo "  Proxima varredura em ${interval}s... (Ctrl+C para sair)"
    sleep "$interval"
  done
}

show_help() {
  echo "airscan v${VERSION} - Scanner de Redes Wi-Fi (somente leitura)"
  echo
  echo "  Uso: airscan [opcoes]"
  echo
  echo "  Opcoes:"
  echo "    -s           Executar varredura unica"
  echo "    -w <seg>     Modo monitoramento continuo"
  echo "    -j           Saida em JSON"
  echo "    -b <2.4|5|6> Filtrar por banda"
  echo "    -m <n>       Filtrar por sinal minimo (ex: -65)"
  echo "    -f <nome>    Buscar redes por SSID"
  echo "    -o <mac>     Consultar fabricante pelo MAC"
  echo "    -C           Desativar cores"
  echo "    -h           Mostrar esta ajuda"
  echo "    -v           Mostrar versao"
  echo
  echo "  Exemplos:"
  echo "    airscan -s            Varredura unica"
  echo "    airscan -w 5          Monitoramento a cada 5s"
  echo "    airscan -s -b 5       Apenas redes 5GHz"
  echo "    airscan -s -f 'Casa'  Buscar por 'Casa'"
  echo "    airscan -j            Saida JSON"
  echo
  echo "  Dependencias: termux-api, jq"
  echo "    pkg install termux-api jq"
}

show_version() {
  echo "airscan v${VERSION}"
  echo "Scanner de Redes Wi-Fi (somente leitura)"
  echo "Para Termux / Android"
}

interactive_menu() {
  while true; do
    print_banner
    echo "  $(get_scanner_info)"
    echo
    echo "  [1] Varredura Rapida     - Listar redes em tabela"
    echo "  [2] Varredura Detalhada  - Informacoes completas"
    echo "  [3] Monitor Continuo     - Atualizar automaticamente"
    echo "  [4] Filtrar por Banda    - 2.4GHz, 5GHz ou 6GHz"
    echo "  [5] Buscar por SSID      - Localizar rede pelo nome"
    echo "  [6] Consultar Fabricante - Descobrir vendor pelo MAC"
    echo "  [7] Saida JSON           - Dados brutos"
    echo
    echo "  [0] Sair"
    echo
    printf "  Escolha uma opcao: "
    read -r opt
    echo

    case "$opt" in
      1)
        if perform_scan; then show_summary; echo "  Total: $TOTAL_NETWORKS redes"
        else msg_error "Falha na varredura. Wi-Fi ativado?"; fi
        echo; printf "  Pressione Enter para continuar..."; read -r ;;
      2)
        if perform_scan; then show_networks; echo "  Total: $TOTAL_NETWORKS redes"
        else msg_error "Falha na varredura. Wi-Fi ativado?"; fi
        echo; printf "  Pressione Enter para continuar..."; read -r ;;
      3)
        printf "  Intervalo em segundos [5]: "; read -r intervalo
        watch_mode "${intervalo:-5}" ;;
      4)
        printf "  Banda (2.4, 5, 6): "; read -r banda
        if perform_scan; then
          data=$(filter_band "$NETWORKS" "$banda")
          count=$(echo "$data" | jq 'length' 2>/dev/null || echo 0)
          echo "  Redes em ${banda}GHz: $count"
          [ "$count" -gt 0 ] && show_summary "$data"
        fi
        echo; printf "  Pressione Enter para continuar..."; read -r ;;
      5)
        printf "  Termo de busca: "; read -r termo
        if perform_scan; then
          data=$(search_ssid "$NETWORKS" "$termo")
          count=$(echo "$data" | jq 'length' 2>/dev/null || echo 0)
          echo "  Resultados para '${termo}': $count"
          [ "$count" -gt 0 ] && show_summary "$data"
        fi
        echo; printf "  Pressione Enter para continuar..."; read -r ;;
      6)
        printf "  MAC (ex: AA:BB:CC:DD:EE:FF): "; read -r mac
        vendor=$(oui_vendor "$mac"); [ -z "$vendor" ] && vendor="Nao encontrado"
        msg_info "Fabricante: $vendor"
        echo; printf "  Pressione Enter para continuar..."; read -r ;;
      7)
        if perform_scan; then echo "$NETWORKS" | jq '.'
        else msg_error "Falha na varredura"; fi
        echo; printf "  Pressione Enter para continuar..."; read -r ;;
      0) echo "  Saindo..."; exit 0 ;;
      *) msg_error "Opcao invalida"; sleep 1 ;;
    esac
  done
}

main() {
  local mode="" watch_interval=5 banda min_signal search_term json_output=false

  [ $# -eq 0 ] && { interactive_menu; return; }

  while [ $# -gt 0 ]; do
    case "$1" in
      -s) mode="scan" ;;
      -w) mode="watch"; watch_interval="${2:-5}"; [ $# -gt 1 ] && shift ;;
      -j) json_output=true; mode="scan" ;;
      -b) banda="$2"; shift ;;
      -m) min_signal="$2"; shift ;;
      -f) search_term="$2"; shift ;;
      -o) oui_vendor "$2"; exit 0; shift ;;
      -C) BOLD=''; DIM=''; R=''; G=''; Y=''; N='' ;;
      -h) show_help; exit 0 ;;
      -v) show_version; exit 0 ;;
      *)  echo "Opcao invalida: $1"; show_help; exit 1 ;;
    esac; shift
  done

  local deps; deps=$(check_deps)
  [ -n "$deps" ] && { msg_error "Faltam dependencias:${deps}"; echo "  pkg install${deps}"; exit 1; }

  [ "$(detect_scanner)" = "none" ] && {
    msg_error "Nenhum scanner Wi-Fi encontrado!"
    echo "  Instale Termux:API (termux-wifi-scaninfo) ou use root (iw)"
    exit 1
  }

  case "$mode" in
    scan)
      if ! perform_scan; then msg_error "Falha na varredura. Wi-Fi ativado?"; exit 1; fi
      data="$NETWORKS"
      [ -n "$min_signal" ] && data=$(filter_min_signal "$data" "$min_signal")
      [ -n "$banda" ] && data=$(filter_band "$data" "$banda")
      [ -n "$search_term" ] && data=$(search_ssid "$data" "$search_term")

      if [ "$json_output" = true ]; then
        echo "$data" | jq '.'
      else
        print_banner; show_networks "$data"
        echo "  Total: $(echo "$data" | jq 'length' 2>/dev/null || echo 0) redes"
      fi ;;
    watch)
      print_banner; watch_mode "$watch_interval" ;;
  esac
}

[ "$AIRSCAN_SOURCE" = "1" ] || main "$@"
