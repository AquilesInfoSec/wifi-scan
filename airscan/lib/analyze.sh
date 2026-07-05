#!/system/bin/sh

# analyze.sh - Network analysis functions for airscan

# --- Frequency → Channel mapping ---
freq_to_channel() {
  local freq="$1"
  local ch="?"

  if [ -z "$freq" ] || [ "$freq" = "null" ]; then
    echo "?"; return
  fi

  # Strip decimal
  freq="${freq%.*}"

  case "$freq" in
    # 2.4 GHz band (2412–2484 MHz)
    2412) ch=1;;  2417) ch=2;;  2422) ch=3;;  2427) ch=4;;
    2432) ch=5;;  2437) ch=6;;  2442) ch=7;;  2447) ch=8;;
    2452) ch=9;;  2457) ch=10;; 2462) ch=11;; 2467) ch=12;;
    2472) ch=13;; 2484) ch=14;;
    # 5 GHz band
    5180) ch=36;; 5200) ch=40;; 5220) ch=44;; 5240) ch=48;;
    5260) ch=52;; 5280) ch=56;; 5300) ch=60;; 5320) ch=64;;
    5500) ch=100;; 5520) ch=104;; 5540) ch=108;; 5560) ch=112;;
    5580) ch=116;; 5600) ch=120;; 5620) ch=124;; 5640) ch=128;;
    5660) ch=132;; 5680) ch=136;; 5700) ch=140;; 5720) ch=144;;
    5745) ch=149;; 5765) ch=153;; 5785) ch=157;; 5805) ch=161;;
    5825) ch=165;; 5845) ch=169;; 5865) ch=173;;
    # 6 GHz band (Wi-Fi 6E)
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
    # fallback: calculate
    *)
      if [ "$freq" -ge 2412 ] && [ "$freq" -le 2484 ]; then
        ch=$(( (freq - 2412) / 5 + 1 ))
      elif [ "$freq" -ge 5180 ] && [ "$freq" -le 5865 ]; then
        ch=$(( (freq - 5000) / 5 ))
      elif [ "$freq" -ge 5955 ] && [ "$freq" -le 7115 ]; then
        ch=$(( (freq - 5950) / 5 ))
      fi
      ;;
  esac

  echo "$ch"
}

freq_to_band() {
  local freq="$1"
  [ -z "$freq" ] || [ "$freq" = "null" ] && echo "?" && return
  freq="${freq%.*}"
  if [ "$freq" -ge 2412 ] && [ "$freq" -le 2484 ]; then
    echo "2.4GHz"
  elif [ "$freq" -ge 5180 ] && [ "$freq" -le 5865 ]; then
    echo "5GHz"
  elif [ "$freq" -ge 5955 ] && [ "$freq" -le 7115 ]; then
    echo "6GHz"
  else
    echo "${freq}MHz"
  fi
}

# --- Parse capabilities string → encryption info ---
parse_encryption() {
  local caps="$1"
  [ -z "$caps" ] && echo "OPEN" && return

  local auth="" cipher="" wps=""
  caps=$(echo "$caps" | tr ',' ' ' | tr '][' '\n' | grep -v '^$' | tr -d '"')

  local enc_type="OPEN"
  local version=""

  if echo "$caps" | grep -qi "WPA3-SAE\|SAE"; then
    enc_type="WPA3"
    version="SAE"
  fi
  if echo "$caps" | grep -qi "WPA2\|RSN\|CCMP"; then
    if [ "$enc_type" = "WPA3" ]; then
      enc_type="WPA3/WPA2"
    else
      enc_type="WPA2"
    fi
  fi
  if echo "$caps" | grep -qi "WPA-PSK\|WPA1\|TKIP"; then
    if [ "$enc_type" = "WPA2" ] || [ "$enc_type" = "WPA3/WPA2" ]; then
      enc_type="${enc_type}/WPA"
    elif [ "$enc_type" = "WPA3" ]; then
      enc_type="WPA3/WPA2/WPA"
    else
      enc_type="WPA"
    fi
  fi
  if echo "$caps" | grep -qi "WEP"; then
    enc_type="WEP"
  fi
  if echo "$caps" | grep -qi "OWE"; then
    enc_type="OWE"
  fi
  if echo "$caps" | grep -qi "EAP\|802.1X\|WPA-EAP"; then
    enc_type="${enc_type}-Enterprise"
  fi
  if echo "$caps" | grep -qi "WPS\|WPS-PBC\|WPS-PIN"; then
    wps="+WPS"
  fi

  echo "${enc_type}${wps}"
}

get_encryption_flags() {
  local caps="$1"
  [ -z "$caps" ] && echo "OPEN" && return
  echo "$caps" | tr ',' ' ' | tr '][' '\n' | grep -v '^$' | tr '\n' ' '
}

# --- RSSI → Signal Quality (percentage) ---
rssi_to_percent() {
  local rssi="$1"
  if [ -z "$rssi" ] || [ "$rssi" = "null" ]; then echo 0; return; fi
  if [ "$rssi" -ge -30 ]; then echo 100
  elif [ "$rssi" -le -100 ]; then echo 0
  else echo $(( (rssi + 100) * 100 / 70 ))
  fi
}

# --- RSSI → Estimated distance (meters, very rough) ---
estimate_distance() {
  local rssi="$1"
  local freq="${2:-2437}"
  if [ -z "$rssi" ] || [ "$rssi" = "null" ]; then echo "?m"; return; fi

  # Free-space path loss model (very rough)
  # RSSI = -20 * log10(dist) + constant
  if [ "$rssi" -ge -40 ]; then echo "< 5m"
  elif [ "$rssi" -ge -55 ]; then echo "5-15m"
  elif [ "$rssi" -ge -65 ]; then echo "15-30m"
  elif [ "$rssi" -ge -75 ]; then echo "30-50m"
  elif [ "$rssi" -ge -85 ]; then echo "50-100m"
  else echo "> 100m"
  fi
}

# --- RSSI quality label ---
signal_quality() {
  local rssi="$1"
  if [ -z "$rssi" ] || [ "$rssi" = "null" ]; then echo "???"; return; fi
  if [ "$rssi" -ge -40 ]; then echo "Excellent"
  elif [ "$rssi" -ge -60 ]; then echo "Good"
  elif [ "$rssi" -ge -70 ]; then echo "Fair"
  elif [ "$rssi" -ge -80 ]; then echo "Weak"
  else echo "Very Weak"
  fi
}

# --- OUI → Vendor lookup ---
# Embedded database of common OUI prefixes
oui_vendor() {
  local bssid="$1"
  [ -z "$bssid" ] && echo "Unknown" && return

  local oui
  oui=$(echo "$bssid" | tr '[:lower:]' '[:upper:]' | sed 's/[^A-F0-9]//g' | cut -c1-6)

  [ ${#oui} -ne 6 ] && echo "Unknown" && return

  # Try external OUI file first
  local oui_file
  oui_file="$(dirname "$0")/../data/oui.txt"
  [ -f "$oui_file" ] && {
    local result
    result=$(grep -i "^$oui" "$oui_file" 2>/dev/null | cut -d'|' -f2-)
    [ -n "$result" ] && echo "$result" && return
  }

  # Embedded common OUI database
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
    *) echo "" ;;  # Will be resolved if OUI file exists
  esac
}

# --- Channel duplicate / width detection ---
detect_channel_width() {
  local freq="$1"
  local ch="$2"
  [ -z "$freq" ] && echo "20MHz" && return
  freq="${freq%.*}"

  if [ "$freq" -ge 2412 ] && [ "$freq" -le 2484 ]; then
    echo "20MHz"
  elif [ "$freq" -ge 5180 ] && [ "$freq" -le 5865 ]; then
    # 5GHz typical widths
    local mod40=$((freq % 40))
    local mod80=$((freq % 80))
    if [ "$mod80" -eq 0 ]; then echo "80MHz"
    elif [ "$mod40" -eq 0 ]; then echo "40MHz"
    else echo "20MHz"
    fi
  else
    echo "20MHz"
  fi
}

# --- Network risk assessment ---
assess_risk() {
  local enc="$1" wps="$2"
  case "$enc" in
    *OPEN*)     echo "HIGH|No encryption - traffic visible to all" ;;
    *WEP*)      echo "HIGH|WEP is deprecated and trivially crackable" ;;
    *WPA*PSK*|*WPA1*) echo "MEDIUM|WPA-PSK vulnerable to dictionary attacks" ;;
    *WPA2*)
      if echo "$wps" | grep -qi "WPS"; then
        echo "MEDIUM|WPA2 with WPS enabled - vulnerable to PIN attack"
      else
        echo "LOW|WPA2 is reasonably secure if using strong password"
      fi
      ;;
    *WPA3*)     echo "LOW|WPA3 is the most secure option available" ;;
    *OWE*)      echo "LOW|OWE provides encrypted open networks" ;;
    *)          echo "UNKNOWN|Cannot determine security level" ;;
  esac
}

# --- VLAN / Network type heuristics ---
guess_network_type() {
  local ssid="$1" enc="$2"
  local ssid_up; ssid_up=$(echo "$ssid" | tr '[:lower:]' '[:upper:]')

  [ -z "$ssid" ] || [ "$ssid" = "null" ] && echo "Hidden Network" && return

  case "$ssid_up" in
    *FREE*|*PUBLIC*|*HOTSPOT*|*STARBUCKS*|*MCDONALDS*)
      echo "Public Hotspot";;
    *GUEST*)      echo "Guest Network";;
    *IOT*|*SMART*) echo "IoT/Smart Home";;
    *CORP*|*ENTERPRISE*|*EMPLOYEE*) echo "Corporate";;
    *STUDENT*|*UNIVERSITY*|*CAMPUS*) echo "Educational";;
    *5G*|*DUAL*)  echo "Dual-band Router";;
    *MESH*)       echo "Mesh Network";;
    *)            echo "Standard Router";;
  esac
}
