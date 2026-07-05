#!/bin/bash
#
# airscan demo - Show output format with simulated data
# Run this to see how airscan displays results
#

DEMO_JSON='[
  {"ssid":"HomeNet-5G","bssid":"00:1b:2f:12:34:56","frequency":5180,"level":-42,"capabilities":"[WPA2-PSK-CCMP][WPS][ESS]","timestamp":1234567890},
  {"ssid":"HomeNet","bssid":"00:1b:2f:78:9a:bc","frequency":2437,"level":-48,"capabilities":"[WPA2-PSK-CCMP][WPS][ESS]","timestamp":1234567890},
  {"ssid":"Neighbor_WiFi","bssid":"ac:85:3d:ab:cd:ef","frequency":2412,"level":-65,"capabilities":"[WPA2-PSK-CCMP][ESS]","timestamp":1234567890},
  {"ssid":"Free_Public_WiFi","bssid":"04:14:e4:11:22:33","frequency":2412,"level":-71,"capabilities":"[ESS]","timestamp":1234567890},
  {"ssid":"","bssid":"00:0b:6b:aa:bb:cc","frequency":2462,"level":-55,"capabilities":"[WPA3-SAE-CCMP][WPA2-PSK-CCMP][ESS]","timestamp":1234567890},
  {"ssid":"IoT_Devices","bssid":"88:63:df:11:22:33","frequency":2412,"level":-82,"capabilities":"[WPA-PSK-TKIP][WPA2-PSK-CCMP][WPS][ESS]","timestamp":1234567890},
  {"ssid":"Campus_Student","bssid":"90:f6:52:11:22:33","frequency":5240,"level":-58,"capabilities":"[WPA2-EAP-CCMP][ESS]","timestamp":1234567890},
  {"ssid":"Mesh_NET","bssid":"f0:1d:bc:11:22:33","frequency":5745,"level":-61,"capabilities":"[WPA2-PSK-CCMP][ESS]","timestamp":1234567890}
]'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LIB_DIR="$SCRIPT_DIR/lib"

for lib in format scanner analyze; do
  . "$LIB_DIR/$lib.sh"
done

print_banner "airscan" "1.0.0"
echo -e "  ${D}*** DEMO MODE ***  Showing simulated scan output${N}"
echo

NETWORKS="$DEMO_JSON"
TOTAL_NETWORKS=$(echo "$NETWORKS" | jq 'length')
LAST_SCAN_TIME="2024-01-01 12:00:00"
SCANNER_TYPE="demo"

show_networks "$NETWORKS"
echo -e "  ${D}Total displayed: ${W}$TOTAL_NETWORKS${N}${D} networks (simulated)${N}"
