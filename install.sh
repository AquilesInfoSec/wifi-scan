#!/system/bin/sh
#
# airscan - Instalador
# Scanner de Redes Wi-Fi para Termux/Android
#

instalar() {
  local dest="${PREFIX:-/usr/local}/bin/airscan"
  echo "[*] Instalando airscan em $dest..."

  if [ "$(id -u)" -ne 0 ] && [ -z "$PREFIX" ]; then
    echo "[!] Necessario root. Tentando sudo..."
    exec sudo "$0" "$@"
  fi

  cp "$(dirname "$0")/airscan.sh" "$dest"
  chmod +x "$dest"

  echo "[*] Instalando dependencias..."
  if command -v pkg >/dev/null 2>&1; then
    pkg update -y && pkg install -y termux-api jq
  elif command -v apt >/dev/null 2>&1; then
    apt update && apt install -y jq
  fi

  echo "[+] Instalacao concluida!"
  echo "    Execute: airscan"
}

desinstalar() {
  local dest="${PREFIX:-/usr/local}/bin/airscan"
  rm -f "$dest"
  echo "[+] airscan removido."
}

case "$1" in
  uninstall|remove|desinstalar) desinstalar ;;
  *) instalar "$@" ;;
esac
