#!/system/bin/sh
#
# airscan - Installer
# Wi-Fi Reconnaissance Scanner for Termux/Android
#

termux_install() {
  echo "[*] Installing airscan for Termux..."

  # Install dependencies
  echo "[*] Installing dependencies..."
  pkg update -y
  pkg install -y termux-api jq

  # Install airscan
  local dest="$PREFIX/bin/airscan"
  echo "[*] Copying airscan to $dest..."
  cp "$(dirname "$0")/airscan.sh" "$dest"
  chmod +x "$dest"

  # Create lib directory in Termux
  local lib_dest="$PREFIX/lib/airscan"
  mkdir -p "$lib_dest"
  cp "$(dirname "$0")/lib/"*.sh "$lib_dest/"

  echo "[+] Installation complete!"
  echo "    Run 'airscan --help' to get started."
}

linux_install() {
  echo "[*] Installing airscan for Linux..."
  local dest="/usr/local/bin/airscan"
  local lib_dest="/usr/local/lib/airscan"

  if [ "$(id -u)" -ne 0 ]; then
    echo "[!] This install requires root. Trying sudo..."
    exec sudo "$0" "$@"
  fi

  cp "$(dirname "$0")/airscan.sh" "$dest"
  chmod +x "$dest"
  mkdir -p "$lib_dest"
  cp "$(dirname "$0")/lib/"*.sh "$lib_dest/"
  echo "[+] Installation complete! Run 'airscan --help'."
}

uninstall() {
  local target="${PREFIX:-/usr/local}"
  rm -f "$target/bin/airscan"
  rm -rf "$target/lib/airscan"
  echo "[+] airscan uninstalled."
}

case "$1" in
  uninstall|remove) uninstall ;;
  *)
    if [ -n "$PREFIX" ] && [ "$PREFIX" != "/usr/local" ]; then
      termux_install
    else
      linux_install
    fi
    ;;
esac
