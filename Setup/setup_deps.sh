#!/bin/sh
# ==============================================================================
# System dependency installer for TRANS3 V1.0
# ==============================================================================
set -e

if [ "$EUID" -ne 0 ]; then
    echo "[-] Root privileges required: sudo $0"
    exit 1
fi

echo "[*] Updating package lists..."
apt-get update -q

# 1. Liste des paquets (sans parenthèses, compatible sh/dash)
REQUIRED_PACKAGES="build-essential meson ninja-build linux-headers-$(uname -r) pkg-config libxtables-dev iptables iptables-persistent iproute2 ethtool ebtables bridge-utils netcat-openbsd tcpdump tshark iperf3 python3 shc binutils git"

# 2. Vérification des paquets manquants
MISSING_PACKAGES=""
for pkg in $REQUIRED_PACKAGES; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
        MISSING_PACKAGES="$MISSING_PACKAGES $pkg"
    fi
done

# 3. Installation uniquement si nécessaire
if [ -n "$MISSING_PACKAGES" ]; then
    echo "[*] Installing missing packages:$MISSING_PACKAGES"
    DEBIAN_FRONTEND=noninteractive apt-get install -y $MISSING_PACKAGES
else
    echo "[+] All required APT packages are already installed."
fi

echo "[*] Enabling bridge netfilter (required for L2 physdev rules)..."
modprobe br_netfilter 2>/dev/null || true
grep -q "br_netfilter" /etc/modules 2>/dev/null || echo "br_netfilter" >> /etc/modules
cat > /etc/sysctl.d/99-trans3-bridge.conf << SYSCTL
net.bridge.bridge-nf-call-iptables=1
net.bridge.bridge-nf-call-ip6tables=1
SYSCTL
sysctl -p /etc/sysctl.d/99-trans3-bridge.conf >/dev/null 2>&1 || true
echo "[+] br_netfilter enabled and persistent"

echo "[*] Checking Leancrypto library..."
if ! ldconfig -p | grep -q leancrypto; then
    echo "[*] Leancrypto not found — building from source with Meson..."
    cd /tmp
    rm -rf leancrypto
    git clone https://github.com/smuellerDD/leancrypto.git
    cd leancrypto
    
    meson setup build
    meson compile -C build
    meson install -C build
    
    LC_LIB_PATH="/usr/local/lib/$(uname -m)-linux-gnu"
    [ -d "$LC_LIB_PATH" ] || LC_LIB_PATH="/usr/local/lib"
    echo "$LC_LIB_PATH" > /etc/ld.so.conf.d/leancrypto.conf
    ldconfig
    cd - > /dev/null
    echo "[+] Leancrypto installed successfully"
else
    echo "[+] Leancrypto already installed"
fi

echo "[+] All dependencies resolved"
