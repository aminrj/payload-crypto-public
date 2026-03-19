#!/bin/bash
# ==============================================================================
# install.sh — NEGENCRY TRANS3 full system installer (Layer 3)
# ==============================================================================
set -e

if [ "$EUID" -ne 0 ]; then
    echo "[-] Root privileges required: sudo ./install.sh"
    exit 1
fi

# Détection intelligente du dossier racine (xt_TRANS3)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ "$SCRIPT_DIR" == *"Setup"* ]]; then
    PROJECT_DIR="$(dirname "$SCRIPT_DIR")" # Remonte d'un cran si on est dans Setup/
else
    PROJECT_DIR="$SCRIPT_DIR"
fi

echo "[*] Project root detected at: $PROJECT_DIR"

echo "[*] Step 1: Installing system dependencies..."
chmod +x "$PROJECT_DIR/Setup/setup_deps.sh"
bash "$PROJECT_DIR/Setup/setup_deps.sh"

echo ""
echo "[*] Step 2: Building NEGENCRY TRANS3 (Bare-Metal AEAD)...$PROJECT_DIR/src"
cd "$PROJECT_DIR/src"
make clean
make

echo ""
echo "[*] Step 3: Installing binaries..."
make install

echo ""
echo "[*] Step 4: Configuring module autoload at boot..."
if ! grep -q "^xt_TRANS3$" /etc/modules 2>/dev/null; then
    echo "xt_TRANS3" >> /etc/modules
    echo "[+] xt_TRANS3 registered in /etc/modules"
fi

cat > /etc/modules-load.d/xt_trans3.conf << MODEOF
xt_TRANS3
nf_conntrack
nf_defrag_ipv4
MODEOF
echo "[+] Boot module list written to /etc/modules-load.d/xt_trans3.conf"

modprobe nf_conntrack
modprobe nf_defrag_ipv4
modprobe xt_TRANS3
echo "[+] Kernel modules loaded"

echo ""
echo "[*] Step 5: Compiling admin interface..."
SETUP_DIR="$PROJECT_DIR/Setup/trans3_admin.sh"

if [ ! -f "$SETUP_DIR" ]; then
    echo "[-] Error: $SETUP_DIR not found"
    exit 1
fi
cd "$PROJECT_DIR/Setup"

# Compile shell script to hardened ELF binary via shc
shc -f trans3_admin.sh -o trans3_bin
install -m 700 trans3_bin /usr/local/bin/trans3

# Cleanup shc temporary files
rm -f trans3_bin trans3_admin.sh.x trans3_admin.sh.x.c

echo "[+] 'trans3' binary installed at /usr/local/bin/trans3"

echo ""
echo "========================================================"
echo "[+] TRANS3 V3.0 (Layer 3 Mode) — Installation complete"
echo ""
echo "  Next steps:"
echo "    sudo trans3              → Launch admin interface"
echo "========================================================"
