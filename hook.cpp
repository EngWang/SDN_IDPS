#include <windows.h>
#include <stdio.h>
#include <time.h>
#include <psapi.h>
#include <string>

#pragma comment(lib, "psapi.lib")

// Original function pointers
typedef HANDLE(WINAPI* CreateFileA_t)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef HANDLE(WINAPI* CreateFileW_t)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL(WINAPI* ReadFile_t)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL(WINAPI* WriteFile_t)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);

// Global variables
CreateFileA_t OriginalCreateFileA = NULL;
CreateFileW_t OriginalCreateFileW = NULL;
ReadFile_t OriginalReadFile = NULL;
WriteFile_t OriginalWriteFile = NULL;

char g_LogFileName[MAX_PATH] = { 0 };
CRITICAL_SECTION g_LogSection;
BOOL g_HooksInstalled = FALSE;

// Function declarations
void GetTimeStamp(char* buffer, size_t size);
void WriteLog(const char* message);
std::string AccessModeToString(DWORD dwDesiredAccess);
BOOL HookIAT(LPCSTR szImportModule, LPCSTR szFunc, PVOID pNewFunc, PVOID* pOldFunc);
void InitializeLogFile();
void InstallHooks();

// Get current timestamp in required format
void GetTimeStamp(char* buffer, size_t size) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    sprintf_s(buffer, size, "%04d-%02d-%02d %02d:%02d:%02d",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
}

// Thread-safe log writing
void WriteLog(const char* message) {
    EnterCriticalSection(&g_LogSection);

    FILE* logFile = NULL;
    errno_t err = fopen_s(&logFile, g_LogFileName, "a");
    if (err == 0 && logFile != NULL) {
        fprintf(logFile, "%s\n", message);
        fflush(logFile); // Ensure immediate write
        fclose(logFile);
    }

    LeaveCriticalSection(&g_LogSection);
}

// Convert Windows access mode flags to readable string
std::string AccessModeToString(DWORD dwDesiredAccess) {
    std::string result;

    // Generic access rights
    if (dwDesiredAccess & GENERIC_READ) result += result.empty() ? "GENERIC_READ" : "|GENERIC_READ";
    if (dwDesiredAccess & GENERIC_WRITE) result += result.empty() ? "GENERIC_WRITE" : "|GENERIC_WRITE";
    if (dwDesiredAccess & GENERIC_EXECUTE) result += result.empty() ? "GENERIC_EXECUTE" : "|GENERIC_EXECUTE";
    if (dwDesiredAccess & GENERIC_ALL) result += result.empty() ? "GENERIC_ALL" : "|GENERIC_ALL";

    // Specific file access rights
    if (dwDesiredAccess & FILE_READ_DATA) result += result.empty() ? "FILE_READ_DATA" : "|FILE_READ_DATA";
    if (dwDesiredAccess & FILE_WRITE_DATA) result += result.empty() ? "FILE_WRITE_DATA" : "|FILE_WRITE_DATA";
    if (dwDesiredAccess & FILE_APPEND_DATA) result += result.empty() ? "FILE_APPEND_DATA" : "|FILE_APPEND_DATA";
    if (dwDesiredAccess & DELETE) result += result.empty() ? "DELETE" : "|DELETE";
    if (dwDesiredAccess & READ_CONTROL) result += result.empty() ? "READ_CONTROL" : "|READ_CONTROL";
    if (dwDesiredAccess & WRITE_DAC) result += result.empty() ? "WRITE_DAC" : "|WRITE_DAC";
    if (dwDesiredAccess & WRITE_OWNER) result += result.empty() ? "WRITE_OWNER" : "|WRITE_OWNER";
    if (dwDesiredAccess & SYNCHRONIZE) result += result.empty() ? "SYNCHRONIZE" : "|SYNCHRONIZE";

    // If no known flags, show hex value
    if (result.empty() || (dwDesiredAccess & ~(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL |
        FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA |
        DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER | SYNCHRONIZE))) {
        char hexStr[32];
        sprintf_s(hexStr, "0x%08X", dwDesiredAccess);
        result += result.empty() ? hexStr : std::string("|") + hexStr;
    }

    return result;
}

// Hooked CreateFileA function
HANDLE WINAPI HookedCreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {

    HANDLE result = OriginalCreateFileA(lpFileName, dwDesiredAccess, dwShareMode,
        lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);

    if (result != INVALID_HANDLE_VALUE && lpFileName) {
        const char* filename = lpFileName;
        if (strstr(filename, "\\??\\") == filename) filename += 4;

        if (strstr(filename, "\\Windows\\") == NULL &&
            strstr(filename, "\\System32\\") == NULL &&
            strstr(filename, "CONOUT$") == NULL &&
            strstr(filename, "CONIN$") == NULL) {

            char timestamp[64];
            GetTimeStamp(timestamp, sizeof(timestamp));

            std::string accessMode = AccessModeToString(dwDesiredAccess);

            char logEntry[2048];
            sprintf_s(logEntry, "[%s] CreateFileA: Filename=\"%s\", accessMode=%s, handle=0x%08X",
                timestamp, filename, accessMode.c_str(), (DWORD)(ULONG_PTR)result);

            WriteLog(logEntry);
        }
    }

    return result;
}

// Hooked CreateFileW function
HANDLE WINAPI HookedCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {

    HANDLE result = OriginalCreateFileW(lpFileName, dwDesiredAccess, dwShareMode,
        lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);

    if (result != INVALID_HANDLE_VALUE && lpFileName) {
        char filenameA[MAX_PATH];
        WideCharToMultiByte(CP_ACP, 0, lpFileName, -1, filenameA, MAX_PATH, NULL, NULL);

        if (strstr(filenameA, "\\Windows\\") == NULL &&
            strstr(filenameA, "\\System32\\") == NULL &&
            strstr(filenameA, "CONOUT$") == NULL &&
            strstr(filenameA, "CONIN$") == NULL) {

            char timestamp[64];
            GetTimeStamp(timestamp, sizeof(timestamp));

            std::string accessMode = AccessModeToString(dwDesiredAccess);

            char logEntry[2048];
            sprintf_s(logEntry, "[%s] CreateFileW: Filename=\"%S\", accessMode=%s, handle=0x%08X",
                timestamp, lpFileName, accessMode.c_str(), (DWORD)(ULONG_PTR)result);

            WriteLog(logEntry);
        }
    }

    return result;
}

// Hooked ReadFile function
BOOL WINAPI HookedReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead,
    LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) {

    BOOL result = OriginalReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);

    if (result && lpNumberOfBytesRead && *lpNumberOfBytesRead > 0) {
        if (hFile != GetStdHandle(STD_INPUT_HANDLE) &&
            hFile != GetStdHandle(STD_OUTPUT_HANDLE) &&
            hFile != GetStdHandle(STD_ERROR_HANDLE)) {

            char timestamp[64];
            GetTimeStamp(timestamp, sizeof(timestamp));

            char logEntry[512];
            sprintf_s(logEntry, "[%s] ReadFile: handle=0x%08X, bytesToRead=%d, bytesRead=%d",
                timestamp, (DWORD)(ULONG_PTR)hFile, nNumberOfBytesToRead, *lpNumberOfBytesRead);

            WriteLog(logEntry);
        }
    }

    return result;
}

// Hooked WriteFile function
BOOL WINAPI HookedWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
    LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {

    BOOL result = OriginalWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);

    if (result && lpNumberOfBytesWritten && *lpNumberOfBytesWritten > 0) {
        if (hFile != GetStdHandle(STD_INPUT_HANDLE) &&
            hFile != GetStdHandle(STD_OUTPUT_HANDLE) &&
            hFile != GetStdHandle(STD_ERROR_HANDLE)) {

            char timestamp[64];
            GetTimeStamp(timestamp, sizeof(timestamp));

            char logEntry[512];
            sprintf_s(logEntry, "[%s] WriteFile: handle=0x%08X, bytesToWrite=%d, bytesWritten=%d",
                timestamp, (DWORD)(ULONG_PTR)hFile, nNumberOfBytesToWrite, *lpNumberOfBytesWritten);

            WriteLog(logEntry);
        }
    }

    return result;
}

// Enhanced IAT hooking function to hook all modules
BOOL HookIAT(LPCSTR szImportModule, LPCSTR szFunc, PVOID pNewFunc, PVOID* pOldFunc) {
    if (!szImportModule || !szFunc || !pNewFunc || !pOldFunc) {
        return FALSE;
    }

    // Get all modules in the process
    HMODULE hModules[1024];
    DWORD cbNeeded;
    HANDLE hProcess = GetCurrentProcess();
    if (!EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded)) {
        char logEntry[512];
        sprintf_s(logEntry, "[ERROR] EnumProcessModules failed: %d", GetLastError());
        WriteLog(logEntry);
        return FALSE;
    }

    DWORD nModules = cbNeeded / sizeof(HMODULE);
    BOOL hooked = FALSE;

    for (DWORD i = 0; i < nModules; i++) {
        HMODULE hModule = hModules[i];
        __try {
            PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
            if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) continue;

            PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);
            if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) continue;

            PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hModule +
                pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

            if (!pImportDesc) continue;

            while (pImportDesc->Name) {
                LPCSTR szModuleName = (LPCSTR)((BYTE*)hModule + pImportDesc->Name);
                if (_stricmp(szModuleName, szImportModule) == 0) {
                    PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + pImportDesc->FirstThunk);
                    PIMAGE_THUNK_DATA pOrigThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + pImportDesc->OriginalFirstThunk);

                    while (pThunk->u1.Function) {
                        if (!(pOrigThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                            PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)hModule + pOrigThunk->u1.AddressOfData);
                            if (strcmp((char*)pImportByName->Name, szFunc) == 0) {
                                DWORD dwOldProtect;
                                if (VirtualProtect(&pThunk->u1.Function, sizeof(PVOID), PAGE_READWRITE, &dwOldProtect)) {
                                    *pOldFunc = (PVOID)pThunk->u1.Function;
                                    pThunk->u1.Function = (ULONG_PTR)pNewFunc;
                                    VirtualProtect(&pThunk->u1.Function, sizeof(PVOID), dwOldProtect, &dwOldProtect);
                                    hooked = TRUE;

                                    char moduleName[MAX_PATH];
                                    GetModuleBaseNameA(hProcess, hModule, moduleName, MAX_PATH);
                                    char logEntry[512];
                                    sprintf_s(logEntry, "[INFO] Hooked %s in module %s", szFunc, moduleName);
                                    WriteLog(logEntry);
                                }
                            }
                        }
                        pThunk++;
                        pOrigThunk++;
                    }
                }
                pImportDesc++;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            char moduleName[MAX_PATH];
            GetModuleBaseNameA(hProcess, hModule, moduleName, MAX_PATH);
            char logEntry[512];
            sprintf_s(logEntry, "[ERROR] Exception while hooking %s in module %s", szFunc, moduleName);
            WriteLog(logEntry);
            continue;
        }
    }

    return hooked;
}

// Initialize log file with process name and PID
void InitializeLogFile() {
    DWORD processId = GetCurrentProcessId();
    char processName[MAX_PATH] = { 0 };
    char dllPath[MAX_PATH] = { 0 };
    char logDir[MAX_PATH] = { 0 };

    HMODULE hModule = NULL;
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCSTR)&InitializeLogFile, &hModule) && hModule) {
        GetModuleFileNameA(hModule, dllPath, MAX_PATH);
        strcpy_s(logDir, dllPath);
        char* lastSlash = strrchr(logDir, '\\');
        if (lastSlash) *lastSlash = '\0';
    }
    else {
        strcpy_s(logDir, ".");
    }

    HANDLE hProcess = GetCurrentProcess();
    if (GetModuleBaseNameA(hProcess, NULL, processName, MAX_PATH) == 0) {
        strcpy_s(processName, "Unknown");
    }

    char* ext = strstr(processName, ".exe");
    if (ext) *ext = '\0';

    sprintf_s(g_LogFileName, "%s\\%s-%d.txt", logDir, processName, processId);

    char timestamp[64];
    GetTimeStamp(timestamp, sizeof(timestamp));
    char logEntry[512];
    sprintf_s(logEntry, "[%s] API Monitor started for process %s (PID: %d)",
        timestamp, processName, processId);
    WriteLog(logEntry);
}

// Install all API hooks
void InstallHooks() {
    if (g_HooksInstalled) return;

    InitializeCriticalSection(&g_LogSection);
    InitializeLogFile();

    BOOL success = TRUE;

    if (!HookIAT("kernel32.dll", "CreateFileA", HookedCreateFileA, (PVOID*)&OriginalCreateFileA)) {
        WriteLog("[ERROR] Failed to hook CreateFileA");
        success = FALSE;
    }

    if (!HookIAT("kernel32.dll", "CreateFileW", HookedCreateFileW, (PVOID*)&OriginalCreateFileW)) {
        WriteLog("[ERROR] Failed to hook CreateFileW");
        success = FALSE;
    }

    if (!HookIAT("kernel32.dll", "ReadFile", HookedReadFile, (PVOID*)&OriginalReadFile)) {
        WriteLog("[ERROR] Failed to hook ReadFile");
        success = FALSE;
    }

    if (!HookIAT("kernel32.dll", "WriteFile", HookedWriteFile, (PVOID*)&OriginalWriteFile)) {
        WriteLog("[ERROR] Failed to hook WriteFile");
        success = FALSE;
    }

    if (success) {
        WriteLog("[INFO] All API hooks installed successfully");
        g_HooksInstalled = TRUE;
    }
}

// DLL Entry Point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        InstallHooks();
        break;

    case DLL_PROCESS_DETACH:
        if (g_HooksInstalled) {
            WriteLog("[INFO] API Monitor shutting down");
        }
        DeleteCriticalSection(&g_LogSection);
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}

extern "C" __declspec(dllexport) void DummyExport() {}