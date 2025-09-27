#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <string>
#include "MinHook.h"  
#pragma comment(lib, "libMinHook.x64.lib")  

FILE* logFile = NULL;
CRITICAL_SECTION logLock;

// Original function pointers
typedef HANDLE(WINAPI* PFN_CreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef HANDLE(WINAPI* PFN_CreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL(WINAPI* PFN_ReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL(WINAPI* PFN_WriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);

PFN_CreateFileA origCreateFileA = NULL;
PFN_CreateFileW origCreateFileW = NULL;
PFN_ReadFile origReadFile = NULL;
PFN_WriteFile origWriteFile = NULL;

// Helper to translate dwDesiredAccess to string (real access mode)
std::string GetAccessModeString(DWORD dwDesiredAccess) {
    std::string mode;
    if (dwDesiredAccess & GENERIC_ALL) mode += "GENERIC_ALL | ";
    if (dwDesiredAccess & GENERIC_EXECUTE) mode += "GENERIC_EXECUTE | ";
    if (dwDesiredAccess & GENERIC_WRITE) mode += "GENERIC_WRITE | ";
    if (dwDesiredAccess & GENERIC_READ) mode += "GENERIC_READ | ";
    if (dwDesiredAccess & FILE_APPEND_DATA) mode += "FILE_APPEND_DATA | ";
    if (dwDesiredAccess & DELETE) mode += "DELETE | ";
    if (dwDesiredAccess & READ_CONTROL) mode += "READ_CONTROL | ";
    if (dwDesiredAccess & WRITE_DAC) mode += "WRITE_DAC | ";
    if (dwDesiredAccess & WRITE_OWNER) mode += "WRITE_OWNER | ";
    if (dwDesiredAccess & SYNCHRONIZE) mode += "SYNCHRONIZE | ";
    // Add more if needed, e.g., FILE_READ_DATA, etc.
    if (!mode.empty()) mode.erase(mode.size() - 3);  // Remove last " | "
    return mode.empty() ? "0" : mode;
}

// Helper to log with timestamp
void LogMessage(const char* format, ...) {
    EnterCriticalSection(&logLock);
    if (logFile) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(logFile, "[%04d-%02d-%02d %02d-%02d-%02d] ", st.wYear, st.wDay, st.wMonth, st.wHour, st.wMinute, st.wSecond);  // YYYY-DD-MM as specified

        va_list args;
        va_start(args, format);
        vfprintf(logFile, format, args);
        va_end(args);

        fprintf(logFile, "\n");
        fflush(logFile);
    }
    LeaveCriticalSection(&logLock);
}

// Detour for CreateFileA
HANDLE WINAPI DetourCreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    HANDLE hFile = origCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    std::string accessStr = GetAccessModeString(dwDesiredAccess);
    LogMessage("CreateFile: Filename=\"%s\", accessMode=%s, handle=0x%p", lpFileName ? lpFileName : "(null)", accessStr.c_str(), hFile);
    return hFile;
}

// Detour for CreateFileW (similar, but wchar)
HANDLE WINAPI DetourCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    HANDLE hFile = origCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    char fileNameAnsi[MAX_PATH] = { 0 };
    if (lpFileName) WideCharToMultiByte(CP_ACP, 0, lpFileName, -1, fileNameAnsi, MAX_PATH, NULL, NULL);  // Convert to ANSI for logging
    std::string accessStr = GetAccessModeString(dwDesiredAccess);
    LogMessage("CreateFile: Filename=\"%s\", accessMode=%s, handle=0x%p", fileNameAnsi, accessStr.c_str(), hFile);
    return hFile;
}

// Detour for ReadFile
BOOL WINAPI DetourReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) {
    BOOL result = origReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
    DWORD bytesRead = lpNumberOfBytesRead ? *lpNumberOfBytesRead : 0;
    LogMessage("ReadFile: handle=0x%p, bytesToRead=%u, bytesRead=%u", hFile, nNumberOfBytesToRead, bytesRead);
    return result;
}

// Detour for WriteFile
BOOL WINAPI DetourWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {
    BOOL result = origWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
    DWORD bytesWritten = lpNumberOfBytesWritten ? *lpNumberOfBytesWritten : 0;
    LogMessage("WriteFile: handle=0x%p, bytesToWrite=%u, bytesWritten=%u", hFile, nNumberOfBytesToWrite, bytesWritten);
    return result;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH: {
        // Get DLL directory
        char dllPath[MAX_PATH];
        GetModuleFileNameA(hModule, dllPath, MAX_PATH);
        char* lastSlash = strrchr(dllPath, '\\');
        if (lastSlash) *(lastSlash + 1) = '\0';  // Truncate to directory

        // Get process name (basename of exe)
        char exePath[MAX_PATH];
        GetModuleFileNameA(NULL, exePath, MAX_PATH);
        char* exeName = strrchr(exePath, '\\');
        std::string processName = exeName ? (exeName + 1) : "unknown.exe";

        // Get PID
        DWORD pid = GetCurrentProcessId();

        // Build log path in DLL dir
        std::string logPath = std::string(dllPath) + processName + "-" + std::to_string(pid) + ".txt";
        logFile = fopen(logPath.c_str(), "a");
        if (!logFile) {
            // Fallback or error handling (e.g., MessageBox for debug)
            return FALSE;
        }

        InitializeCriticalSection(&logLock);

        // Initialize MinHook
        if (MH_Initialize() != MH_OK) {
            fclose(logFile);
            DeleteCriticalSection(&logLock);
            return FALSE;
        }

        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");

        // Hook CreateFileA
        MH_CreateHook(GetProcAddress(hKernel32, "CreateFileA"), DetourCreateFileA, (LPVOID*)&origCreateFileA);
        // Hook CreateFileW (important for Unicode apps)
        MH_CreateHook(GetProcAddress(hKernel32, "CreateFileW"), DetourCreateFileW, (LPVOID*)&origCreateFileW);
        // Hook ReadFile
        MH_CreateHook(GetProcAddress(hKernel32, "ReadFile"), DetourReadFile, (LPVOID*)&origReadFile);
        // Hook WriteFile
        MH_CreateHook(GetProcAddress(hKernel32, "WriteFile"), DetourWriteFile, (LPVOID*)&origWriteFile);

        // Enable all hooks (suspends threads internally for safety)
        MH_EnableHook(MH_ALL_HOOKS);
        break;
    }
    case DLL_PROCESS_DETACH: {
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
        if (logFile) {
            fclose(logFile);
        }
        DeleteCriticalSection(&logLock);
        break;
    }
    }
    return TRUE;
}