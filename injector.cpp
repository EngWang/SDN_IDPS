#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string>

DWORD GetProcessIdByName(const wchar_t* processName) {
    PROCESSENTRY32W pe32 = { sizeof(pe32) };
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, processName) == 0) {
                CloseHandle(hSnapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    return 0;
}

bool InjectDLL(DWORD pid, const char* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        printf("Failed to open process %u: %u\n", pid, GetLastError());
        return false;
    }

    size_t dllPathLen = strlen(dllPath) + 1;
    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, dllPathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        printf("Failed to allocate memory: %u\n", GetLastError());
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, remoteMem, dllPath, dllPathLen, NULL)) {
        printf("Failed to write DLL path: %u\n", GetLastError());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    LPVOID loadLibraryAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (!loadLibraryAddr) {
        printf("Failed to get LoadLibraryA address: %u\n", GetLastError());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, remoteMem, 0, NULL);
    if (!hThread) {
        printf("Failed to create remote thread: %u\n", GetLastError());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return true;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("Usage: %s <process name or PID> <DLL path>\n", argv[0]);
        return 1;
    }

    DWORD pid = 0;
    if (isdigit(argv[1][0])) {
        pid = atoi(argv[1]);
    }
    else {
        pid = GetProcessIdByName(std::wstring(argv[1], argv[1] + strlen(argv[1])).c_str());
    }

    if (pid == 0) {
        printf("Process not found\n");
        return 1;
    }

    char fullDllPath[MAX_PATH];
    if (!GetFullPathNameA(argv[2], MAX_PATH, fullDllPath, NULL)) {
        printf("Failed to get full DLL path: %u\n", GetLastError());
        return 1;
    }

    if (InjectDLL(pid, fullDllPath)) {
        printf("DLL injected successfully into PID %u\n", pid);
    }
    else {
        printf("DLL injection failed\n");
    }
    return 0;
}