#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>

DWORD GetProcessIdByName(const std::wstring& processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (processName == pe32.szExeFile) {
                CloseHandle(hSnapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return 0;
}

bool InjectDLL(DWORD processId, const std::string& dllPath) {
    // Open target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess) {
        std::cerr << "Failed to open process. Error: " << GetLastError() << std::endl;
        return false;
    }

    // Allocate memory in target process
    LPVOID pDllPath = VirtualAllocEx(hProcess, NULL, dllPath.length() + 1,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pDllPath) {
        std::cerr << "Failed to allocate memory in target process" << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    // Write DLL path to target process
    if (!WriteProcessMemory(hProcess, pDllPath, dllPath.c_str(), dllPath.length() + 1, NULL)) {
        std::cerr << "Failed to write DLL path to target process" << std::endl;
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Get LoadLibraryA address
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    FARPROC pLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");
    if (!pLoadLibraryA) {
        std::cerr << "Failed to get LoadLibraryA address" << std::endl;
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Create remote thread to load DLL
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pLoadLibraryA,
        pDllPath, 0, NULL);
    if (!hThread) {
        std::cerr << "Failed to create remote thread. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Wait for thread completion
    WaitForSingleObject(hThread, INFINITE);

    // Get thread exit code (HMODULE of loaded DLL)
    DWORD exitCode;
    GetExitCodeThread(hThread, &exitCode);

    // Cleanup
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    if (exitCode == 0) {
        std::cerr << "Failed to load DLL in target process" << std::endl;
        return false;
    }

    std::cout << "DLL injected successfully!" << std::endl;
    return true;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cout << "Usage: " << argv[0] << " <process_name_or_pid> <hook_dll_path>" << std::endl;
        std::cout << "Example: " << argv[0] << " notepad.exe C:\\path\\to\\HookDLL.dll" << std::endl;
        std::cout << "Example: " << argv[0] << " 1234 C:\\path\\to\\HookDLL.dll" << std::endl;
        return 1;
    }

    std::string target = argv[1];
    std::string dllPath = argv[2];

    DWORD processId = 0;

    // Check if argument is PID (numeric) or process name
    if (target.find_first_not_of("0123456789") == std::string::npos) {
        // It's a PID
        processId = std::stoul(target);
    }
    else {
        // It's a process name
        std::wstring processName(target.begin(), target.end());
        processId = GetProcessIdByName(processName);
        if (processId == 0) {
            std::cerr << "Process not found: " << target << std::endl;
            return 1;
        }
    }

    std::cout << "Target Process ID: " << processId << std::endl;
    std::cout << "DLL Path: " << dllPath << std::endl;

    if (InjectDLL(processId, dllPath)) {
        std::cout << "Injection completed. Check log file for API calls." << std::endl;
    }
    else {
        std::cerr << "Injection failed." << std::endl;
        return 1;
    }

    return 0;
}