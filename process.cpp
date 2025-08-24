#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <dbghelp.h>
#include <winternl.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "dbghelp.lib")

// Helper function to convert wide string to string
std::string WStringToString(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();

    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

struct ProcessInfo {
    std::string name;
    DWORD pid;
    DWORD ppid;
    std::string architecture;
    std::string path;
    std::string cmdLine;
};

struct ThreadInfo {
    DWORD tid;
    std::string status;
};

struct DllInfo {
    std::string path;
    std::vector<std::string> functions;
};

class ProcessAnalyzer {
private:
    ProcessInfo processInfo;
    std::vector<ThreadInfo> threads;
    std::vector<DllInfo> dlls;

public:
    bool GetProcessByName(const std::string& processName) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return false;
        }

        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        if (!Process32FirstW(hSnapshot, &pe32)) {
            CloseHandle(hSnapshot);
            return false;
        }

        do {
            std::string currentName = WStringToString(pe32.szExeFile);
            if (currentName == processName) {
                processInfo.name = WStringToString(pe32.szExeFile);
                processInfo.pid = pe32.th32ProcessID;
                processInfo.ppid = pe32.th32ParentProcessID;
                CloseHandle(hSnapshot);
                return GetAdditionalProcessInfo();
            }
        } while (Process32NextW(hSnapshot, &pe32));

        CloseHandle(hSnapshot);
        return false;
    }

    bool GetProcessByPID(DWORD pid) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return false;
        }

        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        if (!Process32FirstW(hSnapshot, &pe32)) {
            CloseHandle(hSnapshot);
            return false;
        }

        do {
            if (pe32.th32ProcessID == pid) {
                processInfo.name = WStringToString(pe32.szExeFile);
                processInfo.pid = pe32.th32ProcessID;
                processInfo.ppid = pe32.th32ParentProcessID;
                CloseHandle(hSnapshot);
                return GetAdditionalProcessInfo();
            }
        } while (Process32NextW(hSnapshot, &pe32));

        CloseHandle(hSnapshot);
        return false;
    }

private:
    bool GetAdditionalProcessInfo() {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processInfo.pid);
        if (!hProcess) {
            return false;
        }

        // Get process path
        WCHAR path[MAX_PATH];
        DWORD pathSize = MAX_PATH;
        if (QueryFullProcessImageNameW(hProcess, 0, path, &pathSize)) {
            processInfo.path = WStringToString(path);
        }

        // Get architecture
        BOOL isWow64 = FALSE;
        if (IsWow64Process(hProcess, &isWow64)) {
            processInfo.architecture = isWow64 ? "x86" : "x64";
        }
        else {
            processInfo.architecture = "Unknown";
        }

        // Get command line
        processInfo.cmdLine = GetProcessCommandLine(hProcess);

        CloseHandle(hProcess);

        // Get threads and DLLs
        GetThreadInfo();
        GetDllInfo();

        return true;
    }

    std::string GetProcessCommandLine(HANDLE hProcess) {
        std::string commandLine;

        typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
            HANDLE ProcessHandle,
            DWORD ProcessInformationClass,
            PVOID ProcessInformation,
            ULONG ProcessInformationLength,
            PULONG ReturnLength);

        _NtQueryInformationProcess NtQueryInformationProcess =
            (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

        if (NtQueryInformationProcess) {
            PROCESS_BASIC_INFORMATION pbi;
            ULONG len;
            NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &len);

            if (NT_SUCCESS(status)) {
                PEB peb;
                if (ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), NULL)) {
                    RTL_USER_PROCESS_PARAMETERS upp;
                    if (ReadProcessMemory(hProcess, peb.ProcessParameters, &upp, sizeof(upp), NULL)) {
                        WCHAR* buffer = new WCHAR[upp.CommandLine.Length / sizeof(WCHAR) + 1];
                        if (ReadProcessMemory(hProcess, upp.CommandLine.Buffer, buffer, upp.CommandLine.Length, NULL)) {
                            buffer[upp.CommandLine.Length / sizeof(WCHAR)] = L'\0';
                            commandLine = WStringToString(buffer);
                        }
                        delete[] buffer;
                    }
                }
            }
        }

        if (commandLine.empty()) {
            commandLine = processInfo.path;
        }

        return commandLine;
    }

    void GetThreadInfo() {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return;
        }

        THREADENTRY32 te32;
        te32.dwSize = sizeof(THREADENTRY32);

        if (!Thread32First(hSnapshot, &te32)) {
            CloseHandle(hSnapshot);
            return;
        }

        do {
            if (te32.th32OwnerProcessID == processInfo.pid) {
                ThreadInfo threadInfo;
                threadInfo.tid = te32.th32ThreadID;

                HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID);
                if (hThread) {
                    DWORD exitCode = 0;
                    if (GetExitCodeThread(hThread, &exitCode)) {
                        threadInfo.status = (exitCode == STILL_ACTIVE) ? "Running" : "Terminated";
                    }
                    else {
                        threadInfo.status = "Unknown";
                    }
                    CloseHandle(hThread);
                }
                else {
                    threadInfo.status = "Unknown";
                }

                threads.push_back(threadInfo);
            }
        } while (Thread32Next(hSnapshot, &te32));

        CloseHandle(hSnapshot);
    }

    std::vector<std::string> ParseImportTable(const std::string& modulePath) {
        std::vector<std::string> functions;

        HANDLE hFile = CreateFileA(modulePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            return functions;
        }

        HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
        if (hMapping == NULL) {
            CloseHandle(hFile);
            return functions;
        }

        LPVOID baseAddress = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
        if (baseAddress == NULL) {
            CloseHandle(hMapping);
            CloseHandle(hFile);
            return functions;
        }

        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)baseAddress;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            UnmapViewOfFile(baseAddress);
            CloseHandle(hMapping);
            CloseHandle(hFile);
            return functions;
        }

        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)baseAddress + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            UnmapViewOfFile(baseAddress);
            CloseHandle(hMapping);
            CloseHandle(hFile);
            return functions;
        }

        DWORD importDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        if (importDirRVA == 0) {
            UnmapViewOfFile(baseAddress);
            CloseHandle(hMapping);
            CloseHandle(hFile);
            return functions;
        }

        PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)baseAddress + importDirRVA);

        while (importDesc->Name != 0) {
            char* dllName = (char*)((BYTE*)baseAddress + importDesc->Name);

            PIMAGE_THUNK_DATA thunk = NULL;
            if (importDesc->OriginalFirstThunk != 0) {
                thunk = (PIMAGE_THUNK_DATA)((BYTE*)baseAddress + importDesc->OriginalFirstThunk);
            }
            else {
                thunk = (PIMAGE_THUNK_DATA)((BYTE*)baseAddress + importDesc->FirstThunk);
            }

            while (thunk->u1.AddressOfData != 0) {
                if (!(thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                    PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)baseAddress + thunk->u1.AddressOfData);
                    std::string funcInfo = std::string(dllName) + " : " + std::string((char*)importByName->Name);
                    functions.push_back(funcInfo);
                }
                thunk++;
            }
            importDesc++;
        }

        UnmapViewOfFile(baseAddress);
        CloseHandle(hMapping);
        CloseHandle(hFile);

        return functions;
    }

    void GetDllInfo() {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processInfo.pid);
        if (!hProcess) {
            return;
        }

        HMODULE hMods[1024];
        DWORD cbNeeded;

        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                char modName[MAX_PATH];
                if (GetModuleFileNameExA(hProcess, hMods[i], modName, sizeof(modName))) {
                    DllInfo dllInfo;
                    dllInfo.path = modName;

                    // Parse import table for this DLL
                    dllInfo.functions = ParseImportTable(modName);

                    dlls.push_back(dllInfo);
                }
            }
        }

        CloseHandle(hProcess);
    }

public:
    void DisplayInfo() {
        std::cout << "PROCESS" << std::endl;
        std::cout << "Process name: " << processInfo.name << std::endl;
        std::cout << "PID: " << processInfo.pid << std::endl;
        std::cout << "PPID: " << processInfo.ppid << std::endl;
        std::cout << "Architecture: " << processInfo.architecture << std::endl;
        std::cout << "Path: " << processInfo.path << std::endl;
        std::cout << "Cmd: " << processInfo.cmdLine << std::endl;
        std::cout << std::endl;

        std::cout << "THREAD" << std::endl;
        for (const auto& thread : threads) {
            std::cout << "TID: " << thread.tid << std::endl;
            std::cout << "Status: " << thread.status << std::endl;
            std::cout << std::endl;
        }

        std::cout << "PE" << std::endl;
        for (const auto& dll : dlls) {
            for (const auto& func : dll.functions) {
                std::cout << "Dll: " << func << std::endl;
            }
        }
    }

    void SaveToFile() {
        std::string cleanName = processInfo.name;
        size_t pos = cleanName.find(".exe");
        if (pos != std::string::npos) {
            cleanName = cleanName.substr(0, pos);
        }

        std::string filename = cleanName + " - " + std::to_string(processInfo.pid) + ".txt";
        std::ofstream file(filename);
        if (!file.is_open()) {
            std::cerr << "Error: Could not create output file: " << filename << std::endl;
            return;
        }

        file << "PROCESS" << std::endl;
        file << "Process name: " << processInfo.name << std::endl;
        file << "PID: " << processInfo.pid << std::endl;
        file << "PPID: " << processInfo.ppid << std::endl;
        file << "Architecture: " << processInfo.architecture << std::endl;
        file << "Path: " << processInfo.path << std::endl;
        file << "Cmd: " << processInfo.cmdLine << std::endl;
        file << std::endl;

        file << "THREAD" << std::endl;
        for (const auto& thread : threads) {
            file << "TID: " << thread.tid << std::endl;
            file << "Status: " << thread.status << std::endl;
            file << std::endl;
        }

        file << "PE" << std::endl;
        for (const auto& dll : dlls) {
            for (const auto& func : dll.functions) {
                file << "Dll: " << func << std::endl;
            }
        }

        file.close();
        std::cout << "Information saved to: " << filename << std::endl;
    }
};

bool IsNumber(const std::string& str) {
    for (char c : str) {
        if (!std::isdigit(c)) {
            return false;
        }
    }
    return !str.empty();
}

void ShowUsage() {
    std::cout << "Usage:" << std::endl;
    std::cout << "  module1.exe <process_name>" << std::endl;
    std::cout << "  module1.exe <PID>" << std::endl;
    std::cout << std::endl;
    std::cout << "Examples:" << std::endl;
    std::cout << "  module1.exe notepad.exe" << std::endl;
    std::cout << "  module1.exe 1234" << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        ShowUsage();
        return 1;
    }

    std::string input = argv[1];
    ProcessAnalyzer analyzer;
    bool found = false;

    if (IsNumber(input)) {
        DWORD pid = std::stoul(input);
        found = analyzer.GetProcessByPID(pid);
        if (!found) {
            std::cerr << "Error: Process with PID " << pid << " not found or access denied." << std::endl;
        }
    }
    else {
        found = analyzer.GetProcessByName(input);
        if (!found) {
            std::cerr << "Error: Process '" << input << "' not found or access denied." << std::endl;
        }
    }

    if (found) {
        analyzer.DisplayInfo();
        analyzer.SaveToFile();
    }

    return found ? 0 : 1;
}