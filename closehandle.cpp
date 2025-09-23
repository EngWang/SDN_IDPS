#include <windows.h>
#include <iostream>

bool CheckDebuggerWithCloseHandle() {
    bool isDebugged = false;

    __try {
        // Attempt to close an invalid handle
        CloseHandle((HANDLE)0xDEADBEEF); // Invalid handle to trigger exception
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Get the exception code
        DWORD exceptionCode = GetExceptionInformation()->ExceptionRecord->ExceptionCode;

        // Normal case: Expect 0xC0000008 (ERROR_INVALID_HANDLE)
        if (exceptionCode != 0xC0000008) {
            // Debugger likely altered the exception
            std::cout << "Debugger detected (CloseHandle). Exception code: " << std::hex << exceptionCode << "\n";
            isDebugged = true;
        } else {
            // Normal execution: Exception is as expected
            std::cout << "No debugger detected (CloseHandle).\n";
        }
    }

    return isDebugged;
}

int main() {
    if (CheckDebuggerWithCloseHandle()) {
        // Non-crashing response: Switch to restricted mode
        std::cout << "Running in restricted mode due to debugger detection.\n";
        // Example actions: Disable sensitive features, log to server, or show warning
    } else {
        std::cout << "No debugger detected. Running normally.\n";
        // Proceed with full functionality
    }
    return 0;
}
