#include <windows.h>
#include <iostream>

bool CheckDebuggerWithTimeGetTime() {
    // Get start time
    DWORD startTime = timeGetTime();

    // Lightweight code block to measure
    volatile int sum = 0;
    for (int i = 0; i < 100000; i++) {
        sum += i; // Simple operation to avoid compiler optimization
    }

    // Get end time and calculate difference
    DWORD endTime = timeGetTime();
    DWORD timeDiff = endTime - startTime;

    // Log the time for debugging (optional)
    std::cout << "Execution time: " << timeDiff << " ms\n";

    // Threshold of 10ms (tuned to detect debugger delays while avoiding false positives)
    if (timeDiff > 10) {
        std::cout << "Debugger detected (timeGetTime). Switching to restricted mode.\n";
        return true; // Debugger detected
    }
    return false; // No debugger
}

int main() {
    if (CheckDebuggerWithTimeGetTime()) {
        // Non-crashing response: Enter restricted mode
        std::cout << "Running in restricted mode due to debugger detection.\n";
        // Example: Disable sensitive features or use fallback logic
        // e.g., Skip premium content, limit API access, or log to server
    } else {
        std::cout << "No debugger detected. Running normally.\n";
        // Proceed with normal application logic
    }
    return 0;
}
