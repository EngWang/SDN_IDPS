#include <windows.h>
#include <iostream>
#include <string>
#include <vector>

// Simple XOR-based string decryption for obfuscation
std::string DecryptString(const char* encrypted, size_t len, BYTE key) {
    std::string decrypted;
    for (size_t i = 0; i < len; ++i) {
        decrypted += encrypted[i] ^ key;
    }
    return decrypted;
}

// Simple hash for dynamic key selection
DWORD SimpleHash(const std::string& str) {
    DWORD hash = 0;
    for (char c : str) {
        hash = ((hash << 5) + hash) + c; // Simple DJB2-inspired hash
    }
    return hash;
}

// Complicated registry check for VM artifacts
bool CheckVMWithRegistry() {
    bool isVM = false;
    
    // Obfuscated registry key components (XOR-encrypted with key 0x1F)
    const char encBaseKey[] = {0x44, 0x4B, 0x4C, 0x4D, 0x5C, 0x53, 0x4F, 0x46, 0x54, 0x57, 0x41, 0x52, 0x45}; // HKLM\SOFTWARE
    const char encVMware[] = {0x3F, 0x3E, 0x39, 0x32, 0x36, 0x3B, 0x2C, 0x2F, 0x1E, 0x2F, 0x2E, 0x3A, 0x2E}; // VMware, Inc.
    const char encVBox[] = {0x3F, 0x36, 0x32, 0x3A, 0x33, 0x3B, 0x1E, 0x32, 0x3F, 0x36, 0x32, 0x37, 0x3A, 0x3B, 0x3C}; // Oracle\VirtualBox
    const char encHyperV[] = {0x3E, 0x3A, 0x3C, 0x36, 0x32, 0x3F, 0x3A, 0x37, 0x33, 0x2C, 0x3A, 0x3C, 0x3A, 0x37}; // Microsoft\Hyper-V
    
    // Decrypt at runtime
    std::string baseKey = DecryptString(encBaseKey, sizeof(encBaseKey) - 1, 0x1F);
    std::vector<std::string> vmKeys = {
        DecryptString(encVMware, sizeof(encVMware) - 1, 0x1F),
        DecryptString(encVBox, sizeof(encVBox) - 1, 0x1F),
        DecryptString(encHyperV, sizeof(encHyperV) - 1, 0x1F)
    };
    
    // Dynamic key path generation
    std::vector<std::string> fullPaths;
    for (const auto& vmKey : vmKeys) {
        std::string path = baseKey + "\\" + vmKey;
        fullPaths.push_back(path);
    }
    
    // Additional obfuscation: Use hash to select order of checks
    DWORD seed = GetTickCount(); // Not used for timing, just for randomization
    std::vector<int> checkOrder = {0, 1, 2};
    for (size_t i = 0; i < checkOrder.size(); ++i) {
        size_t j = (SimpleHash(fullPaths[i]) ^ seed) % checkOrder.size();
        std::swap(checkOrder[i], checkOrder[j]);
    }
    
    // Check registry keys
    HKEY hKey;
    for (int idx : checkOrder) {
        std::string path = fullPaths[idx];
        
        // Inline assembly to obfuscate registry open call (complicates analysis)
        HKEY resultKey;
        LONG result;
        __asm {
            push 0              // Reserved
            lea eax, [path]     // Key name
            push eax
            push KEY_READ       // Access rights
            push 0              // Options
            push HKEY_LOCAL_MACHINE
            call RegOpenKeyExA
            mov result, eax
            mov resultKey, eax
        }
        
        if (result == ERROR_SUCCESS) {
            isVM = true; // Key exists, likely a VM
            RegCloseKey(hKey);
            std::cout << "VM detected (registry key: " << path << ").\n";
            break;
        } else if (result != ERROR_FILE_NOT_FOUND) {
            // Handle access denied or other errors gracefully
            std::cout << "Registry access error for " << path << ": " << result << "\n";
        }
    }
    
    // Fallback: Check an additional obscure key (e.g., VMware Tools)
    if (!isVM) {
        const char encVMwareTools[] = {0x3F, 0x3E, 0x39, 0x32, 0x36, 0x3B, 0x2C, 0x1E, 0x39, 0x2F, 0x2F, 0x3C, 0x37}; // VMware Tools
        std::string vmToolsKey = baseKey + "\\" + DecryptString(encVMwareTools, sizeof(encVMwareTools) - 1, 0x1F);
        
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, vmToolsKey.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            isVM = true;
            std::cout << "VM detected (VMware Tools key).\n";
            RegCloseKey(hKey);
        }
    }
    
    return isVM;
}

int main() {
    if (CheckVMWithComplicatedRegistry()) {
        std::cout << "Virtual environment detected! Running in restricted mode.\n";
        // Non-crashing: Disable features, log, or show warning
        // e.g., Disable premium content or limit API access
    } else {
        std::cout << "No virtual environment detected. Running normally.\n";
        // Proceed with full functionality
    }
    return 0;
}
