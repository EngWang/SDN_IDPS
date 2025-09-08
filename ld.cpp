#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: %s <shellcode.bin>\n", argv[0]);
        return 1;
    }

    const char* filename = argv[1];
    FILE* file = fopen(filename, "rb");
    if (!file) {
        perror("Failed to open file");
        return 2;
    }

    fseek(file, 0, SEEK_END);
    size_t size = ftell(file);
    fseek(file, 0, SEEK_SET);

    void* shellcode = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!shellcode) {
        perror("Failed to allocate memory");
        fclose(file);
        return 3;
    }

    if (fread(shellcode, 1, size, file) != size) {
        perror("Failed to read file");
        VirtualFree(shellcode, 0, MEM_RELEASE);
        fclose(file);
        return 4;
    }

    fclose(file);

    ((void(*)())shellcode)();

    VirtualFree(shellcode, 0, MEM_RELEASE);
    return 0;
}