BITS 32
global _start
section .text
_start:
    xor eax, eax            ; Avoid Null Bytes
    mov eax, [fs:eax + 0x30] ; EAX = PEB
    mov eax, [eax + 0xc]    ; EAX = PEB->Ldr
    mov esi, [eax + 0x14]   ; ESI = PEB->Ldr.InMemoryOrderModuleList
    lodsd                   ; EAX = Second module (ntdll.dll)
    xchg eax, esi           ; move to next element
    lodsd                   ; EAX = Third(kernel32)
    mov eax, [eax + 0x10]   ; EAX = Base address
    mov ebx, [eax + 0x3c]   ; RVA of PE signature
    add ebx, eax            ; VA of PE signature
    mov ebx, [ebx + 0x78]   ; RVA of the exported directory
    add ebx, eax            ; VA of the exported directory
    mov esi, [ebx + 0x20]   ; RVA of the exported function names table
    add esi, eax            ; VA of the exported function names table
    mov edx, eax            ; save eax into edx
    push esi                ; save the VA of the exported function names table
    push 0x00059ba3         ; Hash for LoadLibraryA
    xor ecx, ecx            ; prepare counter
    call _find_addr
    call _get_addr
    push edi
    mov esi, [esp + 8]      ; restore VA of the exported function names table
    push 0x0015bdfd         ; Hash for GetProcAddress
    xor ecx, ecx            ; prepare counter
    call _find_addr
    call _get_addr
    push edi
    mov esi, [esp + 16]     ; restore VA of the exported function names table
    push 0x00002ef5         ; Hash for WinExec
    xor ecx, ecx            ; prepare counter
    call _find_addr
    call _get_addr
    push edi
    jmp _do_main

_get_addr:
    mov esi, [ebx + 0x24]   ; RVA of function ordinal table
    add esi, edx            ; VA of function ordinal table
    mov cx, WORD [esi + ecx * 2] ; get biased_ordinal
    dec ecx                 ; get ordinal
    mov esi, [ebx + 0x1c]   ; RVA of AddressOfFunctions
    add esi, edx            ; VA of the Export Table
    mov edi, [esi + ecx * 4] ; RVA of function
    add edi, edx            ; VA of function
    ret

_find_addr:
    inc ecx                 ; increment name index counter
    lodsd                   ; load name rva into eax and increment esi by 4 to next rva
    add eax, edx            ; add kernel32.dll base address to get va of function name
    call _calculate_hash    ; get the hash
    cmp edi, [esp + 4]      ; compare our hash
    jnz _find_addr          ; loop if not matching
    ret                     ; return, ecx now holds the name array index of our function

_calculate_hash:
    push ecx
    push edx
    xor ecx, ecx
    mov edi, ecx
    mov edx, edi
_loop:
    shl edi, 1
    mov dl, BYTE [eax + ecx]
    add edi, edx
    inc ecx
    cmp BYTE[eax + ecx], 0
    jne _loop
    pop edx
    pop ecx
    ret

_do_main:
    mov ebp, [esp + 16]     ; LoadLibraryA address
    mov ebx, [esp + 8]      ; GetProcAddress address
    mov edi, [esp]          ; WinExec address
    push "ll"
    push "32.d"
    push "user"
    push esp
    call ebp                ; Call LoadLibraryA("user32.dll"), eax = user32 base
    push "oxA"
    push "ageB"
    push "Mess"
    push esp
    push eax
    call ebx                ; Call GetProcAddress(user32, "MessageBoxA"), eax = MessageBoxA
    push 0x00327865         ; "ex2\0" (e=0x65, x=0x78, 2=0x32, null=0x00)
    mov esi, esp            ; Pointer to "ex2"
    push 0x79000000         ; "y\0\0\0" (y=0x79, nulls)
    push 0x6C6C7566         ; "lluf" (l=0x6C, l=0x6C, u=0x75, f=0x66)
    push 0x73736563         ; "ssecc" (s=0x73, s=0x73, e=0x65, c=0x63)
    mov edx, esp            ; Pointer to "successfully"
    xor ecx, ecx
    push ecx                ; uType (0)
    push esi                ; lpCaption ("ex2")
    push edx                ; lpText ("successfully")
    push ecx                ; hWnd (0)
    call eax                ; Call MessageBoxA
    push 0x00000000         ; Null terminator
    push 0x6578652e         ; ".exe"
    push 0x636c6163         ; "calc"
    mov esi, esp            ; Pointer to "calc.exe"
    push 5                  ; SW_SHOW
    push esi                ; "calc.exe"
    call edi                ; Call WinExec