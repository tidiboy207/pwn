# ROPchain_chall_demo_file
## ROPchain.c
```C
#include <stdio.h>
#include <unistd.h>

void vuln() {
    char buffer[64];
    printf("Nhập dữ liệu: ");
    fgets(buffer, 200, stdin); // Buffer overflow
}

int main() {
    setbuf(stdout, NULL);
    printf("=== ROP CHALLENGE ===\n");
    vuln();
    printf("Thất bại!\n");
    return 0;
}
```
* Hàm vuln() chứa lỗ hổng
## Kiểm tra chế độ bảo vệ
```bash
checksec chall2
```
**Kết quả:**
```
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
```
- Các cơ chế bảo vệ: No canary, no PIE, NX enabled (vì vậy phải dùng ROP).
## Tìm gadgets để kiểm soát thanh ghi
```bash
1
```






