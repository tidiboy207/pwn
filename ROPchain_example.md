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
