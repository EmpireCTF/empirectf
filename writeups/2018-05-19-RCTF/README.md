# 2018-05-19-RCTF #

[CTFTime link](https://ctftime.org/event/624) | [Website](https://rctf2018.xctf.org.cn/)

---

## Challenges ##

### Misc ###

 - [x] [206 Number Game](#206-misc--number-game)
 - [x] [52 git](#52-misc--git)
 - [ ] [606 520 gift](#606-misc--520-gift)
 - [x] [377 cats Rev.2](#377-misc--cats-rev2)
 - [x] [256 cats](#256-misc--cats)
 - [x] [73 sign](#73-misc--sign)

### Crypto ###

 - [ ] [416 ECDH](#416-crypto--ecdh)
 - [x] [176 cpushop](#176-crypto--cpushop)

### Reverse ###

 - [x] [540 magic](#530-reverse--magic)
 - [x] [161 babyre](#161-reverse--babyre)
 - [ ] [588 compiler](#588-reverse--compiler)
 - [x] [317 simple vm](#317-reverse--simple-vm)
 - [x] [606 simple re](#606-reverse--simple-re)
 - [x] [338 sql](#338-reverse--sql)
 - [x] [444 babyre2](#444-reverse--babyre2)

### Web ###

 - [ ] [769](#769-web--no-js)
 - [ ] [606](#606-web--backdoor)
 - [ ] [487](#487-web--amp)
 - [ ] [869](#869-web--retter)
 - [x] [500](#500-web--r-cursive)
 - [ ] [769](#769-web--rblog-2018-rev2)
 - [ ] [434](#434-web--rblog-2018)

### Pwn ###

 - [ ] [317](#317-pwn--babyheap)
 - [ ] [540](#540-pwn--stringer)
 - [ ] [465](#465-pwn--rnote4)
 - [ ] [384](#384-pwn--rnote3)
 - [ ] [454](#454-pwn--simulator)

---

## 206 Misc / Number Game ##

**No files provided**

**Description**

> Guess Guess Guess
> 
> nc 149.28.139.172 10002

**Solution**

Upon connecting, we get a standard PoW prompt:

    sha256(****+UJBS55MXKhMOcSQO) == 4e3cefcf649092ef546aaabfcfa628e63377ce08bf17012f628ac48fbba2307d
    Give me XXXX:

([simple PoW solver](scripts/pow.py))

After solving the PoW:

      o__ __o             o__ __o    ____o__ __o____   o__ __o__/_ 
     <|     v\           /v     v\    /   \   /   \   <|    v      
     / \     <\         />       <\        \o/        < >          
     \o/     o/       o/                    |          |           
      |__  _<|       <|                    < >         o__/_       
      |       \       \                    |          |           
     <o>       \o       \         /         o         <o>          
      |         v\       o       o         <|          |           
     / \         <\      <\__ __/>         / \        / \          


​                                                                   
​                                                                   
    In every round of the game, I'll choose some different numbers from the figure interval. You are required to guess those numbers,ofc so does the order of them.
    On each surmise of yours, 2 numbers will be told as a hint for you, but you need to speculate the fuctions of these 2 figures. (XD
    GLHF
                                                                   
    ================== round 1 ================== 
    Give me 4 numbers, in[0, 10), You can only try 6 times

Some string format vulns and overflows were tried, but no luck, we actually have to solve the game properly. Providing 4 numbers returns e.g.:

    Nope. 1, 0

Should be familiar, it's the [Mastermind game](https://en.wikipedia.org/wiki/Mastermind_(board_game)), apparently also known as "cows and bulls". In each round, there is a hidden sequence of four numbers, 0 through 9. We get 6 attempts to guess the correct sequence. With each incorrect attempt, we get two pieces of feedback:

 - "blacks" - how many of our numbers are in the hidden sequence AND in the same position
 - "whites" - how many of our numbers are in the hidden sequence but NOT in the same position

So I ~~stole~~ adapted a Mastermind solver from [here](https://github.com/Michael0x2a/mastermind-solver/blob/master/python/solve_mastermind.py) (thanks @Michael0x2a!). The principle is simple:

 1. generate a pool of all possible guesses, for 10 different numbers and a sequence of 4 numbers, there are 10000 possible sequences
 2. pick a guess and get feedback for it
 3. if incorrect, eliminate all guesses from the pool that are inconsistent with the feedback and go back to step 2

The first guess is always `[0, 0, 1, 1]` for the 10 number 4-sequence (as it turns out all rounds are actually like this). There is an additional heuristic in picking a good guess, namely, a guess which may reduce the pool to the fewest remaining sequences.

I added socket interaction and the PoW solver to make it automated. After letting it run for a bit, I was disappointed to see that it rarely got past 4 rounds, and at this point I found out on the IRC that there are 8 rounds before you get the flag.

Mostly hopeless, I looked at the correct solutions it got to the few rounds it managed. Interestingly enough, among all the correct solutions, there was never a sequence with duplicate numbers! So, I removed these sequences from the initial pool and made the initial guess to always be `[0, 1, 2, 3]`.

With this modification the results were immediately better and in just a couple of attempts the flag was obtained!

`RCTF{0lD_GaM3_nAmed_Bu11s_4nd_C0ws}`

([full script here](scripts/number-game-solver.py))

## xxx name ##

**Files provided**

 - `file`

**Description**

> ...

**Solution**



### babyre

There are many useless codes in this program, and it is unnecessary to reverse them. The only critical function is 

```c
int __cdecl sub_80488E0(char *s, __int64 c, int seed, int a5, int a6)
{
  unsigned int v5; // ST4C_4
  int i; // [esp+1Ch] [ebp-1Ch]

  memset(s, 0, 0x20u);
  scanf("%s", s);//get input
  for ( i = 0; i <= 29; ++i )
  {
    v5 = critical_hash(s[i], c, seed, a6, a5);
    printf("%lx\n", v5);
  }
  return i;
}
```

The second argument is a given constant; the "s" is a buffer; the last 3 arguments are decided by debugging, which depends on seed that we input and the uninitialized local variable access(possibly UB?), and they can be different depending on the input and in each time running the program. However, what I did is to obtain these 3 arguments by gdb debugging with arbitrary input seed, and it works!

By the way, the first input in main fuction is useless, it does not affect the result.

 I did not reverse the "critical\_hash" function, but did by bruteforce attack.

```c
#include <stdio.h>
#include <memory.h>

unsigned int keys[] =
{
0xB80C91FE,0x70573EFE,
0xBEED92AE,0x7F7A8193,
0x7390C17B,0x90347C6C,
0xAA7A15DF,0xAA7A15DF,
0x526BA076,0x153F1A32,
0x545C15AD,0x7D8AA463,
0x526BA076,0xFBCB7AA0,
0x7D8AA463,0x9C513266,
0x526BA076,0x6D7DF3E1,
0xAA7A15DF,0x9C513266,
0x1EDC3864,0x9323BC07,
0x7D8AA463,0xFBCB7AA0,
0x153F1A32,0x526BA076,
0xF5650025,0xAA7A15DF,
0x1EDC3864,0xB13AD888
};

unsigned int critical_hash(unsigned int a1, unsigned long long a2, int a3, int a4, int a5)
{
  unsigned long long v5; // rax
  unsigned int i; // [esp+1Ch] [ebp-ACh]
  unsigned int v8; // [esp+20h] [ebp-A8h]
  unsigned int j; // [esp+24h] [ebp-A4h]
  int ub_hash; // [esp+28h] [ebp-A0h]
  int s[32]; // [esp+2Ch] [ebp-9Ch]
  unsigned int v12; // [esp+ACh] [ebp-1Ch]

  memset(s, 0, 0x20u);
  for ( i = 0; i <= 0x1D; ++i )
    s[i] = (4 * a3 + ub_hash) ^ a5 ^ a4;
  v8 = a1;
  for ( j = 0; j <= 527; ++j )
  {
    v5 = a2 >> (j & 0x1F);
    if ( j & 0x20 )
      v5 = (v5 >> 32) | (v5 & 0xffffffff00000000LL) ;
    v8 = (v8 >> 1) ^ (((unsigned int)v5 ^ v8 ^ (v8 >> 16) ^ (1551120942 >> (((v8 >> 1) & 1)
                                                                          + 2
                                                                          * (2
                                                                           * (((v8 >> 20) & 1)
                                                                            + 2
                                                                            * (2 * ((v8 & 0x80000000) != 0)
                                                                             + ((v8 >> 26) & 1)))
                                                                           + ((v8 >> 9) & 1))))) << 31);
  }
  return v8;
}

int solve()
{
	unsigned int v5; // ST4C_4
	int i; // [esp+1Ch] [ebp-1Ch]
	char flag[0x20];
	memset(flag, 0, 0x20u);

	for (i = 0; i <= 29; ++i )
	{
		for (int c = 0; c < 256; ++c)
		{
			v5 = critical_hash(c, 
       /*value obtained from gdb pwndbg*/0x1D082C23A72BE4C1LL, 0xffff9cc0, 0x6e00, 0x6e);
			if (v5 == keys[i])
			{
				printf("%c", c);
			}
		}
	}

	return i;
}

int main(int argc, char const *argv[])
{
	solve();
	return 0;
}
//output: RCTF{Kee1o9_1s_a1ready_so1ved}
```

### simplevm

```c
__int64 sub_400896()
{//code of vm engine
  __int64 instr_pointer; // rax
  _BYTE *vm_code; // rbp
  int nxt_instr_pointer; // ebx
  __int64 v4; // rdx
  __int64 v5; // rax
  __int64 v6; // rax
  __int64 v7; // rax
  __int64 v8; // rax
  __int64 v9; // rax
  int v10; // eax
  __int64 v11; // rax
  char v12; // dl
  int v13; // eax
  int v14; // eax
  _BYTE *v15; // rax
  __int64 v16; // rax
  __int64 v17; // rax
  __int64 v18; // rax

  instr_pointer = 0LL;
  vm_code = ::vm_code;
  while ( 1 )
  {
    nxt_instr_pointer = instr_pointer + 1;
    switch ( vm_code[instr_pointer] )
    {
      case 0:
        return *(unsigned int *)&vm_code[nxt_instr_pointer];
      case 1:
        goto LABEL_35;
      case 2:
        v4 = nxt_instr_pointer;
        nxt_instr_pointer = instr_pointer + 9;
        vm_code[*(signed int *)&vm_code[v4]] = *(_DWORD *)&vm_code[(signed int)instr_pointer + 5];
        break;
      case 3:
        v5 = nxt_instr_pointer;
        nxt_instr_pointer += 4;
        v6 = *(signed int *)&vm_code[v5];
        goto LABEL_27;
      case 4:
        v7 = nxt_instr_pointer;
        nxt_instr_pointer += 4;
        v8 = *(signed int *)&vm_code[v7];
        goto LABEL_31;
      case 5:
        v9 = nxt_instr_pointer;
        nxt_instr_pointer += 4;
        v10 = (char)vm_code[*(signed int *)&vm_code[v9]];
        goto LABEL_21;
      case 6:
        v11 = nxt_instr_pointer;
        v12 = g_var;
        nxt_instr_pointer += 4;
        v8 = *(signed int *)&vm_code[v11];
        goto LABEL_9;
      case 7:
        v13 = g_var;
        goto LABEL_23;
      case 8:
        v14 = ~(g_var & condition);
        goto LABEL_12;
      case 0xA:
        v14 = getchar();
        goto LABEL_12;
      case 0xB:
        putchar(condition);
        break;
      case 0xC:
        v15 = &vm_code[*(signed int *)&vm_code[nxt_instr_pointer]];
        if ( *v15 )
        {
          nxt_instr_pointer = *(_DWORD *)&vm_code[nxt_instr_pointer + 4];
          --*v15;
        }
        else
        {
          nxt_instr_pointer += 8;
        }
        break;
      case 0xD:
        ++condition;
        break;
      case 0xE:
        ++g_var;
        break;
      case 0xF:
        v14 = g_var;
        goto LABEL_12;
      case 0x10:
        v10 = condition;
        goto LABEL_21;
      case 0x11:
        v16 = nxt_instr_pointer;
        nxt_instr_pointer += 4;
        v13 = *(_DWORD *)&vm_code[v16];
LABEL_23:
        condition += v13;
        break;
      case 0x12:
        v6 = g_var;
        goto LABEL_27;
      case 0x13:
        v6 = condition;
LABEL_27:
        v14 = (char)vm_code[v6];
        goto LABEL_12;
      case 0x14:
        v17 = nxt_instr_pointer;
        nxt_instr_pointer += 4;
        v14 = *(_DWORD *)&vm_code[v17];
        goto LABEL_12;
      case 0x15:
        v18 = nxt_instr_pointer;
        nxt_instr_pointer += 4;
        v10 = *(_DWORD *)&vm_code[v18];
LABEL_21:
        g_var = v10;
        break;
      case 0x16:
        v8 = g_var;
LABEL_31:
        v12 = condition;
LABEL_9:
        vm_code[v8] = v12;
        break;
      case 0x17:
        v14 = condition - g_var;
LABEL_12:
        condition = v14;
        break;
      case 0x18:
        if ( condition )
LABEL_35:
          nxt_instr_pointer = *(_DWORD *)&vm_code[nxt_instr_pointer];
        else
          nxt_instr_pointer = instr_pointer + 5;
        break;
      default:
        break;
    }
    if ( nxt_instr_pointer >= file_size )
      return 0LL;
    instr_pointer = nxt_instr_pointer;
  }
}
```

and the code to analyze the vmcode:

```python
def match(opcodes, opcode):
	assert opcodes[0] == opcode
	opcodes.pop(0)

def parse_uint32_l(opcodes):
	return hex(opcodes.pop(0) + \
		(opcodes.pop(0) << 8) + \
		(opcodes.pop(0) << 16) + \
		(opcodes.pop(0) << 24))

def return_vm(opcodes, ret_list):
	match(opcodes, 0)
	ret_list.append("return " + parse_uint32_l(opcodes))

def jmp_vm(opcodes, ret_list):
	match(opcodes, 1)
	ret_list.append("jmp " + parse_uint32_l(opcodes))

def assign_vm(opcodes, ret_list):
	match(opcodes, 2)
	ret_list.append("[" + parse_uint32_l(opcodes) + "] = " + parse_uint32_l(opcodes))

def set_cond_vm(opcodes, ret_list):
	match(opcodes, 3)
	ret_list.append("cond = byte [" + parse_uint32_l(opcodes) + "]")

def get_cond_vm(opcodes, ret_list):
	match(opcodes, 4)
	ret_list.append("byte [" + parse_uint32_l(opcodes) + "] = (byte)cond")

def set_global_vm(opcodes, ret_list):
	match(opcodes, 5)
	ret_list.append("global = byte [" + parse_uint32_l(opcodes) + "]")

def get_global_vm(opcodes, ret_list):
	match(opcodes, 6)
	ret_list.append("[" + parse_uint32_l(opcodes) + "] = global")

def cond_plus_global(opcodes, ret_list):
	match(opcodes, 7)
	ret_list.append("cond += global")

def some_logic_oper_vm(opcodes, ret_list):
	match(opcodes, 8)
	ret_list.append("cond = ~(global & cond)")

def get_char(opcodes, ret_list):
	match(opcodes, 0xa)
	ret_list.append("cond = getchar()")

def put_char(opcodes, ret_list):
	match(opcodes, 0xb)
	ret_list.append("putchar(cond)")

def cond_jmp(opcodes, ret_list):
	match(opcodes, 0xc)
	ret_list.append("[" + parse_uint32_l(opcodes) + "] ? jmp " + parse_uint32_l(opcodes) + " and --")

def cond_plus_1(opcodes, ret_list):
	match(opcodes, 0xd)
	ret_list.append("cond += 1")

def global_plus_1(opcodes, ret_list):
	match(opcodes, 0xe)
	ret_list.append("global += 1")

def cond_eq_global(opcodes, ret_list):
	match(opcodes, 0xf)
	ret_list.append("cond = global")

def global_eq_cond(opcodes, ret_list):
	match(opcodes, 0x10)
	ret_list.append("global = cond")

def plus(opcodes, ret_list):
	match(opcodes, 0x11)
	ret_list.append("cond += " + parse_uint32_l(opcodes))

def assign_reg_vm(opcodes, ret_list):
	match(opcodes, 0x12)
	ret_list.append("cond = byte [global]")

def assign_creg_vm(opcodes, ret_list):
	match(opcodes, 0x13)
	ret_list.append("cond = byte [cond]")

def asssign_cond(opcodes, ret_list):
	match(opcodes, 0x14)
	ret_list.append("cond = " + parse_uint32_l(opcodes))

def asssign_global(opcodes, ret_list):
	match(opcodes, 0x15)
	ret_list.append("global = " + parse_uint32_l(opcodes))

def gobal_ref_eq_cond(opcodes, ret_list):
	match(opcodes, 0x16)
	ret_list.append("[global] = cond")

def cond_minus_global(opcodes, ret_list):
	match(opcodes, 0x17)
	ret_list.append("cond -= global")

def cond_jmp_based_on_cond(opcodes, ret_list):
	match(opcodes, 0x18)
	ret_list.append("cond ? jmp " + parse_uint32_l(opcodes))

def nop(opcodes, ret_list):
	opcodes.pop(0)
	ret_list.append("nop")

opcode_dic = {
0 : return_vm,
1 : jmp_vm,
2 : assign_vm,
3 : set_cond_vm,
4 : get_cond_vm,
5 : set_global_vm,
6 : get_global_vm,
7 : cond_plus_global,
8 : some_logic_oper_vm,
0xa : get_char,
0xb : put_char,
0xc : cond_jmp,
0xd : cond_plus_1,
0xe : global_plus_1,
0xf : cond_eq_global,
0x10 : global_eq_cond,
0x11 : plus,
0x12 : assign_reg_vm,
0x13 : assign_creg_vm,
0x14 : asssign_cond,
0x15 : asssign_global,
0x16 : gobal_ref_eq_cond,
0x17 : cond_minus_global,
0x18 : cond_jmp_based_on_cond
}

def disassemble_vm(opcodes):
	total_len = len(opcodes)
	ret_list = []
	while len(opcodes) > 0:
		ret_list.append(hex(total_len - len(opcodes) + 0x30))
		if opcodes[0] in opcode_dic:
			opcode_dic[opcodes[0]](opcodes, ret_list)
		else:
			nop(opcodes, ret_list)
		print "\n".join(ret_list)
		print "\n\n"

with open('./p.bin', 'r') as content_file:
	content = content_file.read()

content = map(ord, list(content[0x30:0xe2]))

print content

disassemble_vm(content)
```

with the output:

```c

0x30: global = 0x100
0x35: global += 1
0x36: cond = byte [global]
0x37: putchar(cond)
0x38: byte [0x100] ? jmp 0x35 and --
0x41: nop
//output the "Input Flag:"
0x42: global = 0x110
0x47: global += 1
0x48: cond = getchar()
0x49: nop
0x4a: [global] = (byte)cond
0x4b: byte [0x110] ? jmp 0x47 and --
//[0x110] == 0x1f, flag size is 32
//input stored in [0x111]


0x54: nop

//do some bit operation to each character 
0x55: cond = byte [0x140]//[0x140] == 0x20 + i
0x5a: global = cond
0x5b: cond += 0xf1//cond points to input
0x60: cond = byte [cond]
//cond = input[i], [0x111]
0x61: [0x143] = (byte)cond
0x66: cond = ~(global & cond)
0x67: [0x141] = (byte)cond
0x6c: global = cond
0x6d: cond = byte [0x140]
0x72: cond = ~(global & cond)
0x73: [0x142] = (byte)cond
0x78: cond = byte [0x141]
0x7d: cond = byte [0x143]
0x82: cond = ~(global & cond)
0x83: global = cond
0x84: cond = byte [0x142]
0x89: cond = ~(global & cond)
0x8a: [0x144] = (byte)cond
0x8f: nop
0x90: cond = byte [0x140]
0x95: cond += 0xf1
0x9a: global = cond
0x9b: cond = byte [0x144]
0xa0: [global] = (byte)cond
0xa1: global = byte [0x140]
0xa6: global += 1
0xa7: [0x140] = global
0xac: byte [0x145] ? jmp 0x55 and --

//compare with key
0xb5: nop
0xb6: cond = byte [0x146] //[0x146] is i
0xbb: cond += 0x5 //5[i]
0xc0: cond = byte [cond] //take 5[i]
0xc1: global = cond //global = 5[i], which is key
0xc2: cond = byte [0x146]
0xc7: cond += 0x111
0xcc: cond = byte [cond] //0x111[i] == 5[i], 0x111[i] is the result of bit operation
0xcd: cond -= global
0xce: cond ? jmp 0x160
0xd3: byte [0x146] ? jmp 0xb6 and --
0xdc: jmp 0x176//success
0xe1: nop

```

gobal and cond are actually registers; take care about the byte access or dword access, and signed extension or unsigned extension(movzx or movsx), which are likely to be handled mistakenly. 

obtaining the vmcode and understanding what it does, we can write bruteforce crack

```python
keys = [0x10,0x18,0x43,0x14,0x15,0x47,0x40,0x17,0x10,0x1d,0x4b,
0x12,0x1f,0x49,0x48,0x18,0x53,0x54,0x01,0x57,0x51,0x53,0x05,0x56,0x5a,0x08,0x58,
0x5f,0x0a,0x0c,0x58,0x09]

def some_bit_oper(c, i):
	i += 0x20
	g = i
	t3 = c
	t1 = (~(i & c)) & 0xff
	t2 = (~(t1 & i)) & 0xff
	t4 = (~((~(t1 & t3)) & t2)) & 0xff
	return t4


flag = []
for i in xrange(0, 32):
	for c in xrange(0, 256):
		if some_bit_oper(c, i) == keys[i]:
			flag.append(chr(c))

print "".join(flag)
#09a71bf084a93df7ce3def3ab1bd61f6
```

### babyre2

open executable in ida, and many SSE instruction is found :\(

for SSE instructions, it is even more clear to read assembly than to read F5 decompiler result

After changing some of the data structure of the variable, F5 gives such results

```c
  

  s[7] = -1LL;
  s[8] = -1LL;
  input[0] = 'UUUUUUUU';
  input[1] = 'UUUUUUUU';
  input[2] = 'UUUUUUUU';
  input[3] = 'UUUUUUUU';
  input[4] = 'UUUUUUUU';
  input[5] = 'UUUUUUUU';
  input[6] = 'UUUUUUUU';
  input[7] = 'UUUUUUUU';
  input[8] = 'UUUUUUUU';
  input[9] = 'UUUUUUUU';
  input[10] = 'UUUUUUUU';
  input[11] = 'UUUUUUUU';
  input[12] = 'UUUUUUUU';
  input[13] = 'UUUUUUUU';
  input[14] = 'UUUUUUUU';
  input[15] = 'UUUUUUUU';
  s[0] = ' emocleW';
  s[9] = -1LL;
  s[1] = ' FTCR ot';
  s[10] = -1LL;
  s[2] = 'eH !8102';
  s[11] = -1LL;
  s[3] = ' a si er';
  s[12] = -1LL;
  s[13] = -1LL;
  s[14] = -1LL;
  s[15] = -1LL;
  s[4] = 'c ERybaB';
  s[5] = 'egnellah';
  s[6] = 'uoy rof ';
  LOWORD(s[7]) = '.';
  puts((const char *)s);
  __printf_chk(1LL, "Give me your flag: ");
  __isoc99_scanf("%127s", input);
/*
  unsigned __int64 input[16]; // [rsp+0h] [rbp-198h]
  unsigned __int64 s[16]; // [rsp+80h] [rbp-118h]
  q_xmm_word result[8]; // [rsp+100h] [rbp-98h]
  //result is regared as uint64_t when assigning the result
  //and regarded as uint128_t when checking the correctness of the result
 
00000000 q_xmm_word      union ; (sizeof=0x10, mappedto_16)
00000000                                         ; XREF: main+1B8/w
00000000                                         ; main+1E1/w ...
00000000 qwords          two_qwords ?
00000000 xmms            xmmword ?
00000000 q_xmm_word      ends
00000000
00000000 ; ---------------------------------------------------------------------------
00000000
00000000 two_qwords      struc ; (sizeof=0x10, mappedto_14)
00000000                                         ; XREF: q_xmm_word/r
00000000 low             dq ?
00000008 high            dq ?
00000010 two_qwords      ends
*/
  result[0].qwords.low = sub_400BA0((q_xmm_word)(input[0] * (unsigned __int128)s[0]), 0xFFFFFFFFFFFFFFC5LL, 0LL);
  result[0].qwords.high = sub_400BA0((q_xmm_word)(input[1] * (unsigned __int128)s[1]), 0xFFFFFFFFFFFFFFC5LL, 0LL);
  result[1].qwords.low = sub_400BA0((q_xmm_word)(input[2] * (unsigned __int128)s[2]), 0xFFFFFFFFFFFFFFC5LL, 0LL);
  result[1].qwords.high = sub_400BA0((q_xmm_word)(input[3] * (unsigned __int128)s[3]), 0xFFFFFFFFFFFFFFC5LL, 0LL);
  result[2].qwords.low = sub_400BA0((q_xmm_word)(input[4] * (unsigned __int128)s[4]), 0xFFFFFFFFFFFFFFC5LL, 0LL);
  result[2].qwords.high = sub_400BA0((q_xmm_word)(input[5] * (unsigned __int128)s[5]), 0xFFFFFFFFFFFFFFC5LL, 0LL);
  result[3].qwords.low = sub_400BA0((q_xmm_word)(input[6] * (unsigned __int128)s[6]), 0xFFFFFFFFFFFFFFC5LL, 0LL);
  result[3].qwords.high = sub_400BA0((q_xmm_word)(input[7] * (unsigned __int128)s[7]), 0xFFFFFFFFFFFFFFC5LL, 0LL);
  result[4].qwords.low = sub_400BA0((q_xmm_word)(input[8] * (unsigned __int128)s[8]), 0xFFFFFFFFFFFFFFC5LL, 0LL);
  result[4].qwords.high = sub_400BA0((q_xmm_word)(input[9] * (unsigned __int128)s[9]), 0xFFFFFFFFFFFFFFC5LL, 0LL);
  result[5].qwords.low = sub_400BA0((q_xmm_word)(input[10] * (unsigned __int128)s[10]), 0xFFFFFFFFFFFFFFC5LL, 0LL);
  result[5].qwords.high = sub_400BA0((q_xmm_word)(input[11] * (unsigned __int128)s[11]), 0xFFFFFFFFFFFFFFC5LL, 0LL);
  result[6].qwords.low = sub_400BA0((q_xmm_word)(input[12] * (unsigned __int128)s[12]), 0xFFFFFFFFFFFFFFC5LL, 0LL);
  result[6].qwords.high = sub_400BA0((q_xmm_word)(input[13] * (unsigned __int128)s[13]), 0xFFFFFFFFFFFFFFC5LL, 0LL);
  result[7].qwords.low = sub_400BA0((q_xmm_word)(input[14] * (unsigned __int128)s[14]), 0xFFFFFFFFFFFFFFC5LL, 0LL);
  v3 = sub_400BA0((q_xmm_word)(input[15] * (unsigned __int128)s[15]), 0xFFFFFFFFFFFFFFC5LL, 0LL);
  v4 = _mm_load_si128((const __m128i *)result);
  result[7].qwords.high = v3;
```

The logic is to regard 2 char arrays as array of uint64\_t multiply the input by s, which is welcome message and 0xffffffff after then.

then store the result in result array

take a look at xmm instructions after then:

```assembly
movdqa  xmm1, xmmword ptr [rsp+198h+result] ; regard result as array of uint128_t
mov     qword ptr [rsp+198h+result+78h], rax
movdqa  xmm0, xmmword ptr cs:unk_602070
pxor    xmm1, xmmword ptr cs:keys ; xmm1 = result[0] ^ keys[0]
movdqa  xmm4, xmmword ptr [rsp+198h+result+20h]
pxor    xmm0, xmmword ptr [rsp+198h+result+10h] ; xmm0 = keys[1] ^ result[1]
movdqa  xmm3, xmmword ptr [rsp+198h+result+30h]
pxor    xmm4, xmmword ptr cs:unk_602080 ; xmm4 = xor 2
movdqa  xmm2, xmmword ptr [rsp+198h+result+40h]
pxor    xmm3, xmmword ptr cs:unk_602090 ; xmm5 = xor3
por     xmm1, xmm0      ; xmm1 = [0] | [1]
pxor    xmm2, xmmword ptr cs:unk_6020A0 ; xmm2 = xor 4
movdqa  xmm0, xmmword ptr [rsp+198h+result+60h]
por     xmm4, xmm1      ; xmm4 = [0] | [1] | [2]
movdqa  xmm1, xmmword ptr [rsp+198h+result+50h]
pxor    xmm0, xmmword ptr cs:unk_6020C0 ; xmm0 = xor 6
por     xmm3, xmm4      ; xmm3 = [0] | [1] | [2] | [3]
pxor    xmm1, xmmword ptr cs:unk_6020B0 ; xmm1 = xor [5]
por     xmm2, xmm3      ; xmm2 = [0] | [1] | [2] | [3] | [4]
movdqa  xmm3, xmm2
movdqa  xmm2, xmm1
movdqa  xmm1, xmm0
movdqa  xmm0, xmmword ptr cs:unk_6020D0
por     xmm2, xmm3      ; xmm2 = [0] | [1] | [2] | [3] | [4] | [5]
pxor    xmm0, xmmword ptr [rsp+198h+result+70h] ; xmm0 = xor7
por     xmm1, xmm2
por     xmm0, xmm1
movdqa  xmm1, xmm0
psrldq  xmm1, 8
por     xmm0, xmm1
movq    rax, xmm0
test    rax, rax
jz      short loc_400A86 ; jmp if correct
mov     edi, offset s   ; "Incorrect."
call    _puts
```

The logic is, "xor" the result with the key, and "or" all of them together; if the final value obtained is 0, the answer is correct. This means that, all of the "xor" result must be 0, which means that result array from sub\_400BA0 must be same as key.

Interestingly, we can see the optimization of compiler, which generate the code that will be faster on out\-of\-order CPUs.

so take a look at sub\_400BA0

```c
unsigned __int64 __fastcall sub_400BA0(q_xmm_word res, unsigned __int64 fc5, unsigned __int64 zero)
{
  unsigned __int64 fc5_; // r10
  unsigned __int64 result; // rax
  unsigned __int64 v5; // rdx
  __int64 v6; // rbp
  int v7; // ebp
  unsigned __int64 v8; // rbx
  unsigned __int64 v9; // r10
  unsigned __int64 v10; // r8
  q_xmm_word v11; // tt
  unsigned __int64 v12; // rsi
  q_xmm_word v13; // ax
  unsigned __int64 v14; // rcx
  __int64 v15; // rdi
  q_xmm_word v16; // ax
  q_xmm_word tmp; // tt

  fc5_ = fc5;
  result = res.qwords.low;
  if ( zero )
  { // can't reach here, zero is always 0, possibly obsfucation
    if ( zero > res.qwords.high )
    {
      result = res.qwords.low;
    }
    else
    {
      _BitScanReverse64((unsigned __int64 *)&v6, zero);
      v7 = v6 ^ 0x3F;
      if ( v7 )
      {
        v8 = fc5 << v7;
        v9 = (zero << v7) | (fc5 >> (64 - (unsigned __int8)v7));
        v10 = res.qwords.low << v7;
        v11.qwords.low = ((unsigned __int64)res.qwords.low >> (64 - (unsigned __int8)v7)) | (res.qwords.high << v7);
        v11.qwords.high = res.qwords.high >> (64 - (unsigned __int8)v7);
        v12 = v11.xmms % v9;
        v13.xmms = (fc5 << v7) * (unsigned __int128)(unsigned __int64)(v11.xmms / v9);
        v14 = v8 * (unsigned __int128)(unsigned __int64)(v11.xmms / v9) >> 64;
        v15 = v8 * (v11.xmms / v9);
        if ( v12 < v13.qwords.high || v12 == v13.qwords.high && v10 < v13.qwords.low )
        {
          v16.xmms = v13.xmms - __PAIR__(v9, v8);
          v14 = v16.qwords.high;
          v15 = v16.qwords.low;
        }
        result = ((v10 - v15) >> v7) | ((__PAIR__(v12, v10) - __PAIR__(v14, v15)) >> 64 << (64 - (unsigned __int8)v7));
      }
      else if ( zero < res.qwords.high || fc5 <= res.qwords.low )
      {
        result = res.qwords.low - fc5;
      }
    }
  }
  else
  {
    if ( fc5 <= res.qwords.high )
    {
      if ( !fc5 )
        fc5_ = 1 / 0uLL;                        // never, fc5 is always a constant
      tmp.qwords.low = res.qwords.low; // never, since for ret.high > fc5, the input is no longer readable
      tmp.qwords.high = res.qwords.high % fc5_;
      v5 = tmp.xmms % fc5_;
    }
    else
    {//only useful part
      v5 = res.xmms % fc5;
    }
    result = v5;
  }
  return result;
}
```

This function again contains many useless code: firstly, zero is always zero, so all codes above are useless; secondly, fc5 is always non-zero, so the div by 0 exception can't occur; thirdly, fc5 \<= res\.qwords\.high is always false, since for the result of multiplication to be larger than or equal to 0xFFFFFFFFFFFFFFC50000000000000000, the input characters are not readable anymore, even if we take 0xFFFFFFFFFFFFFFFF as the factor:

```python
>>> hex(0xFFFFFFFFFFFFFFC50000000000000000 / 0xFFFFFFFFFFFFFFFF)
'0xffffffffffffffc5L'
```

also, the bytes after flags are 'U' instead of 0xff as shown above, number larger than 0xffffffffffffffc5L won't occur in input array

so, this means we need to solve the following equation:

```c
(input[0] * 0x20656d6f636c6557) % 0xFFFFFFFFFFFFFFC5 == 0x2b7192452905e8fb
(input[1] * 0x2046544352206f74) % 0xFFFFFFFFFFFFFFC5 == 0x7ba58f82bd898035
(input[2] * 0x6548202138313032) % 0xFFFFFFFFFFFFFFC5 == 0xa3112746582e1434
(input[3] * 0x2061207369206572) % 0xFFFFFFFFFFFFFFC5 == 0x163f756fcc221ab0
(input[4] * 0x6320455279626142) % 0xFFFFFFFFFFFFFFC5 == 0xecc78e6fb9cba1fe
(input[5] * 0x65676e656c6c6168) % 0xFFFFFFFFFFFFFFC5 == 0xdcdd8b49ea5d7e14
(input[6] * 0x756f7920726f6620) % 0xFFFFFFFFFFFFFFC5 == 0xa2845fe0b3096f8e
(input[7] * 0xffffffffffff002e) % 0xFFFFFFFFFFFFFFC5 == 0xaaaaaaaaaa975d1c
(input[8] * 0xffffffffffffffff) % 0xFFFFFFFFFFFFFFC5 == 0x55555555555559a3
(input[9] * 0xffffffffffffffff) % 0xFFFFFFFFFFFFFFC5 == 0x55555555555559a3
(input[10] * 0xffffffffffffffff) % 0xFFFFFFFFFFFFFFC5 == 0x55555555555559a3
(input[11] * 0xffffffffffffffff) % 0xFFFFFFFFFFFFFFC5 == 0x55555555555559a3
(input[12] * 0xffffffffffffffff) % 0xFFFFFFFFFFFFFFC5 == 0x55555555555559a3
(input[13] * 0xffffffffffffffff) % 0xFFFFFFFFFFFFFFC5 == 0x55555555555559a3
(input[14] * 0xffffffffffffffff) % 0xFFFFFFFFFFFFFFC5 == 0x55555555555559a3
(input[15] * 0xffffffffffffffff) % 0xFFFFFFFFFFFFFFC5 == 0x55555555555559a3
```



todo, equation solving

### magic

todo, answer in my windows computer, didn't bring it to uni

### simplere

**1. unpack**

Actually this is my first time to deal with linux packed executables, but the machanism is actually similar to that on Windows.

Open the executable in ida. ida says \.GOT\.PLT cannot be found, which suggests it may be packed; also, it says the entry  point of program is invalid, this won't happen even if the program is packed, so let's see what is going on.

Firstly, the entry point is 0x4018C8 specified in ELF header, but it is red (invalid)

![elfheader](simplereELFheader.png)

IDA says such address is not in loadable section, and if we go to that address in IDA, it is not shown either.

However, if we load this in gdb and breakpoint at 0x4018c8, it would work

The problem is the at PHT entry, the size is only 0x18c8, which excludes the entry point

![simplerePHT](simplerePHT.png)

so, patch the 18C8h to 2000h, IDA analysis will be normal

```assembly
public start
start           proc near               ; DATA XREF: LOAD:0000000000400018↑o
; start+7↓o
mov     rbp, offset _init_proc
mov     r9, offset start
loc_4018D6:     ; CODE XREF: start+23↓j
mov     r8, 0CCh
xor     qword ptr [rbp], r8
mov     r8, [rbp+0]
inc     rbp
cmp     rbp, r9
jl      short loc_4018D6
mov     rbp, offset _start
jmp     rbp
start           endp
```

This codes decode the \.text segment using xor, so we can write a IDA python to decode

```python
def xor_decode(start, end, key):
	for p in xrange(start, end):
		PatchByte(p, Byte(p) ^ key)
#xor_decode(0x400958, 0x4018C8, 0xCC)
```

then apply the patch to the file, and reopen the file, the executable is unpacked

**2. first attempt**

```c
//we can see following codes in main function
  puts("input flag:");
  read(0, ::flag, 0x21uLL);
  flag[0] = ::flag[0];
  flag[1] = ::flag[1];
  flag[2] = ::flag[2];
  flag[3] = ::flag[3];
  v7 = word_602100;
  v9[0] = 0x67452301;
  v9[1] = 0xEFCDAB89;
  v9[2] = 0x98BADCFE;
  v9[3] = 0x10325476;
  length = (unsigned int)strlen((const char *)flag) >> 2;
  if ( length && return_true((unsigned int *)flag, length, v9) )
    puts("Right!");
  kill(pid, 9);
  return 0LL;
//There are actually other codes in previous part, which calls APIs like fork, wait, ptrace. Initially I thought this is just anti-debug technique and is not useful for obtaining the flag.
```

where return\_true is

```c
// length == 8
bool __fastcall return_true(unsigned int *input, int length, unsigned int *key)
{
  unsigned int next; // ST2C_4
  unsigned int v4; // ST34_4
  unsigned int hash_gen_2bits; // [rsp+28h] [rbp-18h]
  int i_1; // [rsp+30h] [rbp-10h]
  unsigned int prev; // [rsp+34h] [rbp-Ch]
  int i; // [rsp+38h] [rbp-8h]
  unsigned int hash_gen; // [rsp+3Ch] [rbp-4h]

  hash_gen = 0;
  for ( i = 52 / length + 6; i; --i )
  {
    prev = input[length - 1];
    i_1 = 0;
    hash_gen -= 0x61C88647;
    hash_gen_2bits = (hash_gen >> 2) & 3;
    while ( length - 1 > i_1 )
    {
      next = input[i_1 + 1];
      input[i_1] += ((next ^ hash_gen) + (prev ^ key[hash_gen_2bits ^ i_1 & 3])) ^ ((4 * next ^ (prev >> 5)) + ((next >> 3) ^ 16 * prev));
      prev = input[i_1++];
    }
    input[length - 1] += ((*input ^ hash_gen) + (prev ^ key[hash_gen_2bits ^ i_1 & 3])) ^ ((4 * *input ^ (prev >> 5)) + ((*input >> 3) ^ 16 * prev));
    v4 = input[length - 1];
  }
  __debugbreak();
  return memcmp(input, "quehsj_kcneop_amneuf_ieha_ehdhde", 0x20uLL) == 0;
}
```

Firstly search magic number 0x61C88647, it seems that it is a magic number used for hashing algorithm.

This seems like a hashing algorithm, input is added according to the previous element and next element(for the first element and last element, they use the last element as the previous element and first element as next element, like a circle), and this will be executed 52 / length + 6 times, with hash\_gen being changed in each iteration. However, the \[0\] (first element) element will use \[len-1\] and \[1\], which are unecoded; the \[i\] element where 0\<i\<len\-1 will use \[i\-1\]\(encoded\) and \[i\+1\]\(unencoded\); the \[len-1\] element will use \[len\-2\] and \[0\], which are **encoded**. Therefore, we can recover the last element given the result of the hashing, and in turns recover all of the previous elements by a reverse loop, as shown.

```c
#include <stdint.h>
#include <stdio.h>
#include <memory.h>
#include <sys/ptrace.h>

#define LEN 8
unsigned char buf[33] = "quehsj_kcneop_amneuf_ieha_ehdhde";
unsigned int* test = (unsigned int*)testbufin;
unsigned int* flag = (unsigned int*)buf;

uint32_t key[4]={
 0x67452301
,0xEFCDAB89
,0x98BADCFE
,0x10325476};

void print_hex(unsigned char* buf, size_t len)
{
  for (int i = 0; i < len; ++i)
  {
    printf("\\x%.2x", buf[i]);
  }
  printf("\n");
}

unsigned int hash_gens[13];

void init_hash_gens()
{
  unsigned int hash_gen = 0;
  for (int i = 0; i < 12; ++i)
  {
    hash_gen -= 0x61C88647;
    hash_gens[i] = hash_gen;
  }
}

void one_iteration(unsigned int* flag, int i)
{
  unsigned int hash_gen_2bits = (hash_gens[i] >> 2) & 3;
  flag[LEN - 1] -= ((*flag ^ hash_gens[i]) +
        (flag[LEN - 2] ^ key[hash_gen_2bits ^ ((LEN - 1) & 3)]))
        ^ ((4 * *flag ^ (flag[LEN - 2] >> 5))
        + ((*flag >> 3) ^ 16 * flag[LEN - 2]));
  //now flag[LEN - 1] has been recovered
  for (int j = LEN - 2; j >= 1; --j)
  {
    flag[j] -= ((flag[j + 1] ^ hash_gens[i]) + (flag[j - 1] ^ key[hash_gen_2bits ^ (j & 3)])) ^ ((4 * flag[j + 1] ^ (flag[j - 1] >> 5)) + ((flag[j + 1] >> 3) ^ 16 * flag[j - 1]));
  }
  flag[0] -= ((flag[1] ^ hash_gens[i]) + (flag[LEN - 1] ^ key[hash_gen_2bits ^ (0 & 3)])) ^ ((4 * flag[1] ^ (flag[LEN - 1] >> 5)) + ((flag[1] >> 3) ^ 16 * flag[LEN - 1]));
}

int main()
{
  init_hash_gens();
  printf("recover:\n");
  for (int i = 52 / LEN + 6; i; i--)
  {
    one_iteration(flag, i - 1/*damn it, stuck for 2 hours!!!!!!!*/);
    print_hex(buf, 33);
    printf("%s\n", buf);
  }
}
```

However, the result is not readable, and indeed, if we nop the fork and ignore all previous codes, and redirect the result unreadable bytes in to stdin of the program, it will work, but this is certainly not the flag, so it must has something to do with the previous part of code.

```
./simplere_unpacked_nofork < flag.txt 
input flag:
Right!
```

**3. second attempt**

Then I looked at the previous codes, which does not seems like checking, but I found something interesting.

```assembly
;in main function
loc_401221: ; CODE XREF: main+136↑j
lea     rax, cs:1F2498h
mov     rdi, rax
call    plus_0x20edac
mov     [rbp+var_18], rax
push    [rbp+var_18]
retn    ; jmp 0x401244


LOAD:0000000000400EC1 plus_0x20edac   proc near               ; CODE XREF: sub_400FB1+12↓p
LOAD:0000000000400EC1                                         ; main+1AA↓p
LOAD:0000000000400EC1                 push    rbp
LOAD:0000000000400EC2                 mov     rbp, rsp
LOAD:0000000000400EC5                 push    rbx
LOAD:0000000000400EC6                 mov     rbx, rdi        ; rbx = arg
LOAD:0000000000400EC9                 lea     rdi, cs:300E37h
LOAD:0000000000400ED0                 call    add_0x1000AC
LOAD:0000000000400ED5                 push    rax             ; rax = 0x400ee3
LOAD:0000000000400ED6                 retn                    ; jmp 400ee3
LOAD:0000000000400ED6 plus_0x20edac   endp ; sp-analysis failed
LOAD:0000000000400ED6
LOAD:0000000000400ED6 ; ------------------------------------------------------------------
LOAD:0000000000400ED7                 db 0AAh
LOAD:0000000000400ED8                 db 0B7h
LOAD:0000000000400ED9                 db 91h, 5, 6, 17h, 82h, 19h, 0C7h
LOAD:0000000000400EE0                 db 0DDh, 0AAh, 0
LOAD:0000000000400EE3 ; ------------------------------------------------------------------
LOAD:0000000000400EE3                 mov     rdi, rbx
LOAD:0000000000400EE6                 call    add_0x1000AC
LOAD:0000000000400EEB                 add     rax, 10ED00h    ; rax = arg + 0x20edac
LOAD:0000000000400EF1                 pop     rbx
LOAD:0000000000400EF2                 pop     rbp
LOAD:0000000000400EF3                 retn

LOAD:0000000000400EA7 add_0x1000AC    proc near
LOAD:0000000000400EA7                                         ; LOAD:0000000000400EE6↓p
LOAD:0000000000400EA7
LOAD:0000000000400EA7 var_8           = qword ptr -8
LOAD:0000000000400EA7
LOAD:0000000000400EA7                 push    rbp
LOAD:0000000000400EA8                 mov     rbp, rsp
LOAD:0000000000400EAB                 mov     [rbp+var_8], rdi
LOAD:0000000000400EAF                 mov     eax, cs:dword_6020B8 ; eax = 0x1000AC
LOAD:0000000000400EB5                 movsxd  rdx, eax
LOAD:0000000000400EB8                 mov     rax, [rbp+var_8]
LOAD:0000000000400EBC                 add     rax, rdx
LOAD:0000000000400EBF                 pop     rbp
LOAD:0000000000400EC0                 retn
LOAD:0000000000400EC0 add_0x1000AC    endp
```

This is a kind of obsfucation technique, in which program "push xxx; retn" to implement a jmp xxx, so IDA will just fail the stack frame analysis.

Thus, actually, the main function should be like this (after nop some useless codes)

```assembly
LOAD:0000000000401221                 lea     rax, cs:1F2498h
LOAD:0000000000401228                 mov     rdi, rax
LOAD:000000000040122B                 call    plus_0x20edac
LOAD:0000000000401230                 mov     qword ptr [rbp+stat_loc+4], rax
LOAD:0000000000401234                 nop
LOAD:0000000000401235                 nop
LOAD:0000000000401236                 nop
LOAD:0000000000401237                 nop                     ; jmp 0x401244
LOAD:0000000000401238
LOAD:0000000000401238 loc_401238:
LOAD:0000000000401238                 nop
LOAD:0000000000401239                 nop
LOAD:000000000040123A                 nop
LOAD:000000000040123B                 nop
LOAD:000000000040123C                 nop
LOAD:000000000040123D                 nop
LOAD:000000000040123E                 nop
LOAD:000000000040123F                 nop
LOAD:0000000000401240                 nop
LOAD:0000000000401241                 nop
LOAD:0000000000401242                 nop
LOAD:0000000000401243                 nop
LOAD:0000000000401244                 lea     rdx, [rbp+var_1A0]
```

originally there is a obsfucation "jmp", but now I simply nop them and the codes that should have been jmp, which should have same effect.

F5 decompile:

 ```c
//...
      plus_0x20edac();
      *(int **)((char *)&stat_loc.__iptr + 4) = v3;
      ptrace(PTRACE_GETSIGINFO, v12, 0LL, &v5);
      if ( v5 == SIGTRAP )
      {
        ptrace(PTRACE_GETREGS, v12, 0LL, flag);
        v8 = sub_400FB1;
        ptrace(PTRACE_SETREGS, v12, 0LL, flag);
      }
      ptrace(PTRACE_CONT, v12, 0LL, 0LL);
    }
  }
  //...
 ```

The ptrace seems process flag in someway, but I could not understand it\. :\) Why does the program put register context into flag buffer?

Also, the function sub\_400FB1 is strange, it is referenced and assigned to a local variable, but never used. If we have a look about it,

```assembly
LOAD:0000000000400FB1 sub_400FB1      proc near               ; DATA XREF: main+214↓o
LOAD:0000000000400FB1                 push    rbp
LOAD:0000000000400FB2                 mov     rbp, rsp
LOAD:0000000000400FB5                 sub     rsp, 20h
LOAD:0000000000400FB9                 lea     rax, cs:1F2230h
LOAD:0000000000400FC0                 mov     rdi, rax
LOAD:0000000000400FC3                 call    plus_0x20edac
LOAD:0000000000400FC8                 mov     [rbp+var_10], rax
LOAD:0000000000400FCC                 push    qword ptr [rbp-10h]
LOAD:0000000000400FCF                 retn
```

same technique as above, so I would not talk about it again. After nop, the function sub\_400FB1 decompile to the code as shown

```c
void __noreturn sub_400FB1()
{
  __int64 v0; // rax
  char s; // [rsp+1h] [rbp-1Fh]
  char v2; // [rsp+2h] [rbp-1Eh]
  char v3; // [rsp+3h] [rbp-1Dh]
  char v4; // [rsp+4h] [rbp-1Ch]
  char v5; // [rsp+5h] [rbp-1Bh]
  char v6; // [rsp+6h] [rbp-1Ah]
  char v7; // [rsp+7h] [rbp-19h]
  _BOOL8 (__fastcall *v8)(unsigned int *); // [rsp+8h] [rbp-18h]
  __int64 v9; // [rsp+10h] [rbp-10h]
  unsigned __int64 i; // [rsp+18h] [rbp-8h]

  plus_0x20edac();
  v9 = v0;
  v8 = real_check;
  s = 'R';
  v2 = 'i';
  v3 = 'g';
  v4 = 'h';
  v5 = 't';
  v6 = '!';
  v7 = 0;
  for ( i = 0LL; i < 354; ++i )
    *((_BYTE *)v8 + i) ^= 0x28u;//xor SMC, use same xor_decode IDA python code to decode
  if ( (unsigned __int8)real_check((unsigned int *)::flag) )
    puts(&s);
  if ( pid )
    kill(pid, 9);
  exit(0);
}

_BOOL8 __fastcall real_check(unsigned int *flag)
{
  unsigned int result[6]; // [rsp+8h] [rbp-40h]
  unsigned int mult[6]; // [rsp+28h] [rbp-20h]
  int v5; // [rsp+40h] [rbp-8h]
  int i; // [rsp+44h] [rbp-4h]

  mult[0] = 0x556E4969;
  mult[1] = 0x2E775361;
  mult[2] = 0x893DAE7;
  mult[3] = 0x96990423;
  mult[4] = 0x6CF9D3E9;
  mult[5] = 0xA505531F;
  result[0] = 0x54A0B9BD;
  result[1] = 0x4B818640;
  result[2] = 0x8EB63387;
  result[3] = 0xA9EABEFD;
  result[4] = 0xB8CDF96B;
  result[5] = 0x113C3052;
  for ( i = 0; i <= 5; ++i )
  {
    if ( mult[i] * flag[i] != result[i] )
      return 0LL;
  }
  if ( (unsigned int)sub_400EF4(flag[6], *((unsigned __int16 *)flag + 14), 0xF64BB17D) != 0x6F82C8DC
    || (unsigned int)sub_400F5B(*((_WORD *)flag + 14), *((_WORD *)flag + 15)) != 0xA496 )
  {
    return 0LL;
  }
  v5 = 0;
  for ( i = 24; i <= 31; ++i )
    v5 ^= *((char *)flag + i);
  return v5 == 22 && *((_BYTE *)flag + 32) == 's';
}
```



so, after xor decode again, we can see the real\_check function that examine the flag, although I don't know how this will be called :D

The first 24 bytes are easy, considering the overflow that might happen when doing multiplication, we use bruteforce approach.

```c
int main1(int argc, char const *argv[])
{
	unsigned long long mult[6];
	unsigned long long result[6];
	mult[0] = 0x556E4969;
	mult[1] = 0x2E775361;
	mult[2] = 0x893DAE7;
	mult[3] = 0x96990423;
	mult[4] = 0x6CF9D3E9;
	mult[5] = 0xA505531F;
	result[0] = 0x54A0B9BD;
	result[1] = 0x4B818640;
	result[2] = 0x8EB63387;
	result[3] = 0xA9EABEFD;
	result[4] = 0xB8CDF96B;
	result[5] = 0x113C3052;
	for (int i = 0; i < 6; ++i)
	{
		for (unsigned long long x = 0L; x < 0x100000000L; ++x)
		{
			if ((x & 0xfffffffL) == 0)
			{
				printf("%llx\n", x);
			}
			if (((x * mult[i]) & 0xffffffffL)  == result[i])
			{
				printf("%s\n", (char*)&x);
			}
		}
	}//5o_M@ny_an7i_Rev3rsing_T
	return 0;
}
```

However, the next 2 checks are harder

```c
unsigned __int64 __fastcall sub_400EF4(unsigned int a1, unsigned int a2, unsigned int a3_0xF64BB17D)
{
  unsigned int flag2; // [rsp+4h] [rbp-18h]
  unsigned __int64 v5; // [rsp+Ch] [rbp-10h]
  unsigned __int64 v6; // [rsp+14h] [rbp-8h]

  flag2 = a2;
  v6 = 1LL;
  v5 = a1;
  while ( flag2 )
  {
    if ( flag2 & 1 )
      v6 = v5 * v6 % a3_0xF64BB17D;
    v5 = v5 * v5 % a3_0xF64BB17D;
    flag2 >>= 1;
  }
  return v6;                                    // need 0x6F82C8DC
}

__int64 __fastcall sub_400F5B(unsigned __int16 a1, unsigned __int16 a2)
{
  unsigned __int16 v2; // ST16_2
  unsigned __int16 i; // [rsp+0h] [rbp-18h]
  unsigned __int16 v5; // [rsp+4h] [rbp-14h]

  v5 = a1;
  for ( i = a2; i & v5; i = 2 * (i & v2) )
  {
    v2 = v5;
    v5 ^= i;
  }
  return (unsigned __int16)(i | v5);
}
```

so the flag is like 5o\_M@ny\_an7i\_Rev3rsing\_T11112233s, where 1111 and 22 will be putted into first check, and 22 and 33 will be putted into second check, also there is a xor checksum that must be satisfied.

Although we think there should be an math method that can solve it, we could not find that and instead used a bruteforce approach.

**4. bruteforce part**

todo