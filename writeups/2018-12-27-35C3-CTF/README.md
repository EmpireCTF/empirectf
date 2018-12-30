## 0pack

To solve this challenge, we need to unpack the binary first. After some inspection, we can dump the binary using gdb `dump binary memory code.bin 0x555555554628 0x555555567094`, because this is the region where the writable codes lie.

Then put it into the executable.

```python
p = open("code.bin", "r")
d = p.read()
p.close()

f = open("0pack.elf", "r+")
f.seek(0x628)
f.write(d)
f.close()
```

Using `backtrace` command in gdb, we can find the function that calls the function to get input, here it is `fgets`

```c
__int64 __usercall sub_5555555669A0@<rax>(__int64 a1@<rsi>, _BYTE *a2@<r15>)
{
  char need1; // [rsp+1Dh] [rbp-83h]
  char s[15]; // [rsp+20h] [rbp-80h]
  char v5[16]; // [rsp+30h] [rbp-70h]
  char out[58]; // [rsp+50h] [rbp-50h]
  unsigned __int64 v7; // [rsp+98h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  need1 = 1;
  strcpy(v5, "Input password: ");
  printf("%s", v5, a1);
  fgets(s, 15, stdin);
  putchar(10);
  if ( s[0] != a2[74869] || antidbg() ) //clear plain text comparison
    need1 = 0;
  if ( s[1] != a2[74968] || antidbg() )
    need1 = 0;
  if ( s[2] != a2[74298] || antidbg() )
    need1 = 0;
  if ( s[3] != a2[74319] || antidbg() )
    need1 = 0;
  if ( s[4] != a2[74868] || antidbg() )
    need1 = 0;
  if ( s[5] != a2[74319] || antidbg() )
    need1 = 0;
  if ( s[6] != a2[74664] || antidbg() )
    need1 = 0;
  if ( s[7] != a2[74869] || antidbg() )
    need1 = 0;
  if ( s[8] != a2[74874] || antidbg() )
    need1 = 0;
  if ( s[9] != a2[74298] || antidbg() )
    need1 = 0;
  if ( s[10] != a2[74309] || antidbg() )
    need1 = 0;
  if ( s[11] != a2[74954] || antidbg() )
    need1 = 0;
  if ( s[12] != a2[74792] || antidbg() )
    need1 = 0;
  if ( s[13] != a2[74968] || antidbg() )
    need1 = 0;
  if ( need1 )
  {
    *(_QWORD *)out = '��_��� (';
    *(_QWORD *)&out[8] = '��� (\n)�';
    *(_QWORD *)&out[16] = '��>)���_';
    *(_QWORD *)&out[24] = '���-����';
    *(_QWORD *)&out[32] = '��␌�(\n';
    *(_QWORD *)&out[40] = 'uf )���_';
    *(_QWORD *)&out[48] = '!haey kc';
    *(_WORD *)&out[56] = '\n';
  }
  else
  {
    *(_QWORD *)out = '�� wwwwA';
    *(_DWORD *)&out[8] = '��_�';
    *(_WORD *)&out[12] = '\n�';
    out[14] = 0;
  }
  printf("%s", out);
  return 0LL;
}
```

By debugging, we can find that `a2 == 0x555555554000`, so get the flag using IDA script

```python
s = [None] * 14
s[0] = chr(Byte(0x555555554000 + 74869))
s[1] = chr(Byte(0x555555554000 + 74968))
s[2] = chr(Byte(0x555555554000 + 74298))
s[3] = chr(Byte(0x555555554000 + 74319))
s[4] = chr(Byte(0x555555554000 + 74868))
s[5] = chr(Byte(0x555555554000 + 74319))
s[6] = chr(Byte(0x555555554000 + 74664))
s[7] = chr(Byte(0x555555554000 + 74869))
s[8] = chr(Byte(0x555555554000 + 74874))
s[9] = chr(Byte(0x555555554000 + 74298))
s[10] = chr(Byte(0x555555554000 + 74309))
s[11] = chr(Byte(0x555555554000 + 74954))
s[12] = chr(Byte(0x555555554000 + 74792))
s[13] = chr(Byte(0x555555554000 + 74968))

print ''.join(s)
```

But one thing that I don't understand is the way the packer works. The entry point is `0` for this executable, and so the initial rip should be `0x555555554000` with ASLR disabled. However, the data there in IDA pro and gdb are `0xe9 0xfb 0x5f 0x41 0x00`, which is `jmp 0x55555596a000`. The instructions in `0x55555596a000` make sense, because they seem to be the entry point of a packer. However, I don't know where `0xe9 0xfb 0x5f 0x41 0x00` comes from, because that address should be magic number of ELF header, `"\x7fELF"`, and indeed in the ELF file it is so. And I cannot find `0xe9 0xfb 0x5f 0x41 0x00` in binary ELF file. Well, so I am not sure how these bytes are changed.

## corebot

The core function is easy, decrypt specific data using the key generated from `VolumeSerialNumber`, and compare the first 4 bytes of decryption result with `35C3`. In other word, we need to find the correct serial number that can decrypt the data to the flag.

The best way is to use the brute force crack.

```c
#include <windows.h>
#include <stdio.h>
struct key
{
	DWORD head[3];
	WORD serials[0x10];
}data;

DWORD cmode = CRYPT_MODE_ECB;
bool crack(DWORD serialNumber)
{
	DWORD len = 0x20;
	BYTE res[] = "\x10\x29\xB8\x45\x9D\x2A\xAB\x93\xFE\x89\xFB\x82\x93\x42\xA1\x8C\x2E\x90\x63\x00\x06\x11\x80\x64\xB8\x21\xC2\x9F\x35\xE7\x7E\xF2";
	HCRYPTPROV cryptContext;
	HCRYPTKEY key;
	CryptAcquireContextA(&cryptContext, 0, 0, 0x18u, 0);
    //initialization that gets the context
	int i = 16;
	do
	{
		--i;
		data.serials[i] = (WORD)serialNumber;
		serialNumber ^= ((DWORD)(WORD)serialNumber >> 4) ^ 
			((WORD)serialNumber << 11) ^ ((WORD)serialNumber << 7);
        //actually only low 16 bits of serial are used here, so we only need to crack 0x10000 times
	}// do some transformation
	while (i);
	CryptImportKey(cryptContext, (const BYTE *)&data, 0x2Cu, 0, 0, (HCRYPTKEY *)&key);
    //import the key from raw bytes to some struct
	CryptSetKeyParam(key, KP_MODE, (const BYTE *)&cmode, 0);
    //set mode to ECB
	CryptDecrypt(key, 0, 1, 0, (BYTE *)&res, (DWORD *)&len);
    //decrypt
	return (memcmp(res, "35C3", 4) == 0);
}

void init()
{
	data.head[0] = 0x208;
	data.head[1] = 0x6610;
	data.head[2] = 0x20;
}

int main()
{
	init();
	for (size_t i = 0; i < 0xffffffff; i++)
	{
		if (i % 0x1000 == 0)
			printf("%x\n", i);
		if (crack(i))
			printf("%x\n", i);
	}
	return 0;
}
```

A tricky point is that this program is written by assembly directly, because almost no compiler will generate assembly code like this. Especially, when doing the transformation, the hex-ray will give the wrong pseudo code.

For example,

```c
//in the loop
HIWORD(v18) = serialNumber;                 // wrong!
```

This is actually many continuous `push` that create an array finally, instead of assigning to the same variable for 16 times

```assembly
push    ax              ; push 16 * 2 = 0x20 bytes
```

along with the extra 0xC bytes being pushed after the loop, we have 0x2C bytes, which matches the `dwDataLen` argument of `CryptImportKey` exactly.

```assembly
push    20h
push    6610h
push    small 0
push    small 208h      ; 0xc bytes
```

## Collection

This should be an easy challenge, but I have missed some basic Python knowledge essential to solving the chanllenge, so I failed to solve it in the contest. :(

Anyway let's start looking at it. The `Python3.6` and `libc` given are exactly same as the ones in `Ubuntu 18.04`, so they are not important. According to the instruction and the files given, we can find that a new data type `Collection` implemented in `Collection.cpython-36m-x86_64-linux-gnu.so` is given. Anything that can help to get the flag directly in Python is disabled, and it is obvious that we need to exploit the given `Collection` data type to get the flag.

But how does the extended data type works? For example, there should be some convention that helps the CPython to know how to correspond Python function with particular native C function, just like Android native function. After some investigation and Google, I found this [documentation](https://docs.python.org/3/extending/), and I will not detail the software development part here because they are well explained in the link I provides.

### reverse engineering

After understanding the basic concept above, we can start looking at the `.so` binary.

```c
__int64 PyInit_Collection()
{
  __int64 v0; // rax
  __int64 ret; // rbx

  if ( (signed int)PyType_Ready((__int64)type_Collection) < 0 )
    return 0LL;
  v0 = PyModule_Create2((__int64)def_module, 1013LL); // create the module
  ret = v0;
  if ( !v0 )
    return ret;
  ++type_Collection[0];
  PyModule_AddObject(v0, (__int64)"Collection", (__int64)type_Collection);
  // add the type into module
  // These codes are basically same as the demo in official doc
  mprotect((void *)0x439000, 1uLL, 7);
  MEMORY[0x43968F] = _mm_load_si128((const __m128i *)&16_0xcc);
  MEMORY[0x43969F] = MEMORY[0x43968F];          // write int3 into python3.6???
  mprotect((void *)0x439000, 1uLL, 5);
  init_sandbox(); // disable most syscall, we can only read the flag by `readv` and `write`
  return ret;
}
```

Then we need to look at `type_Collection` to find the member functions of data type `Collection`

