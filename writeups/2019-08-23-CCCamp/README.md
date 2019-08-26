## 320 Pwn / regfuck

### Overview

In this challenge, a small virtual machine engine is provided and we need get the shell by providing the virtual machine metadata and byte-codes. The vulnerability I exploited is an OOB access by moving index to `got` table and changing function pointer stored in `got` table to `one_gadget`. We cannot write to `got` table directly but can only increment and decrement the value, so the idea is to increment or decrement a constant offset. However, since functions imported in this binary are quite far from `one_gadget`, and the problem is program counter is only an `int16_t`, so maximum size of program is not enough to increment or decrement the constant offset as large as that. The idea is to re-execute the main function to increment or decrement for several times so that we can reach desired pointer.

### Reverse Engineering

This binary is not hard to reverse. The only point to note is that the `switch` statement of the instruction execution is not well identified by IDA, so we need to patch the binary a bit to enable IDA to identify it properly.

Originally `0x402008`, which the address of switch table, stores the offsets of switch blocks to `0x402008`, but I patched it to the 8-byte addresses of these blocks directly by using IDA Python. Then I also patched the switch instructions to `jmp ds:off_402008[rax*8]` by using `keypatch`, so that switch statement can be identified. Also, `Edit->Other->Specify switch idiom` can be used to modify the switch statement.

Also, the way to parse opcode of this virtual machine is a bit interesting. The VM code is not byte-wise but bit-wise, with the highest bit of the byte being the first bit of this byte. Opcode is a sequence of `1` separated by a `0`, and different number of `1` specifies different instruction.

```c
__int64 __fastcall exec_ins(_DWORD *data, char *input, _WORD *pc, __int16 *idx, int prelen)
{
  __int16 dref_pc; // ax
  __int16 v6; // dx
  _DWORD *v8; // rax
  _DWORD *v9; // rax
  __int16 *pc_; // [rsp+18h] [rbp-18h]

  pc_ = pc;
  dref_pc = *pc;
  v6 = *pc + 7;
  if ( dref_pc < 0 )
    dref_pc = v6;
  if ( (input[(signed __int16)(dref_pc >> 3)] >> (7 - (unsigned __int16)(*pc_ % 8))) & 1 )
  {
    ++*data;
  }
  else
  {
    switch ( *data )
    {
      case 1:
        if ( *idx == prelen - 1 )
          return 1LL;
        ++*idx;
        break;
        return 1LL;
      case 2:
        if ( *idx == -1 )
          return 1LL;
        --*idx;
        break;
        return 1LL;
      case 3:
        v8 = &data[*idx + 2LL];
        ++*v8;
        break;
      case 4:
        v9 = &data[*idx + 2LL];
        --*v9;
        break;
      case 5:
        if ( data[*idx + 2LL] )
          *pc_ = data[1] >> 16;
        break;
      case 6:
        data[1] = data[*idx + 2LL];
        break;
      case 7:
        putchar(data[*idx + 2LL]);
        break;
      case 8:
        data[*idx + 2LL] = (*pc_ << 16) | (unsigned __int16)*idx;
        break;
      case 9:
        if ( data[*idx + 2LL] )
          *idx = data[1];
        break;
      default:
        break;
    }
    *data = 0;
  }
  return 0LL;
}
```

### Vulnerability

There are actually many bugs in this binary, such as integer overflows. However, I only used the one that sets `*idx` to an OOB value.

```c
case 2:
  if ( *idx == -1 )
     return 1LL;
  --*idx; // *idx can be -1
  break;
case 4:
  v9 = &data[*idx + 2LL];
  --*v9; // data[1] can be changed
  break;
case 9:
  if ( data[*idx + 2LL] )
    *idx = data[1]; // set *idx without checking
```

Therefore by using this payload, we can switch `*idx` to `got` table.

```python
idx = -((p.got["exit"] - 0x405000) / 4 - 2)
ins(2) # idx = -1
for i in xrange(idx):
	ins(4) # data[1] = (p.got["exit"] - 0x405000) / 4 - 2
ins(9)
```

### Exploitation

As I suggested, we cannot change the a constant offset directly. I have considered many approaches but finally I found this one that works. The idea is to change `putchar` to main function so that we can re-enter VM codes and execute for the many times. However, the problem is `mmap` now will return create a new page at `0x7fxxxxxxxxxx` since `0x405000` has already been used, so we cannot switch to `got` table as before. Therefore, we want to change pointer in `mmap` `got` entry to somewhere that returns `0x405000`.

```assembly
add     rax, rcx
mov     r9d, 0          ; offset
mov     r8d, 0FFFFFFFFh ; fd
mov     ecx, 22h        ; flags
mov     edx, 3          ; prot
mov     rsi, rax        ; len
mov     edi, 405000h    ; addr
call    _mmap
```

Initially I want to find a gadget like `mov rax,rdi; ret`, but such gadget is too far from `mmap` function. However, since we can control the second argument, which is equal to `rax`, we can just let `mmap` to be a `ret` instruction and crafting its return value by ourselves. A point to note about this is that the `read` function later on uses this value as the size. Even if this value is larger than mapped memory, it can still work. Since the `read` is replaced by a custom `read`, it will continue to call original `read` until error occurs, which will occurs if `read(0, unmapped_memory, xxx)` is called.

Also, we need to choose a `got` table entry to rewrite to `one_gadget`. I choose `puts`, since it is only called once, and we can skip this function when we jump back to main function to avoid any crash, and fortunately by debugging I found this can satisfy the `[rsp+0x40]` `one_gadget` condition.

The final exploit is [here](exp.py), although a bit ugly.

