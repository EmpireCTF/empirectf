# 2020-08-22-Google-CTF #

[CTFTime link](https://ctftime.org/event/1041) | [Website](https://capturetheflag.withgoogle.com/)

---

## Challenges ##

Note: incomplete listing.

### reversing ###

 - [x] [173 sprint](173-reversing--sprint)
 
---

## 173 reversing / sprint ##

**Description**

> Sprint faster than this binary!

**Files provided**

 - [sprint](https://storage.googleapis.com/gctf-2020-attachments-project/c39e555802aa479765c70804396ea5a55ca69583a8de716cc9f03f238a916cb01850b146a0313e9f684c5b86a164498324e42bd17502dea14ad91f1247c660ad)

**Solution** (by [Aurel300](https://github.com/Aurel300))

We are given a 64-bit ELF binary. Upon decompilation, we can see a single function of interest – `main` itself.

## `main`

With some manual clean-up, we can write its source code as (the meaning of the variable names will be clear soon):

```c
char *SPRINT_ROM;

int main(int argc, const char **argv, const char **envp) {
  char *memory = (char *)mmap((void *)0x4000000, 0x4000000uLL, 0x3, 0x22, -1, 0LL);
  memcpy(memory, SPRINT_ROM, 0xF134uLL);
  uint16_t *regA = (uint16_t *)memory;
  int64_t regB = 0LL;
  int64_t regC = 0LL;
  int64_t regD = 0LL;
  int64_t regE = 0LL;
  int64_t regF = 0LL;
  int64_t regG = 0LL;
  int64_t regH = 0LL;
  int64_t regI = 0LL;
  char *regIP = memory;
  puts("Input password:");
  scanf("%255s", &memory[0xE000]);
  while (regIP != &memory[0xFFFE]) {
    sprintf(
      &memory[0x2000000],
      regIP, "", 0LL, &regIP, &memory[0x2000000],
      *regA, regA, &regA, regB, &regB, regC, &regC, regD, &regD, regE, &regE,
      regF, &regF, regG, &regG, regH, &regH, regI, &regI);
  }
  if (*((int16_t *)(&memory[0xE800]))) {
    printf("Flag: %s\n", &memory[0xE800]);
  }
  return 0;
}
```

### Memory initialisation

Let's look at this bit by bit.

```c
char *memory = (char *)mmap(
  (void *)0x4000000,            // (preferred) address
  0x4000000uLL,                 // size in bytes
  PROT_EXEC | PROT_WRITE,       // protection
  MAP_ANONYMOUS | MAP_PRIVATE,  // flags
  -1,                           // file descriptor
  0LL);                         // offset
```

We start with [`mmap`](https://linux.die.net/man/3/mmap) to allocate a largish (64 MiB) area of contiguous memory.

Due to `MAP_ANONYMOUS`, the allocated memory is just fresh, empty memory, rather than a file. This also explains the dummy `-1` value passed as the file descriptor and the `0` offset, since both of these values only make sense when mapping a file into memory.

The fact that the mapped memory is executable (`PROT_EXEC`) is strange, although it turns out not to be relevant for this challenge.

The memory should be allocated exactly at the address `0x4000000`. Whether this actually happens depends on the specific implementation of `mmap` and might require the `MAP_FIXED` flag. For this challenge we assume it works this way (as it did on our VMs). The large size of the allocated region might also play a role in this, since only a small portion of the memory is used in the end.

```c
memcpy(
  memory,      // destination
  SPRINT_ROM,  // source
  0xF134uLL);  // size in bytes
```

The first `0xF134` (`61748`) bytes of the memory region are initialised with the constant `SPRINT_ROM`, which is part of the executable. In IDA Pro this incorrectly decompiles to a copy of the string literal `"%1$00038s%3$hn%1$65498s%1$28672s%9$hn"`, but this is only the first part of the data. The full constant actually contains 146 format strings (all null-terminated), followed by some amount of 0-byte padding, and finally `0x134` (`308`) bytes of additional data.

We'll see the exact contents of `SPRINT_ROM` later.

### Registers

```c
uint16_t *regA = (uint16_t *)memory;
int64_t regB = 0LL;
int64_t regC = 0LL;
int64_t regD = 0LL;
int64_t regE = 0LL;
int64_t regF = 0LL;
int64_t regG = 0LL;
int64_t regH = 0LL;
int64_t regI = 0LL;
char *regIP = memory;
```

A number of "register" variables is initialised. Nothing terribly exciting here, but these variables will be used in the `sprintf` machinery that will soon follow.

### User prompt

```c
puts("Input password:");
scanf(
  "%255s",           // format string
  &memory[0xE000]);  // destination
```

The user is prompted for a "password", consisting of up to 255 characters. These are loaded at the offset `0xE000` in the allocated memory.

### Flag output

```c
if (*((int16_t *)(&memory[0xE800]))) {
  printf("Flag: %s\n", &memory[0xE800]);
}
```

The memory location at offset `0xE800` is checked at the end of the program execution. If the word (2 bytes) at that location is not zero, they should form the beginning of the flag as a null-terminated string.

### Main loop

Finally, let's tackle the elephant in the room.

```c
while (regIP != &memory[0xFFFE]) {
  sprintf(
    &memory[0x2000000],  // destination
    regIP,               // format string
    "",                  // 1$
    0LL,                 // 2$
    &regIP,              // 3$
    &memory[0x2000000],  // 4$
    *regA, regA, &regA,  // 5$, 6$, 7$
    regB, &regB,         // 8$, 9$
    regC, &regC,         // 10$, 11$
    regD, &regD,         // 12$, 13$
    regE, &regE,         // 14$, 15$
    regF, &regF,         // 16$, 17$
    regG, &regG,         // 18$, 19$
    regH, &regH,         // 20$, 21$
    regI, &regI);        // 22$, 23$
}
```

[`sprintf`](https://linux.die.net/man/3/sprintf) is just like `printf`, but rather than outputting the formatted string to the standard output, it is instead pasted into the destination passed as the first argument.

The format string itself is at the address `regIP`. From the `while` loop condition we can easily deduce that `regIP` should be changing as execution proceeds, and that the offset `0xFFFE` in the allocated memory is a stopping point.

All the additional arguments to the format string (23 of them!) refer to one of the many "register" variables defined earlier, in addition to some utility constants. Each register is passed in directly, but also as a pointer, allowing the format string to change the values in these registers. The `1$` – `23$` numbering comes from the ["parameter field"](https://en.wikipedia.org/wiki/Printf_format_string#Parameter_field), which allows format strings to refer to their arguments with more flexibility.

But the code we saw so far still doesn't answer the key question: what does all of this actually *do*?

## The format strings

### Atoms

Let's take a closer look at the 146 format strings from `SPRINT_ROM`. They are all composed of smaller parts, i.e. individual format specifiers.

The first one to note is the use of the `%n` specifier, which allows the `sprintf` call to write data back to its arguments, rather than just to its destination string. More specifically, `%n` writes the number of characters output *so far* into the indicated argument. As an example:

```c
int x = 0;
sprintf(some_string, "abcdabcdabcd%n", &x);
```

This would result in the value `12` being stored in `x`. `%n` can also be combined with the `h` length field to refer to a 16-bit integer rather than a 32-bit one. So, if `sprintf` has output `100000` characters so far, a `%hn` will result in the value `34464` (`100000 % 65536`) being written to the argument.

`%n` is often used for [format string exploits](https://en.wikipedia.org/wiki/Uncontrolled_format_string), but here we don't control the format strings.

Every single format string in `SPRINT_ROM` uses `%n` at least once, in the form `%3$hn`, i.e. "write the number of bytes output so far into the third argument as a 16-bit integer". The third argument passed to `sprintf` is `&regIP`.

With all of this in mind, let's try to categorise all of the format strings into a smaller number of "instructions".

### `%1$NNNNNs%3$hn`

Concrete example: `%1$00430s%3$hn`

The shortest strings are of the form `%1$NNNNNs%3$hn`. These first write exactly `NNNNN` bytes to the output, then write that same number back into `regIP`. We can express the effect of this instruction as:

```c
bytesWritten += NNNNN;
regIP = bytesWritten;
```

The first argument `1$` always refers to the empty string, ensuring that this instruction works even if `NNNNN` happened to be zero.

### `%1$NNNNNs%3$hn%1$MMMMMs...`

Concrete example: `%1$00789s%3$hn%1$64747s`

The prefix `%1$NNNNNs%3$hn%1$MMMMMs...` can be found in most of the other format strings. Importantly, the two numbers sum to `65536`, which is just `0` again when downcast to a 16-bit integer. So the effect of this prefix is:

```c
bytesWritten += NNNNN;
regIP = bytesWritten;
bytesWritten -= NNNNN; // bytesWritten = 0
```

This means that `regIP` will be set to the new address, and the number of bytes output by `sprintf` is "reset" back to zero. In an even simpler form:

```c
regIP = NNNNN;
```

In the remaining instructions we'll shorten this common prefix to `<PRE>` and ignore its effects where possible.

### `<PRE>%1$NNNNNs%X$hn`

Concrete example: `%1$28672s%9$hn`

Just like the writes to `3$`, format strings can write 16-bit values to other registers using the same method. If `X` is `7`, the value is written to `regA`, if `X` is `9`, it is written to `regB`, and so forth.

```c
regX = NNNNN;
```

As noted in the [main loop section](#main-loop), each register is passed twice, once as its value, and once as a pointer. If `X` is `6`, the value is instead written to `*regA`, i.e. the location pointed to by `regA`. Likewise `8` is `*regB`, etc.

```c
*regX = NNNNN;
```

### `<PRE>%1$*X$s%Y$hn`

Concrete example: `%1$*8$s%7$hn`

An asterisk (`*`) can be used as the width specifier, in which case the width of the printed field depends on an argument to `sprintf`. And just like the other arguments, a number can be used to specify *which* argument will be used here. So the effect oft he first part is to output exactly `X` bytes. Then this value is written as a 16-bit integer into `Y` as usual.

```c
bytesWritten += regX;
regY = bytesWritten;
```

### `<PRE>%1$*X$s%1$NNNNNs%Y$hn`

Concrete example: `%1$*8$s%1$2s%7$hn`

This is almost the same as the last instruction, with an extra `%1$NNNNNs`. The effect of this part is to output some constant amount of extra bytes.

```c
bytesWritten += regX;
bytesWritten += NNNNN;
regY = bytesWritten;
```

More combinations of summations occur in the instructions, some using constants, some using the registers, some writing to where a register points, some writing to the register itself. We will not enumerate all of these options, since they consist of blocks we have already seen.

### `%X$c%1$NNNNNs%2$c%4$s%1$MMMMMs%3$hn`

Concrete example: `%14$c%1$00419s%2$c%4$s%1$65499s%3$hn`

This one is quite interesting. Note that this instruction does not have the common prefix. It does the following:

 - `%X$c` output `regX` as a single character
 - `%1$NNNNNs` output `NNNNN` bytes
 - `%2$c` output a zero byte (`2$` is `0LL` in the `sprintf` call)
 - `%4$s` output the string at `4$` (!)
 - `%1$MMMMMs` output `MMMMM` bytes
 - `%3$hn` write the number of bytes output so far into `regIP` as a 16-bit integer

The fourth step is very important here. `4$` in the `sprintf` call is `&memory[0x2000000]`. But `&memory[0x2000000]` is also the destination for the `sprintf` calls, so the first three parts of this instruction actually create a string that is then read by `sprintf` and output once again!

The final piece of the puzzle is then the fact that strings are null-terminated in C, so all of the above will allow some conditional logic in the code. Consider what happens when register `X` (or rather its least significant byte) is zero, and what happens when it is not:

| Step | `regX & 0xFF == 0` | `regX & 0xFF != 0` |
| --- | --- | --- |
| `%X$c` | Output a null byte | Output any other byte |
| `%1$NNNNNs` | Output `NNNNN` bytes | Output `NNNNN` bytes |
| `%2$c` | Output a null byte | Output a null byte |
| `%4$s` | Output an empty string | Output a string of `NNNNN + 1` bytes |
| `%1$MMMMMs` | Output `MMMMM` bytes | Output `MMMMM` bytes |
| `%3$hn` | Write `1 + NNNNN + 1 + 0 + MMMMM` to `regIP` | Write `1 + NNNNN + 1 + NNNNN + 1 + MMMMM` to `regIP` |

In the format strings, `NNNNN` and `MMMMM` are set just right, so that this instruction encodes a conditional branch, setting `regIP` to different values depending on whether `regX` was zero or not.

```c
if (regX & 0xFF) {
  regIP = (2 + NNNNN + MMMMM) & 0xFFFF;
} else {
  regIP = (3 + NNNNN + NNNNN + MMMMM) & 0xFFFF;
}
```

### Pseudo-assembly

Putting it all together, we can finally understand the format strings as a series of instructions with some conditional logic. `regIP` initially points to the first format string, but it is modified as the program executes. Most instructions contain a common prefix which sets `regIP` to the next instruction before performing a step with the other registers. The conditional branches always encode a jump to either the next instruction, or a completely different instruction. There is no restriction on the jump destinations, so backward jumps are possible. An unconditional jump to `0xFFFE` stops execution, due to the condition of the main `while` loop.

```
0x0000: regB  = 0x7000
0x0026: regA  = regB
0x004A: *regA = 0x1
0x006C: regA  = 0x2 + regB
0x0095: *regA = 0x1
0x00B7: regC  = 0x2
...
```

([Full pseudo-assembly here](files/sprint-assembly.txt))

Interestingly a lot of the arguments to `sprintf` were not used at all. We can only surmise that this is because the generator for this challenge was made somewhat generic, and the regular layout of the register arguments is neater. `regI` is only ever written to, and seems to indicate a sort of exit code, even though it is not checked, not by the `sprintf` program, nor by the host program.

## Pseudocode

With our assembly in hand, we can perform analyses to get to something more readable, easier to understand.

We first split the code into blocks. Any address mentioned in a `goto` (including conditional ones) is a jump destination and begins a new block. Equivalently, `goto`s and conditionals (and `halt`s) terminate a block.

([Analysis source code: block splitting](scripts/SprintAnalyse.hx#L49-L106))

Then we can look at which registers are read and written by each block. A block can both read and write the same register.

([Analysis source code: register reads/writes](scripts/SprintAnalyse.hx#L108-L112))

With this information, we can infer variables, to reverse the process of [register allocation](https://en.wikipedia.org/wiki/Register_allocation). In short, when the current block writes into a register, this register is propagated through to all the blocks that can follow the current one. As long as the blocks read the given register, we can fuse them into the same variable. Once we find a block that overwrites our chosen register, we stop the recursion.

([Analysis source code: variable reconstruction](scripts/SprintAnalyse.hx#L126-L149))

At this point, we will have less difficulty re-organising code blocks, because we don't have to be afraid that we are missing what particular registers mean at any given point. Additionally, we can (manually) do some constant folding, further eliminating variables that are only written to once.

```
0x0000: (from -)
  [0x7000] = 0x0001
  [0x7002] = 0x0001
  var2 = 0x0002

0x00DA: (from 0x0324, 0x0000)
  if ([0x7000 + var2 * 2]) goto 0x0324 else goto 0x0180

0x0180: (from 0x00DA)
  var6 = var2 * 2

0x01AE: (from 0x0269, 0x0180)
  [0xFFEF] = var6
  if ([0xFFF0]) goto 0x0324 else goto 0x0269
...
```

([Full pseudo-assembly with blocks and variables here](files/sprint-renum.txt))

Now we can take a better look at the way control flows through the program and recover proper loops and conditional blocks. The goal is to eliminate all `goto` instructions. This analysis can be also be done automatically (by looking at the "shapes" in the node graph), but the code was short enough where it was faster to do it by hand.

```
[0x7000] = 0x0001;
[0x7002] = 0x0001;
var2 = 0x0002;

do {
  if ([0x7000 + var2 * 2] == 0) {
    var6 = var2 * 2;
    while (true) {
      [0xFFEF] = var6;
...
```

([Full pseudo-code after CF analysis here](files/sprint-reflow.txt))

And finally, we can name the variables more sensibly. This would be much more difficult if we were working directly with the assembly. We will analyse the resulting code one piece at a time.

The code is almost working C. The memory access operations would have to index into some pre-defined memory buffer. Almost all operations are 16-bit (i.e. word-based), except for conditions, which only check the least significant 8 bits. One idiom that is used multiple times is based on unaligned memory access:

```
[0xFFEF] = sub_position;
if ([0xFFF0]) break; // or another operation on [0xFFF0]
```

The variable is written into location `0xFFEF`, but because of the 16-bit operations, both `0xFFEF` and `0xFFF0` are modified. The second byte is then checked. In the example above, `break` is executed if `sub_position` is greater or equal to `256`.

### Initialisation

```
// initialise the map walls
[0x7000] = 0x0001;
[0x7002] = 0x0001;

let map_position = 0x0002;
do {
  if ([0x7000 + map_position * 2] == 0) {
    let sub_position = map_position * 2;
    while (true) {
      [0xFFEF] = sub_position;
      if ([0xFFF0]) break;
      [0x7000 + sub_position * 2] = 0x0001;
      sub_position += map_position;
    }
  }
  map_position += 0x0001;
} while (map_position);
```

We start off by initialising the memory at `0x7000`. The words at `0x7000` and `0x7002` are set to `1`, then in our loop we repeat a memory fill operation 254 times.

This strange loop produces the following pattern at memory location `0x7000`:

```
X X     X   X   X X X   X   X X 
X   X   X X X   X X X X X   X   
X X X X X   X X X   X   X X X   
X X X X X   X X X X X   X   X X 
X X X   X X X   X   X X X X X   
X X X   X X X X X   X X X X X X 
X   X X X   X   X X X   X   X X 
X   X X X X X X X X X X X X X   
X X X   X X X X X   X   X X X X 
X X X X X   X   X X X X X   X X 
X X X   X X X   X X X X X   X X 
X X X   X   X X X X X X X X X   
X   X X X   X   X X X X X X X X 
X X X   X X X X X X X X X X X   
X X X   X   X X X   X X X X X   
X   X X X X X X X X X   X X X X 
```

Where `X` represents a `1` byte, and spaces represent `0` bytes.

### User input

```
// calculate the length of user input
let user_input_ptr = 0xE000;
let user_input_negative_length = 0;
while ([user_input_ptr]) {
  user_input_negative_length -= 1;
  user_input_ptr += 1;
}

// if the user input is not 254 characters long, halt
if (-254 != user_input_negative_length) {
  error_num = 5;
  [0xE800] = 0;
  halt;
}
```

The next step is to check the length of the user input, which was loaded into memory at offset `0xE000` before the main loop. Nothing particularly interesting here, except that maybe the user input can be any length that is `254 + n * 256` for some `n`. We will assume it should be `254` though.

### Maze navigation

```
// check user password, navigate the maze
let pw_position = 0;
let checkpoint_counter = 0;
let map_position = [0xF100];
let pw_valid = 1;
error_num = 0;

while (true) {
  // take the next byte of the password
  let pw_byte = [0xE000 + pw_position];
  if (!pw_byte) break;
  pw_position += 1;

  // up / right / down / left
  let map_delta;
  if (pw_byte == 'u') {
    map_delta = -16;
  } else if (pw_byte == 'r') {
    map_delta = 1;
  } else if (pw_byte == 'd') {
    map_delta = 16;
  } else if (pw_byte == 'l') {
    map_delta = -1;
  } else {
    pw_valid = 0x0000;
    map_delta = 0;
    error_num = 1;
  }
  map_position += map_delta;

  // if we went out of bounds, halt
  [0xFFEF] = map_position;
  if ([0xFFF0]) {
    error_num = 4;
    halt;
  }

  // if we bumped into a wall, halt (eventually)
  [0xFFEF] = [0xF000 + map_position];
  [0xFFF0] = 0x0000;
  if ([0x7000 + [0xFFEF] * 2]) { // note [0xFFEF] re-mapping coordinates
    pw_valid = 0;
    error_num = 2;
    continue;
  }

  // if we hit a checkpoint, increase the checkpoint counter
  if ([0xF103 + checkpoint_counter] == -map_position) {
    checkpoint_counter += 1;
  }
}
```

Here is the really interesting part. Our password is checked one byte at a time. Each byte must be one of `u`, `r`, `d`, or `l`. Considering what we see in the memory and what each of the characters maps to, we can conclude that our password is actually a series of `up`, `right`, `down`, and `left` steps in a maze!

The maze is `16 ⨉ 16` tiles in size, but it is stored linearly in memory, so an `up` step is encoded as an offset of `-16`, and likewise a `down` step is encoded as the offset `16`. This way the single variable `map_position` can be used to encode our position in the map.

Speaking of `map_position`, it is loaded from the memory location `0xF100`. The word stored there is `0x0011`, i.e. we start in the second column, second row.

But the pattern generated into memory location `0x7000` does not really look like a maze. It is somewhat chaotic, but there are clearly no ways to navigate the empty positions. The answer comes from the conditional used to check wall bumps. Understanding the unaligned memory write-then-read access idiom, it can be expressed instead as:

```
if ([0x7000 + ([0xF000 + map_position] & 0xFF) * 2]) ...
```

There is a double indirection happening. The data at `0xF000` encodes how our position in the map maps to the walls encoded at `0x7000`. If we undo this re-mapping, we get a maze that looks like this:

```
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XX  XX          XX              XX
XX  XX  XXXXXXXXXX  XXXXXXXXXXXXXX
XX              XX  XX  XX      XX
XX  XXXXXXXXXX  XX  XX  XX  XXXXXX
XX  XX  XX                      XX
XXXXXX  XXXXXX  XXXXXXXXXXXXXX  XX
XX      XX      XX      XX      XX
XX  XXXXXXXXXX  XXXXXX  XXXXXXXXXX
XX              XX  XX      XX  XX
XX  XX  XXXXXXXXXX  XX  XXXXXX  XX
XX  XX  XX  XX  XX              XX
XX  XXXXXX  XX  XX  XX  XXXXXXXXXX
XX                  XX          XX
XXXXXX  XX  XXXXXXXXXX  XX  XXXXXX
XX      XX  XX          XX      XX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

That looks a lot more like a maze! The right and bottom walls are not actually encoded directly, but they are there because:

 - Walking off the bottom edge puts the player out of bounds (`map_position >= 0x100`), which is checked for.
 - Walking off the right edge of the map puts the player in the leftmost column of the next row, which is always either a wall, or out of bounds.

We also have a `checkpoint_counter` variable. There are certain positions in the map encoded at the `0xF103` memory location. If we number these in order and add them to the map, we get:

```
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XX  XX          XX             8XX
XX  XX  XXXXXXXXXX  XXXXXXXXXXXXXX
XX              XX  XX  XX     5XX
XX  XXXXXXXXXX  XX  XX  XX  XXXXXX
XX 2XX 4XX                      XX
XXXXXX  XXXXXX  XXXXXXXXXXXXXX  XX
XX      XX 7    XX      XX 0    XX
XX  XXXXXXXXXX  XXXXXX  XXXXXXXXXX
XX              XX  XX      XX  XX
XX  XX  XXXXXXXXXX  XX  XXXXXX  XX
XX  XX  XX  XX 3XX              XX
XX  XXXXXX  XX  XX  XX  XXXXXXXXXX
XX                  XX          XX
XXXXXX  XX  XXXXXXXXXX  XX  XXXXXX
XX 6    XX  XX          XX     1XX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

([Full map analysis script](scripts/SprintMap.hx))

### Additional password checks

```
// if some characters were invalid or we bumped into a wall, halt
if (!pw_valid) {
  [0xE800] = 0x0000;
  halt;
}

// if we did not make it through exactly 9 checkpoints, halt
if (checkpoint_counter != 9) {
  error_num = 3;
  [0xE800] = 0x0000;
  halt;
}
```

Not much to comment on here. `pw_valid` is set to `0` if the password includes an invalid character, or if we bumped into a wall. We also learn here that there are 9 checkpoints.

### Flag decoding

```
// success, let's decode the flag
let flag_position = 0;
let pw_position = 0;
while (flag_position != 39) {
  let block_counter = 4;
  let checksum = 0;

  do {
    checksum *= 4;
    let pw_byte = [0xE000 + pw_position];
    if (pw_byte == 'u') {
      // checksum += 0x0000;
    } else if (pw_byte == 'r') {
      checksum += 0x0001;
    } else if (pw_byte == 'd') {
      checksum += 0x0002;
    } else if (pw_byte == 'l') {
      checksum += 0x0003;
    } else {
      [0xE800] = 0x0000;
      halt;
    }
    pw_position += 1;
    block_counter -= 1;
  } while (block_counter);

  [0xE800 + flag_position] = [0xF10C + flag_position] + checksum;
  flag_position += 0x0001;
}

// add a null byte and let's call it a string
[0xE800 + flag_position] = 0x0000;
halt;
```

Once the password passes all checks, we proceed to decoding the flag. Decoding consists of 39 rounds where 4 bytes of the password are taken at a time, an 8-bit checksum value is generated from them, then the checksum is added
to a byte the encrypted flag stored in the program memory at `0xF10C`:

```
9E FF A1 26 14 3B 68 60 6B C7 34 C4 0A 1B 6D 8C C9 47 76 65 32 74 5F E2 25 72 32 74 62 0A B9 81 6E C6 17 E3 C5 66 7D
```

### Bruteforcing

We have everything we need to find the correct password, but let's quickly talk about bruteforcing. This might have been relevant had we wanted to reach a solution as quickly as possible, without reverse engineering the program completely.

In the flag decoding part, we do 39 rounds of 4 bytes of the password. `39 * 4 == 156`, which is less than `254`. So, even though the password needs to pass the checks, only the first `156` bytes matter for the decryption.

Although the password consists of 4 different characters, and 4 bytes of the password have `4 ** 4 == 256` different values, knowing that there is a maze at all might lead us to guess the fact that directions always come in pairs. This leaves us with in fact `4 ** 2 == 16` different values for each byte of the encrypted flag. Since the decryption is linear, at least half of these values would result in bytes outside of the ASCII range.

With these restrictions, we have:

```
>OA&d;h`kg4dZkm,iGve2t_2%r2tbZY!nfg3ef}
CTFvi+XP[l$i_ ]|n7fU"dO7ub"dR_^q^kl8jVm
HYK+n@mep!9ndpr1#L{j7yd<*w7ygdc&s !=ok"
M^P{#0]U`q)#i%b6s<kZ'iTAzg'iWihvcpqB$[r
   0sErju&>s uw;(Q o<~i /|<~l  +x%& tp'
     5bZev.  *g xAp_,nY 4l,n\  {huv  `w
   5 Jwoz C  z|  V%tA#n $!A#q  0}    u,
   % :g_j 3   l  Fud1s^  q1sa   m    e|
```

Where each column has exactly one character of the flag. We can see the `CTF` prefix, which happens to line up at the same offsets, but the remained of the flag is not trivial to deduce. Still, some dictionary-based attack might be possible.

([Full brute force script](scripts/SprintSolve.hx))

## Finding the correct password

Well, let's navigate the maze! We start in the top-left corner and we need to hit the checkpoints `0`...`8` in order. The shortest (unique) paths are:

- `ddrrrrrrddrrrrrrrrddll` - start to `0`
- `rruullllllllddddllllllddddrrrrrrrruurrddrrddrr` - `0` to `1`
- `lluulluullddlllllllluuuurrrrrruuuuuulllllldd` - `1` to `2`
- `uurrrrrrddddddllllllddddrrrrrruu` - `2` to `3`
- `ddlllllluuuuuurruu` - `3` to `4`
- `ddllddrrrrrruuuurrrrrruurr` - `4` to `5`
- `llddllllllddddllllllddddrrddll` - `5` to `6`
- `rruulluuuurrrrrruull` - `6` to `7`
- `rruurruuuurrrrrr` - `7` to `8`

Putting it all together, we have `ddrrrrrrddrrrrrrrrddllrruullllllllddddllllllddddrrrrrrrruurrddrrddrrlluulluullddlllllllluuuurrrrrruuuuuulllllldduurrrrrrddddddllllllddddrrrrrruuddlllllluuuuuurruuddllddrrrrrruuuurrrrrruurrllddllllllddddllllllddddrrddllrruulluuuurrrrrruullrruurruuuurrrrrr`. Exactly `254` characters long, which is promising.

And, sure enough:

```bash
$ ./sprint
Input password:
ddrrrrrrddrrrrrrrrddllrruullllllllddddllllllddddrrrrrrrruurrddrrddrrlluulluullddlllllllluuuurrrrrruuuuuulllllldduurrrrrrddddddllllllddddrrrrrruuddlllllluuuuuurruuddllddrrrrrruuuurrrrrruurrllddllllllddddllllllddddrrddllrruulluuuurrrrrruullrruurruuuurrrrrr
Flag: CTF{n0w_ev3n_pr1n7f_1s_7ur1ng_c0mpl3te}
```
