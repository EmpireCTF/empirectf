from pwn import *

r4 = 0

def get_op(instr):
	return (instr >> 0x10) & 0xF

def get_dst(instr):
	return instr & 3

def get_src(instr):
	return (instr >> 2) & 3

def arith_op(codes, ip, sym):
	instr = codes[ip]
	if r4:
		if sym == "":
			return "r%d = [r%d]" % (get_dst(instr), get_src(instr))
		else:
			return "r%d = [r%d] %s [r%d]" % (get_dst(instr), get_dst(instr), sym, get_src(instr))
	else:
		return "r%d %s= r%d" % (get_dst(instr), sym, get_src(instr))

def store(codes, ip):
	instr = codes[ip]
	return ("[r%d] = [r%d]" if r4 else "[r%d] = r%d") % (get_dst(instr), get_src(instr))

def switch(codes, ip):
	global r4
	r4 ^= 1
	return "switch"

commands = {
	1 : lambda codes,ip : arith_op(codes, ip, "+"),
	2 : lambda codes,ip : arith_op(codes, ip, "-"),
	3 : lambda codes,ip : arith_op(codes, ip, "*"),
	4 : lambda codes,ip : arith_op(codes, ip, "/"),
	5 : lambda codes,ip : arith_op(codes, ip, ""),
	6 : store,
	7 : lambda codes,ip : ("jmp +r%d" if r4 else "jmp r%d") % get_dst(codes[ip]),
	8 : switch,
	9 : lambda codes,ip : ("r%d ? jz +r%d" if r4 else "r%d ? jz r%d") % (get_dst(codes[ip]), get_src(codes[ip])), 
	10 : lambda codes,ip : "r%d = %d" % (get_dst(codes[ip]), get_src(codes[ip])), 
	11 : lambda codes,ip : ("[r%d] += 1" if r4 else "r%d += 1" ) % get_dst(codes[ip]),
	12 : lambda codes,ip : "nop",
	0 : lambda codes,ip : "stop"
}

f = open("chal.o.2", "rb")
data = f.read()
f.close()

codes = []
for i in xrange(0, len(data), 4):
	codes.append(u32(data[i:i+4]))

asm = ""
for i in xrange(len(codes)):
	asm += commands[get_op(codes[i])](codes, i)
	asm += '\n'
print asm


#[0] == 'w'