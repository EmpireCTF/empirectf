from pwn import *

def load_prog():
	f = open("encrypt" ,"rb")
	b = f.read()
	f.close()
	ret = []
	for i in xrange(0,len(b),2):
		ret.append(u16(b[i:i+2]))
	print map(hex, ret)
	return ret





def load_const(pc, r8d, di, si):
	return ("loadconst [%s] = %s\n" % (hex(si), hex(2*(pc+1))), pc + 0x21)


def load_toproc(pc, r8d, di, si):
	#print r8d
	assert r8d == 14
	return ("loadto %s\n" % hex(si), pc+1)

def store_toproc(pc, r8d, di, si):
	assert si == 14
	return ("storeto %s\n" % hex(di), pc+1)

def cmp_eq(pc, r8d, di, si):
	return ("[%s] == [%s] ? jmp [%s]\n" % (hex(r8d), hex(si), hex(di)), pc+1)

def cmp_bigger(pc, r8d, di, si):
	return ("[%s] < [%s] ? jmp [%s]\n" % (hex(si), hex(r8d), hex(di)), pc+1)

def add(pc, r8d, di, si):
	return ("[%s] = [%s] + [%s]\n" % (hex(si), hex(r8d), hex(di)), pc+1)

def xor(pc, r8d, di, si):
	return ("[%s] = [%s] ^ [%s]\n" % (hex(si), hex(r8d), hex(di)), pc+1)

def someoper(pc, r8d, di, si):
	return ("[%s] = [%s] ? [%s]\n" % (hex(si), hex(r8d), hex(di)), pc+1)

def disassemble(prog):
	pc = 0
	ret = ""
	while pc < len(prog):
		v8 = prog[pc]
		di = v8 >> 12;
		si = (v8 >> 4) & 0xF;
		r8d = (v8 >> 8) & 0xF;
		(asm, pc) = tab[v8 & 0xf](pc, r8d, di, si)
		ret += hex(pc*2)[2:] + ": " + asm
	print ret

tab = {
	0 : load_toproc,
	1 : store_toproc,
	2 : cmp_eq,
	3 : cmp_bigger,
	5 : add,
	7 : xor,
	8 : someoper,
	10 : load_const,
	15 : lambda pc, r8d, di, si : ("store result\n", pc+1)
}

print disassemble(load_prog())