from struct import unpack

u64 = lambda x : unpack('<Q', x)[0x0]
f = open("dump.bin", "rb")
data = f.read()
f.close()

asm = []
for x in xrange(0, 152*7*8, 7*8):
	tmp = []
	for i in xrange(x, x+7*8, 8):
		tmp.append(u64(data[i:i+8]))
	asm.append(tmp)

ram = []
for i in xrange(152*7*8+8*5, len(data) / 8 * 8, 8):
	ram.append(u64(data[i:i+8]))

def disasm(asms):
	ret = []
	for asm in asms:
		opcode = asm[4]
		if opcode == 0x00:
			if asm[5] == 0x00:
				ret.append("[0x0] += [0x1]")
			elif asm[5] == 0x01:
				ret.append("[0x0] *= [0x1]")
			elif asm[5] == 0x02:
				ret.append("[0x0] = [0x0]==[0x1]")
			elif asm[5] == 0x03:
				ret.append("[0x0] = getchar()")
			elif asm[5] == 0x04:
				ret.append("putchar([0x0])")
			else:
				assert(False)
		elif opcode == 0x01:
			ret.append(str(asm[6]) + ' ' + str(asm[5]))
		elif opcode == 0x02:
			ret.append("[[%s]] = [[%s]]" % (hex(asm[5]), hex(asm[6]))) #todo
		elif opcode == 0x03:
			ret.append("[%s] = [%s]" % (hex(asm[5]), hex(asm[6])))
		else:
			assert(False)
	return ret


print '\n'.join(disasm(asm))
# for i in xrange(0, len(asm)):
# 	print i,
# 	for x in asm[i]:
# 		print hex(x),
# 	print ""
for i in xrange(0xc0):
	print hex(i) + ':' + hex(ram[4*i+3])

arr = lambda i : ram[4*i+3]

res = [0xd817,0xb60b,0x223d,0x4ebf,0x2a68,0xd930,0x5648,0x6841,0x4723,0x4c69,0x9d8c,0x999f,0xd01b,0x64f0,0xd00a,0x3d42,0x7695,0x265e,0x9bd8,0xc06,0x94f,0xc4c0,0xf687,0xc76c,0x356f,0x498e,0x8bdd,0x9f21,0xbefd,0x59de,0xe2cc,0x734f,0x91e6,0x1af6]

def mul(a, b):
	return (a * b) % 65537
def add(a, b):
	return (a + b) % 65537
def sub(a, b):
	return (a - b) % 65537
def powff(a, b):
	acc = 1
	for i in xrange(b):
		acc = mul(acc, a)
	return acc
def div(a, b):
	inv = powff(b, 65537 - 2)
	return mul(a, inv)

def polynomial(a, b, p):
	acc = 0
	for i in xrange(p+1):
		acc = add(acc, powff(a, i))
	return mul(acc, b)

def encode1(flag):
	r = [0] * 0x22
	flag = map(ord, flag)
	for y in xrange(0x22):
		c = flag[y]
		last = 0
		for x in xrange(0x22):
			c = (((c * arr((y + 8) % 65537)) % 65537) + arr((y + 0x2c) % 65537)) % 65537
			r[x] = (r[x] + c) % 65537
		# if last == res[y]:
		# 	flag.append(chr(c))
		# 	print hex(last)
	return r

r1 = encode1("TSGCTF{xxxxxxxxxxxxxxxxxxxxxxxxxx}")

mat = []
for y in xrange(0x22):
	tmp = []
	for x in xrange(0x22):
		tmp.append(powff(arr(x+8), y + 1))
	mat.append(tmp)


def convert_res(res):
	for y in xrange(0x22):
		for x in xrange(0x22):
			res[y] = sub(res[y], polynomial(arr(x+8), arr(x+0x2c), y))
	return res

def encode2(mat, flag):
	r = []
	for y in xrange(0x22):
		acc = 0
		for i in xrange(0x22):
			acc += flag[i] * mat[y][i]
		acc %= 65537
		r.append(acc)
	return r

r2 = encode2(mat, map(ord, "TSGCTF{xxxxxxxxxxxxxxxxxxxxxxxxxx}"))
print map(hex,convert_res(r1))
print map(hex,r2)
# same, which means our conversion is correct

from genericmatrix import GenericMatrix

m = GenericMatrix(size=(0x22,0x22),zeroElement=0,\
	identityElement=1,\
	add=add,mul=mul,sub=sub,div=div)

for i in xrange(0x22):
	m.SetRow(i, mat[i])

print "".join(map(chr,m.Solve(convert_res(res))))