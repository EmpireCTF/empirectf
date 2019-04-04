from Crypto.PublicKey import RSA
from Crypto.Util.number import *
import gmpy2
import os

flag = open("flag.txt",'r')

p = getPrime(512)
q = 9896984395151566492448748862139262345387297785144637332499966426571398040295087125558780121504834847289828037371643927199404615218623314326851473129699891
n = p*q
e = 65537
phi = (p-1)*(q-1)
d = gmpy2.invert(e,phi)

message = bytes_to_long(flag.read())

ciphertext = pow(message,e,n)
ciphertext = long_to_bytes(ciphertext).encode('hex')

encrypt = open("flag.enc",'w')

encrypt.write("ciphertext: \n" + ciphertext + "\nn: " + str(n))
encrypt.close()
flag.close()
os.remove("./flag.txt")

# encryptCTF{74K1NG_B4BY_S73PS}
