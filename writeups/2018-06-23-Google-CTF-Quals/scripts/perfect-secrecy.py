#!/usr/bin/env python3

from decimal import *
from multiprocessing import Pool
import socket

if __name__ == "__main__":
  # public modulus
  n = 0x00da53a899d5573091af6cc9c9a9fc315f76402c8970bbb1986bfe8e29ced12d0adf61b21d6c281ccbf2efed79aa7dd23a2776b03503b1af354e35bf58c91db7d7c62f6b92c918c90b68859c77cae9fdb314f82490a0d6b50c5dc85f5c92a6fdf19716ac8451efe8bbdf488ae098a7c76add2599f2ca642073afa20d143af403d1
  
  # public exponent
  e = 0x10001
  
  # encrypted "2"
  enctwo = pow(2, e, n)
  
  # key size in bits
  k = 1024
  
  # flag ciphertext
  cipher = 0xa9c565cbc2cf1c7d4267fd1769dce9f03481800bbae86bb0926ae617a7e6d09f2c61a9d70a856783973c4c55bf43a24c1d70f7b02ac034ff39c537ab39c78d90523a8107a0980195df3521d654d72069f9428208431cc763def39bcd8cd3ea9d45e99e23f7810fa03b6ce906d6f41373e0e2a7c022301828d7f80ed3c630ae56
  
  # multiply the ciphertext by the encrypted "2"
  #  (and hence the plaintext by just "2")
  print("calculating ciphertext multiples ...")
  multiples = []
  for i in range(k):
    cipher = (cipher * enctwo) % n
    multiples.append(cipher)
  
  # run threads to gather parity bits from the server
  def getbit(cipher):
    while True:
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.connect(('perfect-secrecy.ctfcompetition.com', 1337))
      # 0x40 has LSB 0, 0x41 has LSB 1
      sock.sendall(b"\x40\x41")
      sock.sendall(cipher.to_bytes(128, "big"))
      data = b""
      while len(data) < 100:
        data += sock.recv(1024)
      sock.close()
      ones = sum(data)
      zeros = 100 - ones
      # only return if the result was decisive
      if ones >= 60:
        return 1
      elif zeros >= 60:
        return 0
  print("gathering parity bits from server ...")
  pool = Pool(8)
  parities = pool.map(getbit, multiples)
  
  # binary search based on parity bits
  print("calculating flag value ...")
  getcontext().prec = k
  l = Decimal(0)
  u = Decimal(n)
  for i in range(k):
    h = (l + u) / 2
    if parities[i] == 0:
      u = h
    else:
      l = h
  print("flag:")
  print(hex(int(u)))
  print(int(u).to_bytes(128, "big"))
