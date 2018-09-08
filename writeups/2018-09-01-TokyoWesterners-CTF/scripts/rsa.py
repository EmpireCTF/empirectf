#!/usr/bin/env python3

import gmpy2

n = gmpy2.mpz(0x008529063ea0ad3b46296f92f72356772ea4e703f7b79220c18de1b7e3ca0a7728d19e69dc48b8685cd604f5887a4f8f3a945a1ca1593cf086d348ec4dc92142083fc9e2203c6530311ee510be50a42aee4a63e7fa66bfce3512fc2fb117402a55cdf0897770c1bb86f2d9306da5b899d294edbcb17ad87e17592ccc3f62b1305724181732ac7474cf23beb722833373ef07b6a92188cf28bcfef26b2368ada38f7f4fd8921dbe3b6488e4b92028ffbd46ae26d8b43c9a86dbbc63f0b51398bb54098ff7004b646afb42f24354ab6a2d30efeee8b333473abe1cc92eb68a465819d9e9a0ff58feaf2c722ae65b7cedc9e30be915029d69342523b981ad8395cdf7)
e = gmpy2.mpz(0x10001)

for x in range(1, 0x100000):
  discriminant = gmpy2.mpz(1 + 4 * n * e * x)
  root = gmpy2.iroot(discriminant, 2)[0]
  if root * root == discriminant:
    print("x = {}".format(x))
    break

numerator = 1 + gmpy2.iroot(gmpy2.mpz(1 + 4 * n * e * x), 2)[0]
denominator = 2 * e

print("integer fraction found: {}".format(numerator % denominator == 0))

q = numerator // denominator

print("prime of n found: {}".format(n % q == 0))

p = n // q

print("p = {}".format(p))
print("q = {}".format(q))

phi = (p - 1) * (q - 1)

print("phi = {}".format(phi))

d = gmpy2.invert(e, phi)

print("d = {}".format(d))

def int_to_bytes(x):
  return x.to_bytes((x.bit_length() + 7) // 8, "big")

def bytes_to_int(bs):
  return int.from_bytes(bs, "big")

with open("rsa-flag.encrypted", "rb") as flag:
  cipher = bytes_to_int(bytes(flag.read()))

print("cipher = {}".format(cipher))

plain = gmpy2.powmod(cipher, d, n)

print("plain = {}".format(plain))

print(int_to_bytes(int(plain)))
