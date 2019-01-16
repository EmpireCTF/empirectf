#!/usr/bin/env python3
# run with
# ./queens 15 | python3 decode.py

import os, re, sys
from stat import S_ISREG
from hashlib import sha256
from Crypto.Cipher import AES

# chall.tar order -> alphabetical order
reorder = [8,206,184,188,210,202,215,64,9,80,114,73,79,5,164,53,88,134,65,141,14,58,131,133,217,169,121,191,122,2,135,106,4,74,41,213,190,33,108,117,54,6,18,98,182,181,22,192,38,176,0,7,208,31,103,12,16,173,171,107,221,186,19,205,153,85,139,180,10,211,147,138,91,132,93,178,75,34,21,59,158,36,187,219,218,46,163,196,35,119,96,143,124,185,200,55,203,87,189,50,204,151,45,69,123,201,1,155,214,47,63,25,167,15,166,72,159,224,207,97,129,82,43,118,68,142,193,48,90,61,40,99,116,49,160,102,100,39,137,150,84,165,146,42,144,71,212,170,37,172,30,149,110,104,177,195,111,57,11,78,66,216,23,198,161,60,51,83,136,157,220,128,56,126,105,62,179,28,92,32,197,77,76,94,112,26,89,29,127,145,162,101,120,70,209,52,183,223,222,67,154,194,115,168,17,113,130,20,125,174,199,24,156,27,109,140,148,13,175,86,81,95,44,3,152]

flag_fmt = r"35C3_[\w]*"
enc_flag = b'\x99|8\x80oh\xf57\xd4\x81\xa5\x12\x92\xde\xf5y\xbc\xc0y\rG\xa8#l\xb6\xa1/\xfeE\xc5\x7f\x85\x9a\x82\x0b\x02Y{\xd9/\x92X>p\\\xb7H\xb1{\xcf\x8b/r=\x87-#\xae\x95\xb6\xd1\r\x03\x13'

count = 0
for line in sys.stdin:
  raw = line.rstrip("\n,").split(",")
  magic = "".join([ ("700" if raw[idx] == "1" else "400") for idx in reorder ])
  if count % 1000 == 0:
    print(str(count))
  try:
    flag = AES.new(sha256(magic.encode()).digest(), AES.MODE_ECB).decrypt(enc_flag)
    if re.fullmatch(flag_fmt, flag.decode()) is not None:
      print("FLAG: {}".format(flag))
      exit(0)
  except Exception:
    pass
  count += 1
