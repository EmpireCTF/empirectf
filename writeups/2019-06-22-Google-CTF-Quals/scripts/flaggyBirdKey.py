#!/usr/bin/env python3

import itertools
from hashlib import sha256

sums = [9,8,7,2,11,15,13,10,6,5,14,4,3,0,12,1]

# target is the `a` array in `Checker`
target = [
  46, 50, 92, -111, -55, 20, 120, -77,
  92, 46, 12, -74, 91, 120, 81, -58,
  -6, -104, -123, 90, 119, -61, -65, -45,
  -16, 8, 64, -68, -103, -84, -30, 107
]

# bytes are signed in Java, we need to add 256 to any negative byte
target = bytes([ x % 256 for x in target ])

for pairs in itertools.product([0, 1], repeat = 16):
  candidate = []
  for i in range(16):
    candidate += [0, sums[i], 0][pairs[i]:][:2]
  if sha256(bytes(candidate)).digest() == target:
    print(candidate)
    break
else:
  print("no solution found!")
