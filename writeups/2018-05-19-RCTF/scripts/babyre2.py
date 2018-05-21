#!/usr/bin/env python3

def extendedGCD(p, q):
    if q == 0:
        return (p, 1, 0)
    vals = extendedGCD(q, p % q)
    return (vals[0], vals[2], vals[1] - vals[2] * (p / q))

def solve(a, b, m):
    a = a % m
    b = b % m
    gcd = extendedGCD(a, m)
    if b % gcd[0] != 0:
        return None
    return (gcd[1] * (b / gcd[0])) % m

if __name__ == "__main__":
    m = 0xFFFFFFFFFFFFFFC5
    pairs = [
        (0x20656d6f636c6557, 0x2b7192452905e8fb),
        (0x2046544352206f74, 0x7ba58f82bd898035),
        (0x6548202138313032, 0xa3112746582e1434),
        (0x2061207369206572, 0x163f756fcc221ab0),
        (0x6320455279626142, 0xecc78e6fb9cba1fe),
        (0x65676e656c6c6168, 0xdcdd8b49ea5d7e14),
        (0x756f7920726f6620, 0xa2845fe0b3096f8e),
        (0xffffffffffff002e, 0xaaaaaaaaaa975d1c),
        (0xffffffffffffffff, 0x55555555555559a3),
        (0xffffffffffffffff, 0x55555555555559a3),
        (0xffffffffffffffff, 0x55555555555559a3),
        (0xffffffffffffffff, 0x55555555555559a3),
        (0xffffffffffffffff, 0x55555555555559a3),
        (0xffffffffffffffff, 0x55555555555559a3),
        (0xffffffffffffffff, 0x55555555555559a3),
        (0xffffffffffffffff, 0x55555555555559a3)
    ]
    for (a, b) in pairs:
        print(hex(solve(a, b, m))[2:-1])
