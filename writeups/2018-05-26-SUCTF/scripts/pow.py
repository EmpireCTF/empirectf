#!/usr/bin/env python3

from hashlib import sha256
import itertools
import sys

def pow_hash(prefix, candidate):
    plain = "{}{}".format(prefix, candidate)
    return sha256(bytes(plain, "ascii")).hexdigest()

def solve_pow(prefix, target):
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    for candidate in map("".join, itertools.product(*[ alphabet for i in range(4) ])):
        if pow_hash(prefix, candidate) == target:
            return candidate
    return None

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("usage: ./pow.py <prefix> <target>")
        sys.exit()
    print("solution: {}".format(solve_pow(sys.argv[1], sys.argv[2])))