#!/usr/bin/env python

import socket
import sys

padding = b"1234567890ABCDEFGHIJ"
known_flag = b""
alphabet = b"abcdefghijklmnopqrstuvwxyz_"

def line(sock):
  buf = b""
  while True:
    c = sock.recv(1)
    if c == "\n":
      return buf
    buf += c

while True:
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  sock.connect(("crypto.chal.csaw.io", 8043))
  
  bestCandidate = None
  bestLen = 10000
  worstLen = -1
  
  for candidate in alphabet:
    check = padding + candidate + known_flag + padding
    line(sock)
    sock.sendall(check + "\n")
    result = line(sock)
    
    # the length is the ASCII character at the end of the line
    resultLen = ord(result[-1])
    
    # update best and worst results
    if resultLen < bestLen:
      bestLen = resultLen
      bestCandidate = candidate
    worstLen = max(worstLen, resultLen)
  
  if worstLen == bestLen:
    print "done!"
    break
  
  known_flag = bestCandidate + known_flag
  print known_flag
