import re
import socket

def solve(s):
  eqSplit = s.split(" = ")
  result = int(eqSplit[1])
  div = 1
  eq = eqSplit[0]
  ops = [
    [re.compile(r"\((\-?[0-9]+) \+ (\-?[0-9]+)\)"), lambda m: str(int(m.group(1)) + int(m.group(2)))],
    [re.compile(r"\((\-?[0-9]+) \- (\-?[0-9]+)\)"), lambda m: str(int(m.group(1)) - int(m.group(2)))],
    [re.compile(r"\((\-?[0-9]+) \* (\-?[0-9]+)\)"), lambda m: str(int(m.group(1)) * int(m.group(2)))]
  ]
  
  def log():
    print '%s = %s / %s' % (eq, result, div)
    
  log()
  changed = True
  while changed:
    changed = False
    for o in ops:
      match = o[0].search(eq)
      if match is not None:
        span = match.span()
        eq = eq[:span[0]] + o[1](match) + eq[span[1]:]
        changed = True
        log()
  
  alg = [
    [re.compile(r" \- (\-?[0-9]+)$"), lambda m: (result + int(m.group(1)) * div, div)],
    [re.compile(r" \+ (\-?[0-9]+)$"), lambda m: (result - int(m.group(1)) * div, div)],
    [re.compile(r" \* (\-?[0-9]+)$"), lambda m: (result, div * int(m.group(1)))],
    [re.compile(r"^(\-?[0-9]+) \- "), lambda m: (-result + int(m.group(1)) * div, div)],
    [re.compile(r"^(\-?[0-9]+) \+ "), lambda m: (result - int(m.group(1)) * div, div)],
    [re.compile(r"^(\-?[0-9]+) \* "), lambda m: (result, div * int(m.group(1)))],
  ]
  
  changed = True
  while changed:
    changed = False
    for o in alg:
      match = o[0].search(eq)
      if match is not None:
        span = match.span()
        result, div = o[1](match)
        eq = eq[:span[0]] + eq[span[1]:]
        changed = True
        if eq == "X":
          changed = False
          break
        else:
          eq = eq[1:-1]
        log()
  
  if result == 0:
    return 0
  return (result + 0.) / div

# print solve("((((1 - 5) + (X - 15)) * ((18 + 2) + (11 + 3))) - (((4 + 8) * (3 * 3)) * ((2 * 5) * (13 - 9)))) - ((((8 - 14) - (11 - 6)) - ((14 + 12) + (13 * 15))) - (((9 - 1) - (3 * 9)) * ((5 * 4) * (19 + 4)))) = -13338")

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("misc.chal.csaw.io", 9002))

def line(sock):
  buf = ""
  while True:
    c = sock.recv(1)
    if c == "\n":
      return buf
    buf += c

# skip header
for i in range(7):
  line(sock)

while True:
  problem = line(sock)
  print problem
  if "X" not in problem or " = " not in problem:
    print "not an equation!"
    while True:
      print line(sock)
  sock.sendall(str(solve(problem)) + "\n")
  print(line(sock))
