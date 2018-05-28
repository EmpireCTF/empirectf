#!/usr/bin/env python3

holes = [257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373]
res = [222, 203, 33, 135, 203, 62, 227, 82, 239, 82, 11, 220, 74, 92, 8, 308, 195, 165, 87, 4]

def solver(depth, holes, res):
    for i in range(len(holes)):
        print("a[%d] = _ * %d + %d".format(depth, holes[i], res[i]))
    print("---")
    if len(holes) == 1:
        return res[0]
    subholes = []
    subres = []
    for i in range(1, len(holes)):
        flag = 0 + res[0]
        pos = 0
        while pos < 1000:
            if (flag - res[i]) % holes[i] == 0:
                subholes.append(holes[i])
                subres.append(pos)
                break
            flag += holes[0]
            pos += 1
        else:
            print("no solution at depth %d!".format(depth))
    return solver(depth + 1, subholes, subres) * holes[0] + res[0]

print(bytes.fromhex(hex(solver(0, holes, res))[2:]))
