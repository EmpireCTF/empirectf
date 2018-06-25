#!/usr/bin/env python3

def gcd(x, y):
   while(y):
       x, y = y, x % y
   return x

def lcm(x, y):
   return (x * y) // gcd(x, y)

def iroot(k, n):
    u, s = n, n + 1
    while u < s:
        s = u
        t = (k - 1) * s + n // pow(s, k - 1)
        u = t // k
    return s

def multiplicative_inverse(e, phi):
    d = 0
    x1 = 0
    x2 = 1
    y1 = 1
    temp_phi = phi
    
    while e > 0:
        temp1 = temp_phi // e
        temp2 = temp_phi - temp1 * e
        temp_phi = e
        e = temp2
        
        x = x2 - temp1 * x1
        y = d - temp1 * y1
        
        x2 = x1
        x1 = x
        d = y1
        y1 = y
    
    if temp_phi == 1:
        return d + phi
    return None

if __name__ == "__main__":
    # problem statement
    e = 33
    cipher = 1926041757553905692219721422025224638913707
    n = 3436415358139016629092568198745009225773259
    print("x ** {} = {} mod {}".format(e, cipher, n))
    
    # factorise n
    p, q = -1, -1
    for i in range(2, 10000):
        if n % i == 0:
            p = i
            q = n // i
            break
    else:
        raise Exception("cannot factorise n!")
    print("n = {} * {}".format(p, q))
    
    # factorise e
    e1, e2 = -1, -1
    for i in range(2, 10000):
        if e % i == 0:
            e1 = i
            e2 = e // i
            break
    else:
        raise Exception("cannot factorise e!")
    print("e = {} * {}".format(e1, e2))
    
    # find totient
    phi = lcm(p - 1, q - 1)
    print("phi = {}".format(phi))
    
    # find modular multiplicative inverse
    d1 = multiplicative_inverse(e1, phi)
    d2 = multiplicative_inverse(e2, phi)
    if d1 == None and d2 == None:
        raise Exception("cannot find a multiplicative inverse")
    if d1 == None:
        d2, d1 = d1, d2
        e2, e1 = e1, e2
    print("{}^-1 mod {} = {}".format(e1, n, d1))
    
    # partially decrypt cipher
    power = pow(cipher, d1, n)
    
    # find an exact power and its root
    for i in range(1000000):
        solution = iroot(e2, power)
        if solution ** e2 == power:
            print("exact power = {} + n * {}".format(cipher, i))
            break
        power += n
    else:
        raise Exception("cannot find exact root")
    print("{} * 33 = {} mod {}".format(solution, cipher, n))
