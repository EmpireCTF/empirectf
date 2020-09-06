import gmpy2

flag = "CTF{y0u_c4n_k3ep_y0u?_m4gic_1_h4Ue_laser_b3ams!}"

coeffs = [
  0x0271986B,
  0xA64239C9,
  0x271DED4B,
  0x01186143,
  0xC0FA229F,
  0x690E10BF,
  0x28DCA257,
  0x16C699D1,
  0x55A56FFD,
  0x7EB870A1,
  0xC5C9799F,
  0x2F838E65
]

I64 = 0xFFFFFFFFFFFFFFFF

def bezout(a, b):
  if a == 0:
    return [0, 1]
  r = bezout(b % a, a)
  return [(r[1] - (((b // a) * r[0]) & I64)) & I64, r[0]]

for i in range(12):
  piece = int.from_bytes(flag[i * 4:(i + 1) * 4].encode("utf-8"), "little")
  c = bezout(piece, 0x100000000)
  print(hex(coeffs[i]), hex(c[0]))
