import gmpy2

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

flag_pieces = []
for c in coeffs:
  flag_piece = int(gmpy2.invert(c, 0x100000000))
  flag_pieces.append(flag_piece.to_bytes(4, "little").decode("utf-8"))

print("".join(flag_pieces))
