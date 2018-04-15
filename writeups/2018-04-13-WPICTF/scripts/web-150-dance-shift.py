#!/usr/bin/env python
import base64, string
flag = "E1KSn2SSktOcG2AeV3WdUQAoj24fm19xVGmomMSoH3SuHEAuG2WxHDuSIF5wIGW9MZx="
upper = string.ascii_uppercase
lower = string.ascii_lowercase
for key in range(1, 26):
    shift = string.maketrans(
        upper + lower,
        upper[key:] + upper[:key] + lower[key:] + lower[:key])
    print key, base64.b64decode(string.translate(flag, shift))
