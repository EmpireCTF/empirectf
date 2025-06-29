import unicodedata

# find equivalent characters
def offsets(c):
    valid = []
    for offset in range(4):
        try:
            x = [0] * offset + list(chr(c).encode())
        except:
            continue
        check = list([(i % 2 != j % 2) * (j % ((i % 4) + 1) == 0) for i, j in enumerate(x)])
        if all(check[offset:]):
            valid.append(offset)
    return valid

eq_to = {}
for c in range(32, 128):
    eq_to[c] = []

for c in range(32, 0x10FFFF):
    try:
        uc = chr(c)
    except:
        continue
    norm_to = unicodedata.normalize("NFKC", uc)
    if len(norm_to) == 1 and ord(norm_to[0]) in eq_to:
        valid = offsets(c)
        if valid:
            eq_to[ord(norm_to[0])].append((c, valid))
            ch = ("000000"+hex(c)[2:])[-6:]
            name = unicodedata.name(chr(c), "???")
            utflen = len(uc.encode())
            # print(f"char {ch} ({name}) is {utflen} bytes long and normalises to {norm_to}, valid at offsets: {valid}")

# look for accepted builtins
builtins = [
    # https://docs.python.org/3/library/functions.html#built-in-functions
    "abs", "aiter", "all", "anext", "any", "ascii",
    "bin", "bool", "breakpoint", "bytearray", "bytes",
    "callable", "chr", "classmethod", "compile", "complex",
    "delattr", "dict", "dir", "divmod",
    "enumerate", "eval", "exec",
    "filter", "float", "format", "frozenset",
    "getattr", "globals",
    "hasattr", "hash", "help", "hex",
    "id", "input", "int", "isinstance", "issubclass", "iter",
    "len", "list", "locals",
    "map", "max", "memoryview", "min",
    "next",
    "object", "oct", "open", "ord",
    "pow", "print", "property",
    "range", "repr", "reversed", "round",
    "set", "setattr", "slice", "sorted", "staticmethod", "str", "sum", "super",
    "tuple", "type",
    "vars",
    "zip",
    "__import__",
    # other useful identifiers
    "read",
    "write",
]

for b in builtins:
    valid = []
    def check(offset, base, remaining):
        if len(remaining) > 0:
            for (eq, _) in eq_to[remaining[0]]:
                check(offset, base + list(chr(eq).encode()), remaining[1:])
        else:
            chall = list([(i % 2 != j % 2) * (j % ((i % 4) + 1) == 0) for i, j in enumerate(base)])
            if all(chall[offset:]):
                code = bytes(base[offset:]).decode()
                valid.append((offset, code))
    for offset in range(4):
        check(offset, [0] * offset, list(b.encode()))
    if valid:
        print(f"{b}: {valid}")
