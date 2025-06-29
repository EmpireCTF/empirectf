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
    # additional keywords and useful identifiers
    "__",
    "for",
    "if",
    "def",
    "class",
    "pass",
    "while",
    "in",
    "read",
    "with",
    "gi_frame",
    "ag_frame",
    "_getframe",
    "read",
    "write",
]

for b in builtins:
    for offset in range(4):
        x = [0] * offset + list(b.encode())
        check = list([(i % 2 != j % 2) * (j % ((i % 4) + 1) == 0) for i, j in enumerate(x)])
        if all(check[offset:]):
            print(f"i % 4 == {offset}: {b}")
