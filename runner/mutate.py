from __future__ import annotations

import os
import random

# Helpful tokens for reaching common branches in your target.
TOKENS = [
    b"CMD:",
    b"CRASH",
    bytes.fromhex("B0 0B"),
    b"AAAA",  # 0x41414141 in ASCII
]

def clamp_size(b: bytearray, max_size: int) -> bytearray:
    if len(b) <= max_size:
        return b
    del b[max_size:]
    return b

def mutate_once(data: bytes, rnd: random.Random, *, max_size: int) -> bytes:
    b = bytearray(data)

    if len(b) == 0:
        b.extend(rnd.randbytes(1) if hasattr(rnd, "randbytes") else bytes([rnd.randrange(256)]))

    op = rnd.choice(["bitflip", "byteflip", "overwrite", "insert", "delete", "token"])

    if op == "bitflip":
        i = rnd.randrange(len(b))
        bit = 1 << rnd.randrange(8)
        b[i] ^= bit

    elif op == "byteflip":
        i = rnd.randrange(len(b))
        b[i] ^= 0xFF

    elif op == "overwrite":
        i = rnd.randrange(len(b))
        n = rnd.randrange(1, 9)
        for k in range(n):
            if i + k >= len(b):
                break
            b[i + k] = rnd.randrange(256)

    elif op == "insert":
        i = rnd.randrange(len(b) + 1)
        n = rnd.randrange(1, 9)
        payload = os.urandom(n)
        b[i:i] = payload

    elif op == "delete":
        if len(b) > 1:
            i = rnd.randrange(len(b))
            n = rnd.randrange(1, min(9, len(b) - i) + 1)
            del b[i : i + n]

    elif op == "token":
        tok = rnd.choice(TOKENS)
        i = rnd.randrange(len(b) + 1)
        b[i:i] = tok

    return bytes(clamp_size(b, max_size))

def mutate(data: bytes, rnd: random.Random, *, rounds: int, max_size: int) -> bytes:
    out = data
    for _ in range(max(1, rounds)):
        out = mutate_once(out, rnd, max_size=max_size)
    return out