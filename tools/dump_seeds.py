#!/usr/bin/env python3
import argparse
import glob
from dataclasses import dataclass
from pathlib import Path

MAGIC = bytes.fromhex("B0 0B")

@dataclass
class Rec:
    off: int
    t: int
    flags: int
    length: int
    value: bytes
    ok: bool
    note: str = ""

def u16le(b: bytes) -> int:
    return b[0] | (b[1] << 8)

def is_printable_ascii(b: bytes) -> bool:
    # allow common whitespace
    for x in b:
        if x in (9, 10, 13):  # \t \n \r
            continue
        if x < 0x20 or x > 0x7E:
            return False
    return True

def hexdump(b: bytes, max_len: int = 64) -> str:
    if len(b) <= max_len:
        return b.hex(" ")
    return b[:max_len].hex(" ") + f" ... (+{len(b)-max_len} bytes)"

def find_magic_positions(b: bytes, magic: bytes = MAGIC) -> list[int]:
    pos = []
    i = 0
    while True:
        j = b.find(magic, i)
        if j == -1:
            break
        pos.append(j)
        i = j + 1
    return pos

def parse_stream(buf: bytes, *, max_depth: int, depth: int = 0, max_records: int = 100000) -> list[Rec]:
    recs: list[Rec] = []
    off = 0
    steps = 0

    while off + 4 <= len(buf) and len(recs) < max_records:
        steps += 1
        if steps > len(buf) * 10:  # simple guardrail for sliding loops
            recs.append(Rec(off=off, t=0, flags=0, length=0, value=b"", ok=False, note="step guardrail hit"))
            break

        t = buf[off]
        flags = buf[off + 1]
        length = u16le(buf[off + 2:off + 4])

        end = off + 4 + length
        if end <= len(buf):
            value = buf[off + 4:end]
            recs.append(Rec(off=off, t=t, flags=flags, length=length, value=value, ok=True))
            off = end
        else:
            # sliding recovery: advance by 1 byte, record the failed header for visibility
            recs.append(
                Rec(
                    off=off,
                    t=t,
                    flags=flags,
                    length=length,
                    value=b"",
                    ok=False,
                    note=f"truncated record: need {4+length} bytes, have {len(buf)-off}",
                )
            )
            off += 1

    if off < len(buf) and off + 4 > len(buf):
        # leftover tail smaller than header
        recs.append(Rec(off=off, t=0, flags=0, length=0, value=buf[off:], ok=False, note="tail < 4 bytes"))

    return recs

def render_rec(rec: Rec, *, depth: int) -> str:
    indent = "  " * depth
    if rec.ok:
        base = f"{indent}- off={rec.off} type=0x{rec.t:02X} flags=0x{rec.flags:02X} len={rec.length}"
        if rec.t == 0x01:
            if is_printable_ascii(rec.value):
                base += f' value_ascii="{rec.value.decode("ascii", "replace")}"'
            else:
                base += f" value_hex={hexdump(rec.value)}"
        elif rec.t == 0x02:
            base += f" value_hex={hexdump(rec.value)}"
        elif rec.t == 0x10:
            pos = find_magic_positions(rec.value)
            base += f" magic_pos={pos} value_hex={hexdump(rec.value)}"
        elif rec.t == 0x03:
            base += f" (nested stream, {rec.length} bytes)"
        else:
            base += f" value_hex={hexdump(rec.value)}"
        return base
    else:
        if rec.note == "tail < 4 bytes":
            return f"{indent}- off={rec.off} [TAIL] {hexdump(rec.value, max_len=64)}"
        return f"{indent}- off={rec.off} [BAD] type=0x{rec.t:02X} flags=0x{rec.flags:02X} len={rec.length} note={rec.note}"

def dump_file(path: Path, *, max_depth: int) -> None:
    data = path.read_bytes()
    print(f"\n== {path} ({len(data)} bytes) ==")

    def walk(buf: bytes, depth: int) -> None:
        recs = parse_stream(buf, max_depth=max_depth, depth=depth)
        for r in recs:
            print(render_rec(r, depth=depth))
            if r.ok and r.t == 0x03 and depth + 1 <= max_depth:
                walk(r.value, depth + 1)

    walk(data, 0)

def main() -> None:
    ap = argparse.ArgumentParser(description="Dump/decode TLV seed corpus.")
    ap.add_argument("paths", nargs="*", default=["corpus/*.bin"], help="Files/globs (default: corpus/*.bin)")
    ap.add_argument("--max-depth", type=int, default=4, help="Max nested TLV depth to render (default: 4)")
    args = ap.parse_args()

    files: list[str] = []
    for p in args.paths:
        files.extend(glob.glob(p))
    files = sorted(set(files))

    if not files:
        raise SystemExit("No input files matched.")

    for f in files:
        dump_file(Path(f), max_depth=args.max_depth)

if __name__ == "__main__":
    main()