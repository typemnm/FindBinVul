#!/usr/bin/env python3
import argparse
from pathlib import Path

def le16(n: int) -> bytes:
    return bytes((n & 0xFF, (n >> 8) & 0xFF))

def tlv(t: int, flags: int, value: bytes) -> bytes:
    if not (0 <= t <= 0xFF and 0 <= flags <= 0xFF):
        raise ValueError("type/flags must fit in a byte")
    if len(value) > 0xFFFF:
        raise ValueError("value too long for 2-byte len")
    return bytes([t, flags]) + le16(len(value)) + value

def write_seed(out_dir: Path, name: str, data: bytes) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / name
    path.write_bytes(data)
    print(f"Wrote {path} ({len(data)} bytes)")

def build_seeds() -> dict[str, bytes]:
    seed_01 = tlv(0x01, 0x00, b"A")
    seed_02 = tlv(0x01, 0x00, b"CMD:HELP")
    seed_03 = tlv(0x01, 0x01, b"CMD:  RUN  ")
    seed_04 = tlv(0x02, 0x00, (1).to_bytes(4, "little"))
    seed_05 = tlv(0x02, 0x01, (2).to_bytes(4, "little") + (1).to_bytes(4, "little"))
    seed_06 = tlv(0x10, 0x00, bytes.fromhex("00 B0 0B 03 41 42"))
    seed_07 = tlv(0x10, 0x03, bytes.fromhex("99 88 B0 0B 01 5A 00"))

    seed_08 = (
        tlv(0x01, 0x00, b"HELLO")
        + tlv(0x02, 0x00, (42).to_bytes(4, "little"))
        + tlv(0x10, 0x00, bytes.fromhex("00 B0 0B 02 4F 4B"))
    )

    inner_09 = tlv(0x01, 0x00, b"CMD:A")
    seed_09 = tlv(0x03, 0x00, inner_09)

    inner_most_10 = tlv(0x01, 0x00, b"CMD:PING")
    middle_10 = tlv(0x03, 0x00, inner_most_10)
    outer_10 = tlv(0x03, 0x00, middle_10)
    seed_10 = outer_10 + bytes.fromhex("DE AD BE EF")

    return {
        "seed_01.bin": seed_01,
        "seed_02.bin": seed_02,
        "seed_03.bin": seed_03,
        "seed_04.bin": seed_04,
        "seed_05.bin": seed_05,
        "seed_06.bin": seed_06,
        "seed_07.bin": seed_07,
        "seed_08.bin": seed_08,
        "seed_09.bin": seed_09,
        "seed_10.bin": seed_10,
    }

def main() -> None:
    ap = argparse.ArgumentParser(description="Generate TLV corpus seeds.")
    ap.add_argument("--out", default="corpus", help="Output directory (default: corpus)")
    args = ap.parse_args()

    out_dir = Path(args.out)
    seeds = build_seeds()
    for name, data in seeds.items():
        write_seed(out_dir, name, data)

    print(f"\nGenerated {len(seeds)} seeds in {out_dir.resolve()}")

if __name__ == "__main__":
    main()