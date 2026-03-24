from __future__ import annotations

from dataclasses import dataclass
import random
from typing import Optional

# Helpful tokens for reaching common branches in your target.
TOKENS = [
    b"CMD:",
    b"CRASH",
    bytes.fromhex("B0 0B"),
    b"AAAA",  # 0x41414141 in ASCII
]

TYPE_HINTS = [0x01, 0x02, 0x03, 0x10]
F_UNSAFE = 0x80

DEFAULT_WEIGHTS = {
    "bitflip": 10.0,
    "byteflip": 8.0,
    "overwrite": 9.0,
    "insert": 9.0,
    "delete": 8.0,
    "token": 8.0,
    "tlv_flip_type": 7.0,
    "tlv_flip_flags": 8.0,
    "tlv_adjust_len": 7.0,
    "tlv_dup_record": 6.0,
    "tlv_drop_record": 5.0,
    "tlv_insert_template": 7.0,
    "tlv_wrap_record_t03": 8.0,
    "tlv_insert_t03_chain": 8.0,
    "tlv_promote_t03_unsafe": 7.0,
    # Targeted convergence operators
    "tlv_nudge_t01_len": 6.0,
    "tlv_nudge_t02_magic": 6.0,
}


@dataclass
class TlvRecord:
    start: int
    end: int
    value_start: int
    value_end: int
    rec_type: int
    flags: int
    length: int

def clamp_size(b: bytearray, max_size: int) -> bytearray:
    if len(b) <= max_size:
        return b
    del b[max_size:]
    return b


def _rand_bytes(rnd: random.Random, n: int) -> bytes:
    if n <= 0:
        return b""
    if hasattr(rnd, "randbytes"):
        return rnd.randbytes(n)
    return bytes(rnd.randrange(256) for _ in range(n))


def _read_u16le(data: bytes | bytearray, off: int) -> int:
    return data[off] | (data[off + 1] << 8)


def _write_u16le(data: bytearray, off: int, value: int) -> None:
    v = max(0, min(0xFFFF, value))
    data[off] = v & 0xFF
    data[off + 1] = (v >> 8) & 0xFF


def _build_tlv(rec_type: int, flags: int, value: bytes) -> bytes:
    length = len(value)
    return bytes((rec_type & 0xFF, flags & 0xFF, length & 0xFF, (length >> 8) & 0xFF)) + value


def _find_tlv_records(data: bytes | bytearray) -> list[TlvRecord]:
    records: list[TlvRecord] = []
    size = len(data)
    off = 0

    # Follow the same sliding recovery style as target parser.
    while off + 4 <= size:
        rec_type = data[off]
        flags = data[off + 1]
        length = _read_u16le(data, off + 2)
        end = off + 4 + length

        if end <= size:
            records.append(
                TlvRecord(
                    start=off,
                    end=end,
                    value_start=off + 4,
                    value_end=end,
                    rec_type=rec_type,
                    flags=flags,
                    length=length,
                )
            )
            off = end
        else:
            off += 1

    return records


def _template_record(rnd: random.Random) -> bytes:
    t = rnd.choice(["t01", "t02", "t10", "t03", "t01_nearmiss", "t02_nearmiss"])

    if t == "t01":
        body = b"CMD:CRASH" + _rand_bytes(rnd, rnd.randrange(32, 48))
        return _build_tlv(0x01, F_UNSAFE, body)

    if t == "t02":
        first = b"AAAA"
        tail = _rand_bytes(rnd, 24)  # total len=28 => count=7
        return _build_tlv(0x02, F_UNSAFE, first + tail)

    if t == "t10":
        # Keep magic close to end to stress OOB read condition.
        body = _rand_bytes(rnd, rnd.randrange(0, 2)) + bytes.fromhex("B0 0B") + _rand_bytes(rnd, rnd.randrange(0, 2))
        return _build_tlv(0x10, F_UNSAFE, body)

    if t == "t03":
        # Nested TLV for type 0x03 stress path.
        inner = _build_tlv(0x01, 0x00, b"CMD:PING")
        middle = _build_tlv(0x03, 0x00, inner)
        outer = _build_tlv(0x03, F_UNSAFE, middle)
        return outer

    if t == "t01_nearmiss":
        # T01 near the crash threshold (len < 40); tlv_nudge_t01_len will push it over.
        body = b"CMD:CRASH" + _rand_bytes(rnd, rnd.randrange(20, 31))  # len 29~40
        return _build_tlv(0x01, F_UNSAFE, body)

    # t02_nearmiss: AAAA prefix but count != 7 (len != 28); tlv_nudge_t02_magic corrects it.
    first = b"AAAA"
    tail = _rand_bytes(rnd, rnd.randrange(8, 24))  # len 12~28, count != 7
    return _build_tlv(0x02, F_UNSAFE, first + tail)


def _build_t03_chain(depth: int, rnd: random.Random) -> bytes:
    d = max(1, min(depth, 6))
    payload = _build_tlv(0x01, 0x00, b"CMD:PING")
    for i in range(d):
        # The innermost type-0x03 gets F_UNSAFE to better target nested-stress path.
        flags = F_UNSAFE if i == 0 else (F_UNSAFE if rnd.random() < 0.25 else 0x00)
        payload = _build_tlv(0x03, flags, payload)
    return payload


def _shape_walk(data: bytes, *, depth: int, max_depth: int) -> tuple[int, int, dict[int, int], int]:
    records = _find_tlv_records(data)
    max_seen_depth = depth
    unsafe_count = 0
    total = 0
    type_counts: dict[int, int] = {}

    for rec in records:
        total += 1
        type_counts[rec.rec_type] = type_counts.get(rec.rec_type, 0) + 1
        if rec.flags & F_UNSAFE:
            unsafe_count += 1
        if rec.rec_type == 0x03 and depth < max_depth:
            child = data[rec.value_start : rec.value_end]
            c_depth, c_unsafe, c_types, c_total = _shape_walk(
                child,
                depth=depth + 1,
                max_depth=max_depth,
            )
            max_seen_depth = max(max_seen_depth, c_depth)
            unsafe_count += c_unsafe
            total += c_total
            for t, c in c_types.items():
                type_counts[t] = type_counts.get(t, 0) + c

    return max_seen_depth, unsafe_count, type_counts, total


def tlv_shape_signature(data: bytes) -> str:
    if not data:
        return "shape:empty"
    depth, unsafe_count, type_counts, total = _shape_walk(data, depth=0, max_depth=8)
    return (
        f"shape:r{total}:d{depth}:u{unsafe_count}:"
        f"t01={type_counts.get(0x01,0)}:"
        f"t02={type_counts.get(0x02,0)}:"
        f"t03={type_counts.get(0x03,0)}:"
        f"t10={type_counts.get(0x10,0)}"
    )


def _weighted_choice(weights: dict[str, float], rnd: random.Random) -> str:
    names = list(weights.keys())
    vals = [max(0.0001, weights[n]) for n in names]
    return rnd.choices(names, weights=vals, k=1)[0]


def mutate_once(data: bytes, rnd: random.Random, *, max_size: int) -> bytes:
    out, _ = mutate_once_with_op(data, rnd, max_size=max_size)
    return out


def mutate_once_with_op(
    data: bytes,
    rnd: random.Random,
    *,
    max_size: int,
    op: Optional[str] = None,
    t03_depth_target: Optional[int] = None,
) -> tuple[bytes, str]:
    b = bytearray(data)

    if len(b) == 0:
        b.extend(_rand_bytes(rnd, 1))

    records = _find_tlv_records(b)

    chosen_op = op or rnd.choice(list(DEFAULT_WEIGHTS.keys()))

    if chosen_op == "bitflip":
        i = rnd.randrange(len(b))
        bit = 1 << rnd.randrange(8)
        b[i] ^= bit

    elif chosen_op == "byteflip":
        i = rnd.randrange(len(b))
        b[i] ^= 0xFF

    elif chosen_op == "overwrite":
        i = rnd.randrange(len(b))
        n = rnd.randrange(1, 9)
        for k in range(n):
            if i + k >= len(b):
                break
            b[i + k] = rnd.randrange(256)

    elif chosen_op == "insert":
        i = rnd.randrange(len(b) + 1)
        n = rnd.randrange(1, 9)
        payload = _rand_bytes(rnd, n)
        b[i:i] = payload

    elif chosen_op == "delete":
        if len(b) > 1:
            i = rnd.randrange(len(b))
            n = rnd.randrange(1, min(9, len(b) - i) + 1)
            del b[i : i + n]

    elif chosen_op == "token":
        tok = rnd.choice(TOKENS)
        i = rnd.randrange(len(b) + 1)
        b[i:i] = tok

    elif chosen_op == "tlv_flip_type":
        if records:
            rec = rnd.choice(records)
            b[rec.start] = rnd.choice(TYPE_HINTS)

    elif chosen_op == "tlv_flip_flags":
        if records:
            rec = rnd.choice(records)
            if rnd.random() < 0.7:
                b[rec.start + 1] ^= F_UNSAFE
            else:
                b[rec.start + 1] ^= 1 << rnd.randrange(8)

    elif chosen_op == "tlv_adjust_len":
        if records:
            rec = rnd.choice(records)
            candidates = [
                0,
                1,
                3,
                4,
                7,
                8,
                27,
                28,
                29,
                39,
                40,
                41,
                max(0, rec.length - 1),
                rec.length,
                rec.length + 1,
            ]
            _write_u16le(b, rec.start + 2, rnd.choice(candidates))

    elif chosen_op == "tlv_dup_record":
        if records:
            rec = rnd.choice(records)
            i = rnd.randrange(len(b) + 1)
            b[i:i] = b[rec.start : rec.end]

    elif chosen_op == "tlv_drop_record":
        if records:
            rec = rnd.choice(records)
            del b[rec.start : rec.end]

    elif chosen_op == "tlv_insert_template":
        i = rnd.randrange(len(b) + 1)
        b[i:i] = _template_record(rnd)

    elif chosen_op == "tlv_wrap_record_t03":
        if records:
            rec = rnd.choice(records)
            wrapped = _build_tlv(0x03, F_UNSAFE if rnd.random() < 0.7 else 0x00, bytes(b[rec.start : rec.end]))
            b[rec.start : rec.end] = wrapped

    elif chosen_op == "tlv_insert_t03_chain":
        i = rnd.randrange(len(b) + 1)
        depth = t03_depth_target if t03_depth_target is not None else rnd.choice([2, 3, 4])
        b[i:i] = _build_t03_chain(depth, rnd)

    elif chosen_op == "tlv_promote_t03_unsafe":
        changed = False
        for rec in records:
            if rec.rec_type == 0x03 and (b[rec.start + 1] & F_UNSAFE) == 0:
                b[rec.start + 1] |= F_UNSAFE
                changed = True
                if rnd.random() < 0.6:
                    break
        if not changed and records:
            rec = rnd.choice(records)
            b[rec.start + 1] |= F_UNSAFE

    elif chosen_op == "tlv_nudge_t01_len":
        # Nudge T01 F_UNSAFE record len toward the crash threshold (40).
        # If len < 40, increment by 1-3 and pad value with 0x41 bytes.
        # Leaves records that already meet or exceed threshold untouched.
        for rec in records:
            if rec.rec_type == 0x01 and (rec.flags & F_UNSAFE) and rec.length < 40:
                delta = rnd.randint(1, min(3, 40 - rec.length))
                new_len = rec.length + delta
                _write_u16le(b, rec.start + 2, new_len)
                # Append padding bytes at value end so actual data matches len field
                b[rec.value_end:rec.value_end] = bytes([0x41] * delta)
                break

    elif chosen_op == "tlv_nudge_t02_magic":
        # Converge T02 F_UNSAFE record toward T02_HEAP_OOB trigger conditions:
        #   count == 7 (len == 28) and value[0:4] == 0x41414141
        for rec in records:
            if rec.rec_type == 0x02 and (rec.flags & F_UNSAFE):
                # Fix count=7 (len=28) if needed
                if rec.length != 28:
                    _write_u16le(b, rec.start + 2, 28)
                    # Truncate or extend value area to 28 bytes
                    cur_val = bytes(b[rec.value_start:rec.value_end])
                    new_val = (cur_val + bytes(28))[:28]
                    b[rec.value_start:rec.value_end] = new_val
                # Set first 4 bytes to AAAA (0x41414141)
                vs = rec.value_start
                if vs + 4 <= len(b):
                    b[vs:vs + 4] = b"AAAA"
                break

    else:
        # Unknown op: keep input unchanged but report op name.
        pass

    return bytes(clamp_size(b, max_size)), chosen_op

def mutate(data: bytes, rnd: random.Random, *, rounds: int, max_size: int) -> bytes:
    out, _ = mutate_with_trace(data, rnd, rounds=rounds, max_size=max_size)
    return out


def mutate_with_trace(data: bytes, rnd: random.Random, *, rounds: int, max_size: int) -> tuple[bytes, list[str]]:
    out = data
    ops: list[str] = []
    for _ in range(max(1, rounds)):
        out, used = mutate_once_with_op(out, rnd, max_size=max_size)
        ops.append(used)
    return out, ops


class AdaptiveMutator:
    def __init__(self, rnd: random.Random, *, max_size: int):
        self.rnd = rnd
        self.max_size = max_size
        self.weights: dict[str, float] = dict(DEFAULT_WEIGHTS)
        self.t03_depth_target = 2
        self.non_novel_streak = 0

    def mutate(self, data: bytes, *, rounds: int) -> tuple[bytes, list[str]]:
        out = data
        trace: list[str] = []
        for _ in range(max(1, rounds)):
            eff = dict(self.weights)
            if self.non_novel_streak >= 100:
                eff["tlv_insert_t03_chain"] = eff.get("tlv_insert_t03_chain", 1.0) * 2.0
                eff["tlv_wrap_record_t03"] = eff.get("tlv_wrap_record_t03", 1.0) * 1.7
                eff["tlv_promote_t03_unsafe"] = eff.get("tlv_promote_t03_unsafe", 1.0) * 1.5
            op = _weighted_choice(eff, self.rnd)
            out, used = mutate_once_with_op(
                out,
                self.rnd,
                max_size=self.max_size,
                op=op,
                t03_depth_target=self.t03_depth_target,
            )
            trace.append(used)
        return out, trace

    def feedback(self, op_trace: list[str], signal: str) -> None:
        """Update weights based on feedback signal.
        
        signal:
        - 'new_key': new dedup key discovered (novel bug path)
        - 'new_cov': new execution/input-shape signature discovered
        - 'existing_key': crash with known dedup key
        - 'no_crash': input generated but no crash
        """
        if not op_trace:
            return
        seen = set(op_trace)
        if signal == "new_key":
            self.non_novel_streak = 0
            self.t03_depth_target = min(4, self.t03_depth_target + 1)
            for op in seen:
                cur = self.weights.get(op, 1.0)
                self.weights[op] = min(cur * 1.12 + 0.1, 50.0)
            return

        if signal == "new_cov":
            self.non_novel_streak = max(0, self.non_novel_streak - 3)
            for op in seen:
                cur = self.weights.get(op, 1.0)
                self.weights[op] = min(cur * 1.03 + 0.02, 50.0)
            return

        if signal == "existing_key":
            # Crash produced but already in global dedup — still a positive signal.
            # Rewarding operators that reach any crash prevents AdaptiveMutator from
            # treating known-type crashes identically to no-progress inputs, which is
            # especially important when the dedup index is pre-populated.
            self.non_novel_streak = max(0, self.non_novel_streak - 1)
            for op in seen:
                cur = self.weights.get(op, 1.0)
                self.weights[op] = min(cur * 1.01 + 0.01, 50.0)
            return

        self.non_novel_streak += 1  # no_crash only
        if self.non_novel_streak % 120 == 0:
            self.t03_depth_target = min(4, self.t03_depth_target + 1)


class UniformMutator:
    def __init__(self, rnd: random.Random, *, max_size: int):
        self.rnd = rnd
        self.max_size = max_size
        self.ops = list(DEFAULT_WEIGHTS.keys())

    def mutate(self, data: bytes, *, rounds: int) -> tuple[bytes, list[str]]:
        out = data
        trace: list[str] = []
        for _ in range(max(1, rounds)):
            op = self.rnd.choice(self.ops)
            out, used = mutate_once_with_op(out, self.rnd, max_size=self.max_size, op=op)
            trace.append(used)
        return out, trace

    def feedback(self, op_trace: list[str], signal: str) -> None:
        # Baseline mutator intentionally ignores feedback.
        _ = (op_trace, signal)