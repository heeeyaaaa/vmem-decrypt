#!/usr/bin/env python3
"""
vmem-inspect -- read-only structure inspector for VMware encobj files.

Dumps the plaintext header and locates the encrypted-payload / footer boundaries
of a .vmem / .vmsn / .vmss / .nvram, WITHOUT decrypting anything. Useful to confirm
a file really is an encobj container and to read its layout fields before decrypting.
"""

import argparse
import math
import os
import struct
import sys

MAGIC = 0x8943DD9E


def shannon(data):
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def dump_words(data, base, label):
    print(f"\n=== {label} (file offset 0x{base:x}) ===")
    pad = (-len(data)) % 16
    buf = data + b"\x00" * pad
    for row in range(0, len(buf), 16):
        words = struct.unpack_from("<IIII", buf, row)
        chunk = data[row:row + 16]
        ascii_repr = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
        print(f"0x{base + row:08x}  " + " ".join(f"{w:08x}" for w in words)
              + f"  |{ascii_repr}|")


def main():
    ap = argparse.ArgumentParser(description="Inspect a VMware encobj file (no decryption).")
    ap.add_argument("path")
    ap.add_argument("--tail-bytes", type=int, default=65536)
    args = ap.parse_args()
    if not os.path.isfile(args.path):
        sys.exit(f"not a file: {args.path}")

    size = os.path.getsize(args.path)
    with open(args.path, "rb") as f:
        head = f.read(min(512, size))
        magic = struct.unpack_from("<I", head, 0)[0]
        print(f"file size : {size} bytes ({size / 1024**3:.3f} GiB)")
        print(f"magic     : 0x{magic:08x} "
              + ("[OK encobj]" if magic == MAGIC else f"[expected 0x{MAGIC:08x}]"))
        if magic == MAGIC:
            print("header fields:")
            print(f"  version       @0x04 = {struct.unpack_from('<I', head, 4)[0]}")
            print(f"  data_per_page @0x08 = {struct.unpack_from('<I', head, 8)[0]}")
            print(f"  iv_size       @0x0c = {struct.unpack_from('<I', head, 12)[0]}")
            print(f"  mac_size      @0x10 = {struct.unpack_from('<I', head, 16)[0]}")
            print(f"  logical_size  @0x18 = {struct.unpack_from('<Q', head, 24)[0]}")
        dump_words(head, 0, "first 512 bytes")

        tail_n = min(args.tail_bytes, size)
        f.seek(size - tail_n)
        tail = f.read(tail_n)
    last_nz = next((i for i in range(len(tail) - 1, -1, -1) if tail[i]), -1)
    if last_nz >= 0:
        abs_nz = size - tail_n + last_nz
        print(f"\nlast non-zero byte @0x{abs_nz:x}; trailing zero padding "
              f"= {size - 1 - abs_nz} bytes")
        pre = tail[max(0, last_nz - 4096):last_nz + 1]
        print(f"entropy of ~{len(pre)} bytes before padding: {shannon(pre):.3f} bits/byte")

    print("\nalignment check (encobj payload starts at 0x1000):")
    payload = size - 0x1000
    for unit in (512, 4096):
        q, r = divmod(payload, unit)
        print(f"  (size-0x1000) / {unit} = {q}{' exact' if r == 0 else f' remainder {r}'}")


if __name__ == "__main__":
    main()
