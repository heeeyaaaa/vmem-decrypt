#!/usr/bin/env python3
"""
vmem-flatten -- expand a *decrypted* VMware checkpoint .vmem into a flat physical image.

The decrypted .vmem is a sequence of compressed blocks:

    struct block { u32 uncompressed_size; u32 0; u32 compressed_size; u32 0;
                   u8 stream[compressed_size]; }   // stream -> uncompressed_size bytes

Each block's `stream` is VMware's checkpoint LZ77 (reverse-engineered from vmware-vmx's
DumperFastInflate / fcn.007181c0). Grammar (zero-initialised back-reference window):

    first control byte F (F>>5 must be 0 or 1):
        literal run of (F & 0x1f) + 1 bytes
    then, per control byte C:
        C <= 0x1f : literal run of (C + 1) bytes
        C  > 0x1f : match
            length field lf = C >> 5
            if lf == 7:                                  # length escape
                acc = 6; repeat { b = next; acc += b } while b == 0xff
                length = 3 + acc
            else:
                length = lf + 2
            dlo = next byte
            if (C & 0x1f) == 0x1f and dlo == 0xff:        # distance escape
                eb1 = next; eb2 = next; dist = 0x2000 + (eb1<<8 | eb2)
            else:
                dist = ((C & 0x1f) << 8 | dlo) + 1
            copy `length` bytes from (out_pos - dist), zero if before start

Concatenating all blocks yields the flat physical image VMware/Volatility expect (paired
with the decrypted .vmsn, whose `memory` group maps file offsets to physical addresses).
"""

import argparse
import mmap
import os
import struct
import sys


def decompress_block(data, cp, out, out_size):
    """Decompress one block's LZ stream into bytearray `out`; return new cp."""
    end = len(out) + out_size
    F = data[cp]; cp += 1
    if (F >> 5) > 1:
        raise ValueError(f"bad first control byte 0x{F:02x} at 0x{cp-1:x}")
    n = (F & 0x1f) + 1
    out += data[cp:cp + n]; cp += n
    while len(out) < end:
        c = data[cp]; cp += 1
        if c <= 0x1f:                                   # literal run
            n = c + 1
            out += data[cp:cp + n]; cp += n
        else:                                           # match
            lf = c >> 5
            if lf == 7:                                 # length escape
                acc = 6
                while True:
                    b = data[cp]; cp += 1; acc += b
                    if b != 0xff:
                        break
                length = 3 + acc
            else:
                length = lf + 2
            dlo = data[cp]; cp += 1
            if (c & 0x1f) == 0x1f and dlo == 0xff:       # distance escape
                dist = 0x2000 + ((data[cp] << 8) | data[cp + 1]); cp += 2
            else:
                dist = (((c & 0x1f) << 8) | dlo) + 1
            pos = len(out)
            src = pos - dist
            if src < 0:                                  # zero-init window
                z = min(-src, length)
                out += b"\x00" * z
                length -= z
                src = len(out) - dist
            if length:
                if dist >= length:                       # non-overlapping
                    out += out[src:src + length]
                else:                                    # overlapping run
                    chunk = out[src:src + dist]
                    out += (chunk * (length // dist + 1))[:length]
    del out[end:]                                        # trim any over-copy
    return cp


def flatten(inp, outp, quiet=False):
    # Back-references reach across block boundaries (dist up to ~0x12000), so the
    # decompression window is continuous. Keep a sliding tail as context and flush
    # the rest at block boundaries to bound memory.
    KEEP = 0x40000  # 256 KiB context (> max back-distance)
    # mmap the input so RSS stays tiny (the file is read once, sequentially, and the
    # back-reference window lives in the small output buffer -- not the input).
    fin = open(inp, "rb")
    size = os.fstat(fin.fileno()).st_size
    if size == 0:
        sys.exit("[!] empty input")
    data = mmap.mmap(fin.fileno(), 0, access=mmap.ACCESS_READ)
    try:
        data.madvise(mmap.MADV_SEQUENTIAL)              # let the kernel drop pages behind us
    except (AttributeError, OSError):
        pass
    # sanity: this must be a decrypted .vmem (16-byte block headers), not a .vmsn
    if data[:4] in (b"\xd2\xbe\xd2\xbe", b"\xd0\xbe\xd2\xbe",
                    b"\xd1\xba\xd1\xba", b"\xd3\xbe\xd3\xbe"):
        sys.exit("[!] input looks like a .vmsn/.vmss (VMware snapshot magic), not a .vmem.\n"
                 "    vmem_flatten operates on the decrypted .vmem; the .vmsn needs no flattening.")
    if size >= 16:
        u0, r0, c0, r1 = struct.unpack_from("<IIII", data, 0)
        if r0 or r1 or not (0 < u0 <= 0x400000) or not (0 < c0 <= u0):
            sys.exit("[!] input doesn't look like a decrypted VMware .vmem "
                     "(first block header is invalid).")
    out = bytearray()
    cp = 0
    nblocks = 0
    with open(outp, "wb", buffering=1 << 20) as fh:
        while cp + 16 <= size:
            usize, _r0, csize, _r1 = struct.unpack_from("<IIII", data, cp)
            cp += 16
            if usize == 0 or cp + csize > size:
                break
            if csize == usize:                          # raw (uncompressed) block
                out += data[cp:cp + csize]
            else:
                ncp = decompress_block(data, cp, out, usize)
                if ncp != cp + csize:
                    raise ValueError(f"block {nblocks}: consumed {ncp-cp:#x} != csize {csize:#x}")
            cp += csize
            nblocks += 1
            if len(out) >= (8 << 20):                   # flush early, keep last KEEP as context
                fh.write(out[:-KEEP])
                del out[:-KEEP]
            if not quiet and nblocks % 200 == 0:
                print(f"    block {nblocks}: in 0x{cp:x}/{size:x}, out {fh.tell() + len(out) - KEEP}")
        fh.write(out)
        total = fh.tell()
    data.close()
    fin.close()
    if not quiet:
        print(f"[+] {nblocks} blocks -> {total} bytes flat image -> {outp}")
        if not outp.endswith(".vmem"):
            print("[!] NOTE: name this output '<base>.vmem' (NOT .raw) and put the decrypted")
            print("    '<base>.vmsn' beside it, so Volatility auto-pairs them via its vmware layer:")
            base = "<base>"
        else:
            base = outp[:-len(".vmem")]
        print(f"    next:  vol -f {base}.vmem windows.info        "
              f"(needs {base}.vmsn next to it)")
    return total


def main():
    ap = argparse.ArgumentParser(description="Expand a decrypted VMware .vmem to a flat image.")
    ap.add_argument("input", help="decrypted .vmem (from vmem_decrypt.py)")
    ap.add_argument("output", help="flat image output -- name it '<base>.vmem' and keep the "
                                   "decrypted '<base>.vmsn' beside it for Volatility")
    args = ap.parse_args()
    if not os.path.isfile(args.input):
        sys.exit(f"not a file: {args.input}")
    flatten(args.input, args.output)


if __name__ == "__main__":
    main()
