#!/usr/bin/env python3
"""
vmem-decrypt -- decrypt VMware Workstation/Fusion encrypted VM data files.

Decrypts the "encobj" container used for the .vmem / .vmsn / .vmss / .nvram files
of an encrypted virtual machine -- the encryption VMware forces on Windows 11
guests configured with a vTPM.

This is STAGE 2 (decryption). You need the VM password first (STAGE 1): extract the
KDF hash from the .vmx with VM-Password-Extractor and crack it with hashcat -- see
the README.

Key chain recovered from the .vmx:

    password --PBKDF2-HMAC-SHA1(salt, rounds)--> KEK (key-encryption key)
    KEK[:32] --AES-256-CBC--> keySafe dictionary --> config_key (64 bytes)
    config_key[:32] --AES-256-CBC--> encryption.data --> dataFileKey (64 bytes)
    dataFileKey[:32] = AES-256-CBC key that encrypts the actual data files

(VMware labels these keys "XTS-AES-256" but actually uses the first 256 bits as an
AES-256-CBC key -- it is NOT real XTS. Real XTS will not decrypt these files.)

encobj data-file layout (little-endian, magic 0x8943dd9e):

    [0x000 .. 0x1000)  4096-byte plaintext header
        u32 magic         @0x00 = 0x8943dd9e
        u32 version       @0x04 (1=vmsn, 2=vmem here)
        u32 data_per_page @0x08 = 4064
        u32 iv_size       @0x0c = 16
        u32 mac_size      @0x10 = 16
        u64 logical_size  @0x18  -> trim the decrypted output to this many bytes
    [0x1000 .. EOF)    sequence of 4096-byte on-disk pages, each laid out as
        [ ciphertext : data_per_page ][ IV : iv_size ][ MAC : mac_size ]
        page_plaintext = AES-256-CBC-decrypt(ciphertext,
                                             key = dataFileKey[:32],
                                             iv  = the page's stored IV)
        (The per-page MAC is not needed to decrypt; dataFileKey[32:] is unused.)

OUTPUT: the decrypted bytes are VMware's *native checkpoint* format. For .vmsn /
.vmss / .nvram that is directly usable. For .vmem, VMware compresses-then-encrypts,
so the decrypted memory is still compressed (NOT a flat physical image). Expanding
it to a flat, Volatility-ready dump currently requires VMware's own ESXi tool
`crypto-util`; an offline decompressor is not yet implemented (see README).
"""

import argparse
import base64
import hashlib
import hmac
import os
import re
import struct
import sys
import urllib.parse

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    sys.exit("Missing dependency: pip install cryptography")

MAGIC = 0x8943DD9E
AES_BLOCK = 16
HASH_SIZE = 20  # SHA-1


# --------------------------------------------------------------------------- #
# Stage 2a: recover keys from the .vmx
# --------------------------------------------------------------------------- #

_KEYSAFE_RE = (
    r".+phrase/([A-Za-z0-9+/=]+)"
    r"/pass2key=([A-Z0-9-]+)"
    r":cipher=([A-Z0-9-]+)"
    r":rounds=([0-9]+)"
    r":salt=([A-Za-z0-9+/%]+)"
    r",([A-Z0-9-]+)"
    r",([A-Za-z0-9+/=]+)\)"
)
_DICT_RE = r"type=([a-z]+):cipher=([A-Z0-9-]+):key=([A-Za-z0-9+/%]+)"
_DATA_RE = r'.*"([A-Za-z0-9+/=]+)"'


def _aes_cbc_decrypt(key, iv, data):
    d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return d.update(data) + d.finalize()


def _key_size_for_cipher(cipher):
    # VMware "XTS-AES-256" stores a 64-byte key (data key + HMAC key);
    # "AES-256" stores 32 bytes. The CBC key is always the first 32 bytes.
    return 64 if cipher == "XTS-AES-256" else 32


def _unwrap_dictionary(blob, derived_key, label):
    """Decrypt a keySafe 'dictionary' blob: [IV][ciphertext][HMAC-SHA1]."""
    iv = blob[:AES_BLOCK]
    dec = _aes_cbc_decrypt(derived_key[:32], iv, blob[AES_BLOCK:-HASH_SIZE])
    pad = dec[-1]
    if not 1 <= pad <= 16:
        raise ValueError(f"{label}: bad PKCS#7 padding {pad} (wrong password?)")
    plain = dec[:-pad]
    mac = blob[-HASH_SIZE:]
    if mac != hmac.new(derived_key, plain, hashlib.sha1).digest():
        raise ValueError(f"{label}: HMAC mismatch -- wrong password")
    return plain


def recover_keys(vmx_path, password):
    """Return (dataFileKey: 64 bytes, decrypted_vmx_config: str)."""
    keysafe = data = None
    with open(vmx_path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            s = line.strip()
            if s.startswith("encryption.keySafe"):
                keysafe = s
            elif s.startswith("encryption.data"):
                data = s
    if not keysafe or not data:
        raise ValueError("encryption.keySafe / encryption.data not found in .vmx "
                         "(is this VM actually encrypted?)")

    m = re.match(_KEYSAFE_RE, urllib.parse.unquote(keysafe))
    if not m:
        raise ValueError("unsupported encryption.keySafe format")
    _id, pass2key, dict_cipher, rounds, salt_q, _hmac_alg, dict_b64 = m.groups()
    if pass2key != "PBKDF2-HMAC-SHA-1":
        raise ValueError(f"unsupported KDF: {pass2key}")
    rounds = int(rounds)
    salt = base64.b64decode(urllib.parse.unquote(salt_q))
    key_size = _key_size_for_cipher(dict_cipher)

    # password -> KEK -> keySafe dictionary -> config_key
    kek = hashlib.pbkdf2_hmac("sha1", password.encode(), salt, rounds, key_size)
    dict_plain = _unwrap_dictionary(base64.b64decode(dict_b64), kek, "keySafe")
    dm = re.match(_DICT_RE, dict_plain.decode("ascii", "replace"))
    if not dm:
        raise ValueError("unexpected keySafe dictionary contents")
    config_key = base64.b64decode(urllib.parse.unquote(dm.group(3)))

    # config_key -> encryption.data -> decrypted vmx config (holds dataFileKey)
    dmatch = re.match(_DATA_RE, urllib.parse.unquote(data))
    if not dmatch:
        raise ValueError("unsupported encryption.data format")
    cfg_blob = base64.b64decode(dmatch.group(1))
    cfg = _aes_cbc_decrypt(config_key[:32], cfg_blob[:AES_BLOCK],
                           cfg_blob[AES_BLOCK:-HASH_SIZE])
    pad = cfg[-1]
    if 1 <= pad <= 16:
        cfg = cfg[:-pad]
    cfg_text = cfg.decode("utf-8", "replace")

    fm = re.search(r'dataFileKey\s*=\s*"[^"]*key=([A-Za-z0-9+/%]+)"', cfg_text)
    if not fm:
        raise ValueError("dataFileKey not present in decrypted config")
    return base64.b64decode(urllib.parse.unquote(fm.group(1))), cfg_text


# --------------------------------------------------------------------------- #
# Stage 2b: decrypt an encobj data file
# --------------------------------------------------------------------------- #

def parse_header(fh, page_size):
    fh.seek(0)
    h = fh.read(page_size)
    return {
        "magic": struct.unpack_from("<I", h, 0)[0],
        "version": struct.unpack_from("<I", h, 4)[0],
        "data_per_page": struct.unpack_from("<I", h, 8)[0],
        "iv_size": struct.unpack_from("<I", h, 12)[0],
        "mac_size": struct.unpack_from("<I", h, 16)[0],
        "logical_size": struct.unpack_from("<Q", h, 24)[0],
    }


def decrypt_data_file(inp, outp, data_file_key, header_size=4096, page_size=4096,
                      data_per_page=None, iv_offset=None, iv_size=16,
                      logical_size=None, quiet=False):
    aes_key = data_file_key[:32]
    size = os.path.getsize(inp)
    with open(inp, "rb") as fh:
        hdr = parse_header(fh, page_size)
    if hdr["magic"] != MAGIC:
        print(f"[!] warning: magic 0x{hdr['magic']:08x} != 0x{MAGIC:08x} "
              f"(not an encobj file?)", file=sys.stderr)
    dpp = data_per_page or hdr["data_per_page"] or 4064
    ivo = iv_offset if iv_offset is not None else dpp
    trim = logical_size if logical_size is not None else hdr["logical_size"]

    n_pages = (size - header_size) // page_size
    if not quiet:
        print(f"[*] {os.path.basename(inp)}: magic ok, version {hdr['version']}, "
              f"{n_pages} pages, data/page={dpp}, trim->{trim}")

    written = 0
    with open(inp, "rb") as fh, open(outp, "wb") as out:
        fh.seek(header_size)
        for i in range(n_pages):
            page = fh.read(page_size)
            if len(page) < page_size:
                break
            iv = page[ivo:ivo + iv_size]
            dec = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).decryptor()
            pt = dec.update(page[:dpp]) + dec.finalize()
            if trim and written + len(pt) > trim:
                pt = pt[:trim - written]
            out.write(pt)
            written += len(pt)
            if trim and written >= trim:
                break
            if not quiet and n_pages > 100000 and i and i % 100000 == 0:
                print(f"    {100 * i // n_pages:3d}%  ({written} bytes)")
    if not quiet:
        print(f"[+] wrote {written} bytes -> {outp}")
    return written


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Decrypt VMware encrypted VM data files (.vmem/.vmsn/.vmss/.nvram).")
    ap.add_argument("input", nargs="?", help="encrypted data file to decrypt")
    ap.add_argument("output", nargs="?", help="output path for the decrypted file")

    g = ap.add_mutually_exclusive_group()
    g.add_argument("--vmx", help="encrypted .vmx (with --password) to recover the key")
    g.add_argument("--key", help="dataFileKey as hex (>=32 bytes; first 32 used)")
    ap.add_argument("--password", help="VM password (used with --vmx)")
    ap.add_argument("--print-key", action="store_true",
                    help="recover and print dataFileKey from --vmx/--password, then exit")

    ap.add_argument("--header-size", type=int, default=4096)
    ap.add_argument("--page-size", type=int, default=4096)
    ap.add_argument("--data-per-page", type=int, default=None,
                    help="override ciphertext bytes per page (default: header field)")
    ap.add_argument("--iv-offset", type=int, default=None,
                    help="override IV offset within each page (default: data-per-page)")
    ap.add_argument("--iv-size", type=int, default=16)
    ap.add_argument("--logical-size", type=int, default=None,
                    help="override output trim length (default: header field)")
    ap.add_argument("--no-trim", action="store_true", help="do not trim trailing padding")
    args = ap.parse_args(argv)

    key = None
    if args.key:
        key = bytes.fromhex(args.key)
    elif args.vmx:
        if not args.password:
            ap.error("--vmx requires --password")
        try:
            key, _cfg = recover_keys(args.vmx, args.password)
        except ValueError as exc:
            sys.exit(f"[!] {exc}")
        print(f"[*] recovered dataFileKey: {key.hex()}")

    if args.print_key:
        if key is None:
            ap.error("--print-key needs --vmx and --password")
        return 0

    if not args.input or not args.output:
        ap.error("input and output are required (unless --print-key)")
    if key is None:
        ap.error("provide a key via --vmx/--password or --key")
    if len(key) < 32:
        ap.error("key must be at least 32 bytes")

    decrypt_data_file(
        args.input, args.output, key,
        header_size=args.header_size, page_size=args.page_size,
        data_per_page=args.data_per_page, iv_offset=args.iv_offset,
        iv_size=args.iv_size,
        logical_size=(None if args.no_trim else args.logical_size),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
