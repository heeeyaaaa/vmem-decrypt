# VMware encrypted checkpoint internals

Notes gathered while building this tool. Stage 2a/2b (key chain + `encobj` decryption)
are fully solved; the `.vmem` **decompression** is the open problem and the rest of this
doc is meant to help with it.

## Key chain (.vmx)

```
encryption.keySafe = "vmware:key/list/(pair/(phrase/<id>
    /pass2key=PBKDF2-HMAC-SHA-1:cipher=XTS-AES-256:rounds=10000:salt=<b64>
    ,HMAC-SHA-1,<b64 dict>))"
encryption.data    = "<b64: [IV16][AES-256-CBC ciphertext][HMAC-SHA1 20]>"
```

1. `KEK = PBKDF2-HMAC-SHA1(password, salt, rounds, dklen)` - `dklen` = 64 for an
   `XTS-AES-256` dict, else 32. Only the first 32 bytes are used as the AES key.
2. keySafe dict blob = `[IV16][ciphertext][HMAC-SHA1 20]`; AES-256-CBC decrypt with
   `KEK[:32]`; PKCS#7 unpad; verify `HMAC-SHA1(KEK, plaintext)`.
   Plaintext = `type=key:cipher=XTS-AES-256:key=<b64 config_key(64)>`.
3. `encryption.data` decrypts the same way with `config_key[:32]` → the original `.vmx`
   text, which contains `dataFileKey = "type=key:cipher=XTS-AES-256:key=<b64 64B>"`.
4. `dataFileKey[:32]` = the AES-256-CBC key for the data files.

"XTS-AES-256" is a misnomer throughout: only `key[:32]` is used, as AES-256-**CBC**.

## encobj data-file container (.vmem/.vmsn/.vmss/.nvram)

`magic = 0x8943dd9e`. 4096-byte plaintext header (fields at 0x00/0x04/0x08/0x0c/0x10/0x18,
see README), then 4096-byte on-disk pages `[ct:4064][iv:16][mac:16]`. Each page decrypts
(AES-256-CBC, `dataFileKey[:32]`, page IV) to 4064 plaintext bytes; concatenate and trim
to `logical_size`. Verified byte-exact (decrypted `.vmsn` parses 100%: magic `0xbed2bed2`,
102 groups, valid CPU/region state).

## .vmsn `memory` group (the map for expanding `.vmem`)

Tags (VMware tag stream: `flags, name_len, name, indices[], data`):

- `regionsCount` = 2
- per region *i*: `regionPPN[i]`, `regionPageNum[i]` (file page), `regionSize[i]` (pages)
  - region 0: PPN 0,         file 0,       size 786432  (phys 0..3 GiB)
  - region 1: PPN 0x100000,  file 786432,  size 802816  (phys 4..~7 GiB; 3-4 GiB MMIO hole)
- `MainMemKnownZero` - 1 bit/page bitmap (1,589,248 bits); set = page known zero (4,701 set)
- `hotSet` - 1 bit/page bitmap; set = "hot" page (1,522,627 set)
- `align_mask = 0xffff`

The CPU `cpu` group holds per-vCPU `CR64` (CR0,CR1,CR2,CR3,CR4 as 8-byte words → DTB=CR3),
`gpregs`, `rip`, `GDTR/IDTR`, MSRs, etc.

## The `.vmem` compression: SOLVED

Reverse-engineered from `vmware-vmx` (`DumperFastInflate` / inner decoder `fcn.007181c0`)
and validated: decompressed block 0 reconstructs valid Windows page tables (self-referential
PML4 entry at the DTB), the ACPI firmware, and PE images.

**Block container** (a decrypted `.vmem` is a sequence of these):
```
struct block { u32 uncompressed_size;  // 0x00400000 (4 MiB) for full blocks
               u32 0;
               u32 compressed_size;     // length of the LZ stream that follows
               u32 0;
               u8  stream[compressed_size]; }   // -> uncompressed_size bytes
```
Concatenating all decompressed blocks gives the flat physical image (paired with the
decrypted `.vmsn` `memory` group for region mapping -> Volatility's `vmware` layer).

**Inner LZ77** (zero-initialised back-reference window):
```
first control byte F (F>>5 must be 0 or 1):  literal run of (F & 0x1f) + 1 bytes
then per control byte C:
  C <= 0x1f :  literal run of (C + 1) bytes
  C  > 0x1f :  match
      lf = C >> 5
      if lf == 7:  acc=6; do { b=next; acc+=b } while b==0xff;  length = 3 + acc   # len escape
      else:        length = lf + 2
      dlo = next
      if (C & 0x1f)==0x1f and dlo==0xff:  dist = 0x2000 + (next<<8 | next)          # dist escape
      else:                               dist = ((C & 0x1f)<<8 | dlo) + 1
      copy `length` bytes from (pos - dist)   (overlap allowed; zeros before start)
```
Implemented in `vmem_flatten.py`. See git history below for the earlier (pre-disassembly)
black-box notes.

## (historical) The open problem: `.vmem` is compressed

The decrypted `.vmem` is **not** a flat physical image:

- Information-theoretic: encrypted `.vmem` (~2.91 GiB) < physical span (~6 GiB); AES is 1:1,
  so VMware compresses **before** encrypting.
- 0 valid x64 page-table pages found across **all** 8-byte alignments in 192 MB (a flat
  Windows image would have hundreds).
- Reading the known DTB (CR3 = 0x1ae000) at flat offset yields garbage PML4 entries.
- Short literal strings survive (`ntoskrnl.exe`, `\Windows\System32\...`, EFI firmware),
  but distinctive 48-byte chunks do not → an LZ-style codec that preserves literals.
- Entropy ~6.8 bits/byte (below the ~7.95 of entropy-coded compressors) → fast LZ without
  Huffman/range coding.
- **Not** lz4 / zlib / zstd / snappy / lzo at any tested offset or framing; no recognizable
  block magic at a regular stride. Header begins `00400000 00000000 0012aec8 00000000
  e0000021 07040035 00c00000 ffffffe0 ffffffff...`.

So it is a **custom VMware checkpoint codec** -- specifically a **byte-oriented LZ77**
(literals + back-reference matches), confirmed by inspecting a region with known
structure (the ACPI XSDT, found via the literal `XSDT`/`INTEL 440BX`/`VMW ` strings near
the start of the decrypted stream):

- The XSDT *header* (signature, length, OEMID, creator) appears as verbatim **literals**.
- The XSDT *body* -- an array of 8-byte pointers to other ACPI tables, all sharing high
  bytes (`be 0f` / `bf 0f`) and a trailing `00 00 00 00` -- is replaced by short 2-4 byte
  **match tokens**: e.g. `9f ff 10 44`, `a0 07 00 ed`, `02 e3 00 20`, `80 07 05 3b`.
  Recurring token lead-ins seen: `9f ff XX`, `a0 07 00 XX`, `02 e3 00 XX`, `80 07 XX`.
- This matches the ~6.8 bit/byte entropy (LZ without entropy coding) and the "short
  literal strings survive, 48-byte chunks don't" observation.

### Codec grammar (reverse-engineered, validated byte-exact vs a restore+dump reference)

It is a byte-oriented LZ77. Reference window is **zero-initialised** (back-references
before output start read 0). A control byte `B0` drives each op:

```
B0 < 0x20                  LITERAL run of (B0 + 1) bytes follow verbatim
B0 >= 0x20                 MATCH
    len   = (B0 >> 5) + 2                 # length field = top 3 bits
    dhi5  = B0 & 0x1f                     # distance high 5 bits
    B1    = next byte                     # distance low 8 bits
    dist13= (dhi5 << 8) | B1
    if dist13 == 0x1fff:                  # distance escape
        dist = 0x2000 + (B2 << 8 | B3)    # +2 extra token bytes
    else:
        dist = dist13 + 1
    copy `len` bytes from `dist` back (overlapping allowed)
```
Worked example (ACPI XSDT pointer tails, validated): `80 07`->len6 dist8,
`a0 07`->len7 dist8, `a0 17`->len7 dist24, `bf ff 10 3c`->len7 dist0x303c,
`9f ff 0c 7c`->len6 dist0x2c7c. The `0x27`-class (`0x20<=B0<0x40`) are len-3 matches;
the literal/match boundary is **0x20**, not 0x40.

**Block framing (SOLVED):** the `.vmem` is a sequence of independent blocks:

```
struct block_header {           // 16 bytes
    u32 uncompressed_size;      // = 0x00400000 (4 MiB) for full blocks
    u32 reserved0;              // 0
    u32 compressed_size;        // bytes of LZ stream that follow
    u32 reserved1;              // 0
};
// then `compressed_size` bytes of LZ77 stream -> uncompressed_size bytes
// next block starts at  this_header + 16 + compressed_size
```
Verified: headers at file 0x0, 0x12aed8, 0x217b93, ... and
`next = prev + 0x10 + compressed_size` holds exactly. Each block decompresses to 4 MiB and
they tile physical memory in order (region 0 then region 1 per the `memory` group). Validate
with vol3 flat physical: block 0 -> phys 0..0x400000 (phys 0..0x2000 zeros, RSDP-ish at
0x2000, XSDT at 0x5018).

STILL OPEN to finish `--flatten` (this is the wall):

**Literal/match selection is STATEFUL.** The match-body encoding (above) is validated
byte-exact: from the XSDT (phys 0x5018) the decoder cleanly reproduces 4143 bytes of true
flat physical memory using `B0<0x20 => literal, else match`. But it then desyncs on a
`B0=0x00` that must be a *match* (producing e.g. `e0 00 00 00...`), whereas elsewhere in the
firmware `B0=0x00` is a 1-byte *literal*. Both cases occur immediately after a match op, so
the selector is NOT "previous op type". So there is a hidden per-op flag/control (a separate
flag bitstream, or an LZ4/LZO-style combined token we're mis-splitting) that decides
literal-run vs match. The all-zero block prefix can't disambiguate it (every interpretation
yields zeros via the zero-window).

Also unresolved: the **length escape** for runs > 9 (`lf == 7`, `B0 >= 0xe0`; a `0xff` run
encodes ~8 KiB zero fills). `e0 00` decoded as len9/dist1 RLE *did* reproduce phys, so lf7
is not always escaped -- the escape trigger/encoding is entangled with the stateful framing.

CONCLUSION: black-box inference reproduces all *match bodies* and the *block container*, but
the per-op literal/match framing needs the actual algorithm (disassembly of a VMware binary
that decompresses checkpoints, or a reference implementation). The decrypt half is fully
solved and shippable; offline `--flatten` is blocked on this one framing detail.

KNOWN-PLAINTEXT METHOD that worked: restore the snapshot in VMware (it decompresses on
resume) and DumpIt from inside; boot-invariant regions (ACPI firmware: XSDT checksum then
matches the snapshot, kernel `.text`) give byte-exact ground truth. Convert the DumpIt
crashdump to flat physical with vol3's `WindowsCrashDump64Layer.read()` to validate the
decompressor directly (physical 0..0x2000 = zeros, XSDT at phys 0x5018).

ESXi `crypto-util encobj decrypt` does decrypt **and** decompress, producing a flat `.vmem`.
