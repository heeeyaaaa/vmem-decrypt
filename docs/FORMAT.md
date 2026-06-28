# VMware encrypted checkpoint internals

Notes gathered while building this tool. The full pipeline - key chain, `encobj`
decryption, and the `.vmem` checkpoint **decompression** - is solved and implemented.
This doc records the on-disk formats and the reverse-engineered codec.

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

## The `.vmem` compression

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
If `compressed_size == uncompressed_size` the block is stored **raw** (verbatim, no LZ).
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
Verified: block headers at file 0x0, 0x12aed8, 0x217b93, ... with
`next = prev + 0x10 + compressed_size` holding exactly; each block decompresses to 4 MiB and
they tile physical memory in order (region 0 then region 1 per the `memory` group). Implemented
in `vmem_flatten.py`. The appendix below records how the codec was identified before the
disassembly confirmed it.

## Appendix: how the codec was identified (black-box, pre-disassembly)

Kept for context; the grammar above is the authoritative, validated result.

The decrypted `.vmem` is not a flat physical image - VMware compresses **before** encrypting:

- Information-theoretic: encrypted `.vmem` (~2.91 GiB) < physical span (~6 GiB); AES is 1:1.
- 0 valid x64 page-table pages across **all** 8-byte alignments in 192 MB (a flat Windows
  image would have hundreds); the known DTB (CR3 = 0x1ae000) at flat offset yields garbage.
- Short literal strings survive (`ntoskrnl.exe`, `\Windows\System32\...`, EFI firmware) but
  distinctive 48-byte chunks do not -> an LZ-style codec that preserves literals.
- Entropy ~6.8 bits/byte (below ~7.95 for entropy-coded compressors) -> fast LZ without
  Huffman/range coding. Not lz4 / zlib / zstd / snappy / lzo at any tested offset or framing.

Inspecting a region of known structure (the ACPI XSDT, located via the literal
`XSDT`/`INTEL 440BX`/`VMW ` strings) confirmed byte-oriented LZ77: the XSDT header appears as
verbatim literals, while its body (8-byte pointers sharing high bytes `be 0f`/`bf 0f` with a
trailing `00 00 00 00`) is replaced by short 2-4 byte match tokens (`9f ff 10 44`,
`a0 07 00 ed`, `02 e3 00 20`, `80 07 05 3b`, ...). Disassembly of `vmware-vmx`
(`DumperFastInflate` / `fcn.007181c0`) then pinned the exact grammar - including the length
and distance escapes - giving the validated decoder documented above.

**Known-plaintext validation:** restoring the snapshot in VMware (it decompresses on resume)
and dumping RAM from inside gives boot-invariant ground truth (ACPI firmware: XSDT checksum
matches; kernel `.text`); converting that crashdump to flat physical with vol3's
`WindowsCrashDump64Layer.read()` confirms the decompressor byte-exact (physical 0..0x2000 =
zeros, XSDT at phys 0x5018).

For reference, ESXi's `crypto-util encobj decrypt` performs both the decrypt **and** the
decompress in one step, producing a flat `.vmem` - if you have access to ESXi.
