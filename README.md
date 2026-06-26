# vmem-decrypt

Decrypt the encrypted data files of a **VMware Workstation / Fusion** virtual machine -
`.vmem` (saved RAM), `.vmsn` / `.vmss` (snapshot / suspend state) and `.nvram` - using
only the VM **password**.

VMware forces "partial" VM encryption on **Windows 11** guests that have a **vTPM**, which
also encrypts the memory/snapshot files. That makes them unusable for memory forensics
(Volatility, etc.) until they're decrypted. This tool reproduces VMware's `encobj`
decryption in pure Python so you don't need ESXi or VMware's internal tooling for the
decryption step.

> **Scope / honesty up front:** this tool fully and correctly performs the **decryption**.
> For `.vmsn` / `.vmss` / `.nvram` the decrypted output is directly usable. For `.vmem`,
> VMware **compresses *then* encrypts**, so the decrypted memory is still in VMware's
> proprietary compressed checkpoint layout, which `vmem_flatten.py` then expands to a flat
> image. See [Getting a Volatility-ready image](#getting-a-volatility-ready-image).

**Tested on:** VMware® Workstation Pro **26H1**, guest Windows 11 **25H2** (build 26100),
analysed with Volatility 3 (2.28). The encobj decryption and the block/LZ container were
reverse-engineered against this build's `vmware-vmx`; very different VMware versions *may*
use a different checkpoint format (the tools fail loudly rather than producing silent
garbage, so you'll know).

---

## How VMware encrypts these files

```
                    STAGE 1  (password recovery)                STAGE 2  (this tool)
 .vmx ──VM-Password-Extractor──▶ $vmx$ hash ──hashcat──▶ password ─┐
                                                                   ▼
 password ─PBKDF2-HMAC-SHA1(salt,10000)─▶ KEK
 KEK[:32] ─AES-256-CBC─▶ keySafe dict ─▶ config_key (64 B)
 config_key[:32] ─AES-256-CBC─▶ encryption.data ─▶ dataFileKey (64 B)
 dataFileKey[:32] = AES-256-CBC key for .vmem/.vmsn/.vmss/.nvram
```

VMware labels every key `XTS-AES-256`, but it actually uses the **first 256 bits as an
AES-256-CBC key** - it is **not** real XTS. (Real XTS will not decrypt these files; that
trips up most people who try.)

### encobj data-file layout (`magic 0x8943dd9e`, little-endian)

```
[0x000 .. 0x1000)  4096-byte plaintext header
    u32 magic         @0x00 = 0x8943dd9e
    u32 version       @0x04            (1 = vmsn, 2 = vmem)
    u32 data_per_page @0x08 = 4064
    u32 iv_size       @0x0c = 16
    u32 mac_size      @0x10 = 16
    u64 logical_size  @0x18            (trim the decrypted output to this)
[0x1000 .. EOF)    4096-byte on-disk pages, each:
    [ ciphertext : 4064 ][ IV : 16 ][ MAC : 16 ]
    plaintext = AES-256-CBC( ciphertext, key = dataFileKey[:32], iv = the page's IV )
```

---

## Install

```bash
git clone https://github.com/heeeyaaaa/vmem-decrypt
cd vmem-decrypt
pip install -r requirements.txt   # just: cryptography
```

---

## Usage

### Stage 1 - recover the password (separate tools)

The `.vmx` holds a PBKDF2 verifier, not the keys. Extract it as a crackable hash and
brute/dictionary-crack it:

```bash
# extract the hash from the .vmx  (https://github.com/archidote/VM-Password-Extractor)
python3 VM-Password-Extractor.py --vmx VM.vmx --vmx-password-hash-to-hashcat
#   -> $vmx$0$10000$<salt>$<hash>

# crack it with hashcat  (VMware VMX = mode 27400)
hashcat -m 27400 hash.txt /usr/share/wordlists/rockyou.txt
```

(John the Ripper also works; the same `$vmx$…` hash is its VMware format.)

### Stage 2 - decrypt (this tool)

```bash
# decrypt straight from the .vmx + recovered password
python3 vmem_decrypt.py VM-Snapshot1.vmsn  VM-Snapshot1.dec.vmsn  --vmx VM.vmx --password 'P@ssw0rd'
python3 vmem_decrypt.py VM-Snapshot1.vmem  VM-Snapshot1.dec.vmem  --vmx VM.vmx --password 'P@ssw0rd'

# or recover the key once and reuse it
python3 vmem_decrypt.py --vmx VM.vmx --password 'P@ssw0rd' --print-key
python3 vmem_decrypt.py VM.vmem  VM.dec.vmem  --key 151bcbc1...981f85

# inspect a file's structure without decrypting
python3 vmem_inspect.py VM-Snapshot1.vmem
```

**Verify it worked:** a correctly decrypted `.vmsn`/`.vmss` starts with a VMware snapshot
magic (`0xbed2bed2`, also `0xbed2bed0` / `0xbad1bad1` / `0xbed3bed3`), followed by a `u32`
group count and ASCII group names (`Checkpoint`, `ConfigParams`, `memory`, `cpu`, …).

---

## Getting a Volatility-ready image

For `.vmsn` / `.vmss` / `.nvram`: the decrypted file is already in VMware's native format
and is directly usable.

For `.vmem`: VMware **compresses then encrypts**, so the decrypted `.vmem` is still VMware's
compressed checkpoint format. Expand it with `vmem_flatten.py`, then hand the result to
Volatility **together with the decrypted `.vmsn`**:

```bash
# expand -- IMPORTANT: name the output  <base>.vmem  (NOT .raw)
python3 vmem_flatten.py VM-Snapshot1.dec.vmem  out.vmem

# put the decrypted .vmsn beside it with the SAME basename, then run vol on the .vmem:
cp VM-Snapshot1.dec.vmsn  out.vmsn
vol -f out.vmem windows.info        # vol3 auto-detects its vmware layer from the .vmem/.vmsn pair
vol -f out.vmem windows.pslist
```

> **Why `.vmem` + a paired `.vmsn`, not a bare `.raw`?** The flat image is region 0
> (phys 0-3 GiB) followed by region 1 (phys 4-7 GiB) - there is a 1 GiB MMIO hole at 3-4 GiB,
> so *file offset ≠ physical address*. Volatility's **vmware layer** uses the `.vmsn`'s
> `memory` group to remap the regions; feeding it the bare image as a raw layer fails the
> kernel/DTB validation. The `.vmem`/`.vmsn` naming is what triggers that layer.

The flat image is the concatenation of the 4 MiB physical blocks. The codec is a custom
byte-oriented LZ77 reverse-engineered from `vmware-vmx`'s checkpoint inflater - see
[`docs/FORMAT.md`](docs/FORMAT.md) for the full container + LZ grammar.

(ESXi's `crypto-util encobj decrypt` does decrypt **and** decompress in one step, if you have
access to ESXi.)

---

## Status

| File | Decrypt | Volatility-ready |
|------|:------:|:----------------:|
| `.vmsn` / `.vmss` | ✅ | ✅ (native format) |
| `.nvram` | ✅ | n/a |
| `.vmem` | ✅ | ⚠️ needs decompression (ESXi `crypto-util`, or TODO offline) |

---

## Credits

- Key-chain reference: [RF3/VMwareVMX](https://github.com/RF3/VMwareVMX),
  [axcheron/pyvmx-cracker](https://github.com/axcheron/pyvmx-cracker)
- Hash extraction: [archidote/VM-Password-Extractor](https://github.com/archidote/VM-Password-Extractor)
- `encobj` container format + per-page AES-256-CBC layout reverse-engineered for this tool.

## License

Licensed under the [MIT License](LICENSE).

