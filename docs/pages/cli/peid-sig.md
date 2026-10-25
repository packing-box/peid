# `peid-sig`: create signatures

`peid-sig` derives an **entry-point signature** from several samples packed
with the same packer. It compares the bytes at each sample's entry point and
keeps the bytes they share. Bytes that differ become `??` wildcards.

```console
$ peid-sig [-m MIN] [-M MAX] [-t RATIO] [-a AUTHOR] [-d DB] [-p PACKER] [-v VERSION] [--verbose] [-h] path [path ...]
```

## Arguments

| Argument | Description |
|---|---|
| `path` | Two or more executables packed with the same packer. More samples give a more general signature. |

### Signature arguments

| Option | Default | Description |
|---|---|---|
| `-m N`, `--min-length N` | `16` | Minimum signature length, in bytes. |
| `-M N`, `--max-length N` | `64` | Maximum signature length, in bytes (the number of bytes read from each entry point). |
| `-t R`, `--bytes-threshold R` | `0.5` | Fraction of bytes, between `0` and `1`, that must be identical across all samples. |

### Optional arguments

| Option | Description |
|---|---|
| `-p NAME`, `--packer NAME` | Packer name. With it, the output is a full database entry instead of the bare bytes. |
| `-v VER`, `--version VER` | Packer version appended to the name (`NAME VER`). |
| `-a NAME`, `--author NAME` | Signature author appended to the name (`NAME VER -> AUTHOR`). |
| `-d DB`, `--db DB` | Database to save the new signature into (needs `--packer`). The file is created if it does not exist. |

### Extra arguments

| Option | Description |
|---|---|
| `--verbose` | Show debug information. Unreadable samples are then skipped with a debug message instead of stopping the run. |
| `-h`, `--help` | Show the help message and exit. |

## Output

Without `--packer`, only the bytes are printed:

```console
$ peid-sig samples/*.exe
60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 10
```

With `--packer`, a ready-to-paste database entry is printed:

```console
$ peid-sig prg1.exe prg2.exe prg3.exe --packer PE-Packer --version v1.0 --author dhondta
[PE-Packer v1.0 -> dhondta]
signature = 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 10
ep_only = true
```

If no signature fits the constraints, `peid-sig` prints
`[ERROR] Could not find a suitable signature` and exits with code `1`.

## Algorithm

For a candidate length `L`, starting at `--max-length`:

1. Read the first `L` bytes at each sample's entry point.
2. Walk the positions in order and keep a byte where all samples agree.
   At the first position where they disagree, write `??` and move to the
   next position.
3. Strip trailing `??` tokens, but never below `--min-length`.
4. If the share of `??` tokens is at most `1 - threshold`, return the signature.
5. Otherwise try again with `L - 1`, down to `--min-length`.

The algorithm is implemented by
[`find_ep_only_signature`](../api.md#find_ep_only_signature).

!!! tip "Tuning"
    - No signature found? Lower `-t` to allow more wildcards, or lower `-m`.
    - Too many wildcards? Raise `-t`, or leave out samples that are not
      really packed with the same packer version.
    - Too generic (false positives)? Raise `-m` so that signatures are longer.
    - Check the new signature against unpacked samples before you publish it.
