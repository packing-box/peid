# `peid`: identify packers

`peid` checks one or more executables against a signatures database and
prints the names of the packers (or compilers, cryptors, ...) that match.

```console
$ peid [-a] [-d DB] [-e | -s] [-m] [--version] [-b] [-v] [-h] path [path ...]
```

## Arguments

| Argument | Description |
|---|---|
| `path` | One or more PE or MS-DOS executables. Each must exist. |

### Optional arguments

| Option | Default | Description |
|---|---|---|
| `-a`, `--author` | off | Keep the signature author in the result (for example `-> jsmith` or `by jsmith`). |
| `-d DB`, `--db DB` | embedded DB | Path to a custom [signatures database](../signatures.md). |
| `-e`, `--ep-only` | EP-only **on** | **Turns off** entry-point-only matching (see the note below). |
| `-s`, `--section-start-only` | off | Match only the signatures flagged `section_start_only = true`, at the start of each section. Cannot be combined with `-e`. |
| `-m`, `--match-once` | off | Stop at the first match instead of collecting all of them. |
| `--version` | off | Keep the packer version in the result (for example `v3.97`). |

### Extra arguments

| Option | Description |
|---|---|
| `-b`, `--benchmark` | Print the elapsed time, in seconds, after the results. |
| `-v`, `--verbose` | Show debug information: parsed offsets, entry point and bytes read. |
| `-h`, `--help` | Show the help message and exit. |

!!! note "What `-e` / `--ep-only` really does"
    By default, `peid` reads only the bytes at the executable's **entry point**
    and compares them with the signatures marked `ep_only = true`. This is the
    usual PEiD mode, and it is fast.

    Passing `-e` **turns this mode off**. `peid` then slides over **every
    offset of the file** and matches the signatures that are neither
    `ep_only` nor `section_start_only`. This is much slower on large files.

## Matching modes

| Mode | How to select it | Bytes compared | Signatures used |
|---|---|---|---|
| Entry point (default) | *(nothing)* | The bytes at the entry point | `ep_only = true` |
| Section start | `-s` | The bytes at the start of each section (for MS-DOS: each relocation target) | `section_start_only = true` |
| Whole file | `-e` | Every offset in the file | All other signatures |

See [How it works](../internals.md) for details.

## Output

With **one** input file, `peid` prints one match per line:

```console
$ peid sample.exe
UPX
```

With **several** input files, it prints one line per file: the path, then the
matches separated by commas.

```console
$ peid a.exe b.exe c.exe
a.exe UPX
b.exe
c.exe ASPack,Microsoft Visual C++
```

A file with no match prints nothing (one input) or only its path (several
inputs). The exit code is `0` in both cases.

### Name cleanup

Signature names in the database often carry a version and an author, for
example `UPX v3.97 -> jsmith`. By default, `peid` removes both so that
results stay consistent across signatures from different sources:

- **Author**: removes a trailing ` -> author`, ` --> author` or ` - by author`.
  Use `-a` to keep it.
- **Version**: removes version patterns such as `v1.2`, `Version 2.x`,
  `1.0 beta`, `R3`, version ranges (`v1.0 - v2.0`) and `(unregistered)`.
  Use `--version` to keep it.

## Examples

Use a custom database:

```console
$ peid program.exe --db custom_sigs_db.txt
```

Show the full signature names and time the run:

```console
$ peid program.exe -a --version -b
```

Scan a whole folder:

```console
$ peid samples/*.exe
```

Debug why a file does not match:

```console
$ peid program.exe -v
DEBUG:peid:ep_only=True, sec_start_only=False, match_all=True
DEBUG:peid:Entry point: 0x0001a2b0
DEBUG:peid:Entry point offset: 70320
DEBUG:peid:60 BE 00 ...
```
