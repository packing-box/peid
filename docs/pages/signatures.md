# Signatures database

PEiD uses the classic PEiD `userdb.txt` text format. The embedded database is
at `peid/db/userdb.txt` in the installed package, and the Python API exposes
its path as `peid.db.DB`.

## File format

A database is an optional header of comments followed by signature entries:

```ini
; Merged with Python peid package on November 28, 2021
;  - BobSoft
;  - PEiDTab
; 5591 signatures in list

[Eronana-Packer -> dhondta]
signature = 60 68 00 ?? ?? ?? E8 17 FC FF FF 89 45 FC 61 FF 65 FC
ep_only = true

[Some section signature]
signature = 4D 5A ?? ?? 50 45
ep_only = false
section_start_only = true
```

### Header comments

Lines starting with `;` **at the top of the file** are comments. They usually
list the merged sources and the signature count. `SignaturesDB` keeps them
when it saves the file and updates the `N signatures in list` line.

### Entries

Each entry has these fields, in this order:

| Field | Required | Description |
|---|---|---|
| `[name]` | yes | Display name, usually `Packer version -> author`. See [name cleanup](cli/peid.md#name-cleanup). |
| `signature = ...` | yes | Space-separated byte tokens. The value can span several lines. |
| `ep_only = true\|false` | yes | `true`: match only at the entry point. |
| `section_start_only = true\|false` | no | `true`: match only at the start of each section. |

`ep_only` and `section_start_only` cannot both be `true`. Loading a database
with such an entry raises `ValueError`.

### Byte tokens

- Bytes are two **upper-case** hex digits (`8B`, `E8`, `FF`). PEiD formats the
  file bytes as `%02X` before comparing them, so lower-case tokens never match.
- `??` is a wildcard that matches any byte.
- Wildcards on one nibble only (such as `4?`) are **not** supported.
- **Trailing wildcards** are dropped when the search tree is built, because
  they add nothing to a prefix match.

## Which signatures are used

| `ep_only` | `section_start_only` | Used in mode |
|---|---|---|
| `true` | `false` / absent | Entry point (the `peid` default) |
| `false` | `true` | Section start (`peid -s`) |
| `false` | `false` / absent | Whole file (`peid -e`) |

Most of the embedded signatures are `ep_only = true`.

## Using a custom database

Pass a custom database with `--db` on the command line:

```console
$ peid program.exe --db my_sigs.txt
```

or with `db=` in the API:

```python
identify_packer("program.exe", db="my_sigs.txt")
```

On the command line, the file must exist. With the API, a missing file is
created as an empty database.

!!! note "Search-tree cache"
    The first time a database is loaded, PEiD saves its search tree to a
    hidden JSON file next to it (`my_sigs.txt` → `.my_sigs_txt.json`). The
    cache is rebuilt automatically when the database file is newer than it.
    See [Search-tree cache](internals.md#search-tree-cache).

## Merging databases

To combine several databases, use
[`SignaturesDB.merge`](api.md#signaturesdb). Duplicates are found by
signature bytes, not by name.

```python
from peid import SignaturesDB

db = SignaturesDB("base.txt")
db.merge("bobsoft.txt", "exeinfo.txt", "pev.txt")
db.dump("merged.txt")
```
