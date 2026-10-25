# Python API

The `peid` package exposes three names:

```python
from peid import identify_packer, find_ep_only_signature, SignaturesDB
```

Lower-level building blocks are in `peid.db` (`DB`, `SignaturesTree`) and
`peid.exe` (`open_exe`, `PE`, `MSDOS`).

---

## `identify_packer`

```python
identify_packer(*paths_or_buffers, db=None, ep_only=True, sec_start_only=False,
                match_all=True, logger=None)
```

Identifies the packer of one or more executables.

| Parameter | Type | Description |
|---|---|---|
| `*paths_or_buffers` | `str` or `io.BufferedReader` | Paths, or files opened in binary mode (`open(p, "rb")`). |
| `db` | `str` or `None` | Path to a signatures database. `None` uses the embedded database. |
| `ep_only` | `bool` | Match entry-point signatures at the entry point. |
| `sec_start_only` | `bool` | Match section-start signatures at each section start. Cannot be `True` together with `ep_only`. |
| `match_all` | `bool` | `True` collects every match. `False` stops at the first one. |
| `logger` | `logging.Logger` | Optional logger for debug output. |

**Returns** a list of `(name, matches)` tuples, one per input. `name` is the
path, or the buffer's `.name`. `matches` is:

- a `list[str]` of signature names when `match_all=True` and something matched;
- a single `str` when `match_all=False` and something matched;
- `None` when nothing matched.

To use the section-start or whole-file modes, set `ep_only=False`:

| Mode | `ep_only` | `sec_start_only` |
|---|---|---|
| Entry point | `True` | `False` |
| Section start | `False` | `True` |
| Whole file | `False` | `False` |

**Raises** `OSError` if a file is neither a PE nor an MS-DOS executable,
`MalformedPE` (a `ValueError`) if the entry point lies outside every section,
and `ValueError` if `ep_only` and `sec_start_only` are both `True`.

```python
from peid import identify_packer

for path, matches in identify_packer("a.exe", "b.exe"):
    print(path, ", ".join(matches or []))

with open("c.exe", "rb") as f:
    [(_, matches)] = identify_packer(f, match_all=False)
```

!!! note
    Each call builds (or loads from cache) a `SignaturesTree`. To scan many
    files, pass them all in **one call** rather than calling the function
    once per file.

---

## `find_ep_only_signature`

```python
find_ep_only_signature(*files, minlength=16, maxlength=64,
                       common_bytes_threshold=.5, logger=None)
```

Derives an entry-point signature from several samples. This function powers
[`peid-sig`](cli/peid-sig.md#algorithm).

| Parameter | Description |
|---|---|
| `*files` | Paths to sample executables. |
| `minlength` | Minimum signature length, in bytes. |
| `maxlength` | Maximum signature length, in bytes. |
| `common_bytes_threshold` | Minimum fraction (0 to 1) of non-wildcard bytes. |
| `logger` | If given, unreadable files are logged and skipped. Without it, the error is raised. |

**Returns** the signature as a PEiD-formatted string, for example
`"60 BE ?? ?? ?? ?? 8D BE"`.
**Raises** `ValueError("Could not find a suitable signature")`.

```python
from glob import glob
from peid import find_ep_only_signature

sig = find_ep_only_signature(*glob("upx_samples/*.exe"), minlength=24)
```

---

## `SignaturesDB`

```python
SignaturesDB(path=None, encoding="utf-8", cache=True, logger=None)
```

A subclass of [`SignaturesTree`](#signaturestree) with editing operations.
It loads every entry into `self.signatures`, a `dict` that maps the
**signature byte tuple** to `(name, bytes, trailing_wildcards, ep_only,
section_start_only)`. It also keeps the header comments in `self.comments`.

| Member | Description |
|---|---|
| `len(db)` | Number of signatures. |
| `db == other` | `True` if both contain the same set of signature byte sequences. `other` can be a `SignaturesDB` or a path. |
| `compare(db, encoding=None)` | Generator of the **names** of signatures in `db` that are not in `self`. |
| `filter(pattern, text=True, size=None, remove=False)` | Generator of the signatures whose name matches the regex `pattern` (`None` matches all) and whose length satisfies `size`, a predicate `int -> bool`. Yields formatted strings when `text=True`, tuples otherwise. With `remove=True`, the yielded signatures are removed once the generator is exhausted. |
| `merge(*dbs)` | Adds the signatures of the given databases (paths or instances) that are not in `self` yet. Rewrites the header comments to list the sources. |
| `set(name, signature, ep_only=True, sec_start_only=False, author=None, version=None)` | Adds or replaces a signature. `version` and `author` are appended to the name as `name version -> author`. `signature` can be a list of byte tokens or a space-separated string. |
| `unset(name=None, signature=None)` | Removes a signature by its byte tuple, or every signature with that exact name. |
| `dump(filename=None, encoding=None)` | Writes the database to `filename`, or back to `self.path`, sorted by name. |

```python
from peid import SignaturesDB

db = SignaturesDB()                       # embedded database
print(len(db))

for name, sig, ep, sec, size in db.filter(r"(?i)upx", text=False, size=lambda n: n >= 32):
    print(size, name)

new = list(db.compare("other_userdb.txt"))  # names that are only in the other DB
```

!!! note
    `filter` is a generator. When `remove=True`, nothing is removed until it
    has been fully consumed, for example with `list(db.filter(..., remove=True))`.

---

## `SignaturesTree`

```python
from peid.db import SignaturesTree

SignaturesTree(path=None, encoding="utf-8", cache=True,
               keep_trailing_wildcards=False, logger=None)
```

A lightweight read-only matcher. It loads the database into a prefix tree
(see [How it works](internals.md#the-search-tree)).

| Parameter | Description |
|---|---|
| `path` | Database path. `None` uses `peid.db.DB`. `~` is expanded. |
| `cache` | Save the built tree as JSON next to the database. |
| `keep_trailing_wildcards` | Keep trailing `??` tokens in the tree. This uses a separate cache file with a `_tw` suffix. |

| Method | Description |
|---|---|
| `iter(tree)` | Reads the text database again and yields `(name, bytes, trailing_wildcards, ep_only, section_start_only)`. |
| `match(pe, ep_only=True, sec_start_only=False, match_all=True)` | Matches an executable (path or buffer). Returns the same values as `identify_packer`. |

---

## Executable parsing: `peid.exe`

```python
from peid.exe import open_exe

with open_exe("program.exe") as exe:
    print(type(exe).__name__, exe.entrypoint_offset, exe.sections_offsets)
    first_bytes = next(exe.read(16, exe.entrypoint_offset))
```

`open_exe(path_or_buffer, logger=None)` tries `PE` first, then `MSDOS`. It
raises `OSError` if neither parser accepts the file.

Both classes inherit from `EXE`:

| Member | Description |
|---|---|
| `path`, `size` | File path and size, in bytes. |
| `entrypoint_offset` | The entry point as a **file offset**. |
| `sections_offsets` | `list[int]` of file offsets where sections start. |
| `read(n=64, *offsets)` | Generator of up to `n` bytes read at each offset. Without offsets, it reads at **every** offset of the file. |
| `close()`, context manager | Close the file. |

`PE` also provides `pe_offset`, `number_of_sections`, `size_of_opt_header`
and `itersections()`, which yields `(virtual_size, virtual_address,
raw_size, raw_pointer)` for each section.

`MSDOS` also provides `initial_cs`, `initial_ip`, `header_size`,
`file_size` and the relocation table fields.

---

## Constants

| Name | Description |
|---|---|
| `peid.db.DB` | Absolute path of the embedded `userdb.txt`. |
| `peid.__info__.__version__` | Package version, read from `VERSION.txt`. |
