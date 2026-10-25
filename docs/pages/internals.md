# How it works

## Overview

```text
 userdb.txt ──parse──▶ SignaturesTree ──cache──▶ .userdb_txt.json
                            │
 program.exe ─open_exe─▶ PE / MSDOS ──read bytes at offsets──▶ tree walk ──▶ matches
```

1. **Load the database.** If a JSON cache exists, it is decoded with msgspec.
   Otherwise the text file is parsed and a prefix tree is built and cached.
2. **Parse the executable** just enough to find the offsets to inspect.
3. **Read** `max_depth` bytes (the length of the longest signature) at each
   offset.
4. **Walk the tree** with those bytes and collect the name of every
   signature found on the way.

## The search tree

Signatures are stored in a nested dictionary (a trie) with one key per byte
token. There are three sub-trees, one per [matching mode](cli/peid.md#matching-modes):

```python
{
  "ep_only":            {"60": {"BE": {"??": {...}}}, "55": {...}},
  "section_start_only": {...},
  "":                   {...},          # whole-file signatures
  "max_depth": 1024,
}
```

The node where a signature ends has a `"value"` key holding the signature
name. Two signatures that share a prefix share the same nodes, so each input
byte is compared once per branch, not once per signature.

### Matching

For each read byte sequence, the matcher walks the tree from the root:

- If the current node has a `"value"`, that name is recorded as a match.
- If the node has a `"??"` child, the matcher also continues on that
  wildcard branch from the next byte.
- If the node has a child for the current byte, the matcher goes down to it.
  Otherwise the branch stops.

A file can therefore match several signatures, for example a short generic
one and a longer specific one. With `match_all=False`, the matcher returns
the most recent match.

## Executable parsing

PEiD has its own minimal parsers so that it needs no other dependency.

### PE

1. Check the `MZ` magic.
2. Read `e_lfanew` at offset `0x3C`, then check the `PE\0\0` signature there.
3. Read `NumberOfSections` and `SizeOfOptionalHeader` from the COFF header.
4. **Entry point**: read `AddressOfEntryPoint` (a relative virtual address,
   RVA) at `pe_offset + 40`. Find the section whose virtual range contains
   it, then convert it to a file offset:
   `PointerToRawData + (RVA − VirtualAddress)`. If no section contains the
   RVA, `MalformedPE` is raised.
5. **Section starts**: `PointerToRawData` of each 40-byte entry of the
   section table.

### MS-DOS

If the file has the `MZ` magic but no valid PE header, it is parsed as an
MS-DOS executable:

- **Entry point**: `header_size + (CS << 4) + IP`, where `header_size` is
  the header length in 16-byte paragraphs, times 16.
- **Section starts**: the targets of the relocation table entries
  (`header_size + (segment << 4) + offset`).

## Search-tree cache

Parsing more than 5,500 signatures and building the tree takes time, so the
tree is saved to a JSON file next to the database:

| Database | Cache file |
|---|---|
| `userdb.txt` | `.userdb_txt.json` |
| `userdb.txt` (with `keep_trailing_wildcards=True`) | `.userdb_txt_tw.json` |
| `/path/to/my.db.txt` | `/path/to/.my_db_txt.json` |

The cache is used only if it is **at least as recent** as the database file.
When you edit a database, the next load rebuilds the tree and rewrites the
cache. If the cache cannot be written (for example in a read-only folder),
PEiD logs a debug message and keeps going without it.

!!! note
    `SignaturesDB` reads `self.signatures` from the text file every time.
    Only matching (`SignaturesTree.match`, `identify_packer`, `peid`) uses
    the cache.

## Performance notes

- The **entry-point** mode reads a single sequence per file. It is the
  fastest mode and what most packer signatures are written for.
- The **section-start** mode reads one sequence per section.
- The **whole-file** mode (`peid -e`) reads `max_depth` bytes at **every
  offset** of the file. On a multi-megabyte binary this means millions of
  reads and tree walks. Use it only on small files.
- `peid -b` reports the elapsed time, including the database load.

## Limitations

- Detection relies on signatures only. A packer without a signature, or one
  that hides its stub, is not detected. For a heuristic second opinion, see
  [Bintropy](https://github.com/packing-box/bintropy) or
  [REMINDer](https://github.com/packing-box/reminder).
- Short signatures can cause false positives. Use
  `peid-db --size '<N'` to review them.
- Only PE and MS-DOS executables are supported. ELF and Mach-O files are not.
