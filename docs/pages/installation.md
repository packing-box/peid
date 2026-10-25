# Installation

## Requirements

- Python **3.8 or later**. CI runs on 3.9 to 3.13.
- [`msgspec`](https://pypi.org/project/msgspec/), which pip installs automatically.

## From PyPI

```console
$ pip install peid
```

This installs the `peid` Python package and three console scripts: `peid`,
`peid-db` and `peid-sig`.

## From source

```console
$ git clone https://github.com/packing-box/peid
$ cd peid
$ pip install .
```

For development, use an editable install:

```console
$ pip install -e .
```

## Checking the installation

```console
$ peid --help
PEiD 2.3.1

Author   : Alexandre D'Hondt (alexandre.dhondt@gmail.com)
...
```

```python
>>> import peid
>>> from peid.__info__ import __version__
>>> __version__
'2.3.1'
```

## Write access to the database folder

When a signatures database is loaded for the first time, PEiD writes a JSON
cache of its search tree **next to the database file** (see
[Search-tree cache](internals.md#search-tree-cache)). For the embedded
database, that folder is the installed `peid/db/` package directory. The
wheel already ships a cache for the embedded database (`.userdb_txt.json`).
If the folder is read-only, PEiD still works without the cache, but each run
rebuilds the search tree, which is slower.
