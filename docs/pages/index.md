# Packed Executable iDentifier

<p align="center"><img src="img/logo.png" alt="PEiD logo" width="200"></p>

**PEiD** is a Python implementation of the well-known
[Packed Executable iDentifier](https://www.aldeid.com/wiki/PEiD). It detects
packers, cryptors and compilers in Windows PE (and MS-DOS MZ) executables by
matching byte signatures.

[![PyPi](https://img.shields.io/pypi/v/peid.svg)](https://pypi.python.org/pypi/peid/)
[![Python Versions](https://img.shields.io/pypi/pyversions/peid.svg)](https://pypi.python.org/pypi/peid/)
[![Build Status](https://github.com/packing-box/peid/actions/workflows/python-package.yml/badge.svg)](https://github.com/packing-box/peid/actions/workflows/python-package.yml)
[![Security](https://github.com/packing-box/peid/actions/workflows/security.yml/badge.svg)](https://github.com/packing-box/peid/actions/workflows/security.yml)
[![DOI](https://zenodo.org/badge/383567798.svg)](https://zenodo.org/badge/latestdoi/383567798)
[![License](https://img.shields.io/pypi/l/peid.svg)](https://pypi.python.org/pypi/peid/)

## Features

- **Over 5,500 bundled signatures** merged from several public sources (see
  [Signature sources](#signature-sources)).
- **Three command-line tools**:
    - [`peid`](cli/peid.md) identifies the packer of one or more executables;
    - [`peid-db`](cli/peid-db.md) inspects, filters and prunes a signatures database;
    - [`peid-sig`](cli/peid-sig.md) derives a new signature from a set of packed samples.
- **A small Python API** ([`identify_packer`](api.md#identify_packer),
  [`find_ep_only_signature`](api.md#find_ep_only_signature),
  [`SignaturesDB`](api.md#signaturesdb)) for use in your own scripts.
- **Fast matching** with a prefix tree built from the database and cached as
  JSON (through [msgspec](https://jcristharif.com/msgspec/)).
- **Pure Python, one dependency.** PE parsing is built in, with no need for
  `pefile` or LIEF.

## Quick start

```console
$ pip install peid
$ peid program.exe            # print the matching packer names
$ peid program.exe -a --version  # keep the author and version in the names
```

From Python:

```python
from peid import identify_packer

for path, matches in identify_packer("program.exe"):
    print(path, matches)
```

## Signature sources

The embedded database (`peid/db/userdb.txt`) merges signatures from:

- [wolfram77web/app-peid](https://github.com/wolfram77web/app-peid/)
- [merces/pev](https://github.com/merces/pev/)
- [ExeinfoASL/ASL](https://github.com/ExeinfoASL/ASL)
- [Ice3man543/MalScan](https://github.com/Ice3man543/MalScan)
- [PEiD Tab](https://www.top4download.com/peid-tab/screenshot-gaqrbxek.html)

It also has a few signatures built from the
[packed PE dataset](https://github.com/packing-box/dataset-packed-pe).

## Related projects

PEiD is part of the [packing-box](https://github.com/packing-box) ecosystem:

- [Awesome Executable Packing](https://github.com/packing-box/awesome-executable-packing): a curated list of resources about executable packing.
- [Bintropy](https://github.com/packing-box/bintropy): estimates how likely a binary is to contain compressed or encrypted bytes.
- [Dataset of packed ELF files](https://github.com/packing-box/dataset-packed-elf) and [Dataset of packed PE files](https://github.com/packing-box/dataset-packed-pe).
- [Docker Packing Box](https://github.com/packing-box/docker-packing-box): a Docker image of packers and tools for building datasets of packed executables.
- [DSFF](https://github.com/packing-box/python-dsff): the DataSet File Format library.
- [PyPackerDetect](https://github.com/packing-box/pypackerdetect): a heuristic packing detector for PE files.
- [REMINDer](https://github.com/packing-box/reminder): a packing detector based on a simple entropy heuristic.

## License

PEiD is released under the
[GNU General Public License v3 or later](https://www.gnu.org/licenses/gpl-3.0.html).
