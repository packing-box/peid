# Contributing

Contributions are welcome, especially **new signatures**.

## Reporting issues

Open an issue on [GitHub](https://github.com/packing-box/peid/issues) and
include:

- the PEiD version (`peid --help` prints it);
- the exact command and its output, ideally with `-v`;
- if possible, a link to (or the hash of) the sample.

## Adding signatures

1. Gather several samples packed with the same packer and version. The
   [packed PE dataset](https://github.com/packing-box/dataset-packed-pe) and
   [Docker Packing Box](https://github.com/packing-box/docker-packing-box)
   help with this.
2. Derive a signature:
   ```console
   $ peid-sig samples/*.exe --packer MyPacker --version v1.0 --author yourname
   ```
3. Check that it matches the samples and does **not** match unpacked binaries:
   ```console
   $ peid samples/*.exe --db test_userdb.txt
   ```
4. Add the entry to `src/peid/db/userdb.txt`, update the
   `N signatures in list` header line, and regenerate the cache. It is
   rebuilt automatically because the database is now newer:
   ```console
   $ python -c "from peid.db import SignaturesTree; SignaturesTree()"
   ```
   Commit both files.

## Development setup

```console
$ git clone https://github.com/packing-box/peid
$ cd peid
$ pip install -e .
$ pip install flake8
$ flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
```

CI (`.github/workflows/python-package.yml`) installs the package on Python
3.9 to 3.13 and runs this flake8 check.

## Releasing

The version is stored in `src/peid/VERSION.txt`. When a push to `main`
changes that file, CI builds the package and publishes it to PyPI.

## Building this documentation

```console
$ pip install -r docs/requirements.txt
$ mkdocs serve -f docs/mkdocs.yml          # live preview at http://127.0.0.1:8000
$ mkdocs build --strict -f docs/mkdocs.yml # what Read the Docs runs
```

Read the Docs builds the site from `.readthedocs.yaml` at the root of the
repository.
