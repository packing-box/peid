# `peid-db`: inspect a database

`peid-db` lists, filters and prunes the signatures of a database.

```console
$ peid-db [-d DB] [-f FILTER] [-s SIZE] [-r] [-o OUTPUT] [-h]
```

## Options

| Option | Default | Description |
|---|---|---|
| `-d DB`, `--db DB` | embedded DB | Path to the signatures database to inspect. |
| `-f PATTERN`, `--filter PATTERN` | all | A Python regular expression matched against signature **names** with `re.search`. |
| `-s EXPR`, `--size EXPR` | all | A size expression on the signature length, in bytes (see below). |
| `-r`, `--remove` | off | Remove the matching signatures instead of only listing them. Use with `-o` to save the result. |
| `-o PATH`, `--output PATH` | none | Write the resulting database to `PATH`. |
| `-h`, `--help` | | Show the help message and exit. |

### Size expressions

`--size` takes an operator followed by a byte count, with no spaces:

| Expression | Meaning |
|---|---|
| `==16` | exactly 16 bytes |
| `<16` / `<=16` | shorter than, or at most, 16 bytes |
| `>64` / `>=64` | longer than, or at least, 64 bytes |

The length counts every token of the signature, `??` wildcards included, but
not trailing wildcards.

## Output

Each selected signature is printed in database format. When `--size` is
used, a `size = <n>B` line is added. A summary line comes last:

```console
$ peid-db --filter UPX
[ x64 - UPX exe - NRV2E/7 compression ]
signature = 53 56 57 55 48 8D 35 ?? ?? ?? FF 48 8D BE ?? ?? ?? FF
ep_only = true

[...]
<N> signatures filtered
```

The summary says `removed` instead of `filtered` only when both `--remove`
and `--output` are given.

## Examples

Case-insensitive search:

```console
$ peid-db --filter '(?i)upx'
```

Inspect a custom database:

```console
$ peid-db --db path/to/userdb.txt --filter UPX
```

List very short signatures, which tend to cause false positives:

```console
$ peid-db --size '<8'
```

Remove them and save a cleaned copy:

```console
$ peid-db --size '<8' --remove --output cleaned.txt
```

!!! tip
    Quote size expressions in the shell: `<` and `>` are redirections.
