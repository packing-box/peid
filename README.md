[![PyPi](https://img.shields.io/pypi/v/peid.svg)](https://pypi.python.org/pypi/peid/)
[![Build Status](https://travis-ci.com/dhondta/peid.svg?branch=main)](https://travis-ci.com/dhondta/peid)
[![Python Versions](https://img.shields.io/pypi/pyversions/peid.svg)](https://pypi.python.org/pypi/peid/)
[![Requirements Status](https://requires.io/github/dhondta/peid/requirements/?branch=main)](https://requires.io/github/dhondta/peid/requirements/?branch=main)
[![Known Vulnerabilities](https://snyk.io/test/github/dhondta/peid/badge.svg?targetFile=requirements.txt)](https://snyk.io/test/github/dhondta/peid?targetFile=requirements.txt)
[![License](https://img.shields.io/pypi/l/peid.svg)](https://pypi.python.org/pypi/peid/)

## Introduction

This tool is an implementation in Python of the Packed Executable iDentifier ([PEiD](https://www.aldeid.com/wiki/PEiD)) in the scope of packing detection for Windows PE files based on signatures. It uses the [`userdb.txt` database](https://github.com/wolfram77web/app-peid/blob/master/userdb.txt) from [this repository](https://github.com/wolfram77web/app-peid).

It relies on [`pefile`](https://github.com/erocarrera/pefile) for abstracting PE files and reading signatures databases.

## Setup

This tool is available as a package from PyPi.

```sh
$ pip install peid
```

## Usage

```sh
$ peid --help
[...]

$ peid program.exe
[...]

$ peid program.exe --db custom_sigs_db.txt
```

