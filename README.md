<p align="center"><img src="https://github.com/dhondta/peid/raw/main/logo.png"></p>
<h1 align="center">Packed Executable iDentifier <a href="https://twitter.com/intent/tweet?text=Packed%20Executable%20iDentifier%20-%20Python%20implementation%20of%20PEiD,%20the%20well-known%20packer%20identification%20tool%20for%20PE%20files%20based%20on%20signatures.%0D%0Ahttps%3a%2f%2fgithub%2ecom%2fdhondta%2fpeid%0D%0A&hashtags=python,pe,peid,packer,packingdetection"><img src="https://img.shields.io/badge/Tweet--lightgrey?logo=twitter&style=social" alt="Tweet" height="20"/></a></h1>
<h3 align="center">Detect packers on PE files using signatures.</h3>

[![PyPi](https://img.shields.io/pypi/v/peid.svg)](https://pypi.python.org/pypi/peid/)
[![Build Status](https://travis-ci.com/dhondta/peid.svg?branch=main)](https://travis-ci.com/dhondta/peid)
[![Python Versions](https://img.shields.io/pypi/pyversions/peid.svg)](https://pypi.python.org/pypi/peid/)
[![Requirements Status](https://requires.io/github/dhondta/peid/requirements/?branch=main)](https://requires.io/github/dhondta/peid/requirements/?branch=main)
[![Known Vulnerabilities](https://snyk.io/test/github/dhondta/peid/badge.svg?targetFile=requirements.txt)](https://snyk.io/test/github/dhondta/peid?targetFile=requirements.txt)
[![DOI](https://zenodo.org/badge/383567798.svg)](https://zenodo.org/badge/latestdoi/383567798)
[![License](https://img.shields.io/pypi/l/peid.svg)](https://pypi.python.org/pypi/peid/)

This tool is an implementation in Python of the Packed Executable iDentifier ([PEiD](https://www.aldeid.com/wiki/PEiD)) in the scope of packing detection for Windows PE files based on signatures. It uses a combination of more than 5.500 signatures merged from the following sources:

- [wolfram77web/app-peid](https://github.com/wolfram77web/app-peid/)
- [merces/pev](https://github.com/merces/pev/)
- [ExeinfoASL/ASL](https://github.com/ExeinfoASL/ASL)
- [Ice3man543/MalScan](https://github.com/Ice3man543/MalScan)
- [PEiD Tab](https://www.top4download.com/peid-tab/screenshot-gaqrbxek.html)

It relies on [`pefile`](https://github.com/erocarrera/pefile) for abstracting PE files and reading signatures databases.

```sh
$ pip install peid
```

The main tool checks the input executable against the embedded or user-defined signatures database.

```sh
$ peid --help
[...]

$ peid program.exe
[...]

$ peid program.exe --db custom_sigs_db.txt
```

The second tool allows to create and integrate new signatures.

```sh
$ peidsig *.exe --db path/to/userdb.txt --packer UPX --version v3.97 --author jsmith
```


## :star: Related Projects

You may also like these:

- [Awesome Executable Packing](https://github.com/dhondta/awesome-executable-packing): A curated list of awesome resources related to executable packing.
- [Bintropy](https://github.com/dhondta/bintropy): Analysis tool for estimating the likelihood that a binary contains compressed or encrypted bytes.
- [Dataset of packed ELF files](https://github.com/dhondta/dataset-packed-elf): Dataset of ELF samples packed with many different packers.
- [Dataset of packed PE files](https://github.com/dhondta/dataset-packed-pe): Dataset of PE samples packed with many different packers.
- [Docker Packing Box](https://github.com/dhondta/docker-packing-box): Docker image gathering packers and tools for making datasets of packed executables.
- [PyPackerDetect](https://github.com/dhondta/PyPackerDetect): Packing detection tool for PE files.


## :clap:  Supporters

[![Stargazers repo roster for @dhondta/peid](https://reporoster.com/stars/dark/dhondta/peid)](https://github.com/dhondta/peid/stargazers)

[![Forkers repo roster for @dhondta/peid](https://reporoster.com/forks/dark/dhondta/peid)](https://github.com/dhondta/peid/network/members)

<p align="center"><a href="#"><img src="https://img.shields.io/badge/Back%20to%20top--lightgrey?style=social" alt="Back to top" height="20"/></a></p>
