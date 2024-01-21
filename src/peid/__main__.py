# -*- coding: UTF-8 -*-
import logging
import re
from argparse import ArgumentParser, RawTextHelpFormatter
from os.path import exists
from time import perf_counter

from .__info__ import __author__, __copyright__, __email__, __license__, __source__, __version__
from .__init__ import *
from .db import DB


def _parser(name, description, examples):
    descr = f"{name} {__version__}\n\nAuthor   : {__author__} ({__email__})\nCopyright: {__copyright__}\nLicense  :" \
            f" {__license__}\nSource   : {__source__}\n\n{description}.\n\n"
    examples = "usage examples:\n- " + "\n- ".join(examples)
    return ArgumentParser(description=descr, epilog=examples, formatter_class=RawTextHelpFormatter, add_help=False)


def _setup(parser):
    args = parser.parse_args()
    if hasattr(args, "verbose"):
        logging.basicConfig()
        args.logger = logging.getLogger("peid")
        args.logger.setLevel([logging.INFO, logging.DEBUG][args.verbose])
    return args


def valid_file(path):
    if not exists(path):
        raise ValueError("input file does not exist")
    return path


def valid_percentage(percentage):
    p = float(percentage)
    if not 0. <= p <= 1.:
        raise ValueError("Not a percentage")
    return p


def main():
    """ Tool's main function """
    parser = _parser("PEiD", "This tool is an implementation in Python of the Packed Executable iDentifier (PEiD) in "
                     "the scope of packing detection for Windows PE files based on signatures",
                     ["peid program.exe", "peid program.exe -b", "peid program.exe --db custom_sigs_db.txt"])
    parser.add_argument("path", type=valid_file, nargs="+", help="path to portable executable")
    opt = parser.add_argument_group("optional arguments")
    opt.add_argument("-a", "--author", action="store_true", help="include author in the result")
    opt.add_argument("-d", "--db", default=DB, type=valid_file,
                     help="path to the custom database of signatures (default: None ; use the embedded DB)")
    grp = opt.add_mutually_exclusive_group()
    grp.add_argument("-e", "--ep-only", action="store_false",
                     help="only consider signatures from entry point (default: True)")
    opt.add_argument("-m", "--match-once", action="store_true", help="match only one signature")
    grp.add_argument("-s", "--section-start-only", dest="sec_start_only", action="store_true",
                     help="consider only signatures from section starts (default: False)")
    opt.add_argument("-v", "--version", action="store_true", help="include the version in the result")
    extra = parser.add_argument_group("extra arguments")
    extra.add_argument("-b", "--benchmark", action="store_true",
                       help="enable benchmarking, output in seconds (default: False)")
    extra.add_argument("-h", "--help", action="help", help="show this help message and exit")
    extra.add_argument("--verbose", action="store_true", help="display debug information (default: False)")
    args = _setup(parser)
    # execute the tool
    if args.benchmark:
        t1 = perf_counter()
    results = identify_packer(*args.path, db=args.db, ep_only=args.ep_only, sec_start_only=args.sec_start_only,
                              match_all=not args.match_once, logger=args.logger)
    for pe, r in results:
        r = r or []
        if not args.author:
            r = list(map(lambda x: re.sub(r"\s*\-(\-?\>|\s*by)\s*(.*)$", "", x), r))
        if not args.version:
            VER = r"\s*([vV](ersion)?|R)?\s?(20)?\d{1,2}(\.[xX0-9]{1,3}([a-z]?\d)?){0,3}[a-zA-Z\+]?" \
                  r"(\s*\(?(\s*([Aa]lpha|[Bb]eta|final|lite|LITE|osCE|Demo|DEMO)){1,2}(\s*[a-z]?\d)?\)?)?"
            VER = re.compile(r"^(.*?)\s+" + VER + r"(\s*[-_\/\~]" + VER + r"){0,3}(\s+\(unregistered\))?")
            r = list(map(lambda x: re.sub(r"\s+\d+(\s+SE)?$", "", VER.sub(r"\1", x)), r))
        if len(results) == 1:
            dt = str(perf_counter() - t1) if args.benchmark else ""
            if dt != "":
                r.append(dt)
            if len(r) > 0:
                print("\n".join(r))
            return 0
        else:
            print(f"{pe} {','.join(r)}")
    dt = str(perf_counter() - t1) if args.benchmark else ""
    if dt != "":
        print(dt)
    return 0


def peiddb():
    """ Additional tool for inspecting a database of signatures """
    parser = _parser("PEiD-DB", "This tool aims to inspect the database of signatures of the Packed Executable "
                     "iDentifier (PEiD)", ["peid-db --filter UPX", "peid-db --db custom-userdb.txt --filter '(?i)upx'"])
    opt = parser.add_argument_group("optional arguments")
    opt.add_argument("-d", "--db", default=DB, type=valid_file,
                     help="path to the custom database of signatures (default: None ; use the embedded DB)")
    opt.add_argument("-f", "--filter", help="pattern for filtering signatures (default: None ; display all)")
    extra = parser.add_argument_group("extra arguments")
    extra.add_argument("-h", "--help", action="help", help="show this help message and exit")
    args = _setup(parser)
    db = SignaturesDB(args.db)
    c = 0
    for sig in db.filter(args.filter):
        print(sig, end="")
        c += 1
    print(f"{c} signatures filtered")


def peidsig():
    """ Additional tool for creating signatures """
    parser = _parser("PEiD-Sig", "This tool aims to create signatures for the Packed Executable iDentifier (PEiD)",
                     ["peid-sig *.exe", "peid-sig *.exe --db path/to/userdb.txt --packer PE-Packer",
                      "peid-sig prg1.exe prg2.exe prg3.exe --packer PE-Packer --version v1.0 --author dhondta"])
    parser.add_argument("path", type=valid_file, nargs="+", help="path to packed portable executables")
    sig = parser.add_argument_group("signature arguments")
    sig.add_argument("-m", "--min-length", type=int, default=16, help="minimum length of bytes to be considered for the"
                     " signature (default: 16)")
    sig.add_argument("-M", "--max-length", type=int, default=64, help="maximum length of bytes to be considered for the"
                     " signature (default: 64)")
    sig.add_argument("-t", "--bytes-threshold", type=valid_percentage, default=.5, help="proportion of common bytes"
                     " to be considered from the samples ; 0 <= x <= 1 (default: .5)")
    opt = parser.add_argument_group("optional arguments")
    opt.add_argument("-a", "--author", help="author of the signature")
    opt.add_argument("-d", "--db", help="target signatures database")
    opt.add_argument("-p", "--packer", help="packer name for the new signature")
    opt.add_argument("-v", "--version", help="packer version to be mentioned in the signature\n\nNB: if no parameter or"
                     " at least packer's name is given, only the signature itself is output ;\n     otherwise, a PEiD-"
                     "formatted signature is displayed\n    in addition, if --db is defined, the signature is saved")
    extra = parser.add_argument_group("extra arguments")
    extra.add_argument("-h", "--help", action="help", help="show this help message and exit")
    extra.add_argument("--verbose", action="store_true", help="display debug information (default: False)")
    args = _setup(parser)
    try:
        s = find_ep_only_signature(*args.path, minlength=args.min_length, maxlength=args.max_length,
                                   common_bytes_threshold=args.bytes_threshold, logger=args.logger)
    except ValueError:
        print("[ERROR] Could not find a suitable signature\n")
        return 1
    if args.packer:
        n = args.packer
        if args.version:
            n += " " + args.version
        if args.author:
            n += " -> " + args.author
        if args.db:
            db = SignaturesDB(args.db, logger=args.logger)
            db.set(args.packer, s, True, args.author, args.version)
            db.dump()
        s = "[%s]\nsignature = %s\nep_only = true" % (n, s)
    print(s)
    return 0

