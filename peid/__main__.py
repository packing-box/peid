# -*- coding: UTF-8 -*-
import logging
import re
import sys
from argparse import ArgumentParser, RawTextHelpFormatter
from os.path import exists
from time import perf_counter

from .__info__ import __author__, __copyright__, __email__, __license__, __source__, __version__
from .__init__ import identify_packer, DB


def valid_file(path):
    if not exists(path):
        raise ValueError("input file does not exist")
    return path


def main():
    """ Tool's main function """
    descr = "PEiD {}\n\nAuthor   : {} ({})\nCopyright: {}\nLicense  : {}\nSource   : {}\n" \
            "\nThis tool is an implementation in Python of the Packed Executable iDentifier (PEiD) in the scope of " \
            "packing detection for Windows PE files based on signatures.\n\n"
    descr = descr.format(__version__, __author__, __email__, __copyright__, __license__, __source__)
    examples = "usage examples:\n- " + "\n- ".join([
        "peid program.exe",
        "peid program.exe -b",
        "peid program.exe --db custom_sigs_db.txt",
    ])
    parser = ArgumentParser(description=descr, epilog=examples, formatter_class=RawTextHelpFormatter, add_help=False)
    parser.add_argument("path", type=valid_file, help="path to portable executable")
    opt = parser.add_argument_group("optional arguments")
    opt.add_argument("-a", "--author", action="store_true", help="include author in the result")
    opt.add_argument("-d", "--db", default=DB, type=valid_file,
                     help="path to the custom database of signatures (default: None ; use the embedded DB)")
    opt.add_argument("-e", "--ep-only", action="store_false",
                     help="consider only entry point signatures (default: True)")
    opt.add_argument("-v", "--version", action="store_true", help="include the version in the result")
    extra = parser.add_argument_group("extra arguments")
    extra.add_argument("-b", "--benchmark", action="store_true",
                       help="enable benchmarking, output in seconds (default: False)")
    extra.add_argument("-h", "--help", action="help", help="show this help message and exit")
    extra.add_argument("--verbose", action="store_true", help="display debug information (default: False)")
    args = parser.parse_args()
    logging.basicConfig()
    args.logger = logging.getLogger("peid")
    args.logger.setLevel([logging.INFO, logging.DEBUG][args.verbose])
    code = 0
    # execute the tool
    if args.benchmark:
        t1 = perf_counter()
    try:
        r = identify_packer(args.path, args.db, args.ep_only, args.logger)
        if not args.author:
            r = list(map(lambda x: re.sub(r"\s*\-(\-?\>|\s*by)\s*(.*)$", "", x), r))
        if not args.version:
            VER = r"\s*([vV](ersion)?|R)?\s?(20)?\d{1,2}(\.[xX0-9]{1,3}([a-z]?\d)?){0,3}[a-zA-Z\+]?" \
                  r"(\s*\(?(\s*([Aa]lpha|[Bb]eta|final|lite|LITE|osCE|Demo|DEMO)){1,2}(\s*[a-z]?\d)?\)?)?"
            VER = re.compile(r"^(.*?)\s+" + VER + r"(\s*[-_\/\~]" + VER + r"){0,3}(\s+\(unregistered\))?")
            r = list(map(lambda x: re.sub(r"\s+\d+(\s+SE)?$", "", VER.sub(r"\1", x)), r))
        dt = str(perf_counter() - t1) if args.benchmark else ""
        if dt != "":
            r.append(dt)
        if len(r) > 0:
            print("\n".join(r))
    except Exception as e:
        args.logger.exception(e)
        code = 1
    return code

