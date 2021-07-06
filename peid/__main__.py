# -*- coding: UTF-8 -*-
import logging
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
    parser = ArgumentParser(description=descr, epilog=examples, formatter_class=RawTextHelpFormatter)
    parser.add_argument("path", type=valid_file, help="path to portable executable")
    parser.add_argument("-b", "--benchmark", action="store_true",
                        help="enable benchmarking, output in seconds (default: False)")
    parser.add_argument("-d", "--db", default=DB, type=valid_file,
                        help="path to signatures custom database (default: None)")
    parser.add_argument("-v", "--verbose", action="store_true", help="display debug information (default: False)")
    args = parser.parse_args()
    logging.basicConfig()
    args.logger = logging.getLogger("peid")
    args.logger.setLevel([logging.INFO, logging.DEBUG][args.verbose])
    code = 0
    # execute the tool
    if args.benchmark:
        t1 = perf_counter()
    try:
        r = identify_packer(args.path, args.db, args.logger)
        if not r:
            raise Exception("no result")
        dt = str(perf_counter() - t1) if args.benchmark else ""
        if not isinstance(r, (tuple, list)):
            r = [r]
        r = list(map(str, r))
        if dt != "":
            r.append(dt)
        print(" ".join(r))
    except Exception as e:
        if str(e) != "no result":
            args.logger.exception(e)
        code = 1
    return code

