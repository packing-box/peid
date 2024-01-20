# -*- coding: UTF-8 -*-
import os

from .db import SignaturesTree, SignaturesDB
from .pe import PE

__all__ = ["find_ep_only_signature", "identify_packer", "SignaturesDB"]


def find_ep_only_signature(*files, minlength=16, maxlength=64, common_bytes_threshold=.5, logger=None):
    """ Find a signature among the given files.
    
    :param files:                  list of files to be compared in order to deduce a signature
    :param mainlength:             minimum signature length
    :param maxlength:              maximum signature length
    :param common_bytes_threshold: minimal portion of bytes common to each file to be considered a valid signature
    :return:                       signature string (PEiD format)
    """
    # load maxlength-series of bytes for each input file
    data = []
    for f in files:
        try:
            with PE(f) as pe:
                bytes_from_ep = [f"{b:02X}" for b in list(pe.read(maxlength, pe.entrypoint_offset))[0]]
            maxlength = max(min(len(bytes_from_ep), maxlength), minlength)
            data.append(bytes_from_ep)
        except (TypeError, ValueError) as e:
            if logger:
                logger.debug(f"{f}: {e}")
    # now determine a signature
    length = maxlength
    while length >= minlength:
        sig = []
        for i in range(length):
            for d in data:
                if i >= len(d):
                    continue
                if len(sig) <= i:
                    sig.append(d[i])
                elif d[i] != sig[-1]:
                    sig[-1] = "??"
                    break
        # right-strip "??" tokens up to the minimum length
        while len(sig) > minlength and sig[-1] == "??":
            sig = sig[:-1]
        if sig.count("??") / len(sig) <= 1 - common_bytes_threshold:
            # if it satisfies the condition, then right-strip remaining "??" tokens
            while len(sig) > minlength and sig[-1] == "??":
                sig = sig[:-1]
            return " ".join(sig)
        length -= 1
    raise ValueError("Could not find a suitable signature")


def identify_packer(*paths, db=None, ep_only=True, sec_start_only=False, match_all=True, logger=None):
    """ Identify the packer used in a given executable using the given signatures database.
    
    :param path:    path to the executable file(s)
    :param db:      path to the database
    :param ep_only: consider only entry point signatures
    :return:        return the matching packers
    """
    db, results = SignaturesTree(db), []
    for path in paths:
        results.append((path, db.match(path, ep_only, sec_start_only, match_all)))
    return results

