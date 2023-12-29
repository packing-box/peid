# -*- coding: UTF-8 -*-
import os

from .db import SignaturesTree, SignaturesDB
from .pe import PE

__all__ = ["find_ep_only_signature", "identify_packer", "SignaturesDB"]


def find_ep_only_signature(*files, length=64, common_bytes_threshold=.5, logger=None):
    """ Find a signature among the given files.
    
    :param files:                  list of files to be compared in order to deduce a signature
    :param length:                 signature length
    :param common_bytes_threshold: minimal portion of bytes common to each file to be considered a valid signature
    :return:                       signature string (PEiD format)
    """
    #TODO: improve this algorithm to separate common bytes into [2-MAX] clusters of best patterns, thus yielding
    #       BEST_N (belongs to [2-MAX]) signatures and configurable through the MAX parameter
    sig, data = [], []
    for f in files:
        try:
            with PE(f) as pe:
                data.append(pe.read(length, pe.entrypoint_offst))
        except ValueError as e:
            if logger:
                logger.debug(f"{f}: {e}")
    for i in range(length):
        for d in data:
            if len(sig) <= i:
                sig.append(d[i])
            elif d[i] != sig[-1]:
                sig[-1] = "??"
    if len(sig) == 0 or sig.count("??") / len(sig) > 1 - common_bytes_threshold:
        if logger:
            logger.warning("Could not find a suitable signature")
            return
        else:
            raise ValueError("Could not find a suitable signature")
    return " ".join(sig)


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

