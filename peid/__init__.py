# -*- coding: UTF-8 -*-
import os
from pefile import PE, PEFormatError
from peutils import SignatureDatabase


__all__ = ["identify_packer", "open_sigs", "DB"]


__log = lambda l, m, lvl="debug": getattr(l, lvl)(m) if l else None
DB = os.path.join(os.path.dirname(__file__), "userdb.txt")


def identify_packer(path, db=None, logger=None):
    """ Identify the packer used in a given executable using the given signatures database.
    
    :param path: path to the executable file
    :param db:   path to the database
    :return:     return the matching packers
    """
    logger.debug("Parsing PE file '%s'..." % path)
    return "\n".join(open_sigs(db, logger).match(PE(path), ep_only=True) or [])


def open_sigs(path, logger=None):
    """ Open a signatures database.
    
    :param path: path to the database
    :return:     SignatureDatabase instance
    """
    path = path or DB
    logger.debug("Opening signature database '%s'..." % path)
    with open(path, encoding="latin-1") as f:
        sigs = SignatureDatabase(data=f.read())
    return sigs

