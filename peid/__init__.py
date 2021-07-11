# -*- coding: UTF-8 -*-
import os
from pefile import PE
from peutils import SignatureDatabase


__all__ = ["identify_packer", "open_sigs", "DB"]


__log = lambda l, m, lvl="debug": getattr(l, lvl)(m) if l else None
DB = os.path.join(os.path.dirname(__file__), "userdb.txt")


def identify_packer(pe, db=None, ep_only=True, logger=None):
    """ Identify the packer used in a given executable using the given signatures database.
    
    :param pe:      either the path to the executable file or a PE instance
    :param db:      path to the database
    :param ep_only: consider only entry point signatures
    :return:        return the matching packers
    """
    if not isinstance(pe, PE):
        path = pe
        pe = PE(pe)
        pe.path = path
    db = open_sigs(db, logger)
    if logger:
        logger.debug("Parsing PE file '%s'..." % getattr(pe, "path", "unknown path"))
    return db.match(pe, ep_only=ep_only) or []


def open_sigs(path, logger=None):
    """ Open a signatures database.
    
    :param path: path to the database
    :return:     SignatureDatabase instance
    """
    path = path or DB
    if logger:
        logger.debug("Opening signature database '%s'..." % path)
    with open(path, encoding="latin-1") as f:
        sigs = SignatureDatabase(data=f.read())
    return sigs

