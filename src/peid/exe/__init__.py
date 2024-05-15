# -*- coding: UTF-8 -*-
from .msdos import MSDOS
from .pe import PE


__all__ = ["open_exe", "MSDOS", "PE"]


def open_exe(path, logger=None):
    """ Find a matching format and return the instantiated executable object. """
    for fmt in [PE, MSDOS]:
        try:
            return fmt(path, logger)
        except OSError:
            pass
    raise OSError("Not a valid executable or supported executable format")

