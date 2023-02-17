# -*- coding: UTF-8 -*-
"""Bintropy package information.

"""
import os
from datetime import datetime

__y = str(datetime.now().year)
__s = "2021"

__author__    = "Alexandre D'Hondt"
__copyright__ = "© {} A. D'Hondt".format([__y, __s + "-" + __y][__y != __s])
__email__     = "alexandre.dhondt@gmail.com"
__license__   = "GPLv3 (https://www.gnu.org/licenses/gpl-3.0.fr.html)"
__source__    = "https://github.com/dhondta/peid"

with open(os.path.join(os.path.dirname(__file__), "VERSION.txt")) as f:
    __version__ = f.read().strip()

