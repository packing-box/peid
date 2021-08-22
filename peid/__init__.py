# -*- coding: UTF-8 -*-
import os
from datetime import date
from pefile import PE
from peutils import SignatureDatabase as Base


__all__ = ["identify_packer", "open_sigs", "DB", "SignatureDatabase"]


__log = lambda l, m, lvl="debug": getattr(l, lvl)(m) if l else None
DB = os.path.join(os.path.dirname(__file__), "userdb.txt")


class SignatureDatabase(Base):
    def __init__(self, filename, encoding="latin-1"):
        filename = os.path.abspath(filename)
        with open(filename, encoding=encoding) as f:
            super(SignatureDatabase, self).__init__(data=f.read())
        self.path = filename
        self.encoding = encoding
        self.signatures = {}
        # use the signature bytes as the key
        for fields in self:
            self.signatures[fields[1]] = fields
        # catch comments
        self.comments = []
        with open(self.path, encoding=self.encoding) as f:
            for l in f:
                if not l.startswith(";"):
                    break
                self.comments.extend(list(map(lambda x: x.lstrip("; ").rstrip(". \n"), l.lstrip("; ").split(";"))))
    
    def __eq__(self, db):
        return set(self.signatures) == set(self.__get(db).signatures)
    
    def __iter__(self):
        with open(self.path, encoding=self.encoding) as f:
            for packer, signature, _, ep_only, sec_start_only in self.parse_sig.findall(f.read()):
                ep_only = ep_only == "true"
                sec_start_only = sec_start_only == "true"
                yield packer, signature, _, ep_only, sec_start_only
    
    def __len__(self):
        return len(self.signatures)
    
    def __get(self, db, encoding=None):
        if not isinstance(db, SignatureDatabase):
            db = SignatureDatabase(db, encoding or self.encoding)
        return db
    
    def compare(self, db, encoding=None):
        for sig, fields in self.__get(db, encoding).signatures.items():
            if sig not in self.signatures:
                yield fields[0]
    
    def dump(self, filename="userdb.txt", encoding=None):
        with open(filename, 'wt', encoding=encoding or self.encoding) as f:
            for l in self.comments:
                f.write("; %s\n" % l)
            f.write("\n")
            for sig, fields in sorted(self.signatures.items(), key=lambda x: x[1][0]):
                packer, signature, _, ep_only, sec_start_only = fields
                f.write("[%s]\nsignature = %s\nep_only = %s\n%s\n" % (packer, signature, str(ep_only).lower(),
                        ["", "section_start_only = %s\n" % str(sec_start_only).lower()][sec_start_only]))
    
    def merge(self, *dbs):
        self.comments = ["Merged with Python peid package on " + date.today().strftime("%B %d, %Y")]
        if len(self) > 0:
            self.comments.append(" - " + os.path.basename(self.path))
        for db in dbs:
            db, added = self.__get(db), False
            for sig, fields in db.signatures.items():
                if sig not in self.signatures:
                    self.signatures[sig] = fields
                    added = True
            if added:
                self.comments.append(" - " + os.path.basename(db.path))
        self.comments.append("%d signatures in list" % len(self))


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
    return SignatureDatabase(path)

