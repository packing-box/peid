# -*- coding: UTF-8 -*-
import os
from datetime import date
from pefile import PE
from peutils import SignatureDatabase as Base


__all__ = ["find_ep_only_signature", "identify_packer", "open_signature_db", "DB", "SignatureDatabase"]


__log = lambda l, m, lvl="debug": getattr(l, lvl)(m) if l else None
DB = os.path.join(os.path.dirname(__file__), "userdb.txt")


class SignatureDatabase(Base):
    def __init__(self, filename, encoding="latin-1"):
        filename = os.path.abspath(filename)
        if not os.path.exists(filename):
            with open(filename, 'wt') as f:
                f.write("; 0 signature in list")
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
        """ Compare this database with the given one.
        
        :param db:       path to database to be compared
        :param encoding: encoding for dumping the database
        :return:         generator producing signatures not present in this database but well in the compared one
        """
        for sig, fields in self.__get(db, encoding).signatures.items():
            if sig not in self.signatures:
                yield fields[0]
    
    def dump(self, filename=None, encoding=None):
        """ Dump self.signatures to the given path.
        
        :param filename: path to database dump
        :param encoding: encoding for dumping the database
        """
        with open(filename or self.path, 'wt', encoding=encoding or self.encoding) as f:
            for l in self.comments:
                f.write("; %s\n" % l)
            f.write("\n")
            for sig, fields in sorted(self.signatures.items(), key=lambda x: x[1][0]):
                packer, signature, _, ep_only, sec_start_only = fields
                f.write("[%s]\nsignature = %s\nep_only = %s\n%s\n" % (packer, signature, str(ep_only).lower(),
                        ["", "section_start_only = %s\n" % str(sec_start_only).lower()][sec_start_only]))
    
    def merge(self, *dbs):
        """ Merge multiple signatures databases.
        
        :param dbs: paths to databases
        :post:      signatures from given databases added to self.signatures and self.comments updated
        """
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
    
    def set(self, packer, signature, ep_only=True, author=None, version=None):
        """ Add/update a signature based on the given data.
        
        :param signature: signature's bytes
        :param ep_only:   whether the signature is to be used from the entry point
        :param author:    author to be mentioned for the signature
        :param version:   version of the packer matched by the signature
        :post:            new signature added to self.signatures
        """
        if version:
            packer += " %s" % version
        if author:
            packer += " -> %s" % author
        self.signatures[signature] = (packer, signature, "", ep_only, False)
        for i, c in enumerate(self.comments):
            if c.endswith("signatures in list"):
                break
        c = "%d signatures in list" % len(self)
        try:
            self.comments[i] = c
        except IndexError:
            self.comments.append(c)


def find_ep_only_signature(*files, length=64, common_bytes_threshold=.5):
    """ Find a signature among the given files.
    
    :param files:                  list of files to be compared in order to deduce a signature
    :param length:                 signature length
    :param common_bytes_threshold: minimal portion of bytes common to each file to be considered a valid signature
    :return:                       signature string (PEiD format)
    """
    sig, data = [], []
    for f in files:
        pe = PE(f)
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        data.append(pe.get_memory_mapped_image()[ep:ep+length])
    h = lambda b: hex(b)[2:].zfill(2).upper()
    for i in range(length):
        for d in data:
            if len(sig) <= i:
                sig.append(h(d[i]))
            elif h(d[i]) != sig[-1]:
                sig[-1] = "??"
    if sig.count("??") / len(sig) > 1 - common_bytes_threshold:
        raise ValueError("Could not find a suitable signature")
    return " ".join(sig)


def identify_packer(*paths, db=None, ep_only=True, logger=None):
    """ Identify the packer used in a given executable using the given signatures database.
    
    :param path:    path to the executable file(s)
    :param db:      path to the database
    :param ep_only: consider only entry point signatures
    :return:        return the matching packers
    """
    db, results = open_signature_db(db, logger), []
    for path in paths:
        if isinstance(path, PE):
            pe = path
            path = getattr(pe, "path", "unknown")
        else:
            pe = PE(path)
        if logger:
            logger.debug("Parsing PE file '%s'..." % path)
        results.append((path, db.match(pe, ep_only=ep_only) or []))
    return results


def open_signature_db(path, logger=None):
    """ Open a signatures database.
    
    :param path: path to the database
    :return:     SignatureDatabase instance
    """
    path = path or DB
    if logger:
        logger.debug("Opening signature database '%s'..." % path)
    return SignatureDatabase(path)

