# -*- coding: UTF-8 -*-
import re
from os.path import basename, dirname, join

from ..exe import open_exe


__all__ = ["DB", "SignaturesDB", "SignaturesTree"]


__log = lambda l, m, lvl="debug": getattr(l, lvl)(m) if l else None
DB = join(dirname(__file__), "userdb.txt")
SIG = re.compile(r"\[(.*?)\]\s+?signature\s*=\s*(.*?)((?:\s+\?\?)*)\s*ep_only\s*=\s*(\w+)"
                 r"(?:\s*section_start_only\s*=\s*(\w+)|)", re.S)


class SignaturesTree:
    """ Lightweight class for loading signatures search tree and matching signatures. """
    def __init__(self, path=None, encoding="utf-8", cache=True, keep_trailing_wildcards=False, logger=None):
        from os.path import abspath, exists, expanduser
        self.encoding, self.keep_trailing_wildcards, self.logger = encoding, keep_trailing_wildcards, logger
        self.path = path = abspath(expanduser(path or DB))
        self.json = join(dirname(path), f".{basename(path).replace('.','_')}{['','_tw'][keep_trailing_wildcards]}.json")
        if exists(self.json):
            from msgspec.json import decode
            with open(self.json, 'rb') as f:
                self.__tree = decode(f.read())
        else:
            if not exists(path):
                with open(path, 'wt') as f:
                    f.write("; 0 signature in list")
            self.__load(path, encoding, cache)
    
    def __iter__(self):
        with open(self.path, encoding=self.encoding) as f:
            data = f.read()
        for name, signature, trailing_wildcards, ep_only, sec_start_only in SIG.findall(data):
            if ep_only == "true" and sec_start_only == "true":
                raise ValueError("Bad signature ; ep_only and section_start_only are mutually exclusive")
            yield name, \
                  signature.replace("\n", "").split(), \
                  trailing_wildcards, \
                  ep_only == "true", \
                  sec_start_only == "true"
    
    def __load(self, path, encoding="utf-8", cache=True):
        """ Load the signatures database into a tree. """
        self.__tree = {'': {}, 'ep_only': {}, 'section_start_only': {}, 'max_depth': 0}
        for name, signature, trailing_wildcards, ep_only, sec_start_only in self:
            tree = self.__tree['ep_only' if ep_only else 'section_start_only' if sec_start_only else '']
            if self.keep_trailing_wildcards:
                signature += trailing_wildcards.strip().split()
            l = len(signature)
            if l > self.__tree['max_depth']:
                self.__tree['max_depth'] = l
            for byte in signature:
                tree.setdefault(byte, {})
                tree = tree[byte]
            tree['value'] = name
        if cache:
            from msgspec.json import encode
            with open(self.json, 'wb') as f:
                f.write(encode(self.__tree))
    
    def match(self, pe, ep_only=True, sec_start_only=False, match_all=True):
        """ Match a given bytes sequence against the search tree. """
        if ep_only and sec_start_only:
            raise ValueError("ep_only and section_start_only are mutually exclusive")
        matches, n_bytes = [], self.__tree['max_depth']
        def _match(subtree, byteseq):
            for i, byte in enumerate(byteseq):
                byte = f"{byte:02X}"
                if 'value' in subtree:
                    matches.append(subtree['value'])
                if '??' in subtree:
                    _match(subtree['??'], byteseq[i+1:])
                if byte in subtree:
                    subtree = subtree[byte]
                else:
                    break
        with open_exe(pe, logger=self.logger) as f:
            if ep_only:
                for byteseq in f.read(n_bytes, f.entrypoint_offset):
                    _match(self.__tree['ep_only'], byteseq)
                if not match_all and len(matches) > 0:
                    return matches[-1]
            elif sec_start_only:
                for byteseq in f.read(n_bytes, *f.sections_offsets):
                    _match(self.__tree['section_start_only'], byteseq)
                    if not match_all and len(matches) > 0:
                        return matches[-1]
            else:
                for byteseq in f.read(n_bytes):
                    _match(self.__tree[''], byteseq)
                    if not match_all and len(matches) > 0:
                        return matches[-1]
            if len(matches) > 0:
                return matches


class SignaturesDB(SignaturesTree):
    """ Heavier class for providing more DB-related operations like comparing with another DB, adding new rules, ... """
    def __init__(self, path=None, encoding="utf-8", cache=True):
        super(SignaturesDB, self).__init__(path, encoding, cache)
        self.signatures = {}
        # use the signature bytes as the key
        for fields in self:
            self.signatures[tuple(fields[1])] = fields
        # catch comments
        self.comments = []
        with open(self.path, encoding=self.encoding) as f:
            for l in f:
                if not l.startswith(";"):
                    break
                self.comments.extend(list(map(lambda x: x.lstrip("; ").rstrip(". \n"), l.lstrip("; ").split(";"))))
    
    def __eq__(self, db):
        return set(self.signatures) == set(self.__get(db).signatures)
    
    def __len__(self):
        return len(self.signatures)
    
    def __get(self, db, encoding=None):
        if not isinstance(db, SignaturesDB):
            db = SignaturesDB(db, encoding or self.encoding)
        return db
    
    def __signature(self, name, signature, ep_only, sec_start_only, size):
        """ Output a signature as a string. """
        cond = f"ep_only = true" if ep_only else f"section_start_only = true" if sec_start_only else ""
        sigs = "" if size is None else f"size = {size}B\n"
        return f"[{name}]\nsignature = {signature}\n{cond}\n{sigs}\n"
    
    def __update_nsig(self):
        # find the line with the number of signatures to updated it
        for i, c in enumerate(self.comments):
            if c.endswith("signatures in list"):
                break
        c = f"{len(self)} signatures in list"
        try:  # if the line exists, replace it
            self.comments[i] = c
        except IndexError:  # otherwise add it
            self.comments.append(c)
    
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
                name, signature, _, ep_only, sec_start_only = fields
                cond = ["", "section_start_only = %s\n" % str(sec_start_only).lower()][sec_start_only]
                f.write(f"[{name}]\nsignature = {signature}\nep_only = {str(ep_only).lower()}\n{cond}\n")
    
    def filter(self, pattern, text=True, size=None, remove=False):
        """ Filter signatures based on a given name pattern and/or a signature size. """
        regex, rem = re.compile(pattern or r".*"), []
        for sig, data in self.signatures.items():
            name, signature, trailing_wildcards, ep_only, sec_start_only = data
            if regex.search(name):
                r = (name, f"{' '.join(signature)} {trailing_wildcards}", ep_only, sec_start_only,
                     (s := len(signature)) if size else None)
                if size is None or size(s):
                    yield self.__signature(*r) if text else r
                    if remove:
                        rem.append(sig)
        for sig in rem:
            self.unset(signature=sig)
    
    def merge(self, *dbs):
        """ Merge multiple signatures databases.
        
        :param dbs: paths to databases
        :post:      signatures from given databases added to self.signatures and self.comments updated
        """
        from datetime import date
        self.comments = ["Merged with Python peid package on " + date.today().strftime("%B %d, %Y")]
        if len(self) > 0:
            self.comments.append(" - " + basename(self.path))
        for db in dbs:
            db, added = self.__get(db), False
            for sig, fields in db.signatures.items():
                if sig not in self.signatures:
                    self.signatures[sig] = fields
                    added = True
            if added:
                self.comments.append(" - " + basename(db.path))
        self.comments.append(f"{len(self)} signatures in list")
    
    def set(self, name, signature, ep_only=True, sec_start_only=False, author=None, version=None):
        """ Add/update a signature based on the given data.
        
        :param name:           signature's name
        :param signature:      signature's bytes
        :param ep_only:        whether the signature is to be used from the entry point
        :param sec_start_only: whether the signature is to be used from the start of sections
        :param author:         author to be mentioned for the signature
        :param version:        version of the name matched by the signature
        :post:                 new signature added to self.signatures
        """
        if ep_only and sec_start_only:
            raise ValueError("ep_only and section_start_only are mutually exclusive")
        if version:
            name += " %s" % version
        if author:
            name += " -> %s" % author
        self.signatures[tuple(signature)] = (name, signature, "", ep_only, False)
        self.__update_nsig()
    
    def unset(self, name=None, signature=None):
        """ Remove a single signature based on its name or bytes. """
        if name or signature:
            if signature:
                del self.signatures[tuple(signature)]
            else:
                for sig in [d[1] for s, d in self.signatures.items() if name == d[0]]:
                    del self.signatures[sig]
            self.__update_nsig()
            return
        raise ValueError(f"no name or signature provided")

