# -*- coding: UTF-8 -*-
import _io
from os.path import getsize


__all__ = ["EXE"]


class EXE:
    def __init__(self, path_or_buffer, logger=None):
        self.logger = logger
        self._fd = path_or_buffer if isinstance(path_or_buffer, _io.BufferedReader) else open(path_or_buffer, "rb")
        self.path = self._fd.name
        self.size = getsize(self.path)
        if self._fd.read(2) != b"MZ":
            raise OSError("Invalid MZ signature")
        self._fd.seek(0)
    
    def __enter__(self):
        return self
    
    def __exit__(self, type, value, traceback):
        self.close()
    
    def close(self):
        self._fd.close()
    
    def itersections(self):
        for i in range(self.number_of_sections):
            self._fd.seek(self.pe_offset + 24 + self.size_of_opt_header + i * 40 + 8)
            virtual_size = int.from_bytes(self._fd.read(4), "little")
            virtual_addr = int.from_bytes(self._fd.read(4), "little")
            raw_size     = int.from_bytes(self._fd.read(4), "little")
            raw_pointer  = int.from_bytes(self._fd.read(4), "little")
            yield virtual_size, virtual_addr, raw_size, raw_pointer
    
    def read(self, n=64, *offsets):
        if len(offsets) == 0:
            offsets = range(0, self.size-n)
        for o in offsets:
            self._fd.seek(o)
            r = self._fd.read(min(n, self.size-o))
            if self.logger:
                self.logger.debug(" ".join(f"{b:02X}" for b in r))
            yield r

