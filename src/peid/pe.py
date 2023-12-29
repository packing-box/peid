# -*- coding: UTF-8 -*-
from functools import wraps
from os.path import getsize


__all__ = ["PE"]


class PE:
    def __init__(self, path, debug=False):
        self.path, self.size, self.__debug = path, getsize(path), debug
        self.__fd = f = open(path, "rb")
        # check MZ signature
        if f.read(2) != b"MZ":
            raise OSError("Invalid MZ signature")
        # go to PE header offset location and read the offset
        f.seek(0x3c)
        self.pe_offset = int.from_bytes(f.read(4), "little")
        # go to PE header and check PE signature
        f.seek(self.pe_offset)
        if f.read(4) != b"PE\x00\x00":
            raise OSError("Invalid PE signature")
        # ready NumberOfSections 
        f.seek(self.pe_offset + 6)
        self.number_of_sections = int.from_bytes(f.read(2), "little")
        # ready SizeOfOptionalHeader
        f.seek(self.pe_offset + 20)
        self.size_of_opt_header = int.from_bytes(f.read(2), "little")
    
    def __enter__(self):
        return self
    
    def __exit__(self, type, value, traceback):
        self.close()
    
    def close(self):
        self.__fd.close()
    
    def itersections(self):
        f = self.__fd
        for i in range(self.number_of_sections):
            f.seek(self.pe_offset + 24 + self.size_of_opt_header + i * 40 + 8)
            virtual_size = int.from_bytes(f.read(4), "little")
            virtual_addr = int.from_bytes(f.read(4), "little")
            raw_size     = int.from_bytes(f.read(4), "little")
            raw_pointer  = int.from_bytes(f.read(4), "little")
            yield virtual_size, virtual_addr, raw_size, raw_pointer
    
    def read(self, n=64, *offsets):
        if len(offsets) == 0:
            offsets = range(0, self.size-n)
        for o in offsets:
            self.__fd.seek(o)
            yield self.__fd.read(min(n, self.size-o))
    
    @property
    def entrypoint_offset(self):
        # EP is at byte 40 of the PE header (when image file)
        self.__fd.seek(self.pe_offset + 40)
        ep = int.from_bytes(self.__fd.read(4), "little")
        for vsize, vaddr, rsize, raddr in self.itersections():
            if vaddr <= ep < vaddr + rsize:
                return raddr + ep - vaddr
    
    @property
    def sections_offsets(self):
        f = self.__fd
        # Section Headers Table starts after the Optional Header
        start = self.pe_offset + 24 + self.size_of_opt_header
        f.seek(start)
        # 40 bytes per section header entry
        offsets = []
        for i in range(self.number_of_sections):
            if self.__debug:
                f.seek(start + i * 40)
                print(f.read(8).rstrip(b"\0").decode("utf-8"))
            f.seek(start + i * 40 + 20)
            offsets.append(int.from_bytes(f.read(4), "little"))
        return offsets

