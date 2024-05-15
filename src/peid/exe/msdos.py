# -*- coding: UTF-8 -*-
import struct
from os.path import getsize


__all__ = ["MSDOS"]


class MSDOS:
    def __init__(self, path, logger=None):
        self.path, self.size, self.logger = path, getsize(path), logger
        self.__fd = f = open(path, "rb")
        h = f.read(64)
        # check MZ signature
        if h[:2] != b"MZ":
            raise OSError("Invalid MZ signature")
        # read some header fields
        self.bytes_last_page = struct.unpack("<H", h[2:4])[0] or 512
        self.pages_in_file = struct.unpack("<H", h[4:6])[0]
        self.number_relocations = struct.unpack("<H", h[6:8])[0]
        self.header_paragraphs = struct.unpack("<H", h[8:10])[0]
        self.initial_ip = struct.unpack("<H", h[20:22])[0]
        self.initial_cs = struct.unpack("<H", h[22:24])[0]
        self.relocation_table_offset = struct.unpack("<H", h[24:26])[0]
    
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
            r = self.__fd.read(min(n, self.size-o))
            if self.logger:
                self.logger.debug(" ".join(f"{b:02X}" for b in r))
            yield r
    
    @property
    def entrypoint_offset(self):
        return (self.initial_cs << 4) + self.initial_ip
    
    @property
    def file_size(self):
        return (self.pages_in_file - 1) * 512 + self.bytes_last_page
    
    @property
    def header_size(self):
        return self.header_paragraphs * 16
    
    @property
    def sections_offsets(self):
        f, offsets = self.__fd, []
        f.seek(self.relocation_table_offset)
        for _ in range(self.number_relocations):
            segment, offset = struct.unpack("<HH", f.read(4))
            offsets.append((segment << 4) + offset)
        return offsets

