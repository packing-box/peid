# -*- coding: UTF-8 -*-
import struct

from .__common__ import EXE


__all__ = ["MSDOS"]


class MSDOS(EXE):
    def __init__(self, path_or_buffer, logger=None):
        super().__init__(path_or_buffer, logger)
        h = self._fd.read(64)
        # read some header fields
        self.bytes_last_page = struct.unpack("<H", h[2:4])[0] or 512
        self.pages_in_file = struct.unpack("<H", h[4:6])[0]
        self.number_relocations = struct.unpack("<H", h[6:8])[0]
        self.header_paragraphs = struct.unpack("<H", h[8:10])[0]
        self.initial_ip = struct.unpack("<H", h[20:22])[0]
        self.initial_cs = struct.unpack("<H", h[22:24])[0]
        self.relocation_table_offset = struct.unpack("<H", h[24:26])[0]
    
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
        offsets = []
        self._fd.seek(self.relocation_table_offset)
        for _ in range(self.number_relocations):
            segment, offset = struct.unpack("<HH", self._fd.read(4))
            offsets.append((segment << 4) + offset)
        return offsets

