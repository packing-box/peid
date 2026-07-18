# -*- coding: UTF-8 -*-
import builtins

from .__common__ import EXE


__all__ = ["PE"]


class MalformedPE(ValueError):
    __module__ = "builtins"
builtins.MalformedPE = MalformedPE


class PE(EXE):
    def __init__(self, path_or_buffer, logger=None):
        super().__init__(path_or_buffer, logger)
        # go to PE header offset location and read the offset
        self._fd.seek(60)
        self.pe_offset = int.from_bytes(self._fd.read(4), "little")
        # go to PE header and check PE signature
        self._fd.seek(self.pe_offset)
        if self._fd.read(4) != b"PE\x00\x00":
            raise OSError("Invalid PE signature")
        # read NumberOfSections 
        self._fd.seek(self.pe_offset + 6)
        self.number_of_sections = int.from_bytes(self._fd.read(2), "little")
        # read SizeOfOptionalHeader
        self._fd.seek(self.pe_offset + 20)
        self.size_of_opt_header = int.from_bytes(self._fd.read(2), "little")
    
    @property
    def entrypoint_offset(self):
        # EP is at byte 40 of the PE header (when image file)
        self._fd.seek(self.pe_offset + 40)
        ep = int.from_bytes(self._fd.read(4), "little")
        if self.logger:
            self.logger.debug(f"Entry point: 0x{ep:08x}")
        for vsize, vaddr, rsize, raddr in self.itersections():
            if vaddr <= ep < vaddr + vsize:
                o = raddr + ep - vaddr
                if self.logger:
                    self.logger.debug(f"Entry point offset: {o}")
                return o
        self._fd.seek(0)
        c = self._fd.read()
        raise MalformedPE(f"Entry point (0x{ep:08x}) offset is outside sections (file size: 0x{len(c):08x})")
    
    @property
    def sections_offsets(self):
        # Section Headers Table starts after the Optional Header
        start = self.pe_offset + 24 + self.size_of_opt_header
        self._fd.seek(start)
        # 40 bytes per section header entry
        offsets = []
        for i in range(self.number_of_sections):
            if self.logger:
                self._fd.seek(start + i * 40)
                self.logger.debug(self._fd.read(8).rstrip(b"\0").decode("utf-8"))
            self._fd.seek(start + i * 40 + 20)
            offsets.append(int.from_bytes(self._fd.read(4), "little"))
        return offsets

