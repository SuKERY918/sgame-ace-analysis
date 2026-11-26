import struct

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs
from elftools.elf.elffile import ELFFile


class So:
    def __init__(self, path):
        self.path = path
        self.data = open(path, "rb").read()
        with open(path, "rb") as f:
            self.elf = ELFFile(f)
            self.segs = []
            for s in self.elf.iter_segments():
                if s["p_type"] == "PT_LOAD":
                    self.segs.append((s["p_vaddr"], s["p_vaddr"] + s["p_filesz"], s["p_offset"]))
            self.sections = {}
            for s in self.elf.iter_sections():
                self.sections[s.name] = (s["sh_addr"], s["sh_addr"] + s["sh_size"], s["sh_offset"])
        self.md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        self.md.detail = True

    def read(self, va, n):
        for va0, end, fo in self.segs:
            if va0 <= va < end:
                return self.data[fo + (va - va0): fo + (va - va0) + n]
        raise ValueError("bad va %x" % va)

    def u64(self, va):
        return struct.unpack("<Q", self.read(va, 8))[0]

    def u32(self, va):
        return struct.unpack("<I", self.read(va, 4))[0]

    def cstr(self, va, maxlen=512):
        d = self.read(va, maxlen)
        z = d.find(b"\0")
        return d[:z if z >= 0 else maxlen].decode("latin1", "replace")

    def dis(self, va, n, count=1):
        return list(self.md.disasm(self.read(va, n), va, count=count))

    def elems(self, start, end):
        return list(self.md.disasm(self.read(start, end - start), start))

    def funcs_from_eh(self):
        sec = self.sections.get(".eh_frame_hdr")
        if not sec:
            return []
        va0, _, off = sec
        d = self.data[off: off + 0x20000]
        if d[:4] != b"\x01\x1b\x03\x3b":
            return []
        cnt = struct.unpack("<I", d[8:12])[0]
        starts = []
        for i in range(cnt):
            base = 12 + 8 * i
            if base + 8 > len(d):
                break
            loc = struct.unpack("<i", d[base:base + 4])[0]
            starts.append(va0 + loc)
        starts.sort()
        return starts
