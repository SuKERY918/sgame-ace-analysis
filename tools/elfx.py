import os
import pickle
import struct
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_REG
from elftools.elf.elffile import ELFFile


class Elf:
    def __init__(self, path):
        self.path = path
        self.f = open(path, "rb")
        self.elf = ELFFile(self.f)
        self.segs = []
        self.execs = []
        for s in self.elf.iter_segments():
            if s["p_type"] == "PT_LOAD":
                self.segs.append((s["p_vaddr"], s["p_offset"], s["p_filesz"]))
                if s["p_flags"] & 1:
                    self.execs.append((s["p_vaddr"], s["p_offset"], s["p_filesz"]))
        self.codes = []
        for nm in (".text", ".plt", ".init_array"):
            sec = self.elf.get_section_by_name(nm)
            if sec is not None and sec["sh_size"]:
                self.codes.append((sec["sh_addr"], sec["sh_offset"], sec["sh_size"]))
        if not self.codes:
            self.codes = list(self.execs)
        self.md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        self.md.detail = True
        self.md.skipdata = True
        self._rel = None
        self._xref = None

    def read(self, va, n):
        for v, o, sz in self.segs:
            if v <= va < v + sz:
                self.f.seek(o + (va - v))
                return self.f.read(min(n, v + sz - va))
        return b""

    def u32(self, va):
        return struct.unpack("<I", self.read(va, 4))[0]

    def u64(self, va):
        return struct.unpack("<Q", self.read(va, 8))[0]

    def s32(self, va):
        return struct.unpack("<i", self.read(va, 4))[0]

    def relocs(self):
        if self._rel is None:
            d = {}
            sec = self.elf.get_section_by_name(".rela.dyn")
            if sec is not None:
                for r in sec.iter_relocations():
                    if r["r_info_type"] == 1027:
                        d[r["r_offset"]] = r["r_addend"]
            self._rel = d
        return self._rel

    def ptr(self, va):
        v = self.u64(va)
        if v == 0:
            return self.relocs().get(va, 0)
        return v

    def dis(self, va, n=1):
        data = self.read(va, n * 4 + 32)
        out = []
        for i in self.md.disasm(data, va):
            out.append(i)
            if len(out) >= n:
                break
        return out

    def dump(self, va, n=1):
        for i in self.dis(va, n):
            print("%08x  %-8s %s" % (i.address, i.mnemonic, i.op_str))

    def scan_xrefs(self):
        if self._xref is not None:
            return self._xref
        cache = self.path + ".xref.pkl"
        if os.path.exists(cache):
            self._xref = pickle.load(open(cache, "rb"))
            return self._xref
        res = {}
        for v, o, sz in self.codes:
            self.f.seek(o)
            code = self.f.read(sz)
            adrp = {}
            for ins in self.md.disasm(code, v):
                m = ins.mnemonic
                ops = ins.operands
                if m == "adrp":
                    adrp[ops[0].reg] = ops[1].imm
                elif m == "add" and len(ops) >= 3 and ops[2].type == ARM64_OP_IMM:
                    base = ops[1].reg
                    if base in adrp:
                        tgt = adrp[base] + ops[2].imm
                        res.setdefault(tgt, []).append((ins.address, "adrpadd"))
                elif m in ("b", "bl") or m.startswith("b."):
                    if ops and ops[0].type == ARM64_OP_IMM:
                        res.setdefault(ops[0].imm, []).append((ins.address, m))
                elif m in ("ldr", "str", "ldur", "stur") and len(ops) >= 2:
                    if ops[1].type == ARM64_OP_REG and ops[1].reg in adrp:
                        res.setdefault(adrp[ops[1].reg], []).append((ins.address, m + "/base"))
                    elif ops[1].type == 3 and ops[1].mem.base in adrp:
                        tgt = adrp[ops[1].mem.base] + ops[1].mem.disp
                        res.setdefault(tgt, []).append((ins.address, m))
        self._xref = res
        pickle.dump(res, open(cache, "wb"))
        return res

    def xrefs(self, target, kinds=None):
        r = self.scan_xrefs().get(target, [])
        if kinds:
            r = [x for x in r if any(k in x[1] for k in kinds)]
        return r


def load(name):
    if os.path.isabs(name) or os.path.exists(name):
        return Elf(name)
    return Elf(os.path.join(os.path.dirname(os.path.abspath(__file__)), name))


if __name__ == "__main__":
    cmd = sys.argv[1]
    e = load(sys.argv[2])
    if cmd == "dis":
        e.dump(int(sys.argv[3], 0), int(sys.argv[4]) if len(sys.argv) > 4 else 1)
    elif cmd == "xref":
        for site, kind in e.xrefs(int(sys.argv[3], 0)):
            print("%08x %s" % (site, kind))
    elif cmd == "str":
        va = int(sys.argv[3], 0)
        raw = e.read(va, 256)
        print(raw.split(b"\0")[0].decode("utf-8", "replace"))
    elif cmd == "tab":
        va = int(sys.argv[3], 0)
        n = int(sys.argv[4]) if len(sys.argv) > 4 else 16
        for k in range(n):
            print("%08x -> %08x" % (va + k * 8, e.ptr(va + k * 8)))
