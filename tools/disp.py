import sys
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
import bisect, pickle, os

PATH = r"D:\workspace\ACE\libs\libtersafe.so"
OUT = r"D:\workspace\ACE\out"
e = ELFFile(open(PATH, "rb"))
sec = e.get_section_by_name(".text")
base = sec["sh_addr"]
code = sec.data()
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

fp = os.path.join(OUT, "funcstarts.pkl")
starts = sorted(pickle.load(open(fp, "rb"))) if os.path.exists(fp) else [base]


def owner(a):
    i = bisect.bisect_right(starts, a) - 1
    return starts[i] if i >= 0 else 0


disp = int(sys.argv[1], 0)
mnems = set(sys.argv[2].split(",")) if len(sys.argv) > 2 else {"ldrb", "strb", "ldrsb", "ldr", "str"}
seen = {}
for ins in md.disasm(code, base):
    if ins.mnemonic not in mnems:
        continue
    for op in ins.operands:
        if op.type == 3 and op.mem.disp == disp and op.mem.base != 0:
            fn = owner(ins.address)
            seen.setdefault(fn, []).append((ins.address, ins.mnemonic))
for fn in sorted(seen):
    lst = seen[fn]
    print("0x%08x x%d  %s" % (fn, len(lst), " ".join("%s@0x%x" % (m, a) for a, m in lst[:8])))
print("-- %d funcs, %d sites" % (len(seen), sum(len(v) for v in seen.values())))
