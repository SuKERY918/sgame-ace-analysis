import struct, sys
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

PATH = sys.argv[1]
lo = int(sys.argv[2], 16)
hi = int(sys.argv[3], 16)
target = int(sys.argv[4], 16)
window = int(sys.argv[5], 0) if len(sys.argv) > 5 else 0x800

e = ELFFile(open(PATH, "rb"))
sec = e.get_section_by_name(".text")
base = sec["sh_addr"]
code = sec.data()
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

insns = list(md.disasm(code, base))
for i, ins in enumerate(insns):
    if ins.mnemonic != "adrp":
        continue
    try:
        tgt = ins.operands[1].imm
    except Exception:
        continue
    if not (lo <= tgt < hi):
        continue
    for nxt in insns[i + 1:i + 8]:
        mem = None
        try:
            if nxt.mnemonic in ("ldr", "str", "add", "ldrb", "strb"):
                for op in nxt.operands:
                    if op.type == 3:
                        mem = op
        except Exception:
            pass
        if mem is None:
            continue
        addr = tgt + mem.mem.disp
        if abs(addr - target) <= window:
            print("0x%x: %s %s   (-> 0x%x)" % (ins.address, nxt.mnemonic, nxt.op_str, addr))
