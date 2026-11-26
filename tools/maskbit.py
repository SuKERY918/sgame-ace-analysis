import sys
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

PATH = r"D:\workspace\ACE\libs\libtersafe.so"
e = ELFFile(open(PATH, "rb"))
sec = e.get_section_by_name(".text")
base = sec["sh_addr"]
code = sec.data()
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

for fn in sys.argv[1:]:
    a = int(fn, 0)
    off = a - base
    insns = list(md.disasm(code[off:off + 0x260], a))
    print("== 0x%x" % a)
    for i, ins in enumerate(insns):
        hit = False
        for op in ins.operands:
            if op.type == 3 and op.mem.disp == 0x3BC:
                hit = True
        if hit:
            for n in insns[max(0, i - 2):i + 6]:
                print("   0x%x  %s %s" % (n.address, n.mnemonic, n.op_str))
            print("   ---")
