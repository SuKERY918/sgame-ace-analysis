import struct, sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

PATH = r'D:\workspace\ACE\libs\libtersafe.so'
d = open(PATH, 'rb').read()
BASE = 0x1B6C20
code = d[0x1B6C20:0x50DFC8]

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True
insns = list(md.disasm(code, BASE))

lo, hi, reg = 0x27FAE4, 0x280440, 0x222284
sites = []
for i, ins in enumerate(insns):
    if ins.address < lo or ins.address >= hi:
        continue
    if ins.mnemonic == 'bl' and ins.operands[0].imm == reg:
        sites.append(i)

print('sites', len(sites))
for n, i in enumerate(sites):
    name_idx = None
    ctor = None
    for j in range(max(0, i - 60), i):
        ins = insns[j]
        if ins.mnemonic == 'mov' and ins.op_str.startswith('w0, #'):
            try:
                name_idx = int(ins.op_str.split('#')[1], 0)
            except Exception:
                pass
        if ins.mnemonic == 'bl':
            t = ins.operands[0].imm
            if t != reg:
                ctor = t
    print('%2d site=0x%x name_idx=%s ctor=%s' % (n + 1, insns[i].address, name_idx, hex(ctor) if ctor else None))
