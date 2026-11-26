import json
import sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

PATH = r'D:\workspace\ACE\libs\libtersafe.so'
d = open(PATH, 'rb').read()
BASE = 0x1B6C20
code = d[0x1B6C20:0x50DFC8]

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True
insns = list(md.disasm(code, BASE))

db = json.load(open(r'D:\workspace\ACE\out\db.json', encoding='utf-8'))


def s(idx):
    e = db.get(str(idx))
    return e['s'] if e else '?'


lo, hi, reg = 0x27FAE4, 0x280440, 0x222284
sites = [i for i, ins in enumerate(insns) if lo <= ins.address < hi and ins.mnemonic == 'bl' and ins.operands[0].imm == reg]

for n, i in enumerate(sites):
    seq = []
    last_mov = None
    for j in range(max(0, i - 80), i):
        ins = insns[j]
        if ins.mnemonic == 'mov' and ins.op_str.startswith('w0, #'):
            try:
                last_mov = int(ins.op_str.split('#')[1], 0)
            except Exception:
                last_mov = None
        if ins.mnemonic == 'bl':
            t = ins.operands[0].imm
            tag = ''
            if last_mov is not None and 0x4E64D0 <= t < 0x4ED3CC + 0x120:
                tag = 'STR[%d]=%s' % (last_mov, s(last_mov))
            seq.append('0x%x%s' % (t, tag))
            last_mov = None
    print('%2d @0x%x  %s' % (n + 1, insns[i].address, ' | '.join(seq[-4:])))
