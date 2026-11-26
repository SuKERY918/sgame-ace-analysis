import json
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

SO = r'D:\workspace\ACE\libs\libtersafe.so'
d = open(SO, 'rb').read()
BASE = 0x1B6C20
code = d[BASE:0x50DFC8]

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True
insns = list(md.disasm(code, BASE))
idx = {ins.address: i for i, ins in enumerate(insns)}

db = json.load(open(r'D:\workspace\ACE\out\db.json', encoding='utf-8'))


def s(i):
    e = db.get(str(i))
    return e['s'] if e else None


# jump table: 88 int32 at 0x90EC0, sdata relative to 0x1BD078
JT = 0x90EC0
tbl = struct.unpack_from('<88i', d, JT)
targets = {}
for k in range(88):
    targets[k + 1] = 0x1BD078 + tbl[k]

lo, hi = 0x1BD084, 0x1BE16C
bounds = sorted(set([t for t in targets.values()] + [hi]))

for cmd in range(1, 89):
    t = targets[cmd]
    if t not in idx:
        print('%2d 0x%x <no code>' % (cmd, t))
        continue
    i = idx[t]
    end = len(insns)
    # stop at next case boundary in address order that is > t
    nxt = min([b for b in bounds if b > t] or [hi])
    strs = []
    last_mov = None
    j = i
    while j < len(insns) and insns[j].address < nxt:
        ins = insns[j]
        if ins.mnemonic == 'mov' and ins.op_str.startswith('w0, #'):
            try:
                last_mov = int(ins.op_str.split('#')[1], 0)
            except Exception:
                last_mov = None
        if ins.mnemonic == 'bl' and last_mov is not None and 0x4E64D0 <= ins.operands[0].imm < 0x4ED3CC + 0x120:
            v = s(last_mov)
            if v:
                strs.append(v)
            last_mov = None
        j += 1
    print('%2d 0x%x %s' % (cmd, t, ' | '.join(strs[:6])))
