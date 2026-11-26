from capstone import *
from capstone.arm64 import *
import struct, pickle
from collections import Counter, defaultdict

path = r"D:\workspace\ACE\libs\libtersafe.so"
data = open(path,"rb").read()
segs, dec = pickle.load(open(r"D:\workspace\ACE\out\dec_list.pkl","rb"))
def v2o(v):
    for va,off,fs in segs:
        if va<=v<va+fs: return off+v-va
def o2v(o):
    for va,off,fs in segs:
        if off<=o<off+fs: return va+o-off
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM); md.detail=True
dec = sorted(dec)
decset = set(dec)

def extract(s):
    blob = data[v2o(s):v2o(s)+0x120]
    insns = list(md.disasm(blob, s))
    movs = {}
    for ins in insns:
        if ins.mnemonic=="mov" and len(ins.operands)==2 and ins.operands[0].type==ARM64_OP_REG and ins.operands[1].type==ARM64_OP_IMM:
            movs[ins.operands[0].reg]=ins.operands[1].imm
    E=None; C=None
    for i,ins in enumerate(insns):
        o=ins.operands
        if ins.mnemonic=="add" and len(o)==3 and o[0].type==ARM64_OP_REG and o[1].type==ARM64_OP_REG and o[0].reg==o[1].reg and o[2].type==ARM64_OP_REG:
            K=o[0].reg
            e=None; c=None
            for j in range(i+1, min(i+6,len(insns))):
                jn=insns[j]
                if jn.mnemonic=="eor" and len(jn.operands)==3 and jn.operands[0].type==ARM64_OP_REG and jn.operands[0].reg==K:
                    if jn.operands[2].type==ARM64_OP_IMM: e=jn.operands[2].imm
                    elif jn.operands[2].type==ARM64_OP_REG and jn.operands[2].reg in movs: e=movs[jn.operands[2].reg]
                if jn.mnemonic=="add" and len(jn.operands)==3 and jn.operands[0].type==ARM64_OP_REG and jn.operands[0].reg==K and jn.operands[1].type==ARM64_OP_REG and jn.operands[1].reg==K and jn.operands[2].type==ARM64_OP_IMM:
                    c=jn.operands[2].imm
                if c is not None: break
            if c is not None:
                E=e; C=c; break
    return E,C

params={}
for s in dec:
    params[s]=extract(s)
cnt=Counter(params.values())
print("distinct params:", len(cnt))
for k,v in sorted(cnt.items(), key=lambda x:(x[0][1] is None, x[0][1])): print(k,v)
print("None:", [hex(s) for s,(e,c) in params.items() if e is None or c is None])
pickle.dump(params, open(r"D:\workspace\ACE\out\dparams.pkl","wb"))
