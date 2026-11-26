from capstone import *
from capstone.arm64 import *
import struct, pickle
from collections import Counter, defaultdict

path = r"D:\workspace\ACE\libs\libtersafe.so"
data = open(path,"rb").read()
segs, dec = pickle.load(open(r"D:\workspace\ACE\out\dec_list.pkl","rb"))
params = pickle.load(open(r"D:\workspace\ACE\out\dparams.pkl","rb"))
def v2o(v):
    for va,off,fs in segs:
        if va<=v<va+fs: return off+v-va
def o2v(o):
    for va,off,fs in segs:
        if off<=o<off+fs: return va+o-off
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM); md.detail=True
decset = set(dec); decs = sorted(dec)
decstart = {}
for i,s in enumerate(decs):
    decstart[s]=i

TEXT_S, TEXT_E = 0x1B6C20, 0x50DFC8
blob = data[v2o(TEXT_S):v2o(TEXT_E)]
insns = list(md.disasm(blob, TEXT_S))
print("total insns", len(insns))

# also treat as valid targets anything in [0x4E64D0, 0x4ED3CC+0x120)
LO, HI = 0x4E64D0, 0x4ED3CC+0x120
sites=[]
byaddr = {ins.address:i for i,ins in enumerate(insns)}
for k,ins in enumerate(insns):
    if ins.mnemonic!="bl": continue
    t = ins.operands[0]
    if t.type!=ARM64_OP_IMM: continue
    tgt = t.imm
    if not (LO <= tgt < HI): continue
    # walk back
    val=None
    for j in range(k-1, max(k-9,-1), -1):
        p=insns[j]
        if p.mnemonic in ("mov","movz","movn") and len(p.operands)==2 and p.operands[0].type==ARM64_OP_REG and p.operands[0].reg==ARM64_REG_W0 and p.operands[1].type==ARM64_OP_IMM:
            val=p.operands[1].imm; valaddr=p.address; break
        if p.mnemonic=="movk" and len(p.operands)==2 and p.operands[0].type==ARM64_OP_REG and p.operands[0].reg==ARM64_REG_W0:
            continue
        if p.mnemonic in ("bl","b","ret","br"): break
    if val is not None:
        sites.append((ins.address, tgt, val, valaddr))
print("call sites with const:", len(sites))
print("distinct targets:", len(set(t for _,t,_,_ in sites)))
print("distinct offsets:", len(set(v for _,_,v,_ in sites)))
print("max offset:", max(v for _,_,v,_ in sites))
pickle.dump(sites, open(r"D:\workspace\ACE\out\sites.pkl","wb"))
