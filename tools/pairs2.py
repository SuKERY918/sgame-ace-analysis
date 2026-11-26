from capstone import *
from capstone.arm64 import *
import struct, pickle
from collections import Counter

path = r"D:\workspace\ACE\libs\libtersafe.so"
data = open(path,"rb").read()
e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
e_phnum = struct.unpack_from("<H", data, 0x38)[0]
segs=[]
for i in range(e_phnum):
    off = e_phoff + i*e_phentsize
    p_type = struct.unpack_from("<I", data, off)[0]
    p_offset, p_vaddr, p_paddr, p_filesz, p_memsz = struct.unpack_from("<QQQQQ", data, off+8)
    if p_type==1: segs.append((p_vaddr,p_offset,p_filesz))
def v2o(v):
    for va,off,fs in segs:
        if va<=v<va+fs: return off+v-va

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM); md.detail=True
start, end = 0x1B6C20, 0x50DFC8
blob = data[v2o(start):v2o(start)+(end-start)]
insns = list(md.disasm(blob, start))
print("insns:", len(insns))
# build index by address
addrs = [i.address for i in insns]
idx_of = {a:k for k,a in enumerate(addrs)}

pairs = Counter()
sites = []
for k, ins in enumerate(insns):
    if ins.mnemonic != "eor": continue
    ops = ins.operands
    if len(ops)!=3: continue
    if not (ops[0].type==ARM64_OP_REG and ops[1].type==ARM64_OP_REG and ops[2].type==ARM64_OP_REG): continue
    rd = ops[0].reg; rn = ops[1].reg; rm = ops[2].reg
    if rd != rn: continue
    # look ahead <=6 insns for ADD rd, rd, #imm
    for j in range(k+1, min(k+7, len(insns))):
        jn = insns[j]
        if jn.mnemonic == "add" and len(jn.operands)==3 and jn.operands[0].type==ARM64_OP_REG and jn.operands[0].reg==rd and jn.operands[1].type==ARM64_OP_REG and jn.operands[1].reg==rd and jn.operands[2].type==ARM64_OP_IMM:
            addimm = jn.operands[2].imm
            # find def of rm before k within 80 insns
            eorimm = None
            for t in range(k-1, max(k-90,-1), -1):
                ti = insns[t]
                if ti.mnemonic=="mov" and len(ti.operands)==2 and ti.operands[0].type==ARM64_OP_REG and ti.operands[0].reg==rm and ti.operands[1].type==ARM64_OP_IMM:
                    eorimm = ti.operands[1].imm; break
                if ti.mnemonic=="eor" and len(ti.operands)==3 and ti.operands[0].type==ARM64_OP_REG and ti.operands[0].reg==rm and ti.operands[2].type==ARM64_OP_IMM:
                    eorimm = ("eor",ti.operands[2].imm); break
            if eorimm is not None:
                pairs[(eorimm, addimm)] += 1
                sites.append((ins.address, eorimm, addimm))
            break
print("candidate pairs:", len(pairs))
for p,c in pairs.most_common(80): print(p,c)
pickle.dump((pairs,sites), open(r"D:\workspace\ACE\out\pairs.pkl","wb"))
