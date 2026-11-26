from capstone import *
from capstone.arm64 import *
import struct, pickle
from collections import Counter, defaultdict

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
BASE = 0x4E64D0; STRIDE = 0x11C
wrappers = [BASE + STRIDE*n for n in range(101)]

params = {}
for w in wrappers:
    blob = data[v2o(w):v2o(w)+STRIDE]
    insns = list(md.disasm(blob, w))
    E = None; C = None
    # find MOV Wk,#imm definitions
    movs = {}
    for ins in insns:
        if ins.mnemonic=="mov" and len(ins.operands)==2 and ins.operands[0].type==ARM64_OP_REG and ins.operands[1].type==ARM64_OP_IMM:
            movs[ins.operands[0].reg] = ins.operands[1].imm
    for i,ins in enumerate(insns):
        ops=ins.operands
        if ins.mnemonic=="add" and len(ops)==3 and ops[0].type==ARM64_OP_REG and ops[1].type==ARM64_OP_REG and ops[0].reg==ops[1].reg and ops[2].type==ARM64_OP_IMM:
            C = ops[2].imm
        if ins.mnemonic=="eor" and len(ops)==3 and ops[0].type==ARM64_OP_REG and ops[1].type==ARM64_OP_REG and ops[2].type==ARM64_OP_REG and ops[0].reg==ops[1].reg:
            if ops[2].reg in movs: E = movs[ops[2].reg]
    params[w] = (E, C, [ins.mnemonic for ins in insns][:6])
print("wrappers:", len(params))
print("no C:", [hex(w) for w,(e,c,p) in params.items() if c is None])
print("distinct:", Counter(params.values().__iter__().__class__ and [(e,c) for w,(e,c,p) in params.items()]))
for w in wrappers[:5]+wrappers[69:72]:
    print(hex(w), params[w][0], params[w][1], params[w][2])
pickle.dump(params, open(r"D:\workspace\ACE\out\wparams.pkl","wb"))
