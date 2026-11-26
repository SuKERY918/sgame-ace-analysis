from capstone import *
from capstone.arm64 import *
import struct, re

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

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM); md.detail = True
start, end = 0x4E4000, 0x4EE000
blob = data[v2o(start):v2o(start)+(end-start)]
pairs=[]; prev=None
for ins in md.disasm(blob, start):
    ops = ins.operands
    if ins.mnemonic == "eor" and len(ops)==3 and ops[2].type==ARM64_OP_IMM:
        prev=(ins.address, ops[2].imm)
    elif ins.mnemonic=="add" and len(ops)==3 and ops[2].type==ARM64_OP_IMM and prev and ins.address-prev[0]<=32:
        pairs.append((prev[1], ops[2].imm)); prev=None
    elif prev and ins.address-prev[0]>32:
        prev=None
print("pairs:", len(pairs))
from collections import Counter
for k,v in Counter(pairs).most_common(60): print(k,v)
