from capstone import *
from capstone.arm64 import *
import struct, pickle, re
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
    return None
def o2v(o):
    for va,off,fs in segs:
        if off<=o<off+fs: return va+o-off
    return None

TEXT_S, TEXT_E = 0x1B6C20, 0x50DFC8
ts = v2o(TEXT_S); te = v2o(TEXT_E)
textbytes = data[ts:te]

# 1) find decryptor starts by 12-byte prologue
sig = bytes.fromhex("fd7bbea9f44f01a9fd030091")
starts=[]
i = textbytes.find(sig)
while i != -1:
    starts.append(TEXT_S + i)
    i = textbytes.find(sig, i+1)
print("prologue candidates:", len(starts))

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM); md.detail=True
# 2) keep those calling 0x4E4A68 and 0x4E4A7C in first 0x120 bytes
dec=[]
for s in starts:
    blob = data[v2o(s):v2o(s)+0x120]
    calls=set()
    for ins in md.disasm(blob, s):
        if ins.mnemonic=="bl" and ins.operands and ins.operands[0].type==ARM64_OP_IMM:
            calls.add(ins.operands[0].imm)
    if 0x4E4A68 in calls and 0x4E4A7C in calls:
        dec.append(s)
print("decryptors:", len(dec))
print([hex(x) for x in dec[:5]], "...", [hex(x) for x in dec[-3:]])
pickle.dump((segs,dec), open(r"D:\workspace\ACE\out\dec_list.pkl","wb"))
