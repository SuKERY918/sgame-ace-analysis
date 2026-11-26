from capstone import *
from capstone.arm64 import *
import struct
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
for w in (0x4E64D0, 0x4E65EC, 0x4EB394, 0x4E6708):
    print("=====", hex(w))
    blob = data[v2o(w):v2o(w)+0x11C]
    for ins in md.disasm(blob, w):
        if ins.mnemonic in ("add","eor","sub","movk","mov"): print(" ", hex(ins.address), ins.mnemonic, ins.op_str)
