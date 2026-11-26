import struct, sys

path = r"D:\workspace\ACE\libs\libtersafe.so"
data = open(path,"rb").read()
assert data[:4] == b"\x7fELF"
is64 = data[4] == 2
e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
e_phnum = struct.unpack_from("<H", data, 0x38)[0]
segs = []
for i in range(e_phnum):
    off = e_phoff + i*e_phentsize
    p_type, p_flags = struct.unpack_from("<II", data, off)
    p_offset, p_vaddr, p_paddr, p_filesz, p_memsz = struct.unpack_from("<QQQQQ", data, off+8)
    if p_type == 1:
        segs.append((p_vaddr, p_offset, p_filesz, p_memsz, p_flags))
        print(f"LOAD vaddr=0x{p_vaddr:x} off=0x{p_offset:x} filesz=0x{p_filesz:x} memsz=0x{p_memsz:x} flags={p_flags}")

def v2o(v):
    for va, off, fs, ms, fl in segs:
        if va <= v < va+fs:
            return off + (v-va)
    raise ValueError(hex(v))

tbl_v = 0xFBCB0
tbl_len = 66948
o = v2o(tbl_v)
print("table file offset", hex(o), "end", hex(o+tbl_len))
tbl = data[o:o+tbl_len]
open(r"D:\workspace\ACE\out\strtab.bin","wb").write(tbl)
print("first 64 bytes:", tbl[:64].hex())
# stats
from collections import Counter
lens = Counter()
for i in range(0, tbl_len-2):
    key = tbl[i]; L = tbl[i+1]^key
    lens[L]+=1
print("len byte distribution (top20):", lens.most_common(20))
print("total offsets:", tbl_len)
