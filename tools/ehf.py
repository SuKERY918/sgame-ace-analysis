import struct, pickle, json, bisect
from collections import defaultdict
data = open(r"D:\workspace\ACE\libs\libtersafe.so","rb").read()
# sections from readelf-like known offsets
EH_HDR = 0x10C234; EH_HDR_SZ = 0x1FCEc
h = data[EH_HDR:EH_HDR+EH_HDR_SZ]
print("hdr:", h[:16].hex())
ver = h[0]; enc_ptr=h[1]; enc_cnt=h[2]; enc_tab=h[3]
print(ver, hex(enc_ptr), hex(enc_cnt), hex(enc_tab))
def read_enc(buf, off, enc):
    fmt = enc & 0x0F
    if fmt==0x00: return struct.unpack_from(">Q", buf, off)[0], off+8
    if fmt==0x02: return struct.unpack_from(">H", buf, off)[0], off+2
    if fmt==0x03: return struct.unpack_from(">I", buf, off)[0], off+4
    if fmt==0x04: return struct.unpack_from(">Q", buf, off)[0], off+8
    if fmt==0x09: return struct.unpack_from("<q", buf, off)[0], off+8
    if fmt==0x0A: return struct.unpack_from("<h", buf, off)[0], off+2
    if fmt==0x0B: return struct.unpack_from("<i", buf, off)[0], off+4
    raise Exception(hex(enc))
off=4
dummy, off = read_enc(h, off, enc_cnt)
cnt, off = read_enc(h, off, enc_cnt)
print("fde count:", cnt)
entries=[]
for i in range(cnt):
    loc, off = read_enc(h, off, enc_tab)
    fde, off = read_enc(h, off, enc_tab)
    if (enc_tab & 0x70)==0x30: loc += EH_HDR
    entries.append(loc)
entries.sort()
print("parsed:", len(entries), "first", hex(entries[0]), "last", hex(entries[-1]))
pickle.dump(entries, open(r"D:\workspace\ACE\out\funcstarts.pkl","wb"))
print("sample:", [hex(x) for x in entries[:5]])
