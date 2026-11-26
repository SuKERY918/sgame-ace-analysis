import struct, pickle
data = open(r"D:\workspace\ACE\libs\libtersafe.so","rb").read()
EH_HDR = 0x10C234; EH_HDR_SZ = 0x1FCEc
h = data[EH_HDR:EH_HDR+EH_HDR_SZ]
off=8
cnt = 0x3F9C
entries=[]
for i in range(cnt):
    loc, off = struct.unpack_from("<i", h, off)[0], off+4
    fde, off = struct.unpack_from("<i", h, off)[0], off+4
    entries.append(EH_HDR + loc)
entries.sort()
print("parsed:", len(entries), hex(entries[0]), hex(entries[-1]))
import pickle
pickle.dump(entries, open(r"D:\workspace\ACE\out\funcstarts.pkl","wb"))
