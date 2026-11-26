import struct, pickle
data = open(r"D:\workspace\ACE\libs\libtersafe.so","rb").read()
EH_HDR = 0x10C234; EH_HDR_SZ = 0x1FCEc
h = data[EH_HDR:EH_HDR+EH_HDR_SZ]
cnt = 0x3F9C
off=12
starts=[]
fdes=[]
for i in range(cnt):
    loc = struct.unpack_from("<i", h, off)[0]
    fde = struct.unpack_from("<i", h, off+4)[0]
    off+=8
    starts.append(EH_HDR + loc)
    fdes.append(EH_HDR + off - 8 + fde)
starts.sort()
print("count:", len(starts), hex(starts[0]), hex(starts[-1]))
print([hex(x) for x in starts[:5]])
pickle.dump(starts, open(r"D:\workspace\ACE\out\funcstarts.pkl","wb"))
