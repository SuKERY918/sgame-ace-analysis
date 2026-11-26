import pickle, bisect, json
from capstone import *
from capstone.arm64 import *
base=0
text=open(r"D:\workspace\ACE\libs\libtersafe.so","rb").read()[0x1B6C20:0x50DFC8]
starts=pickle.load(open(r"D:\workspace\ACE\out\funcstarts.pkl","rb"))
startset=set(starts)
rel=pickle.load(open(r"D:\workspace\ACE\out\pltrel.pkl","rb"))
# plt map: verify by decoding stubs
pltbase=0x50DFD0
# decode plt to got map
import struct
data=open(r"D:\workspace\ACE\libs\libtersafe.so","rb").read()
plt2got={}
for i,(got,name) in enumerate(rel):
    a=pltbase+32+16*i
    adrp=struct.unpack_from("<I",data,a)[0]
    ldr=struct.unpack_from("<I",data,a+4)[0]
    # adrp x16, imm ; ldr x17,[x16,#imm]
    immlo=(adrp>>29)&3; immhi=(adrp>>5)&0x7FFFF
    off=((immhi<<2)|immlo)
    if off&(1<<20): off-=1<<21
    page=(a & ~0xFFF)+ (off<<12)
    ldr_off=(ldr>>10)&0xFFF
    plt2got[a]= (name, page+ldr_off*8)
print("plt sample", [(hex(k),v[0],hex(v[1])) for k,v in list(plt2got.items())[:3]])
print("expect", rel[0])
pickle.dump({k:v[0] for k,v in plt2got.items()}, open(r"D:\workspace\ACE\out\pltmap.pkl","wb"))
