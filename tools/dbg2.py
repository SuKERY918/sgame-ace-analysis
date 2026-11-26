import pickle
from capstone import *
from capstone.arm64 import *
data=open(r"D:\workspace\ACE\libs\libtersafe.so","rb").read()
text=data[0x1B6C20:0x50DFC8]
decs=pickle.load(open(r"D:\workspace\ACE\out\decoders.pkl","rb"))
print("0x279f04 in decs?", 0x279F04 in decs, "0x1d69f4", 0x1D69F4 in decs)
md=Cs(CS_ARCH_ARM64,CS_MODE_ARM); md.detail=True
n=0
for ins in md.disasm(text,0x1B6C20):
    if ins.mnemonic=="bl":
        n+=1
print("total bl", n)
# sample a few bl operands
c=0
for ins in md.disasm(text,0x1B6C20):
    if ins.mnemonic=="bl":
        print(hex(ins.address), ins.op_str, ins.operands[0].type)
        c+=1
        if c>3: break
