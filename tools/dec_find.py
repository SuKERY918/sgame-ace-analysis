import pickle, json
from capstone import *
from capstone.arm64 import *
data=open(r"D:\workspace\ACE\libs\libtersafe.so","rb").read()
text=data[0x1B6C20:0x50DFC8]
starts=pickle.load(open(r"D:\workspace\ACE\out\funcstarts.pkl","rb"))
md=Cs(CS_ARCH_ARM64,CS_MODE_ARM); md.detail=True
# find decoder-like functions: within first 24 insns, mov wN,#k then ldrb/eor/strb
decs={}
for f in starts:
    off=f-0x1B6C20
    if off<0 or off>=len(text)-64: continue
    ins=list(md.disasm(text[off:off+96], f))
    key=None; has_ldrb=has_strb=has_eor=False
    for i in ins[:20]:
        if i.mnemonic=="mov" and i.operands[0].type==ARM64_OP_REG and "w" in i.reg_name(i.operands[0].reg) and len(i.operands)>1 and i.operands[1].type==ARM64_OP_IMM:
            v=i.operands[1].imm
            if 0x40<=v<=0xF0: key=v&0xFF
        if i.mnemonic.startswith("ldrb"): has_ldrb=True
        if i.mnemonic.startswith("strb"): has_strb=True
        if i.mnemonic=="eor": has_eor=True
    if key is not None and has_ldrb and has_strb and has_eor and len(ins)<40:
        decs[f]=key
print("decoders",len(decs))
for f,k in list(decs.items())[:40]: print(f"{f:08x} key={k:#04x}")
pickle.dump(decs, open(r"D:\workspace\ACE\out\decoders.pkl","wb"))
