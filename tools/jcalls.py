import pickle
from capstone import *
from capstone.arm64 import *
data=open(r"D:\workspace\ACE\libs\libtersafe.so","rb").read()
text=data[0x1B6C20:0x50DFC8]
md=Cs(CS_ARCH_ARM64,CS_MODE_ARM); md.detail=True
DEC=0x1D69F4
regs={}
last=[]
hits=[]
targets={}
for ins in md.disasm(text,0x1B6C20):
    m=ins.mnemonic; ops=ins.operands
    if m=="bl" and ops[0].type==ARM64_OP_IMM and ops[0].imm==DEC:
        ptr=regs.get("x0"); ln=regs.get("x1")
        hits.append((ins.address,ptr,ln,ins.address))
    # track adrp/add/mov
    if m=="adrp":
        regs[ins.reg_name(ops[0].reg)]=ops[1].imm
    elif m=="add" and ops[1].type==ARM64_OP_REG and ops[2].type==ARM64_OP_IMM:
        r=ins.reg_name(ops[0].reg); b=ins.reg_name(ops[1].reg)
        if b in regs: regs[r]=regs[b]+ops[2].imm
    elif m=="mov" and ops[0].type==ARM64_OP_REG and len(ops)>1:
        r=ins.reg_name(ops[0].reg)
        if ops[1].type==ARM64_OP_IMM: regs[r]=ops[1].imm
        elif ops[1].type==ARM64_OP_REG and ins.reg_name(ops[1].reg) in regs: regs[r]=regs[ins.reg_name(ops[1].reg)]
    if m in ("bl","b","ret") or (m=="br"):
        for k in list(regs): 
            if k not in ("sp","wsp"): regs.pop(k,None)
print("hits",len(hits))
def dec(p,l):
    if p is None or l is None or l<=0 or l>512: return None
    b=data[p:p+l]
    if len(b)!=l: return None
    return bytes(c^((0x91+i)&0xFF) for i,c in enumerate(b))
ok=0
out=[]
for a,p,l,_ in hits:
    s=dec(p,l)
    if s is not None:
        out.append((a,p,l,s))
        ok+=1
print("decoded",ok)
import json
json.dump([[a,p,l,s.decode("latin1")] for a,p,l,s in out], open(r"D:\workspace\ACE\out\java_calls.json","w"))
for a,p,l,s in out[:25]:
    print(f"{a:08x} {p:06x} {l:3d} {s!r}")
