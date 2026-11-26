import pickle, json, re
from capstone import *
from capstone.arm64 import *
data=open(r"D:\workspace\ACE\libs\libtersafe.so","rb").read()
text=data[0x1B6C20:0x50DFC8]
decs=pickle.load(open(r"D:\workspace\ACE\out\decoders.pkl","rb"))
md=Cs(CS_ARCH_ARM64,CS_MODE_ARM); md.detail=True
def N(ins,r):
    n=ins.reg_name(r)
    if n and n[0]=="w" and n[1:].isdigit(): return "x"+n[1:]
    return n
regs={}; out=[]
for ins in md.disasm(text,0x1B6C20):
    m=ins.mnemonic; ops=ins.operands
    if m in ("bl","b","br","blr","ret","cbz","cbnz","tbz","tbnz"):
        if m=="bl" and ops[0].type==ARM64_OP_IMM:
            t=ops[0].imm
            if t in decs:
                p=regs.get("x0"); l=regs.get("x1")
                if p is not None and l is not None and 1<=l<=600:
                    out.append((ins.address,t,decs[t],p,l))
        regs.clear(); continue
    if not ops: continue
    if m=="adrp":
        regs[N(ins,ops[0].reg)]=ops[1].imm; continue
    if m=="add" and len(ops)>=3 and ops[1].type==ARM64_OP_REG and ops[2].type==ARM64_OP_IMM:
        r=N(ins,ops[0].reg); b=N(ins,ops[1].reg)
        if b in regs: regs[r]=regs[b]+ops[2].imm; continue
    if m=="mov" and len(ops)>=2:
        r=N(ins,ops[0].reg)
        if ops[1].type==ARM64_OP_IMM: regs[r]=ops[1].imm; continue
        if ops[1].type==ARM64_OP_REG:
            b=N(ins,ops[1].reg)
            if b in regs: regs[r]=regs[b]
            else: regs.pop(r,None)
            continue
    for o in ops:
        if o.type==ARM64_OP_REG and (o.access & CS_AC_WRITE):
            regs.pop(N(ins,o.reg),None)
print("sites",len(out))
def dec(p,l,k):
    b=data[p:p+l]
    if len(b)!=l: return None
    return bytes(c^((k+i)&0xFF) for i,c in enumerate(b))
res=[]
for a,t,k,p,l in out:
    s=dec(p,l,k)
    if s is not None: res.append((a,t,k,p,l,s))
print("decoded",len(res))
ok=0
for a,t,k,p,l,s in res:
    if all(0x20<=x<=0x7e for x in s.rstrip(b"\x00")) and s.endswith(b"\x00"): ok+=1
print("plausible",ok)
pickle.dump(res, open(r"D:\workspace\ACE\out\inline.pkl","wb"))
for a,t,k,p,l,s in res[:25]:
    print(f"{a:08x} k={k:#04x} {p:06x} {l:3d} {s!r}")
