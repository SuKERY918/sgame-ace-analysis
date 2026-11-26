import pickle, collections, json, re
from capstone import *
from capstone.arm64 import *
data=open(r"D:\workspace\ACE\libs\libtersafe.so","rb").read()
text=data[0x1B6C20:0x50DFC8]
md=Cs(CS_ARCH_ARM64,CS_MODE_ARM); md.detail=True
def N(ins,r):
    n=ins.reg_name(r)
    if n and n[0]=="w" and n[1:].isdigit(): return "x"+n[1:]
    return n
regs={}; sites=[]
for ins in md.disasm(text,0x1B6C20):
    m=ins.mnemonic; ops=ins.operands
    if m in ("bl","b","br","blr","ret","cbz","cbnz","tbz","tbnz"):
        if m=="bl" and ops[0].type==ARM64_OP_IMM:
            p=regs.get("x0"); l=regs.get("x1")
            if p is not None and l is not None and 1<=l<=600 and 0x90000<=p<0x110000:
                sites.append((ins.address,ops[0].imm,p,l))
        regs.clear(); continue
    if not ops: continue
    if m=="adrp": regs[N(ins,ops[0].reg)]=ops[1].imm; continue
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
        if o.type==ARM64_OP_REG and (o.access & CS_AC_WRITE): regs.pop(N(ins,o.reg),None)
print("sites",len(sites))
by=collections.defaultdict(list)
for a,t,p,l in sites: by[t].append((a,p,l))
def dec(p,l,k):
    b=data[p:p+l]
    return bytes(c^((k+i)&0xFF) for i,c in enumerate(b)) if len(b)==l else None
def score(s):
    if s is None or len(s)<1 or not s.endswith(b"\x00"): return 0
    body=s[:-1]
    if not body: return 0
    for c in body:
        if c<0x20 or c>0x7e: return 0
    alnum=sum(1 for c in body if chr(c).isalnum() or c in b"/._-:$%();[]<>@*,+=#!? ")
    return alnum/len(body)
keys={}
total=0
res=[]
for t,lst in by.items():
    best=None
    for k in range(256):
        sc=sum(score(dec(p,l,k)) for a,p,l in lst)
        if best is None or sc>best[0]: best=(sc,k)
    sc,k=best
    good=sum(1 for a,p,l in lst if score(dec(p,l,k))>=0.9)
    keys[t]=(k,good,len(lst))
    for a,p,l in lst:
        s=dec(p,l,k)
        if score(s)>=0.9: res.append((a,t,k,p,l,s.decode("latin1"))); total+=1
print("decoded strings",total)
none=[(hex(t),v) for t,v in keys.items() if v[1]==0]
print("targets with 0 decodes",len(none))
pickle.dump((res,keys), open(r"D:\workspace\ACE\out\inline2.pkl","wb"))
for a,t,k,p,l,s in res[:20]: print(f"{a:08x} {t:08x} k={k:#04x} {s!r}")
