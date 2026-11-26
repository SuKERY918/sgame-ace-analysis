import pickle, collections
from capstone import *
from capstone.arm64 import *
data=open(r"D:\workspace\ACE\libs\libtersafe.so","rb").read()
text=data[0x1B6C20:0x50DFC8]
md=Cs(CS_ARCH_ARM64,CS_MODE_ARM); md.detail=True
def N(ins,r):
    n=ins.reg_name(r)
    if n and n[0]=="w" and n[1:].isdigit(): return "x"+n[1:]
    return n
regs={}; cnt=collections.Counter(); samples=collections.defaultdict(list)
for ins in md.disasm(text,0x1B6C20):
    m=ins.mnemonic; ops=ins.operands
    if m in ("bl","b","br","blr","ret","cbz","cbnz","tbz","tbnz"):
        if m=="bl" and ops[0].type==ARM64_OP_IMM:
            p=regs.get("x0"); l=regs.get("x1")
            if p is not None and l is not None and 1<=l<=600 and 0x90000<=p<0x110000:
                t=ops[0].imm; cnt[t]+=1
                if len(samples[t])<3: samples[t].append((ins.address,p,l))
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
print("distinct targets", len(cnt), "total sites", sum(cnt.values()))
for t,c in cnt.most_common(25): print(f"{t:08x} {c:5d} {samples[t][:2]}")
