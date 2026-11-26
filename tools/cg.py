import pickle, bisect, json
from capstone import *
data=open(r"D:\workspace\ACE\libs\libtersafe.so","rb").read()
text=data[0x1B6C20:0x50DFC8]
starts=pickle.load(open(r"D:\workspace\ACE\out\funcstarts.pkl","rb"))
startset=set(starts)
pltmap=pickle.load(open(r"D:\workspace\ACE\out\pltmap.pkl","rb"))
sites=pickle.load(open(r"D:\workspace\ACE\out\sites.pkl","rb"))
md=Cs(CS_ARCH_ARM64,CS_MODE_ARM); md.detail=False
calls=[]
for ins in md.disasm(text, 0x1B6C20):
    m=ins.mnemonic
    if m.startswith("bl") or m.startswith("b.") or m=="b":
        op=ins.op_str
        if not op.startswith("#"): continue
        try: t=int(op[1:],0)
        except: continue
        i=bisect.bisect_right(starts,ins.address)-1
        fl=starts[i] if i>=0 else None
        if t in startset: calls.append((ins.address,fl,t,"int",""))
        elif t in pltmap: calls.append((ins.address,fl,t,"imp",pltmap[t]))
pickle.dump(calls, open(r"D:\workspace\ACE\out\calls.pkl","wb"))
from collections import defaultdict
INT=defaultdict(set); IMP=defaultdict(set); STR=defaultdict(set)
for pc,fl,t,kind,name in calls:
    if fl is None: continue
    if kind=="int": INT[fl].add(t)
    else: IMP[fl].add(name)
for b,tgt,off,mov in sites:
    i=bisect.bisect_right(starts,b)-1
    fl=starts[i] if i>=0 else None
    if fl is not None: STR[fl].add(off)
cg={}
for f in starts:
    if f in INT or f in IMP or f in STR:
        cg[str(f)]={"i":sorted(INT.get(f,())),"m":sorted(IMP.get(f,())),"s":sorted(STR.get(f,()))}
json.dump(cg, open(r"D:\workspace\ACE\out\cg.json","w"))
print("funcs in cg", len(cg), "imp pairs", sum(len(v["m"]) for v in cg.values()))
