import pickle, json, bisect, os
starts=pickle.load(open(r"D:\workspace\ACE\out\funcstarts.pkl","rb"))
db=json.load(open(r"D:\workspace\ACE\out\db.json",encoding="utf-8"))
res,keys=pickle.load(open(r"D:\workspace\ACE\out\inline2.pkl","rb"))
rows=[]
for k,v in db.items():
    off=int(k)
    f0=int(v["funcs"][0],16) if v["funcs"] else 0
    s0=int(v["sites"][0],16) if v["sites"] else 0
    if not v["funcs"]:
        continue
    for f in v["funcs"]:
        rows.append(("T", off, v["s"], int(f,16), s0))
def fn(a):
    i=bisect.bisect_right(starts,a)-1
    return starts[i] if i>=0 else 0
for a,t,k,p,l,s in res:
    rows.append(("I", p, s.rstrip("\x00"), fn(a), a))
seen=set(); out=[]
for r in rows:
    key=(r[0],r[1],r[2],r[3])
    if key in seen: continue
    seen.add(key); out.append(r)
tmp=r"D:\workspace\ACE\out\allstr.tsv.tmp"
with open(tmp,"w",encoding="utf-8") as f:
    for kind,off,s,func,site in out:
        f.write(f"{kind}\t{off}\t{func:08x}\t{site:08x}\t{s}\n")
os.replace(tmp, r"D:\workspace\ACE\out\allstr.tsv")
print("rows",len(out))
