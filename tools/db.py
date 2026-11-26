import pickle, json, bisect
from collections import defaultdict, Counter
found = pickle.load(open(r"D:\workspace\ACE\out\found.pkl","rb"))
sites = pickle.load(open(r"D:\workspace\ACE\out\sites.pkl","rb"))
params = pickle.load(open(r"D:\workspace\ACE\out\dparams.pkl","rb"))
fs = pickle.load(open(r"D:\workspace\ACE\out\funcstarts.pkl","rb"))
def func_of(a):
    i = bisect.bisect_right(fs, a)-1
    return fs[i] if i>=0 else None
byoff=defaultdict(list)
for addr,tgt,val,va in sites:
    byoff[val].append((addr, func_of(addr), tgt))
rows=[]
for off in sorted(found):
    s=found[off][1]
    refs = byoff.get(off, [])
    funcs = sorted(set(f for _,f,_ in refs))
    rows.append((off, len(s), len(refs), s, funcs))
with open(r"D:\workspace\ACE\out\strings.tsv","w",encoding="utf-8") as f:
    for off,l,n,s,funcs in rows:
        f.write(f"{off}\t{l}\t{n}\t{s}\n")
db={}
for off,l,n,s,funcs in rows:
    db[off]={"s":s,"n":n,"funcs":[hex(x) for x in funcs],"sites":[hex(a) for a,_,_ in byoff.get(off,[])]}
json.dump({str(k):v for k,v in db.items()}, open(r"D:\workspace\ACE\out\db.json","w",encoding="utf-8"), ensure_ascii=False)
print("rows:", len(rows), "unreferenced:", sum(1 for r in rows if r[2]==0))
print("funcs count:", len(set(f for _,f,_ in sites)))
import collections
c=Counter(len(set(f for _,f,_ in byoff[o])) for o in byoff)
print("offsets:", len(byoff))
