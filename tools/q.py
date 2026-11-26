import json,sys,re
db=json.load(open(r"D:\workspace\ACE\out\db.json",encoding="utf-8"))
recs=[(int(k),v) for k,v in db.items()]
def H(x):
    return f"{int(x,0):08x}"
def q(pat, limit=60):
    r=re.compile(pat,re.I); out=[]
    for off,v in sorted(recs):
        if r.search(v["s"]):
            fs=",".join(H(f) for f in v["funcs"]); st=",".join(H(a) for a in v["sites"])
            out.append(f"{off:6d} [{v['n']:2d}] {v['s'][:60]!r} fn={fs} sites={st}")
    print(f"=== {pat} : {len(out)} hits")
    for l in out[:limit]: print(l)
if __name__=="__main__":
    for p in sys.argv[1:]: q(p)
