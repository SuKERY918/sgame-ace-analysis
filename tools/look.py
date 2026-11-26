import sys,re,json
P=r"D:\workspace\ACE\out\allstr.tsv"
rows=[]
for ln in open(P,encoding="utf-8"):
    k,off,func,site,s=ln.rstrip("\n").split("\t",4)
    rows.append((k,int(off),func,int(site,16),s))
def show(regex,limit=200):
    r=re.compile(regex,re.I); n=0
    for k,off,func,site,s in rows:
        if r.search(s):
            n+=1
            if n<=limit: print(f"{k} off={off:6d} fn={func} site={site:08x} {s[:110]}")
    print(f"-- {n} hits")
def forfunc(f,limit=200):
    f=f.lower().lstrip("0x").zfill(8); n=0
    for k,off,func,site,s in rows:
        if func==f:
            n+=1; print(f"{k} off={off:6d} site={site:08x} {s[:110]}")
    print(f"-- {n} strings for {f}")
def calls(f):
    cg=json.load(open(r"D:\workspace\ACE\out\cg.json",encoding="utf-8"))
    v=cg.get(str(int(f,16)))
    if not v: print("no cg"); return
    print("imports:", ", ".join(v["m"]))
    print("callees:", ", ".join(f"{int(x,0):08x}" for x in v["i"]))
if __name__=="__main__":
    a=sys.argv[1:]
    if not a: sys.exit()
    if a[0]=="-f": forfunc(a[1])
    elif a[0]=="-c": calls(a[1])
    else: show(a[0], int(a[1]) if len(a)>1 else 200)
