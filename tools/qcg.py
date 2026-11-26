import json,sys,re
cg=json.load(open(r"D:\workspace\ACE\out\cg.json",encoding="utf-8"))
db=json.load(open(r"D:\workspace\ACE\out\db.json",encoding="utf-8"))
S={int(k):v["s"] for k,v in db.items()}
def A(x): return int(x,0)
def fs(f, maxs=8):
    ss=[S.get(o,"?") for o in cg.get(str(f),{}).get("s",[])]
    return " | ".join(s.replace("\n","\\n")[:48] for s in ss[:maxs])
def cmd_imp(name):
    r=re.compile(name,re.I); n=0
    for f,v in cg.items():
        for m in v["m"]:
            if r.search(m):
                n+=1; print(f"{A(f):08x} via {m:28s} {fs(f)}"); break
    print("total",n)
def cmd_str(pat):
    r=re.compile(pat,re.I); n=0
    for off,v in sorted(((int(k),v) for k,v in db.items())):
        if r.search(v["s"]):
            n+=1; print(f"{off:6d} {v['s'][:70]!r} fn={','.join(f'{A(x):08x}' for x in v['funcs'][:3])}")
    print("total",n)
def cmd_f(f):
    v=cg.get(str(f))
    if not v: print("not in cg"); return
    print(f"== {f:08x}")
    print("imports:", ", ".join(v["m"]))
    ss=[S.get(o,"?") for o in v["s"]]
    print(f"strings({len(ss)}):")
    for s in ss[:40]: print("   ", s.replace("\n","\\n")[:100])
    print("callees:", ", ".join(f"{A(c):08x}" for c in v["i"][:60]))
def cmd_callers(t):
    t=A(t); out=[]
    for f,v in cg.items():
        if t in [A(x) for x in v["i"]]: out.append(A(f))
    print("callers:", ", ".join(f"{x:08x}" for x in sorted(set(out))))
def main():
    c=sys.argv[1]
    if c=="imp": cmd_imp(sys.argv[2])
    elif c=="str": cmd_str(sys.argv[2])
    elif c=="f": cmd_f(A(sys.argv[2]))
    elif c=="callers": cmd_callers(sys.argv[2])
main()
