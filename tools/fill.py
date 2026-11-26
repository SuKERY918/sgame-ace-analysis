import pickle, json, sys
sys.setrecursionlimit(10000)
from collections import Counter, defaultdict
tbl = open(r"D:\workspace\ACE\out\strtab.bin","rb").read()
res = pickle.load(open(r"D:\workspace\ACE\out\res.pkl","rb"))
N = len(tbl)
ALL = [(7*t-C, C) for C in range(1,8) for t in range(1,15)] + [(0,7)]
def dec(idx,E,C):
    if idx+3>N: return None
    key=tbl[idx]; L=tbl[idx+1]^key
    if L==0 or idx+3+L>N: return None
    k=key; p=bytearray(); cs=0xFF
    for j in range(L):
        b=tbl[idx+2+j]^(k&0xFF); p.append(b); cs^=b
        k=(((k+j)^E)+C)&0xFFFFFFFF
    if (tbl[idx+2+L]^cs^key)!=0xFF: return None
    if not all(32<=x<127 or x in (9,10,13) for x in p): return None
    return bytes(p)

known = {o: res[o][0][3] for o in res}
offs = sorted(res)
bounds = [0] + offs + [N]
found = {}
failures = []
for A,B in zip(bounds, bounds[1:]):
    start = A
    if A in known: 
        found[A] = (None, known[A]); start = A+3+len(known[A])
    if start == B: continue
    if start > B: continue
    # dfs
    memo=set()
    def dfs(idx, depth=0):
        if idx == B: return []
        if idx > B or depth>200: return None
        if idx in memo: return None
        for (E,C) in ALL:
            p = dec(idx,E,C)
            if p is None: continue
            r = dfs(idx+3+len(p), depth+1)
            if r is not None: return [(idx,(E,C),p.decode('latin1'))]+r
        memo.add(idx)
        return None
    r = dfs(start)
    if r is None:
        failures.append((A,B,start))
    else:
        for idx,param,p in r: found[idx]=(param,p)
print("filled records:", len(found), "failures:", len(failures))
for f in failures[:10]: print("FAIL", f, tbl[f[2]:f[2]+12].hex())
json.dump({str(k):v[1] for k,v in sorted(found.items())}, open(r"D:\workspace\ACE\out\allstrings.json","w",encoding="utf-8"), ensure_ascii=False, indent=0)
pickle.dump(found, open(r"D:\workspace\ACE\out\found.pkl","wb"))
