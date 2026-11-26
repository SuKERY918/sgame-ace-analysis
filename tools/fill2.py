import pickle, json, sys
sys.setrecursionlimit(10000)
tbl = open(r"D:\workspace\ACE\out\strtab.bin","rb").read()
found = pickle.load(open(r"D:\workspace\ACE\out\found.pkl","rb"))
N=len(tbl)
ALL = [(7*t-C, C) for C in range(1,8) for t in range(1,15)] + [(0,7)]
def dec(idx,E,C,ascii_only):
    if idx+3>N: return None
    key=tbl[idx]; L=tbl[idx+1]^key
    if L==0 or idx+3+L>N: return None
    k=key; p=bytearray(); cs=0xFF
    for j in range(L):
        b=tbl[idx+2+j]^(k&0xFF); p.append(b); cs^=b
        k=(((k+j)^E)+C)&0xFFFFFFFF
    if (tbl[idx+2+L]^cs^key)!=0xFF: return None
    if ascii_only:
        if not all(32<=x<127 or x in (9,10,13) for x in p): return None
    else:
        try:
            s=p.decode("utf-8")
        except UnicodeDecodeError: return None
        if any(ord(ch)<32 and ch not in "\t\n\r" for ch in s): return None
    return bytes(p)

fails=[(9096,12281),(13976,14876),(15390,15736),(19412,19713),(19981,20215),(24110,24473),(26165,26541),(28554,29073),(36671,36953),(44787,44962)]
# recompute boundaries from found
offs=sorted(found)
allbounds=[0]+offs+[N]
gaps=[(a,b) for a,b in zip(allbounds,allbounds[1:]) if (a+3+len(found[a][1]) if a in found else a) != b]
print("total gaps:", len(gaps))
newrecs={}
for A,B in gaps:
    start = A+3+len(found[A][1]) if A in found else A
    if start>=B: continue
    memo=set()
    def dfs(idx, depth=0):
        if idx==B: return []
        if idx>B or depth>300 or idx in memo: return None
        for (E,C) in ALL:
            p=dec(idx,E,C,False)
            if p is None: continue
            r=dfs(idx+3+len(p),depth+1)
            if r is not None: return [(idx,(E,C),p)]+r
        memo.add(idx); return None
    r=dfs(start)
    if r is None:
        print("STILL FAIL", A,B,start)
        continue
    for idx,param,p in r:
        newrecs[idx]=(param,p)
print("new records:", len(newrecs))
for k in sorted(newrecs)[:25]:
    print(k, newrecs[k][0], newrecs[k][1][:60])
merged=dict(found)
for k,v in newrecs.items(): merged.setdefault(k,v)
pickle.dump(merged, open(r"D:\workspace\ACE\out\found2.pkl","wb"))
json.dump({str(k):v[1].decode('utf-8','backslashreplace') for k,v in sorted(merged.items())}, open(r"D:\workspace\ACE\out\allstrings.json","w",encoding="utf-8"), ensure_ascii=False, indent=0)
print("total:", len(merged))
