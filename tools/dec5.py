import pickle, json
from collections import Counter
tbl = open(r"D:\workspace\ACE\out\strtab.bin","rb").read()
segs, dec = pickle.load(open(r"D:\workspace\ACE\out\dec_list.pkl","rb"))
params = pickle.load(open(r"D:\workspace\ACE\out\dparams.pkl","rb"))
sites = pickle.load(open(r"D:\workspace\ACE\out\sites.pkl","rb"))
def decrypt(idx,E,C):
    if idx+3>len(tbl): return None
    key=tbl[idx]; L=tbl[idx+1]^key
    if L==0 or idx+3+L>len(tbl): return None
    k=key; p=bytearray(); cs=0xFF; E=0 if E is None else E
    for j in range(L):
        b=tbl[idx+2+j]^(k&0xFF); p.append(b); cs^=b
        k=(((k+j)^E)+C)&0xFFFFFFFF
    return bytes(p), ((tbl[idx+2+L]^cs^key)==0xFF)
res={}
for addr,tgt,val,va in sites:
    E,C=params[tgt]
    r=decrypt(val,E,C)
    if not r: continue
    p,ok=r
    if not ok or not p or not all(32<=x<127 or x in (9,10,13) for x in p): continue
    res.setdefault(val,[]).append((tgt,E,C,p.decode("latin1")))
out={str(k):v[0][3] for k,v in sorted(res.items())}
json.dump(out, open(r"D:\workspace\ACE\out\strings.json","w",encoding="utf-8"), ensure_ascii=False, indent=0)
print("strings:", len(out))
pickle.dump(res, open(r"D:\workspace\ACE\out\res.pkl","wb"))
for k in list(out)[:40]: print(k, repr(out[k]))
