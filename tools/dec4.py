import pickle
from collections import Counter, defaultdict
tbl = open(r"D:\workspace\ACE\out\strtab.bin","rb").read()
segs, dec = pickle.load(open(r"D:\workspace\ACE\out\dec_list.pkl","rb"))
params = pickle.load(open(r"D:\workspace\ACE\out\dparams.pkl","rb"))
sites = pickle.load(open(r"D:\workspace\ACE\out\sites.pkl","rb"))

def decrypt(idx, E, C):
    if idx+3 > len(tbl): return None
    key=tbl[idx]; L=tbl[idx+1]^key
    if L==0 or idx+3+L>len(tbl): return None
    k=key; p=bytearray(); cs=0xFF
    E = 0 if E is None else E
    for j in range(L):
        b=tbl[idx+2+j]^(k&0xFF); p.append(b); cs^=b
        k=(((k+j)^E)+C)&0xFFFFFFFF
    ok = ((tbl[idx+2+L]^cs^key)==0xFF)
    return bytes(p), ok, L

res={}
bad=[]
for addr,tgt,val,va in sites:
    E,C = params[tgt]
    r = decrypt(val,E,C)
    if r is None: bad.append((addr,tgt,val,"nolen")); continue
    p,ok,L = r
    printable = all(32<=x<127 or x in (9,10,13) for x in p) and len(p)>0
    if not ok or not printable: bad.append((addr,tgt,val,p,ok))
    res[val]=(tgt,E,C,p,ok,printable)
print("decoded offsets:", len(res), "bad:", len(bad))
ck = Counter((params[t][0],params[t][1]) for t in [tgt for _,tgt,_,_ in sites])
for b in bad[:15]: print(b)
import json
out = {}
for off,(tgt,E,C,p,ok,pr) in sorted(res.items()):
    out[off]={"dec":hex(tgt),"E":E,"C":C,"s":p.decode("latin1")}
json.dump(out, open(r"D:\workspace\ACE\out\strings.json","w"), ensure_ascii=False, indent=0)
print("saved strings.json")
