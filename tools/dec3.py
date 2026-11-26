import pickle
tbl = open(r"D:\workspace\ACE\out\strtab.bin","rb").read()
pairs, sites = pickle.load(open(r"D:\workspace\ACE\out\pairs.pkl","rb"))
plist = [p for p,c in pairs.items() if isinstance(p, tuple) and isinstance(p[1], int)]

def is_printable(b):
    return len(b)>0 and all(32 <= x < 127 or x in (9,10,13) for x in b)

def try_all(idx):
    key=tbl[idx]; L=tbl[idx+1]^key
    if L==0 or idx+3+L>len(tbl): return None
    chk=tbl[idx+2+L]; out=[]
    for eor,add in plist:
        k=key; cs=0xFF; p=bytearray()
        for j in range(L):
            b=tbl[idx+2+j]^(k&0xFF); p.append(b); cs^=b
            k=(((k+j)^eor)+add)&0xFFFFFFFF
        if (chk^cs^key)==0xFF and is_printable(p):
            out.append(((eor,add),bytes(p)))
    return out

idx=0; recs=[]; offs=[]
while idx < len(tbl)-3:
    cand = try_all(idx)
    if cand:
        # prefer unique
        recs.append(cand[0][1]); offs.append((idx,cand[0][0],len(cand))); idx += 3+len(cand[0][1])
    else:
        key=tbl[idx]; L=tbl[idx+1]^key
        print("fail at", idx, "L",L, "bytes", tbl[idx:idx+12].hex())
        break

print("records:", len(recs), "next", idx)
print("multi-candidate offsets:", sum(1 for o in offs if o[2]>1))
for i in range(0, 60): print(i, offs[i], repr(recs[i][:80]))
pickle.dump((recs,offs), open(r"D:\workspace\ACE\out\recs2.pkl","wb"))
