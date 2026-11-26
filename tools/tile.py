import pickle
res = pickle.load(open(r"D:\workspace\ACE\out\res.pkl","rb"))
tbl = open(r"D:\workspace\ACE\out\strtab.bin","rb").read()
offs = sorted(res)
print("count", len(offs), "first", offs[:10], "last", offs[-5:])
gaps=[]; overlaps=[]
for a,b in zip(offs, offs[1:]):
    p = res[a][0][3]
    end = a+3+len(p)
    if end != b:
        gaps.append((a,p,end,b))
print("non-adjacent pairs:", len(gaps))
for g in gaps[:20]: print(g)
