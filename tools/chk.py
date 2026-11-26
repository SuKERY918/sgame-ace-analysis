import pickle, json
tbl = open(r"D:\workspace\ACE\out\strtab.bin","rb").read()
found = pickle.load(open(r"D:\workspace\ACE\out\found.pkl","rb"))
sites = pickle.load(open(r"D:\workspace\ACE\out\sites.pkl","rb"))
params = pickle.load(open(r"D:\workspace\ACE\out\dparams.pkl","rb"))
N=len(tbl)
print("records:", len(found), "max off:", max(found))
print("tail bytes 60580..60640:", tbl[60580:60640].hex(' '))
print("zero run tail?", len(tbl[60586:]) , "zeros:", tbl[60586:].count(0))
for a,b in [(53274,53314),(58472,58536)]:
    print(a, tbl[a:b].hex(' '))
# xref counts
from collections import Counter
cnt=Counter(v for _,_,v,_ in sites)
print("most referenced:")
for off,c in cnt.most_common(15):
    print(off, c, repr(found.get(off,(None,"?"))[1]))
pickle.dump(dict(cnt), open(r"D:\workspace\ACE\out\xcnt.pkl","wb"))
