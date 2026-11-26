import pickle
m=pickle.load(open(r"D:\workspace\ACE\out\pltmap.pkl","rb"))
print(type(m), len(m))
items = m.items() if isinstance(m,dict) else m
names=sorted({(v if isinstance(v,str) else str(v)) for k,v in items})
print(len(names))
for n in names: print(n)
