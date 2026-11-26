import pickle
f=pickle.load(open(r"D:\workspace\ACE\out\found.pkl","rb"))
for o in (33682,33695,33715,33731,33748,33770,33792,3164,35969,35983,290270):
    print(o, repr(f.get(o)))
