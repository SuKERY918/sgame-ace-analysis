import pickle
s=pickle.load(open(r"D:\workspace\ACE\out\funcstarts.pkl","rb"))
print([hex(x) for x in s if 0x1BC000<=x<=0x1BF000])
