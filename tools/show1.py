import pickle
recs, params = pickle.load(open(r"D:\workspace\ACE\out\recs.pkl","rb"))
print("records:", len(recs))
for i in range(0, 80):
    p = params[i]
    print(i, p, repr(recs[i][:100]))
