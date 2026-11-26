import pickle,json,collections
calls=pickle.load(open(r"D:\workspace\ACE\out\calls.pkl","rb"))
c=collections.Counter(k for _,_,_,k,_ in calls)
print(c)
imp=collections.Counter(n for _,_,_,k,n in calls if k=="imp")
print(len(imp)); print(imp.most_common(25))
