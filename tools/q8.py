import pickle,sys
addr=int(sys.argv[1],16)
calls=pickle.load(open(r"D:\workspace\ACE\out\calls.pkl","rb"))
print(type(calls), len(calls))
print(calls[:3] if isinstance(calls,list) else list(calls.items())[:3])
