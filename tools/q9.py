import pickle,pprint
for f in ["dec_list","found","dparams"]:
    try:
        o=pickle.load(open(rf"D:\workspace\ACE\out\{f}.pkl","rb"))
    except Exception as e:
        print(f,"ERR",e); continue
    print("==",f,type(o),len(o))
    if isinstance(o,dict):
        for k in list(o)[:3]: print("  ",k,"->",repr(o[k])[:120])
    else:
        print("  ",repr(o[:3])[:200])
