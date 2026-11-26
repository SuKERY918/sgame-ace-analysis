import pickle,sys
starts=pickle.load(open(r"D:\workspace\ACE\out\funcstarts.pkl","rb"))
a=int(sys.argv[1],16)
i=starts.index(a)
print(hex(a),"size",hex(starts[i+1]-a),"next",hex(starts[i+1]))
