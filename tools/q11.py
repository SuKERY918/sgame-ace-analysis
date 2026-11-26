lo,hi=0x4CB000,0x4CD400
for ln in open(r"D:\workspace\ACE\out\allstr.tsv",encoding="utf-8"):
    k,off,func,site,s=ln.rstrip("\n").split("\t",4)
    f=int(func,16)
    if lo<=f<hi: print(f"{func} {site} {s}")
