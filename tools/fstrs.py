import sys
addr=int(sys.argv[1],16)
rows=[]
for ln in open(r"D:\workspace\ACE\out\allstr.tsv",encoding="utf-8"):
    k,off,func,site,s=ln.rstrip("\n").split("\t",4)
    if func==f"{addr:08x}": rows.append((int(site,16),k,int(off),s))
rows.sort()
for site,k,off,s in rows: print(f"{site:08x} {k} {off:6d} {s}")
