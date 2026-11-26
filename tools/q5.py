rows=[]
for ln in open(r"D:\workspace\ACE\out\allstr.tsv",encoding="utf-8"):
    k,off,func,site,s=ln.rstrip("\n").split("\t",4)
    if func=="001bcf84": rows.append((int(site,16),k,int(off),s))
rows.sort()
for site,k,off,s in rows: print(f"{site:08x} {k} {off:6d} {s}")
