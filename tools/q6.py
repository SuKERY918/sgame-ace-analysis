import struct,bisect
data=open(r"D:\workspace\ACE\libs\libtersafe.so","rb").read()
tab=struct.unpack_from("<88i",data,0x90EC0); base=0x1BD078
cases={}
for i,off in enumerate(tab,1):
    t=base+off
    if t!=base: cases.setdefault(t,[]).append(i)
starts=sorted(cases)
sites=[]
for ln in open(r"D:\workspace\ACE\out\allstr.tsv",encoding="utf-8"):
    k,off,func,site,s=ln.rstrip("\n").split("\t",4)
    if func=="001bcf84": sites.append((int(site,16),s))
for site,s in sorted(sites):
    i=bisect.bisect_right(starts,site)-1
    cs=",".join(str(c) for c in cases[starts[i]]) if i>=0 else "-"
    print(f"{site:08x} cmd[{cs:8s}] {s}")
