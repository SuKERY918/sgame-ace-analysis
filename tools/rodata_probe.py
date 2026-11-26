data=open(r"D:\workspace\ACE\libs\libtersafe.so","rb").read()
lo,hi=0x90EC0,0xFBCB0
import collections
# find NUL-terminated blobs starting after a NUL
res=[]
i=lo
cand=0
k0c=collections.Counter()
samples=[]
while i<hi:
    j=data.find(b"\x00",i,hi)
    if j<0: break
    if j-i>=4 and j-i<=120:
        cand+=1
        blob=data[i:j]
        for k0 in range(0,256):
            ok=True
            for t,c in enumerate(blob):
                p=c^((k0+t)&0xFF)
                if p<0x20 or p>0x7e: ok=False; break
            if ok:
                k0c[k0]+=1
                if k0==0x91 and len(samples)<20: samples.append((i,blob))
                break
    i=j+1
print("cands",cand,"k0 dist",k0c.most_common(8))
for a,b in samples: print(hex(a), bytes(c^((0x91+t)&0xFF) for t,c in enumerate(b)))
