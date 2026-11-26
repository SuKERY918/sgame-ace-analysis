import collections, pickle
data=open(r"D:\workspace\ACE\libs\libtersafe.so","rb").read()
lo,hi=0x90EC0,0xFBCB0
# collect NUL-terminated blobs (len 2..200) starting at every offset where previous byte is 0
blobs=[]
i=lo
while i<hi:
    j=data.find(b"\x00",i,hi)
    if j<0: break
    L=j-i
    if 2<=L<=200: blobs.append((i,L))
    i=j+1
print("blobs",len(blobs))
hist=collections.Counter()
assign={}
for a,L in blobs:
    b=data[a:a+L]
    ks=[]
    for k in range(256):
        ok=True
        for t,c in enumerate(b):
            p=c^((k+t)&0xFF)
            if p<0x20 or p>0x7e: ok=False; break
        if ok: ks.append(k)
    for k in ks: hist[k]+=1
print(hist.most_common(20))
pickle.dump((blobs,hist), open(r"D:\workspace\ACE\out\blobhist.pkl","wb"))
