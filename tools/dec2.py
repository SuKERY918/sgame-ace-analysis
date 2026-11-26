import pickle
tbl = open(r"D:\workspace\ACE\out\strtab.bin","rb").read()

def decrypt(idx, eor, add):
    key = tbl[idx]; L = tbl[idx+1]^key
    p = bytearray(); k = key
    for j in range(L):
        p.append(tbl[idx+2+j] ^ (k & 0xFF))
        k = (((k+j) ^ eor) + add) & 0xFFFFFFFF
    return bytes(p)

idx = 0; recs=[]; params=[]; offsets=[]
while idx < len(tbl)-3:
    key = tbl[idx]; L = tbl[idx+1]^key
    if L == 0:
        recs.append(b""); params.append(None); offsets.append(idx); idx += 3; continue
    if idx+3+L > len(tbl):
        print("overrun at", idx); break
    chk = tbl[idx+2+L]; found=None
    for eor in range(256):
        for add in range(256):
            k=key; cs=0xFF
            for j in range(L):
                cs ^= tbl[idx+2+j] ^ (k & 0xFF)
                k = (((k+j) ^ eor) + add) & 0xFFFFFFFF
            if (chk ^ cs ^ key) == 0xFF:
                found=(eor,add); break
        if found: break
    if not found:
        print("no params at", idx, "L=",L); break
    recs.append(decrypt(idx,*found)); params.append(found); offsets.append(idx)
    idx += 3+L

print("records:", len(recs), "next idx:", idx)
pickle.dump((recs,params,offsets), open(r"D:\workspace\ACE\out\recs.pkl","wb"))
for i in range(0, 120):
    print(i, params[i], repr(recs[i][:110]))
