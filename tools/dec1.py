tbl = open(r"D:\workspace\ACE\out\strtab.bin","rb").read()

def try_dec(idx, eor, add):
    key = tbl[idx]
    L = tbl[idx+1] ^ key
    if L == 0 or idx+3+L > len(tbl): return None
    p = bytearray()
    k = key
    for j in range(L):
        p.append(tbl[idx+2+j] ^ (k & 0xFF))
        k = (((k + j) ^ eor) + add) & 0xFFFFFFFF
    cs = 0xFF
    for b in p: cs ^= b
    if (tbl[idx+2+L] ^ cs ^ key) == 0xFF:
        return bytes(p)
    return None

# test record 0
print("idx0:", try_dec(0,0,0))

# sequential walk, brute force params
idx = 0
recs = []
params = []
fail_at = None
while idx < len(tbl)-3:
    key = tbl[idx]
    L = tbl[idx+1]^key
    if L == 0:
        recs.append(b""); params.append(None); idx += 3; continue
    if idx+3+L > len(tbl):
        fail_at = idx; break
    found = None
    # try all eor, add but early exit by check byte
    chk = tbl[idx+2+L]
    for eor in range(256):
        # optimize: we can't easily invert, brute force add
        for add in range(256):
            k = key; cs = 0xFF
            ok = True
            for j in range(L):
                b = tbl[idx+2+j] ^ (k & 0xFF)
                cs ^= b
                k = (((k+j) ^ eor) + add) & 0xFFFFFFFF
            if (chk ^ cs ^ key) == 0xFF:
                found = (eor, add)
                break
        if found: break
    if not found:
        fail_at = idx; break
    recs.append(try_dec(idx, *found)); params.append(found)
    idx += 3+L

print("records:", len(recs), "stopped at", fail_at, "of", len(tbl))
for i,(r,p) in enumerate(recs[:20]):
    print(i, p, r[:80])
import pickle
pickle.dump((recs,params), open(r"D:\workspace\ACE\out\recs.pkl","wb"))
