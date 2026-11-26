import json
db=json.load(open(r"D:\workspace\ACE\out\db.json",encoding="utf-8"))
for k in ["0x2bb8","230c78","23db04"]:
    pass
# print a few records
ks=list(db.keys())
print(len(ks), ks[:3])
for off in [ks[0], "230c78", "23db04"]:
    if off in db: print(off, db[off])
