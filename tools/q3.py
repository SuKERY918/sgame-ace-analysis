import json
db=json.load(open(r"D:\workspace\ACE\out\db.json",encoding="utf-8"))
print(db.get("2349828"))
print(db.get("2297976"))  # 0x230c78
print(len([k for k,v in db.items() if v["sites"]]))
import collections
print(collections.Counter(len(v["sites"]) for v in db.values()).most_common(6))
