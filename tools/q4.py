import json
db=json.load(open(r"D:\workspace\ACE\out\db.json",encoding="utf-8"))
for k,v in db.items():
    if v["sites"]:
        print(k, v["s"]); print(v["sites"][:2]); print(v["funcs"][:2]); break
