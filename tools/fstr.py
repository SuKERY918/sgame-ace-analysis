import json
from collections import defaultdict
db=json.load(open(r"D:\workspace\ACE\out\db.json",encoding="utf-8"))
byfunc=defaultdict(list)
for k,v in db.items():
    off=int(k)
    for f in v["funcs"]:
        byfunc[int(f,16)].append((off,v["s"]))
print("funcs with strings:", len(byfunc))
lines=[]
for f in sorted(byfunc):
    ss=byfunc[f]
    txt=" | ".join(s.replace("\n","\\n").replace("\t","\\t")[:70] for o,s in ss)
    lines.append(f"{f:08x} [{len(ss)}] {txt}")
open(r"D:\workspace\ACE\out\func_strings.txt","w",encoding="utf-8").write("\n".join(lines))
print("saved", len(lines))
import collections
c=collections.Counter(len(v) for v in byfunc.values())
print(sorted(c.items())[:10], "max", max(c))
