import sys, json
CG = json.load(open(r"D:\workspace\ACE\out\cg.json", encoding="utf-8"))
REV = {}
for k, v in CG.items():
    for c in v.get("i", []):
        try:
            c = int(c, 0) if isinstance(c, str) else int(c)
        except Exception:
            continue
        REV.setdefault(c, []).append(int(k, 0) if isinstance(k, str) else int(k))

def hx(x):
    return "%08x" % x

a = sys.argv[1:]
if a[0] == "-r":
    for t in a[1:]:
        t = int(t, 0)
        print("callers of %s: %s" % (hx(t), " ".join(hx(x) for x in sorted(set(REV.get(t, [])))) or "-"))
else:
    for t in a:
        t = int(t, 0)
        v = CG.get(str(t)) or CG.get(hex(t)) or {}
        cal = []
        for c in v.get("i", []):
            try:
                cal.append(int(c, 0) if isinstance(c, str) else int(c))
            except Exception:
                pass
        print("%s imp=[%s] callees=[%s]" % (hx(t), ",".join(v.get("m", [])), " ".join(hx(x) for x in cal)))
