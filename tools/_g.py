import sys
P = r"D:\workspace\ACE\out\allstr.tsv"
rows = []
for ln in open(P, encoding="utf-8"):
    k, off, func, site, s = ln.rstrip("\n").split("\t", 4)
    rows.append((k, int(off), int(func, 16), int(site, 16), s))

if sys.argv[1] == "r":
    a = int(sys.argv[2], 16)
    b = int(sys.argv[3], 16)
    for k, off, func, site, s in rows:
        if a <= site < b:
            print(f"{site:08x} f={func:08x} {k} off={off:6d} {s[:130]}")
else:
    for k, off, func, site, s in rows:
        if sys.argv[1].lower() in s.lower():
            print(f"{site:08x} f={func:08x} {k} off={off:6d} {s[:130]}")
