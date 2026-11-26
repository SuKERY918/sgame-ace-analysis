import pickle, bisect, re, sys, os

OUT = r"D:\workspace\ACE\out"
calls = pickle.load(open(os.path.join(OUT, "calls.pkl"), "rb"))
fp = os.path.join(OUT, "funcstarts.pkl")
starts = sorted(pickle.load(open(fp, "rb"))) if os.path.exists(fp) else sorted({c[1] for c in calls})


def owner(a):
    i = bisect.bisect_right(starts, a) - 1
    return starts[i] if i >= 0 else 0


pat = sys.argv[1]
limit = int(sys.argv[2]) if len(sys.argv) > 2 else 200
rx = re.compile(pat, re.I)
n = 0
seen = {}
for site, frm, to, kind, name in calls:
    if kind == "imp" and rx.search(name or ""):
        fn = owner(site)
        if fn not in seen:
            seen[fn] = []
        seen[fn].append((site, name))
        n += 1
for fn in sorted(seen):
    lst = seen[fn][:6]
    s = " ".join("%s@0x%x" % (nm, sa) for sa, nm in lst)
    print("0x%08x x%d  %s" % (fn, len(seen[fn]), s))
    if len(seen) > limit:
        break
print("-- %d callsites in %d funcs" % (n, len(seen)))
