import pickle, sys, bisect

calls = pickle.load(open(r"D:\workspace\ACE\out\calls.pkl", "rb"))
starts = pickle.load(open(r"D:\workspace\ACE\out\funcstarts.pkl", "rb"))


def fn(a):
    i = bisect.bisect_right(starts, a) - 1
    return starts[i] if i >= 0 else 0


def callers(addr):
    out = set()
    for site, instr, callee, kind, sym in calls:
        if kind in ("int", "imp") and callee == addr:
            out.add((fn(site), site, sym))
    return sorted(out)


def callees(addr):
    end = 0
    i = bisect.bisect_right(starts, addr)
    if i < len(starts):
        end = starts[i]
    out = set()
    for site, instr, callee, kind, sym in calls:
        if addr <= site < end:
            out.add((site, callee, kind, sym))
    return sorted(out)


if __name__ == "__main__":
    a = int(sys.argv[1], 16)
    mode = sys.argv[2] if len(sys.argv) > 2 else "in"
    if mode == "in":
        for f, s, sym in callers(a):
            print(f"caller {f:08x}  site {s:08x}  {sym}")
    else:
        for s, c, kind, sym in callees(a):
            print(f"{s:08x} -> {c:08x} {kind} {sym}")
