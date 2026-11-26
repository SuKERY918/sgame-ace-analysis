import sys

from so_elf import So

path = sys.argv[1]
targets = set(int(x, 0) for x in sys.argv[2:])

so = So(path)
va0, end, _ = so.sections[".text"]
hit = {t: [] for t in targets}
for ins in so.elems(va0, end):
    if ins.mnemonic != "bl":
        continue
    try:
        dst = int(ins.op_str.replace("#", ""), 0)
    except ValueError:
        continue
    if dst in targets:
        hit[dst].append(ins.address)

for t in sorted(targets):
    print("%08x callers %d" % (t, len(hit[t])))
    for a in hit[t][:50]:
        print("  %08x" % a)
