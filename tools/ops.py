import pickle, struct, json
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

data = open(r"D:\workspace\ACE\libs\libtersafe.so", "rb").read()
dec = set(pickle.load(open(r"D:\workspace\ACE\out\dec_list.pkl", "rb"))[1])
found = pickle.load(open(r"D:\workspace\ACE\out\found.pkl", "rb"))
starts = pickle.load(open(r"D:\workspace\ACE\out\funcstarts.pkl", "rb"))
lo = 0x4E3CAC
hi = starts[starts.index(lo) + 1]

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True
ins = list(md.disasm(data[lo:hi], lo))

cur_handler = None
pending_mov = None
rows = []
for i, x in enumerate(ins):
    if x.mnemonic in ("adr", "adrl") and len(x.operands) == 2 and x.reg_name(x.operands[0].reg) == "x8":
        op = x.operands[1]
        if op.type == 2:  # IMM
            tgt = op.imm
            if 0x1B6C20 <= tgt < 0x50DFC8:
                cur_handler = tgt
    elif x.mnemonic == "mov" and len(x.operands) == 2 and x.reg_name(x.operands[0].reg) == "w0":
        op = x.operands[1]
        if op.type == 2:
            pending_mov = op.imm
    elif x.mnemonic == "bl" and x.operands[0].type == 2:
        tgt = x.operands[0].imm
        if tgt in dec and pending_mov is not None:
            v = found.get(pending_mov)
            name = v[1] if isinstance(v, tuple) else v
            rows.append((pending_mov, name, cur_handler, x.address))
            cur_handler = None
            pending_mov = None
    if x.mnemonic in ("str", "stp") and cur_handler is None:
        pass

with open(r"D:\workspace\ACE\out\ops.tsv", "w", encoding="utf-8") as f:
    for o, n, h, site in rows:
        hs = "--------" if h is None else format(h, "08x")
        f.write(f"{o}\t{hs}\t{'' if n is None else n}\n")
print("entries", len(rows))
for off, name, h, site in rows:
    print(f"{off:6d} {h if h is None else format(h,'08x')}  {name}")
