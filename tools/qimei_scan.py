import sys
from collections import Counter

from so_elf import So


def load_table(so, table, tsize):
    d = so.data[table:table + tsize]
    out = {}
    pos = 0
    while pos + 3 <= len(d):
        ln = int.from_bytes(d[pos:pos + 2], "little")
        if ln == 0:
            break
        key = d[pos + 2]
        raw = d[pos + 3:pos + 3 + ln]
        plain = bytes(b ^ ((key + i * 0x53) & 0xFF) for i, b in enumerate(raw))
        out[pos] = plain.split(b"\0")[0].decode("latin1")
        pos += 3 + ln
    return out


def main():
    path = sys.argv[1]
    table = int(sys.argv[2], 0)
    tsize = int(sys.argv[3], 0)
    start = int(sys.argv[4], 0)
    end = int(sys.argv[5], 0)
    getter = int(sys.argv[6], 0) if len(sys.argv) > 6 else None
    so = So(path)
    strings = load_table(so, table, tsize)
    adrp = {}
    calls = []
    refs = []
    imm1 = None
    for ins in so.elems(start, end):
        ops = ins.op_str
        m = ins.mnemonic
        if m == "adrp":
            try:
                reg, imm = ops.split(", ")
                adrp[reg.strip()] = int(imm.replace("#", ""), 0)
            except ValueError:
                pass
        elif m == "add":
            parts = [p.strip() for p in ops.split(",")]
            if len(parts) == 3 and parts[1] in adrp:
                try:
                    va = adrp[parts[1]] + int(parts[2].replace("#", ""), 0)
                except ValueError:
                    continue
                if table <= va < table + tsize:
                    off = va - table
                    refs.append((ins.address, parts[0], off, strings.get(off, "<bad>")))
        elif m in ("mov", "movz") and ops.startswith("w1, #"):
            try:
                imm1 = int(ops.split("#")[1], 0)
            except (IndexError, ValueError):
                imm1 = None
        elif m == "bl":
            try:
                dst = int(ops.replace("#", ""), 0)
            except ValueError:
                continue
            calls.append(dst)
            if getter is not None and dst == getter and imm1 is not None:
                refs.append((ins.address, "w1", imm1, strings.get(imm1, "<bad>")))
                imm1 = None
    print("calls %d" % len(calls))
    for tgt, n in Counter(calls).most_common():
        print("  %08x x%d" % (tgt, n))
    print("refs %d" % len(refs))
    seen = set()
    for addr, reg, off, s in refs:
        if (off, s) in seen:
            continue
        seen.add((off, s))
        print("  %08x %-6s %04x %s" % (addr, reg, off, s[:120]))


main()
