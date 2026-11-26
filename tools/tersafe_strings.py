import sys
import collections
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from so_elf import So

GOOD = set(b'/_.%:;=-|,() ')
BAD = set(b'\\^`{}~\'"<>$#@!?*&')


def scan_params(s, lo, hi):
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    out = set()
    last = None
    for i in md.disasm(s.data[lo:hi], lo):
        t = i.mnemonic + ' ' + i.op_str
        if t.startswith('mov w15, #'):
            last = int(i.op_str.split('#')[1], 0)
        elif t.startswith('add w1, w1, #') and last is not None:
            out.add((last, int(i.op_str.split('#')[-1], 0)))
            last = None
    return out


def records(d, start, limit):
    off = start
    out = []
    while off + 3 <= len(d) and len(out) < limit:
        key = d[off]
        ln = d[off + 1] ^ key
        if ln > 180 or off + 3 + ln > len(d):
            break
        out.append((off, key, ln, d[off + 2 + ln]))
        off += 3 + ln
    return out


def decode(d, off, ln, key, E, C):
    out = bytearray()
    k = key
    for j in range(ln):
        out.append(d[off + 2 + j] ^ k)
        k = ((k + j) ^ E) + C & 0xFF
    return bytes(out)


def verify(p, key, c):
    cs = 0xFF
    for b in p:
        cs ^= b
    return (c ^ cs ^ key) == 0xFF


def esc(p):
    return ''.join(chr(b) if 32 <= b < 127 and b != 9 else '\\x%02x' % b for b in p)


def score(p):
    if not p:
        return 0
    s = 0
    for b in p:
        if 32 <= b < 127:
            s += 2
        else:
            s -= 20
        if 97 <= b <= 122:
            s += 2
        elif 65 <= b <= 90:
            s += 1
        elif 48 <= b <= 57:
            s += 1
        if b in GOOD:
            s += 2
        if b in BAD:
            s -= 6
    return s


def main():
    so_path = sys.argv[1]
    table_off = int(sys.argv[2], 0)
    table_len = int(sys.argv[3], 0)
    param_lo = int(sys.argv[4], 0)
    param_hi = int(sys.argv[5], 0)
    count = int(sys.argv[6], 0)
    out_path = sys.argv[7]
    s = So(so_path)
    d = s.data[table_off:table_off + table_len]
    pool = scan_params(s, param_lo, param_hi)
    recs = records(d, 0, count)
    fails = [r for r in recs if not any(verify(decode(d, r[0], r[2], r[1], E, C), r[1], r[3]) for E, C in pool)]
    cnt = collections.Counter()
    for off, key, ln, c in fails:
        for E in range(0, 128):
            for C in range(8):
                p = decode(d, off, ln, key, E, C)
                if verify(p, key, c) and all(32 <= b < 127 for b in p):
                    cnt[(E, C)] += 1
    add = {k for k, v in cnt.items() if v >= 8} - pool
    pool = sorted(pool | add)
    resolved = 0
    rows = []
    for off, key, ln, c in recs:
        cands = [(E, C, decode(d, off, ln, key, E, C)) for E, C in pool]
        cands = [x for x in cands if verify(x[2], key, c)]
        if not cands:
            rows.append((off, key, ln, -1, -1, ''))
            continue
        uniq = {x[2] for x in cands}
        if len(uniq) == 1:
            resolved += 1
        best = max(cands, key=lambda x: (score(x[2]), len(x[2])))
        rows.append((off, key, ln, best[0], best[1], esc(best[2])))
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write('offset\tkey\tlen\tE\tC\tstring\n')
        for r in rows:
            f.write('%d\t%02x\t%d\t%d\t%d\t%s\n' % r)
    nohit = sum(1 for r in rows if r[3] < 0)
    nonprint = sum(1 for r in rows if r[5] and not all(32 <= ord(ch) < 127 for ch in r[5]))
    print('params', len(pool), 'added', len(add), 'recs', len(rows), 'unique_plain', resolved, 'nohit', nohit, 'nonprint', nonprint)


main()
