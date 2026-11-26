import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))
from so_elf import So
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM


def imm(x):
    x = x.strip()
    if not x.startswith('#'):
        return None
    try:
        return int(x[1:], 0)
    except ValueError:
        return None


def split2(x):
    return [t.strip() for t in x.split(', ', 1)]


def run(so_path, text_lo, text_hi, ro_lo, ro_hi):
    s = So(so_path)
    d = s.data
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    ins = list(md.disasm(d[text_lo:text_hi], text_lo))
    kcache = {}

    def get_key(t):
        if t in kcache:
            return kcache[t]
        k = None
        if text_lo <= t < text_hi:
            body = list(md.disasm(d[t:t + 48], t))[:10]
            for a, b in zip(body, body[1:]):
                if a.mnemonic == 'mov' and b.mnemonic == 'strb':
                    pa = split2(a.op_str)
                    pb = split2(b.op_str)
                    if len(pa) == 2 and len(pb) == 2 and pa[0] == pb[0] and pb[1].startswith('[sp'):
                        v = imm(pa[1])
                        if v is not None and 0 <= v < 256:
                            k = v
                            break
        kcache[t] = k
        return k

    refs = []
    for i, x in enumerate(ins):
        if x.mnemonic != 'adrp':
            continue
        p = x.op_str.split(', ')
        if len(p) != 2:
            continue
        base = imm(p[1])
        if base is None:
            continue
        for j in range(1, 5):
            if i + j >= len(ins):
                break
            y = ins[i + j]
            if y.mnemonic != 'add':
                continue
            q = y.op_str.split(', ')
            if len(q) == 3 and q[0] == p[0] and q[1] == p[0]:
                off = imm(q[2])
                if off is not None and ro_lo <= base + off < ro_hi:
                    refs.append((i + j, base + off))
                break

    out = []
    miss = [0, 0, 0]
    for idx, va in refs:
        blk = None
        dec = None
        for k in range(idx + 1, min(idx + 14, len(ins))):
            if ins[k].mnemonic == 'bl':
                blk = k
                dec = imm(ins[k].op_str)
                break
        if dec is None:
            miss[0] += 1
            continue
        key = get_key(dec)
        if key is None:
            miss[1] += 1
            continue
        ln = None
        for k in range(blk - 1, max(blk - 20, idx), -1):
            y = ins[k]
            if y.mnemonic != 'mov':
                continue
            q = split2(y.op_str)
            if len(q) == 2 and q[0].startswith('w'):
                v = imm(q[1])
                if v is not None and 1 <= v <= 512:
                    ln = v
                    break
        if ln is None:
            miss[2] += 1
            continue
        p = bytes(d[va + i] ^ ((key + i) & 0xFF) for i in range(ln))
        out.append((va, key, ln, dec, p))

    seen = {}
    for va, key, ln, dec, p in out:
        q = p.rstrip(b'\x00')
        if not q or any(c < 0x20 or c > 0x7E for c in q):
            continue
        seen.setdefault(va, (key, ln, q.decode('latin1')))
    rows = sorted(seen.items())
    print('refs=%d decoded=%d uniq=%d miss(no_bl,no_key,no_len)=%s' % (len(refs), len(out), len(rows), miss))
    return rows


if __name__ == '__main__':
    so = sys.argv[1]
    tl, th, rl, rh = (int(x, 0) for x in sys.argv[2:6])
    rows = run(so, tl, th, rl, rh)
    dst = sys.argv[6] if len(sys.argv) > 6 else None
    if dst:
        with open(dst, 'w', encoding='utf-8') as f:
            for va, (k, ln, t) in rows:
                f.write('%06X\t%02X\t%d\t%s\n' % (va, k, ln, t))
        print('wrote', dst)
