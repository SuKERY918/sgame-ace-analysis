import sys
import bisect
import collections
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from so_elf import So


def load_table(path):
    d = {}
    for line in open(path, encoding='utf-8'):
        p = line.rstrip('\n').split('\t')
        if p[0] == 'offset':
            continue
        d[int(p[0])] = p[5]
    return d


def main():
    so_path = sys.argv[1]
    text_lo = int(sys.argv[2], 0)
    text_hi = int(sys.argv[3], 0)
    dec_lo = int(sys.argv[4], 0)
    dec_hi = int(sys.argv[5], 0)
    table_path = sys.argv[6]
    out_path = sys.argv[7]
    s = So(so_path)
    table = load_table(table_path)
    funcs = sorted(s.funcs_from_eh())
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    rows = []
    hist = collections.deque(maxlen=50)
    for i in md.disasm(s.data[text_lo:text_hi], text_lo):
        t = i.mnemonic + ' ' + i.op_str
        if i.mnemonic == 'bl' and t.startswith('bl #'):
            tgt = int(i.op_str[1:], 16)
            if dec_lo <= tgt < dec_hi:
                idx = None
                for j in range(len(hist) - 1, -1, -1):
                    h = hist[j]
                    if h.mnemonic == 'mov' and h.op_str.startswith('w0, #'):
                        idx = int(h.op_str.split('#')[1], 0)
                        break
                if idx is not None:
                    k = bisect.bisect_right(funcs, i.address) - 1
                    f = funcs[k] if k >= 0 else 0
                    rows.append((f, i.address, idx, table.get(idx, '')))
        hist.append(i)
    with open(out_path, 'w', encoding='utf-8') as fo:
        fo.write('func\tcall\tidx\tstring\n')
        for f, a, idx, st in rows:
            fo.write('%x\t%x\t%d\t%s\n' % (f, a, idx, st))
    print('calls', len(rows), 'distinct_idx', len({r[2] for r in rows}), 'funcs', len({r[0] for r in rows}))


main()
