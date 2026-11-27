#!/usr/bin/env python3
"""QIMEI 加密串表的引用审计：解析表记录，统计取串点覆盖情况，列出未被引用的连续死区。

用法:
  qimei_table_audit.py <libqimei.so> <table_off> <table_len> <getter_addr>
示例:
  qimei_table_audit.py libqimei.so 0x6CFA4 0x24FD 0x1EFB8
"""
import sys
import struct

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from elftools.elf.elffile import ELFFile


def load_text(path):
    with open(path, "rb") as f:
        elf = ELFFile(f)
        for sec in elf.iter_sections():
            if sec.name == ".text":
                return sec.data(), sec["sh_addr"]
    raise SystemExit("no .text")


def load_table(path, off, size):
    with open(path, "rb") as f:
        f.seek(off)
        return f.read(size)


def parse_records(blob):
    recs = []
    o = 0
    n = len(blob)
    while o + 3 <= n:
        ln = struct.unpack_from("<H", blob, o)[0]
        key = blob[o + 2]
        if ln == 0 or o + 3 + ln > n:
            break
        cipher = blob[o + 3:o + 3 + ln]
        plain = bytes(c ^ ((key + i * 0x53) & 0xFF) for i, c in enumerate(cipher))
        try:
            s = plain.decode("utf-8")
        except UnicodeDecodeError:
            s = plain.decode("latin-1")
        recs.append((o, s))
        o += 3 + ln
    return recs


def scan_sites(text, base, getter):
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = False
    sites = []
    pending = None
    for ins in md.disasm(text, base):
        mn = ins.mnemonic
        ops = ins.op_str.replace(" ", "")
        if mn == "bl":
            try:
                tgt = int(ops.lstrip("#"), 16)
            except ValueError:
                pending = None
                continue
            if tgt == getter and pending is not None:
                sites.append(pending)
            pending = None
            continue
        if mn == "mov" and ops.startswith("w1,#"):
            try:
                pending = int(ops.split("#")[1], 0)
            except ValueError:
                pending = None
        elif mn in ("b", "ret", "br", "blr", "cbz", "cbnz", "tbz", "tbnz"):
            pending = None
    return sites


def main():
    if len(sys.argv) < 5:
        print(__doc__)
        return 1
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    path = sys.argv[1]
    off = int(sys.argv[2], 0)
    size = int(sys.argv[3], 0)
    getter = int(sys.argv[4], 0)

    text, base = load_text(path)
    recs = parse_records(load_table(path, off, size))
    sites = scan_sites(text, base, getter)
    ref = set(sites)

    by_off = {o: s for o, s in recs}
    hit = [o for o in sorted(ref) if o in by_off]
    print("表记录数: %d  取串点: %d  唯一偏移: %d  覆盖记录: %d" % (len(recs), len(sites), len(ref), len(hit)))

    dead = []
    for o, s in recs:
        if o not in ref:
            dead.append((o, s))
    print("未被引用记录: %d" % len(dead))

    blocks = []
    for o, s in dead:
        if blocks and o - blocks[-1][1] <= 0x40:
            blocks[-1][1] = o
            blocks[-1][2] += 1
        else:
            blocks.append([o, o, 1])
    print("死区块（起-止, 条数）:")
    for a, b, c in blocks:
        print("  0x%04x-0x%04x  %d" % (a, b, c))

    print("死区首条与末条:")
    for o, s in dead[:5]:
        print("  0x%04x  %s" % (o, s[:60]))
    if len(dead) > 5:
        print("  ...")
        for o, s in dead[-3:]:
            print("  0x%04x  %s" % (o, s[:60]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
