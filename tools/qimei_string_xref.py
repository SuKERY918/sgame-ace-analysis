#!/usr/bin/env python3
"""把 libqimei.so 的取串调用点映射到字符串。

取串函数 sub_1EFB8(off)：调用约定 `mov w1, #off; bl 0x1efb8`，函数原地解密并返回 table+off+3。
用法：python qimei_string_xref.py <libqimei.so> <strings.txt> [out.txt]
strings.txt 为 qimei_table_decode.py 的输出（偏移<TAB>明文）。
"""
import sys
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

GETTER = 0x1EFB8


def load_strings(path):
    m = {}
    for line in open(path, encoding="utf-8"):
        a, b = line.rstrip("\n").split("\t", 1)
        m[int(a, 16)] = b
    return m


def main():
    so, spath = sys.argv[1], sys.argv[2]
    out = sys.argv[3] if len(sys.argv) > 3 else None
    d = open(so, "rb").read()
    strings = load_strings(spath)
    elf = ELFFile(open(so, "rb"))
    sec = elf.get_section_by_name(".text")
    text = d[sec["sh_offset"]:sec["sh_offset"] + sec["sh_size"]]
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    insns = list(md.disasm(text, sec["sh_addr"]))
    rows = []
    for k, ins in enumerate(insns):
        if ins.mnemonic != "bl" or ins.op_str != "#0x%x" % GETTER:
            continue
        off = None
        for j in range(k - 1, max(0, k - 60), -1):
            t = insns[j]
            if t.mnemonic == "mov" and t.op_str.startswith("w1, #0x"):
                off = int(t.op_str.split("#")[1], 16)
                break
            if t.mnemonic in ("bl", "ret"):
                break
        fn = None
        for j in range(k, max(0, k - 400), -1):
            t = insns[j]
            if t.mnemonic == "stp" and "x29, x30" in t.op_str and "[sp, #-0x" in t.op_str:
                fn = t.address
                break
        rows.append("%06x\t%06x\t%s\t%s" % (
            ins.address, fn or 0,
            ("%04x" % off) if off is not None else "-",
            strings.get(off, "<dynamic>") if off is not None else "<dynamic>"))
    print("calls %d, resolved %d" % (len(rows), sum(1 for r in rows if "<dynamic>" not in r)))
    if out:
        open(out, "w", encoding="utf-8").write("\n".join(rows))
        print("written", out)
    else:
        print("\n".join(rows))


if __name__ == "__main__":
    main()
