#!/usr/bin/env python3
"""扫描 dex 中与设备标识相关的 const-string，输出 归属类->方法。"""
import sys
import glob
import os

from androguard.core.dex import DEX

try:
    from loguru import logger
    logger.remove()
except Exception:
    pass

DEFAULT_KW = [
    "q16", "q36", "qimei", "QIMEI", "xid", "XID", "oaid", "OAID",
    "android_id", "androidid", "imei", "IMEI",
    "boot_id", "deviceUniqueId", "widevine",
]


def iter_methods(dex_path):
    d = DEX(open(dex_path, "rb").read())
    for c in d.get_classes():
        for m in c.get_methods():
            yield c.get_name(), m


def method_strings(m):
    code = m.get_code()
    if not code:
        return []
    out = []
    for ins in code.get_bc().get_instructions():
        if ins.get_name() != "const-string":
            continue
        try:
            out.append(ins.get_string())
        except Exception:
            continue
    return out


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        print("用法: dex_devkeys.py <dex目录|单个dex> [kw1 kw2 ...]")
        return 1
    target = sys.argv[1]
    kws = [k.lower() for k in (sys.argv[2:] or DEFAULT_KW)]
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    files = sorted(glob.glob(os.path.join(target, "*.dex"))) if os.path.isdir(target) else [target]
    total = 0
    for f in files:
        base = os.path.basename(f)
        for cls, m in iter_methods(f):
            ss = method_strings(m)
            if not ss:
                continue
            hit = sorted({s for s in ss if any(k in s.lower() for k in kws)})
            if not hit:
                continue
            print("%s\t%s->%s%s\t%s" % (base, cls, m.get_name(), m.get_descriptor(), "|".join(hit)))
            total += 1
    print("# 命中方法数: %d" % total, file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
