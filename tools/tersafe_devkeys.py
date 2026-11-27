#!/usr/bin/env python3
"""把 ACE 主串表与引用点表按设备标识关键词连接，输出 idx/字符串/引用函数。"""
import sys

DEFAULT_KW = [
    "imei", "oaid", "qimei", "xid", "androidid", "android_id",
    "mac", "boot", "fake_token", "qimam", "osez", "tdm", "msaoaid",
]


def load_strings(path):
    rows = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for ln in f:
            p = ln.rstrip("\n").split("\t")
            if len(p) < 6:
                continue
            try:
                rows[int(p[0])] = p[-1]
            except ValueError:
                continue
    return rows


def load_usage(path):
    use = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for ln in f:
            p = ln.rstrip("\n").split("\t")
            if len(p) < 4:
                continue
            try:
                idx = int(p[2])
            except ValueError:
                continue
            use.setdefault(idx, []).append((p[0], p[1]))
    return use


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        print("用法: tersafe_devkeys.py <strings.tsv> <strings_usage.tsv> [kw1 kw2 ...]")
        return 1
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    strings = load_strings(sys.argv[1])
    usage = load_usage(sys.argv[2])
    kws = sys.argv[3:] or DEFAULT_KW
    kws = [k.lower() for k in kws]
    for idx in sorted(strings):
        s = strings[idx]
        if not any(k in s.lower() for k in kws):
            continue
        sites = usage.get(idx, [])
        if sites:
            where = " ".join("%s/%s" % (a, b) for a, b in sites[:6])
        else:
            where = "<无引用>"
        print("%6d\t%-40s\t%s" % (idx, s[:40], where))
    return 0


if __name__ == "__main__":
    sys.exit(main())
