#!/usr/bin/env python3
"""解密 libqimei.so 的内置字符串表。

表格式：[u16 len][u8 key][len 字节密文]，明文 = 密文 ^ ((key + i * 0x53) & 0xff)。
用法：python qimei_table_decode.py <libqimei.so> [table_offset] [table_size] [out.txt]
默认表偏移 0x6cfa4、大小 9469（9469 条 = id 上界 0x24fd）。
"""
import sys


def load(path):
    with open(path, "rb") as f:
        return f.read()


def decode_table(d, off=0x6CFA4, size=9469):
    blob = d[off:off + size]
    out, pos = [], 0
    while pos + 3 <= len(blob):
        ln = int.from_bytes(blob[pos:pos + 2], "little")
        if ln == 0:
            break
        key = blob[pos + 2]
        plain = bytes(b ^ ((key + i * 0x53) & 0xFF) for i, b in enumerate(blob[pos + 3:pos + 3 + ln]))
        out.append((pos, plain.split(b"\x00")[0].decode("latin1")))
        pos += 3 + ln
    return out, pos


def main():
    so = sys.argv[1]
    off = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0x6CFA4
    size = int(sys.argv[3], 0) if len(sys.argv) > 3 else 9469
    out = sys.argv[4] if len(sys.argv) > 4 else None
    recs, used = decode_table(load(so), off, size)
    print("records %d, consumed %d of %d" % (len(recs), used, size))
    lines = ["%04x\t%s" % (p, s) for p, s in recs]
    if out:
        open(out, "w", encoding="utf-8").write("\n".join(lines))
        print("written", out)
    else:
        print("\n".join(lines))


if __name__ == "__main__":
    main()
