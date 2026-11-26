#!/usr/bin/env python3
"""ACE (libtersafe.so) 云端下发 blob 静态解析器.

用途: 解析 ano_tmp 目录中的 ob_x/ob_cs2 容器 (a32/a64)、内部 .img 载荷、
comm.dat (tlf 容器)、mrpcs*.data (zip 包) 与 *.sig 签名块.

用法:
  python blob.py info                     # 所有 blob 概览
  python blob.py sections <file>          # 容器段表 (名称/偏移/长度)
  python blob.py img <file> [sec]         # .img 头部与内部表
  python blob.py names <file>             # .img 导入/符号表
  python blob.py strings <file>           # 多相位 XOR 字符串提取
  python blob.py comm                     # comm.dat 结构
  python blob.py mrpcs                    # mrpcs*.data zip 结构
  python blob.py sig                      # 签名块结构
  python blob.py stats <file>             # 熵/字节分布

关键常量来源 (libtersafe.so):
  容器 magic   0x20220118  (= sub_4A0198 读 u32 后比较 539099416)
  段名解密     sub_237DC4: pt[i] = ct[i] ^ "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"[i%36]
  段载荷解密   主循环 case 24: pt = T[ct ^ 0x23], T = libtersafe+0x9A240
  .img magic   0x20220623 (libtprt sub_1528B0 比较 539100707)
  .img 装载    libtprt sub_1528B0 / sub_13C76C
"""
import collections
import hashlib
import os
import re
import struct
import sys
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UNPACK = os.path.join(ROOT, "dyn", "unpack")
ANO = os.path.join(ROOT, "dyn", "ano_tmp_full")

SBX = bytes.fromhex(
    "abe47fa84624589d7db8f09108138060d697ff1569f8c2d9302916ee3ebb83f9"
    "47cd621d4ef47823648fa7747096a575d3393436177392073bc10efa320f03da"
    "be31672aafef8488e5e7d179e9760cccc425a2017bbf6af12e6dc9277a483a9a"
    "555bfe3c0bae896c547c2c42909b1a8dca5f334c6135aa2ba4bc26df85b54fde"
    "0ae80640509f19edb0f2ec6551bac857044dd7a08a56eaf55c71444577ac9312"
    "00e0c3c5bdad6ffc18b10d1b2895f3c772378b871f6eb9b766d0d2d4c6213f2d"
    "1efdf6dc9e8ce25d86101ca1c0097e4a9405d8b49952a649119843a981ce6322"
    "9cb3f714dde18e6859e6db38b2535eebd5cb4b02825aa32041b62ffb3dcfe36b"
)
SKEY = 0x23
XKEY = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
CTR_MAGIC = 0x20220118
IMG_MAGIC = 0x20220623


def sbx_dec(buf):
    return bytes(SBX[c ^ SKEY] for c in buf)


def sbx_enc(buf):
    t = bytes(SBX.index(i) for i in range(256))
    return bytes(t[c ^ SKEY] for c in buf)


def xk(buf, phase=0):
    return bytes(c ^ XKEY[(i + phase) % 36] for i, c in enumerate(buf))


def be32(b, o=0):
    return struct.unpack_from(">I", b, o)[0]


def le32(b, o=0):
    return struct.unpack_from("<I", b, o)[0]


def parse_container(buf):
    """返回 (sections, info). sections = [(name, payload_plain, off, raw)]"""
    if be32(buf, 0) != CTR_MAGIC:
        raise ValueError("bad container magic %08x" % be32(buf, 0))
    n = be32(buf, 4)
    pos = 8
    secs = []
    for _ in range(n):
        ln = be32(buf, pos)
        pos += 4
        name = xk(buf[pos:pos + ln]).decode("latin1")
        pos += ln
        plen = be32(buf, pos)
        pos += 4
        raw = buf[pos:pos + plen]
        secs.append((name, sbx_dec(raw), pos, raw))
        pos += plen
    tail = be32(buf, pos)
    return secs, {"nsec": n, "end": pos, "tail_magic": tail, "size": len(buf)}


def parse_img(p):
    """解析 S 盒解密后的 .img 载荷头. 返回 dict."""
    h = {"magic": le32(p, 0), "f04": le32(p, 4), "f08": le32(p, 8),
         "f0c": le32(p, 12), "f10": le32(p, 16), "countA": le32(p, 0x14),
         "countB": le32(p, 0x18), "countC": le32(p, 0x1C), "countD": le32(p, 0x20),
         "size": len(p)}
    pos = 0x24
    h["pairs"] = [struct.unpack_from("<II", p, pos + 8 * i) for i in range(h["countA"])]
    pos += 8 * h["countA"]
    h["handlers"] = []
    for _ in range(h["countB"]):
        eid = le32(p, pos)
        ln = le32(p, pos + 4)
        raw = p[pos + 8:pos + 8 + ln]
        h["handlers"].append((eid, xk(raw).decode("latin1"), raw))
        pos += 8 + ln
    h["afterB"] = pos
    h["countC_entries"] = []
    for _ in range(h["countC"]):
        ln = le32(p, pos)
        s = xk(p[pos + 4:pos + 4 + ln]).decode("latin1")
        pos += 4 + ln
        a, b = le32(p, pos), le32(p, pos + 4)
        pos += 8
        h["countC_entries"].append((s, a, b))
    h["countD_entries"] = []
    for _ in range(h["countD"]):
        h["countD_entries"].append(struct.unpack_from("<II", p, pos))
        pos += 8
    h["afterD"] = pos
    h["blob_len"] = le32(p, pos) if pos + 4 <= len(p) else None
    return h


def iter_runs(buf, minlen=6):
    cur = bytearray()
    start = 0
    for i, c in enumerate(buf):
        if 32 <= c < 127:
            if not cur:
                start = i
            cur.append(c)
        else:
            if len(cur) >= minlen:
                yield start, bytes(cur)
            cur = bytearray()
    if len(cur) >= minlen:
        yield start, bytes(cur)


PATH_RE = re.compile(rb"(?:/[A-Za-z0-9_.$@+-]{2,}){2,}")
PKG_RE = re.compile(rb"[a-z][a-z0-9_]{2,}(?:\.[a-z0-9_]{2,}){2,}")
SO_RE = re.compile(rb"[A-Za-z0-9_+-]{3,}\.so\b")


def scan_xor_strings(buf, phases=range(36)):
    """多相位 XOR 后按正则捞路径/包名/so. 返回 {string: phase}"""
    out = {}
    for ph in phases:
        x = xk(buf, ph)
        for rx, mn in ((PATH_RE, 8), (PKG_RE, 10), (SO_RE, 7)):
            for m in rx.finditer(x):
                s = m.group().decode("latin1")
                if len(s) >= mn:
                    out.setdefault(s, ph)
    return out


def entropy(b):
    if not b:
        return 0.0
    c = collections.Counter(b)
    import math
    return -sum(v / len(b) * math.log2(v / len(b)) for v in c.values())


def dump_zip(path):
    """手写 zip 中央目录解析, 返回 [(name, method, csize, usize, data_raw, data_dec)]"""
    d = open(path, "rb").read()
    eocd = d.rfind(b"PK\x05\x06")
    if eocd < 0:
        return [], d
    n, cd_off = struct.unpack_from("<HH", d, eocd + 10)[0], struct.unpack_from("<I", d, eocd + 16)[0]
    cnt = struct.unpack_from("<H", d, eocd + 10)[0]
    out = []
    p = cd_off
    for _ in range(cnt):
        if d[p:p + 4] != b"PK\x01\x02":
            break
        (method,) = struct.unpack_from("<H", d, p + 10)
        csize, usize = struct.unpack_from("<II", d, p + 20)
        nlen, elen, clen = struct.unpack_from("<HHH", d, p + 28)
        lho = struct.unpack_from("<I", d, p + 42)[0]
        name = d[p + 46:p + 46 + nlen].decode("latin1")
        if lho + 30 <= len(d):
            ln2, le2 = struct.unpack_from("<HH", d, lho + 26)
            start = lho + 30 + ln2 + le2
            raw = d[start:start + csize]
        else:
            raw = b""
        try:
            dec = zlib.decompress(raw, -15) if method == 8 else raw
        except Exception:
            dec = b""
        out.append((name, method, csize, usize, raw, dec))
        p += 46 + nlen + elen + clen
    return out, d


def cmd_info(argv):
    files = [
        ("ob_x_a64.dat", os.path.join(UNPACK, "ob_x_a64.dat")),
        ("ob_x_a32.dat", os.path.join(UNPACK, "ob_x_a32.dat")),
        ("ob_cs2_a64.dat", os.path.join(UNPACK, "ob_cs2_a64.dat")),
        ("ob_cs2_a32.dat", os.path.join(UNPACK, "ob_cs2_a32.dat")),
    ]
    print("%-16s %8s %5s %10s %10s %6s %6s" % ("file", "size", "nsec", "end", "tailmagic", "ent", "z83"))
    for label, p in files:
        d = open(p, "rb").read()
        secs, info = parse_container(d)
        z83 = d.count(0x83) / len(d)
        print("%-16s %8d %5d %10s %10s %6.3f %6.3f" % (
            label, len(d), info["nsec"], hex(info["end"]), hex(info["tail_magic"]),
            entropy(d), z83))
        for i, (nm, pay, off, raw) in enumerate(secs):
            h = parse_img(pay)
            print("   sec%d %-22s off=%#08x len=%6d img_magic=%08x cA=%3d cB=%3d cC=%d cD=%d code@%#x" % (
                i, nm, off, len(pay), h["magic"], h["countA"], h["countB"], h["countC"], h["countD"],
                h["afterD"]))


def cmd_sections(argv):
    p = argv[0]
    d = open(p, "rb").read()
    secs, info = parse_container(d)
    print("magic=%08x nsec=%d size=%d end=%#x tail=%08x" % (
        be32(d, 0), info["nsec"], len(d), info["end"], info["tail_magic"]))
    for i, (nm, pay, off, raw) in enumerate(secs):
        print("sec%d name=%-22s off=%#08x len=%6d md5=%s" % (
            i, nm, off, len(pay), hashlib.md5(pay).hexdigest()[:16]))


def cmd_img(argv):
    p = argv[0]
    want = argv[1] if len(argv) > 1 else None
    d = open(p, "rb").read()
    secs, info = parse_container(d)
    for nm, pay, off, raw in secs:
        if want and want not in nm:
            continue
        h = parse_img(pay)
        print("== %s len=%d" % (nm, len(pay)))
        print("   +00 magic=%08x  +04=%d +08=%d +0c=%d +10=%d" % (
            h["magic"], h["f04"], h["f08"], h["f0c"], h["f10"]))
        print("   +14 cA=%d +18 cB=%d +1c cC=%d +20 cD=%d  tables_end=%#x blob_len=%s" % (
            h["countA"], h["countB"], h["countC"], h["countD"], h["afterD"], h["blob_len"]))
        print("   pairs:", h["pairs"])
        print("   handlers(%d):" % len(h["handlers"]))
        for eid, s, _ in h["handlers"][:24]:
            print("      id=%-6d %r" % (eid, s))


def cmd_names(argv):
    p = argv[0]
    d = open(p, "rb").read()
    secs, _ = parse_container(d)
    allnames = collections.Counter()
    for nm, pay, off, raw in secs:
        h = parse_img(pay)
        for eid, s, _ in h["handlers"]:
            allnames[s] += 1
    print("distinct import names: %d" % len(allnames))
    for s, c in allnames.most_common(60):
        print("   %-24r x%d" % (s, c))


def cmd_strings(argv):
    p = argv[0]
    d = open(p, "rb").read()
    if p.endswith(".dat"):
        try:
            secs, _ = parse_container(d)
            d2 = b"".join(pay for _, pay, _, _ in secs)
        except Exception:
            d2 = d
    else:
        d2 = d
    res = scan_xor_strings(d2)
    for s in sorted(res):
        if "/" in s or s.count(".") >= 2:
            print("  ph=%02d %s" % (res[s], s))


def cmd_comm(argv):
    p = os.path.join(UNPACK, "comm_comm.dat")
    d = open(p, "rb").read()
    print("size=%d zero_ratio=%.3f entropy=%.3f" % (len(d), d.count(0) / len(d), entropy(d)))
    print("head64:", d[:64].hex())
    print("u32be:", [be32(d, 4 * i) for i in range(10)])
    print("tail32:", d[-32:].hex())
    print("tail xor36:", xk(d[-24:]).hex(), "->", "".join(
        chr(c) if 32 <= c < 127 else "." for c in xk(d[-24:])))
    res = scan_xor_strings(d)
    paths = sorted(s for s in res if s.startswith("/"))
    pkgs = sorted(s for s in res if not s.startswith("/") and not s.endswith(".so"))
    sos = sorted(s for s in res if s.endswith(".so"))
    print("\npaths(%d):" % len(paths))
    for s in paths[:60]:
        print("  ", s)
    print("packages(%d):" % len(pkgs))
    for s in pkgs[:60]:
        print("  ", s)
    print("so(%d):" % len(sos))
    for s in sos[:40]:
        print("  ", s)


def cmd_mrpcs(argv):
    for fn in ("mrpcs.data", "mrpcs_MVM.data", "mrpcs_com.data"):
        p = os.path.join(ANO, fn)
        ents, raw = dump_zip(p)
        print("== %s size=%d entries=%d" % (fn, len(raw), len(ents)))
        for name, method, csize, usize, r, dec in ents:
            print("   entry=%r method=%d csize=%d usize=%d declen=%d" % (name, method, csize, usize, len(dec)))
            if dec:
                print("      head32:", dec[:32].hex(), "ent=%.3f" % entropy(dec))
                for ph in (0,):
                    x = xk(dec, ph)
                    rr = [(o, s) for o, s in iter_runs(x, 8)][:3]
                    for o, s in rr:
                        print("      xor0 run @%#x %r" % (o, s))


def cmd_sig(argv):
    for fn in ("ob_cs2_a64.sig", "ob_x_a64.sig", "comm_sig4", "comm_sig5"):
        p = os.path.join(UNPACK, fn)
        if not os.path.exists(p):
            continue
        d = open(p, "rb").read()
        print("== %s len=%d" % (fn, len(d)))
        print("   head48:", d[:48].hex())
        print("   tail16:", d[-16:].hex(), " zeros=%d" % d.count(0))
        print("   as ints:", [be32(d, i) for i in range(0, min(len(d), 32), 4)])


def _elf_reader(path):
    """返回 (fileobj, [(vaddr, off, filesz)]) ; 失败则按 vaddr==offset 处理."""
    f = open(path, "rb")
    try:
        from elftools.elf.elffile import ELFFile
        segs = [(s["p_vaddr"], s["p_offset"], s["p_filesz"])
                for s in ELFFile(f).iter_segments() if s["p_type"] == "PT_LOAD"]
    except Exception:
        segs = []
    return f, segs


def load_rsa_keys(so_path=None):
    """从 libtersafe.so 取出两把内嵌 RSA-2048 公钥.

    结构 (520 B, sub_489F10 使用): +0 u32 nwords(64) | +4 u32 未知 | +8 n[256] LE
    | +264 R^2 mod n [256] LE (Montgomery 预计算常量, 已校验)
    """
    so_path = so_path or os.path.join(ROOT, "libs", "libtersafe.so")
    f, segs = _elf_reader(so_path)
    out = {}
    for name, va in (("K1", 0x547860), ("K2", 0x547A68)):
        off = va
        for v, o, sz in segs:
            if v <= va < v + sz:
                off = o + va - v
                break
        f.seek(off)
        d = f.read(520)
        n = int.from_bytes(d[8:264], "little")
        out[name] = (n, d[4:8], d[264:520], off)
    f.close()
    return out


def rsa_verify(sig, data, n, e=65537):
    """sig 为 **大端** 字节串. 明文布局 = 00 || MD5(data) || 00*240 (256B)."""
    if len(sig) < 256:
        return None
    m = pow(int.from_bytes(sig[:256], "big"), e, n)
    mb = m.to_bytes(256, "big")
    if mb[0] != 0:
        return None
    return mb[1:17] == hashlib.md5(data).digest()


def cmd_verify(argv):
    keys = load_rsa_keys()
    for k, (n, f4, scr, off) in keys.items():
        r2 = (1 << 4096) % n
        print("%s @file %#x nwords=64 nbits=%d unknown=%s R^2_le_ok=%s" % (
            k, off, n.bit_length(), f4.hex(), scr == r2.to_bytes(256, "big")[::-1]))
    pairs = [(d, d.replace(".dat", ".sig")) for d in (
        "ob_x_a64.dat", "ob_x_a32.dat", "ob_cs2_a64.dat", "ob_cs2_a32.dat")]
    pairs += [("comm_comm.dat", "comm_sig4"), ("comm_comm.dat", "comm_sig5")]
    for dn, sn in pairs:
        dp, sp = os.path.join(UNPACK, dn), os.path.join(UNPACK, sn)
        if not (os.path.exists(dp) and os.path.exists(sp)):
            continue
        data = open(dp, "rb").read()
        sig = open(sp, "rb").read()
        res = {k: rsa_verify(sig, data, v[0]) for k, v in keys.items()}
        print("  %-16s %-14s md5=%s  %s" % (
            dn, sn, hashlib.md5(data).hexdigest(),
            " ".join("%s=%s" % (k, "OK" if r else "no") for k, r in res.items())))


def cmd_stats(argv):
    p = argv[0]
    d = open(p, "rb").read()
    print("size=%d entropy=%.4f" % (len(d), entropy(d)))
    c = collections.Counter(d)
    print("top bytes:", [(hex(k), v) for k, v in c.most_common(8)])
    print("zero=%.3f printable=%.3f" % (
        d.count(0) / len(d), sum(1 for b in d if 32 <= b < 127) / len(d)))


CMDS = {"info": cmd_info, "sections": cmd_sections, "img": cmd_img, "names": cmd_names,
        "strings": cmd_strings, "comm": cmd_comm, "mrpcs": cmd_mrpcs, "sig": cmd_sig,
        "verify": cmd_verify, "stats": cmd_stats}

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in CMDS:
        print(__doc__)
        sys.exit(1)
    CMDS[sys.argv[1]](sys.argv[2:])
