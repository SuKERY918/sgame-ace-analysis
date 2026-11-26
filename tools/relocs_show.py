import struct
import sys

path = r'D:\workspace\ACE\libs\libtersafe.so'
d = open(path, 'rb').read()

# ELF64 header
e_shoff = struct.unpack_from('<Q', d, 0x28)[0]
e_shentsize = struct.unpack_from('<H', d, 0x3A)[0]
e_shnum = struct.unpack_from('<H', d, 0x3C)[0]
secs = []
for i in range(e_shnum):
    off = e_shoff + i * e_shentsize
    name, typ, flags, addr, offset, size, link, info, align, entsize = struct.unpack_from('<IIQQQQIIQQ', d, off)
    secs.append(dict(name=name, typ=typ, addr=addr, offset=offset, size=size, entsize=entsize, link=link))

shstr = secs[struct.unpack_from('<H', d, 0x3E)[0]]
def secname(i):
    n = secs[i]['name']
    end = d.index(b'\0', shstr['offset'] + n)
    return d[shstr['offset'] + n:end].decode()

relocs = {}
for i, s in enumerate(secs):
    if s['typ'] == 4:  # SHT_RELA
        n = s['size'] // 24
        for j in range(n):
            r_off, r_info, r_add = struct.unpack_from('<QQq', d, s['offset'] + j * 24)
            t = r_info & 0xffffffff
            sym = r_info >> 32
            relocs[r_off] = (t, sym, r_add)

lo, hi = int(sys.argv[1], 0), int(sys.argv[2], 0)
for a in range(lo, hi, 8):
    r = relocs.get(a)
    print(hex(a), (hex(r[2]) if r else '-'), (r[0] if r else ''), (r[1] if r else ''))
