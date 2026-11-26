import sys

data = open(r'D:\workspace\ACE\libs\libtersafe.so', 'rb').read()

targets = [(0x964C8, 21), (0x983A5, 26), (0x964C8, 22), (0x983A5, 27), (0x964C8, 24), (0x983A5, 28)]

for off, n in targets:
    c = data[off:off + n]
    print(hex(off), n, c.hex())
    hits = []
    for k in range(256):
        p = bytes(b ^ k for b in c)
        if all(32 <= x < 127 or x == 0 for x in p):
            hits.append(('xor%02x' % k, p))
    for j in range(256):
        p = bytes(b ^ ((j + i) & 0xFF) for i, b in enumerate(c))
        if all(32 <= x < 127 or x == 0 for x in p):
            hits.append(('i%02x' % j, p))
    for tag, p in hits[:6]:
        print('   ', tag, p)
