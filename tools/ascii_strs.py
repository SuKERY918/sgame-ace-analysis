import re
import sys

from so_elf import So

path = sys.argv[1]
minlen = int(sys.argv[2]) if len(sys.argv) > 2 else 5
pat = re.compile(sys.argv[3]) if len(sys.argv) > 3 else None

so = So(path)
data = so.data
hits = 0
for va0, end, fo in so.segs:
    i = fo
    limit = fo + (end - va0)
    while i < limit:
        j = i
        while j < limit and 32 <= data[j] < 127:
            j += 1
        if j - i >= minlen:
            s = data[i:j].decode("latin1")
            if not pat or pat.search(s):
                print("%08x %s" % (va0 + (i - fo), s))
                hits += 1
        i = j + 1
print("hits %d" % hits)
