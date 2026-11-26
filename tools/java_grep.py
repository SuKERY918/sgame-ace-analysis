import os
import re
import sys

pattern = re.compile(sys.argv[2])
root = sys.argv[1]
limit = int(sys.argv[3]) if len(sys.argv) > 3 else 60

rows = []
for base, _, files in os.walk(root):
    for name in files:
        if not name.endswith(".java"):
            continue
        path = os.path.join(base, name)
        try:
            text = open(path, encoding="utf-8", errors="ignore").read()
        except OSError:
            continue
        n = len(pattern.findall(text))
        if n:
            rows.append((n, path))

rows.sort(reverse=True)
for n, path in rows[:limit]:
    print("%4d %s" % (n, path))
print("total %d files" % len(rows))
