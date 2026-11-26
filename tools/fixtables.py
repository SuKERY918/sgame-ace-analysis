import re

p = r'report/main.md'
lines = open(p, encoding='utf-8').read().split('\n')
out = []
n = 0
for l in lines:
    if l.startswith('|'):
        nl = re.sub(r'`([^`]*)`', lambda m: '`' + m.group(1).replace('|', '\\|') + '`', l)
        if nl != l:
            n += 1
        out.append(nl)
    else:
        out.append(l)
open(p, 'w', encoding='utf-8', newline='\n').write('\n'.join(out))
print('fixed rows:', n)
