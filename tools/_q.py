import json, sys, re
cg = json.load(open(r'D:\workspace\ACE\out\cg.json'))
rev = {}
for k, v in cg.items():
    for c in v['i']:
        rev.setdefault(str(c), []).append(int(k))
def s(x): return int(x, 0) if isinstance(x, str) else x
def info(a):
    a = str(s(a)); v = cg.get(a)
    if not v: print('no node', a); return
    print('addr', a)
    print('imports:', v['m'])
    print('callees:', ' '.join(f'{c:08x}' for c in v['i']))
    print('callers:', ' '.join(f'{c:08x}' for c in rev.get(a, [])))
def callers(a):
    a = str(s(a)); print(' '.join(f'{c:08x}' for c in rev.get(a, [])))
def callees(a):
    a = str(s(a)); v = cg.get(a) or {}
    print(' '.join(f'{c:08x}' for c in v.get('i', [])))
def who(a):
    a = s(a)
    for k, v in cg.items():
        if a in v['i']:
            print(f'{int(k):08x}')
if __name__ == '__main__':
    cmd, arg = sys.argv[1], sys.argv[2]
    {'i': info, 'c': callers, 'e': callees, 'w': who}[cmd](arg)
