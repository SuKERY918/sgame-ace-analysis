import re
p=r"D:\workspace\ACE\tools\ops.py"
s=open(p,encoding="utf-8").read()
s=s.replace('dec = set(pickle.load(open(r"D:\\workspace\\ACE\\out\\dec_list.pkl", "rb")))','dec = set(pickle.load(open(r"D:\\workspace\\ACE\\out\\dec_list.pkl", "rb"))[1])')
s=s.replace('''            name = None
            v = found.get(pending_mov)
            if isinstance(v, tuple):
                name = v[1]
            elif isinstance(v, dict):
                name = v.get("s")
            elif isinstance(v, str):
                name = v''','''            v = found.get(pending_mov)
            name = v[1] if isinstance(v, tuple) else v''')
open(p,"w",encoding="utf-8").write(s)
print("patched")
