p=r"D:\workspace\ACE\tools\ops.py"
s=open(p,encoding="utf-8").read()
s=s.replace('print("entries", len(rows))','open(r"D:\\workspace\\ACE\\out\\ops.tsv","w",encoding="utf-8").write("\\n".join(f"{o}\\t{h:08x}\\t{'' if n is None else n}" for o,n,h,site in rows))\nprint("entries", len(rows))')
open(p,"w",encoding="utf-8").write(s)
