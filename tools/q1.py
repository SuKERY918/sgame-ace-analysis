import re
p=r"D:\workspace\ACE\out\func_strings.txt"
lines=open(p,encoding="utf-8").read().splitlines()
for ln in lines:
    if any(k in ln for k in ["IsRoot=","IsEmu=","IsVAP=","CertHash=","root=%d|x86"]):
        print(ln[:400]); print("-"*60)
