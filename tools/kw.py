import json, re
db=json.load(open(r"D:\workspace\ACE\out\db.json",encoding="utf-8"))
strs={int(k):v for k,v in db.items()}
kw = ["/proc","/sys","/dev","/data","/system","/vendor","/sbin","ro.","persist.","init.","magisk","frida","xposed","substrate","ptrace","hook","maps","mem","status","TracerPid","cpuinfo","cmdline","environ","mount","seccomp","Build","getprop","PackageManager","ActivityManager","Sensor","Camera","proc/","/proc/self","/proc/%d","dex","oat","vdex","apk","sign","crc","hash","md5","sha","emulator","qemu","nox","ldplayer","bluestacks","vbox","vm_","sim","wifi","ip","mac","imei","android_id","gsf","oaid","prop"]
from collections import Counter
c=Counter()
for off,v in strs.items():
    s=v["s"]
    for k in kw:
        if k in s: c[k]+=1
for k in kw: print(k, c[k])
