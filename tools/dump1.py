tbl = open(r"D:\workspace\ACE\out\strtab.bin","rb").read()
print(len(tbl))
print(tbl[:96].hex(' '))
print(bytes(tbl[:96]))
