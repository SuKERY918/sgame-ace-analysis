from elftools.elf.elffile import ELFFile
f=open(r"D:\workspace\ACE\libs\libtersafe.so","rb")
e=ELFFile(f)
for s in e.iter_sections():
    print(f"{s.name:24s} 0x{s['sh_addr']:08x} size 0x{s['sh_size']:x}")
f.close()
