from elftools.elf.elffile import ELFFile
import pickle, json
p=r"D:\workspace\ACE\libs\libtersafe.so"
f=open(p,"rb"); e=ELFFile(f)
rela=e.get_section_by_name(".rela.plt")
print("rela.plt count", rela.num_relocations() if rela else None)
ds=e.get_section_by_name(".dynsym")
out=[]
for i in range(rela.num_relocations()):
    r=rela.get_relocation(i)
    sym=ds.get_symbol(r["r_info_sym"])
    out.append((r["r_offset"], sym.name))
print(out[:5])
print("plt sec", e.get_section_by_name(".plt")["sh_addr"], e.get_section_by_name(".plt")["sh_size"])
print(".got.plt", [(s.name,hex(s["sh_addr"]),s["sh_size"]) for s in e.iter_sections() if "got" in s.name])
pickle.dump(out, open(r"D:\workspace\ACE\out\pltrel.pkl","wb"))
