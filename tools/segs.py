from elftools.elf.elffile import ELFFile
for p in (r"D:\workspace\ACE\libs\libtprt.so", r"D:\workspace\ACE\libs\libtersafe.so"):
    f=open(p,"rb"); e=ELFFile(f)
    print(p)
    for s in e.iter_segments():
        if s["p_type"]=="PT_LOAD":
            print("  LOAD vaddr=%#x off=%#x filesz=%#x flags=%s" % (s["p_vaddr"], s["p_offset"], s["p_filesz"], s["p_flags"]))
    for sec in e.iter_sections():
        if sec.name in (".text",".tptext",".rodata"):
            print("  %-8s addr=%#x off=%#x size=%#x" % (sec.name, sec["sh_addr"], sec["sh_offset"], sec["sh_size"]))
    f.close()
