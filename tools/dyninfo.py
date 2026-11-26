from elftools.elf.elffile import ELFFile
for path in [r"D:\workspace\ACE\libs\libtersafe.so", r"D:\workspace\ACE\libs\libtprt.so", r"D:\workspace\ACE\libs\libTPCore-master.so"]:
    f=open(path,"rb"); e=ELFFile(f)
    print("==",path)
    for s in e.iter_sections():
        if s.header.sh_type=="SHT_DYNAMIC":
            for t in s.iter_tags():
                if t.entry.d_tag in ("DT_NEEDED","DT_SONAME","DT_RPATH","DT_RUNPATH"):
                    print("  ",t.entry.d_tag, t.needed if t.entry.d_tag=="DT_NEEDED" else t.soname)
    dyn=e.get_section_by_name(".dynsym")
    syms=list(dyn.iter_symbols())
    und=[s.name for s in syms if s["st_shndx"]=="SHN_UNDEF"]
    defi=[s.name for s in syms if s["st_shndx"]!="SHN_UNDEF"]
    print("  dynsym",len(syms),"undef",len(und),"defined",len(defi))
    print("  defined:",[x for x in defi][:60])
    print("  undef  :",und[:20])
    f.close()
