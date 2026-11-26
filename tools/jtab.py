from capstone import *
import struct
p=r"D:\workspace\ACE\libs\libtersafe.so"
data=open(p,"rb").read()
# vaddr == file offset for this ELF? .text at 0x1b6c20 file off? check program headers is heavy; assume identity (IDA imagebase 0 and segments contiguous from 0)
md=Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail=False
tab=struct.unpack_from("<88i", data, 0x90EC0)
base=0x1BD078
for i,off in enumerate(tab, start=1):
    t=base+off
    if t==0x1BD078: continue
    ins=list(md.disasm(data[t:t+40], t))
    txt="; ".join(f"{x.mnemonic} {x.op_str}" for x in ins[:4])
    print(f"cmd {i:3d} (0x{i:02x}) -> {t:08x}  {txt}")
