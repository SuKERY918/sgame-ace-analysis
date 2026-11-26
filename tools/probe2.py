data=open(r"D:\workspace\ACE\libs\libtersafe.so","rb").read()
def show(addr,n=40):
    b=data[addr:addr+n]
    print(hex(addr), b.hex())
    for k0 in range(256):
        s=bytes(c^((k0+i)&0xFF) for i,c in enumerate(b))
        if all(0x20<=x<=0x7e for x in s):
            print(f"  k0={k0:#04x} {s!r}")
show(0x98550,19)
show(0x94b8c,16)
