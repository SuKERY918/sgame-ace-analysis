# Part E：代码完整性 / 防篡改模块（libtersafe.so）

对象：`libs\libtersafe.so`（AArch64、imagebase 0、strip）。注册总表 `0x27FAE4`：每个模块“ctor 返回对象 → 解密名字（`MOV W0,#偏移` + BL 0x4E6xxx）→ `sub_222284(ctx,obj,name,req,flag)`”，`sub_2222F4` 插入 `{obj,name,req,flag}`。偏移为串表 offset 或 vaddr。

## 0. 总览

| 模块 | 注册点 / ctor | 运行槽 | 职责 |
|---|---|---|---|
| various_opcode | 0x280054 / sub_2A9370（calloc 0x50） | 0x5151E8[2]=0x2A93EC | 自身 `.text` 内存 vs 文件滚动哈希，与 20 槽期望值之一比对 |
| opcode_scan | 0x27FC78 / sub_28D9A0→sub_28DAD4（0x2C8） | 0x514E28[2]=0x28DC98 | 逐页 CRC32+memcmp 自身 `.text`，记录差异 dword |
| shell_checker | 0x28016C / sub_2BA160（0x58） | 0x5155E0[2]=0x2BA1CC | 回传 Java 字段，探测 `/sdcard/sdk/enable.log` |
| cert3 | 0x280194 / sub_2AE04C（0x50） | 0x515378[2]=0x2AE0C4 | 自身 APK 证书 MD5 对云控 official_cert_md5/cert_%d |
| file | 0x27FD28（inline calloc 0x48 + vtable 0x515028） | 0x29B194 | 按云控 `comm.dat` 清单查文件存在性/属性 |
| cc2 | 0x27FF58 / sub_2829A8（0x50） | 0x514CB8[2]=0x282B4C | APK 内 `.so` 条目 CRC 对安装目录实际 `.so` |

> 更正：`sub_2AE04C` 属 cert3；`sub_2AC258` 注册名 16823 `"live"`，不属本组。

## 1. various_opcode（40127）

- 构造：`0x280054` calloc(0x50)+`sub_2A9370`；vtable `0x5151E8`[2]=`0x2A93EC`；对象 +0x4C 为页大小（默认 0x4000）。
- 链：`0x2A93EC` → `sub_2DAD4C()` 取 ctx → `sub_2A95B8()` 门控（推断“检测使能”，假则返回）→ `sub_4DB398` 取模块单例 → `sub_4DB538(singleton,buf,0x400,...)` 拷模块路径 → `sub_2A9628`（开文件/解 36953 `".text"`/取段）→ `sub_2A9674`。
- 采样：`v11=sub_1F524C(ctx+6*(*(ctx+120)&7)+72)`，`slot=v11%20`；`*(ctx+940)!=0` 时走 `BR X1` 混淆分支（推断反调试）。
- 判据一（页级抽检 `0x2A99A4`）：开关 `40272 "vos_chk"` 默认 1，阈值 `max(10,cfg)` 页；`sub_4E64D0(0)` 取路径并打开，`lseek` 到 `.text`，逐页调 `*(&off_515208+slot)` 与文件页比较，差异率≥30% 时用 `40282 "u:%d,t:%d"` 经 `sub_1EE218(102,buf)` 上报；返回 `差异率<30` 才继续。
- 判据二（核心）：`v17=sub_2A9C18` 内存 `[base+struct[8],struct[16]]` 4096 分块滚动哈希（`sub_4DC8F8` 可读性检查，区间表 `sub_2A9FC8` 规避）；`v20=sub_2A9E28` 同文件同区间、同槽原语；`v23=期望表[slot]^0xACC9725E`。期望表由 `sub_1B6CE4` `memcpy(buf,0x521510,0x140)` 得到：`0x521510="#T#E#R#S#I#G#START#"`，缓冲 `s[12..31]` 即 `0x521540–0x52158C` 20 个 dword（XOR 0xACC9725E），`0x521658` 为 `"#T#E#R#S#I#G#END#"`；20 槽实现位于 `0x2AA204–0x2AA698`（表驱动 CRC32 变体，表 `dword_E2270`）。
- 上报/崩溃：`v23!=v17` 时以 `"%08x%08x%08x"` 组串，`sub_4E82F8(40127)` 取 tag，`sub_23A1AC` 上报；再 `sub_1EF680(v17,v20,v19,v11,flags,32B)` 发通用事件。`v17!=v20` 且非 0、`sub_2DB8AC(ctx)&1==0`、且 `sub_23A114/sub_2DB888` 命中 → 开关 `40144 "crash_various_opcode"`（默认 1）→ `sub_46A5FC` + tag `30819 "opcode_scan"` + `29629 "opcode_crash"` + `sub_46CD24(...,1)`。
- 结论：校验对象是**自身 libtersafe.so 的 `.text`**，非 libil2cpp/libGameCore；“20 槽”=20 套静态期望值+20 个哈希入口，每次随机取 1 套。

## 2. opcode_scan（30819）

- 构造：`0x27FC78` 注册（W3=1,W4=0）；`sub_28D9A0` 分配 0x2C8 调 `sub_28DAD4`（清 +0x2A0/+0x2A8/+0x2C0/+0x5C/+0x9C，页大小 +0x58，非 4K/16K→0x4000）；vtable `0x514E28`，单例 0x55F540。
- 运行：`byte_55F54C` 一次性；`sub_28DB5C` 初始化（路径 512B→+0x9C、短路径 64B→+0x5C、模块字段→+0x2B8/+0x2B0、缓冲 0x400→+0x2A0）→ `loc_28DCF0`；完成置 +0x4C=1。
- 主流程：路径后缀匹配 `.so`(17074)/`base.apk`(17080)；`sub_4D6740`+`sub_4EA024(36953)`+`sub_4D6984` 取 `.text` {文件偏移,vaddr,大小}；`sub_4B8488(path,0,0)` 打开，失败 `sub_1EE218(0x18/0x19,path)`。页循环每 50 页 `sub_4B8424(10000)`；`sub_4B66B0` 读页；`sub_489284(file,len,prev)` 为 CRC32（表 dword_E2270）；`sub_4A4690` 与内存页 memcmp，不等进 `sub_28E188`。
- 差异记录（0x28E188）：+0x48 计数 >0x13 即停；`页号=addr/pagesize`；`sub_489248` 算双侧短哈希，`sub_1EF554(a2,1,页号,文件哈希,内存哈希)`；再逐 dword 比对，最多 5 处 `sub_1EF554(a2,10,addr+4*i,内存值,文件值)`。汇总 +0x50=总页、+0x54=`(页数>=2 && <100 && 差异>=1 && 100*差异/页数<10)?0:1`；收尾把 `~CRC32` 写 `ctx+0x84`（即汇总的 `txt_seg_crc`）。
- 崩溃（0x28E364）：解码 15B `unk_96A33`；条件 `总页>=100 && 差异>=1 && 100*差异/总页<=10`；`sub_23A0B0(ctx,0,0)==0`；开关 `29629 "opcode_crash"` 默认 1；则 `sub_46A5FC` + tag `30819`/`29629` + `sub_46CD24(...,1)`。
- 结论：全量逐页校验，只对“少量页被改（≤10%）”崩溃，页哈希与 dword 双值均上报，是本组最完整的实现。

## 3. shell_checker（31767）

- 构造：`0x28016C` ctor `sub_2BA160`，对象 0x58，单例 0x55F610，vtable `0x5155E0`，运行槽 `0x2BA1CC`。
- 运行：+0x51 一次性；两个 1024B 缓冲；经 `[obj+0x48]`（注入的 JNI getter）逐字段取值并格式化，`sub_4CB94C`/`sub_4CC248` 发布：`"apk_path"(0x9153F)→"apk_path:%s"(0x9114A)/"apk_path=%s"(0x91CBF)`；`"shell_ver"(0x93875)→"shell_ver:%s"(0x96A60)/"=%s"(0x9597E)`；`"check_state"(0x973AF)→"check_state:%s"(0x94CDC)/"=%s"(0x93C5B)`；`"debugger"(0x9387F)→"debugger:%s"(0x92C71)/"=%s"(0x91CCB)`（反调试）；另取 `"s_open_id"(0x920F3)`、`"time_magic"(0x92894)`；i=0..4 取 `"chk_err_%d"(0x965BE)`，非空以 `"%s:%s"(0x97C54)` 追加。
- 探针（0x2BA7F4）：解 `"shell_report"`（inline 607635）与 `"%s/%s"`（618404）；开关 `"shell_report"` 默认 0；拼 `"/sdcard/sdk"(8588)`+`"/"`+`"enable.log"(8706)`，存在且开关开→真；另有 `srand(time^rand)` 后 `rand()%1000==722`（1/1000）随机命中。为真则 `"shell_ver=%s"`（64B）→ `sub_1EF818`。
- 上报文件（0x2BA960）：`sub_4EA384(49356)` 取 `"acecrh.dat"`；存在则解析整数；首值 `1799334183(0x6B4D00E7)` 用 `49369 "a:%x;t:%x;m:%x;s:%x"`，否则 `49391 "a:%x"`；`unlink`；+82 为 0 时 `sub_1EE218(128,buf)` 只报一次。
- 结论：只做“Java 字段回传 + enable.log 探针 + acecrh.dat 上报”，无壳特征库、无代码段校验。

## 4. cert3（31606）

- 构造：`0x280194` ctor `sub_2AE04C`，对象 0x50，单例 0x55F5E8，vtable `0x515378`，运行槽 `0x2AE0C4`。
- 运行：解 6B 前缀 `unk_9288D`；`a1+40` 一次性；ctx=`sub_22D820`；`expected=sub_22DFD0(ctx,"official_cert_md5"(59921),buf,64)`（空→`unk_92AD3`）；`white_mode=sub_22DA98(ctx,"white_mode"(16854),0,1)`。
- 数据源：① `v39` 自身 APK 证书（`sub_2AE390`→`sub_2AEB40`：`sub_4D8D60`+`sub_4D8DF4` 解析签名算 MD5，受 `40203 "cal_cert_md5"` 控制，失败 `sub_1EE218(132,...)`，`0x4D8F44/0x4D90A0` 为 zip 解析；`sub_2AEC28` 补 ctx 字段）；② `v38` 正常模式检测表、③ `v37` white_mode 白名单（`sub_2AE3F0` 读 `16843 "cert_cnt"`，循环 `40262 "cert_%d"` 取云端串，切两段，32 字符者分别入表）。元素布局：+0x14 证书 MD5、+0x35 包名/作者、+0x4 类型。
- 判定：逐元素 `cert=elem+0x14`；`sub_4A46C0(expected,cert)!=0`（非官方签名）→ `sub_1EE0C4(pkg,cert,...)`+`sub_2AE8A4`+`sub_1F2344` 上报；`sub_2AE928(ctx,cert,white_mode,v38,v37)`：长度 32 且 `[ctx+76]==0` 时 `hash=sub_489248(cert,32)`，命中/未命中分别写 `[ctx+76]=(hash&0x7FF)|((hash&0x7FF)<<11)|0x400000/0x800000`（22 位证书行为码）。
- 崩溃：white_mode 时不在 v37→崩；否则在 v38→崩；开关 `16830 "cert_crash"` 默认 1；组串 + `sub_4CB94C` + `sub_4CCA80`（`"cert=%s|author=%s"`）+ `sub_46A5FC` + `sub_46CD24(...,"cert_crash",cert,"cert_crash",1)`。
- 与 0x4CBDB4：`"cert_md5=%s|apk_hash_1=0x%08x|apk_hash_2=0x%08x|txt_seg_crc=0x%08x"` 由 `sub_4CBAF4`（`sub_4CBB2C`+`sub_4CBC24`+`sub_4CBD08`+`sub_4CBDB4`）周期汇总；`cert_md5` 来自 `sub_2DB678`，`apk_hash_1/2` 来自 `sub_2DB724` 两次取值，`txt_seg_crc=*(ctx+0x84)`（opcode_scan 写入）。cert3 只提供 `[ctx+76]` 与证书事件。
- 结论：cert3 是“重签名/改包”检测，真正的哈希仅证书 MD5（CRC32 只用于映射行为码），不校验 APK 整体。

## 5. file（5760）

- 构造：`0x27FD28` inline calloc(0x48)+vtable `0x515028`，运行槽 `0x29B194`；req 由 `BIC(W25,W21)` 动态决定（推断与开关有关）。
- 运行：`sub_29B380(unk_9308A,0x16,buf)` 解格式 `"|%s:0x%08x, from_c:%d"`（inline 602250，site 0x29B1C4）；`sub_1F97A8(obj+0x28)` 一次性；`malloc(0x208)` 建 32 槽容器；`sub_2324E8`：`sub_4E7348(713)` 得字面 key `"comm.dat"`，`sub_22E350(key,5,1)` 取配置并切分，token≤255、容器 32 条；每条 16B `{name,qword}` 入表，名字进全局池（`sub_475CC8`）。
- 判据：`sub_4C4F4C` 单例 vtable+0x20 调 `(path,1,1,&attr)` 得 32 位属性与存在标志；API≥17（`sub_4E5F10(0x11)`）且存在则 `sub_4E5710` 日志；`sub_4B841C` 取 stat（+0x30 大小、+0x58 时间，推断）；条件不满足则 `sub_1EFE4C(name,attr,size,time,exists,0,path)` 组事件头 `0x60000233B`（1768B）。
- 结论：云控文件清单的“存在性/属性”检查，不做内容哈希；`from_c` 表是否首次命中。

## 6. cc2（31600）

- 构造：`0x27FF58` ctor `sub_2829A8`，对象 0x50，单例 0x55F460，vtable `0x514CB8`，运行槽 `0x282B4C`。
- 运行：`A=sub_2DB600(ctx)`（ctx+0x6A1 缓存串，否则 `loc_23F958` 走 JNI；推断自身 APK 路径）、`B=sub_2DB25C()`（`sub_23F078`→JNI `getApplicationInfo`(36961/37002)+`nativeLibraryDir`(38402)）；非空则 `0x282BCC`。
- 基线（0x282BCC）：`sub_487694(A)` 以 `"rb"` 打开并校验前 4B `0x04034B50 ("PK\x03\x04")`→A 是 ZIP/APK；`sub_487798` 逐条读中央目录项（magic `0x02014B50`，取 name_len≤0x3FF、CRC32、压缩方法、解压大小、本地头偏移；名字存 +8、CRC32 存 +1032）；`.so` 条目入集合 `v31`，并建映射 `v30`：条目名→`CRC32|0x100000000`；上限 99999；再 `0x282E04(obj,B,v31,v30)`。
- 校验（0x282E04）：解 `"cc2_x86"(613822)`、`"cc2_force"(597139)`、`"%s/%s"(611500)`、`"!cc2:%s, %d, 0x%08x, %d"(599121)`、`"cc2"(602199)`；`v11=cc2_x86 默认 0`、`v38=cc2_force 默认 1`。对每个条目名：`path="%s/%s"(B,name)`；`sub_4B8420(path,4)==0` 时取文件 32 位值 `v50`（vtable+0x20）查 `v30`；未中则 `sub_4892B4(path,&v50)` 重算 CRC32（表 dword_E2270）再查；仍未中→`v37=sub_4A09E8(path)`、`v28=sub_23A114(ctx)&1`、`v36=sub_2DB8AC(ctx)`；API≥17 记 `"!cc2:..."`；`sub_4CB94C`+`sub_4CCBA4` 发布 `32737 "name=%s|size=%d|crc=0x%08x|root=%d"`；`cc2_force && (cc2_x86 || !(v36&1))` 时 `sub_46A5FC`+`sub_46CD24(...,"cc2",name,"cc2",1)`。
- 结论：cc2 校验“APK 内 `.so` 条目 CRC/大小”与“安装目录实际 `.so` 重算 CRC32”的一致性，防 native 库替换；差异以事件 `"cc2"` 上报，force 默认开即崩。

## 7. 小结

证据强度：various_opcode/opcode_scan/cert3/cc2 有反编译与表实测（强）；file/shell_checker 部分平坦化（中）。various_opcode 校验自身 .text 由路径、ELF 段、哈希表互证。

缺陷（仅描述）：
1. 期望值与 20 个哈希入口静态嵌在 .text/.rodata（0x521540、0x2AA204 起），槽选择仅由 ctx 伪随机 %20 决定，样本小、可预测。
2. various_opcode 每次只验 1/20 槽，页级抽检 <30% 仍继续；opcode_scan 只在“差异页≤10% 且总页≥100”崩溃，留窗口。
3. 范围仅本模块路径与 .text；libil2cpp/libGameCore 由 other 模块负责。
4. 判据依赖云控（vos_chk/official_cert_md5/cert_%d/comm.dat/cc2_force/shell_report 可关）；cal_cert_md5 关闭时 cert3 跳过证书解析。
5. shell_checker 含 1/1000 随机项；cc2 的 nativeLibraryDir+zip 名拼接在条目带 lib/arm64-v8a/ 前缀时会系统性拼错（推断）。
6. file 只查存在性/属性，同路径替换即可满足。