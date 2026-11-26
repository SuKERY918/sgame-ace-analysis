# partG：设备信息 / 账号 / 上报策略模块静态分析

对象 `libtersafe.so`（ACE/TSS，AArch64，imagebase 0，strip）。数据源：IDA（database=tersafe）、`out\allstr.tsv`、`out\cg.json`。**A**＝反汇编/反编译直读判据并与字符串互证；**B**＝单侧可读，另一侧推断。

## 1 总览

| 模块 | name id | 注册 site | 构造/对象 | vtable / 运行入口 | W3 | 开关默认 |
|---|---|---|---|---|---|---|
| info | 0x134=308 | 0x27FC0C | sub_2DDE78 / 0xE0 | off_516A50 +0x30 sub_2DDFDC | 1 | 4 采集开关=1 |
| tablet | 0x33FC=13308 | 0x27FBC4 | sub_29C3AC / 0x98 | off_515088，任务 0x27F7A8 | **0** | 7 个 tablet_*=开 |
| user_tag | 0x4167=16743 | 0x27FBE4 | sub_29B444 / 0x158 | off_515058 +0x10 sub_29B5A0 | !W21 | 2 个=0 |
| ksat | 0xBDDF=48607 | 0x27FD24 | sub_2AAA40 / 0x58 | off_5152B8 +0x10 sub_2AAB88 | 1 | att_svr=0 等 3 键 |
| pe_rep | 0x4214=16916 | 0x280290 | sub_28F5C4 / 0x50 | off_514EF8 +0x40 sub_28FDB0 | 1 | 5 键见 2.6 |
| env_chk | 0x4063=16483 | 0x2802E8 | calloc(0x50)+sub_28FD5C | off_514F28 +0x40 同上 | 1 | 同 pe_rep + VP |
| info_publisher | 0x7C27=31783 | 0x27FFC4 | sub_4CB94C / 0xA0 | off_518EA0，32 处调用 | 1 | e_hbeat=1 |
| auto_defence3 | 0xC1D5=49621 | 0x27FB78 | sub_258C50 / 0x60+ | off_514298 +0x20 sub_259210 | 1 | attunlock1=1 + 9 anti_* |

注册统一为 `obj=ctor(); name=sub_4Exxxx(id); sub_222284(ctx,obj,name,W3,W4)`，节点 `{obj;name[32];u8 W3;u8 W4}` 追加进 `ctx+8`（sub_222284/sub_222F4）。整表无代码 xref，仅 `.rela.dyn` 的 `R_AARCH64_RELATIVE r_offset=0x514C40 addend=0x27FAE4`（**A**）。

## 2 分模块

### 2.1 info（设备信息汇总）

- 单例 `sub_2DDE78`（0xE0；`+0xD4` 上次 uid、`+0xD8` 上次时刻），注册 0x27FC0C，name 308，W3=1；运行槽 +0x30=`sub_2DDFDC`，第二接口表 `off_516A98`。
- 判据（**A**）：`uid=sub_1F524C(ctx+0x48+6*(ctx[0x78]&7))`；`uid==0` 返回；`uid==+0xD4 && +0xD8!=0 && now-(+0xD8)<0x1C20`（7200 s）则跳采；否则刷新后串调 15 个采集器（sub_2DE0AC…sub_2DEB80）⇒ 重采＝换号或满 2 h。
- 采集位串：`sub_2DE288` 先 `sub_2E00A0` 解 7 B（`dst[i]=src[i]^(0xBE+i)`），再取 4 开关（默认 1）`device_info`(0x13B)/`report_apk`(0x8D)/`ignore_sys_apk`(0x9A)/`sensor_detect`(0xAB)，按 `inf_cl:1|%d|%d|%d|%08x` 0x2DE394 输出。
- 上报键举例：`vpn:%d` 0x2DE9F4、`Platform:%s;Android %s,level %d,Language:%s` 0x2DED74、`Brand:%s` 0x2DF2AC、`game_ver:%s sdk_ver:%s` 0x2DEB18（内置 `7.7.50.28931`）、`root_alert:%s` 0x2DEC98、`issue.tst` 0x2DF6B8，共 30+ 键（全集 site 0x2DE0AC-0x2DF690）；info 不发报，经 `info=%s`(0x4CC3BC) 交 info_publisher（**B**）。
- 降级：单键失败不影响其它。归属澄清：0x2C8CBC 的 `%d=%s;`(0xC3EF)＋`%s%08X` 与 16 槽错误键表 0x2C9D78 仅被 `0x2C8AC0←0x2C89D4`（引 `force_fake_token` 0x2C89FC）调用，属 FakeToken（**A**）。

### 2.2 tablet（设备形态）

- 单例 `sub_29C3AC`（0x98；init 0x29C4D0 清零 `+0x48/+0x4C/+0x50/+0x90`），注册 0x27FBC4，name 13308，**W3=0**；vtable `off_515088`。触发非轮询：任务表 0x27019C 的 `ScanTablet` 0x27F7A8→开关 0x27F7C4→`sub_27F7FC`（取单例+`sub_29DC34` 递归构树）。
- 七层判据（各带开关）：主链 `sub_29C5F8`（`"%s;%s"` 0x29C6AC + `tbt.img` 0x29CA2C + `obj_tablet_name` 0x29CA8C）→`tablet_certain`(13353)→`tablet_unknown`(0x29CBC8)→`tablet_model`(13383，配 `model` 6434)→`tablet_prop`(13398 + `ro.build.characteristics` 0x29CE3C)→`tablet_layout`(13456，`SCREENLAYOUT_SIZE_MASK`，`layout:%d,%d` 0x29D5B4)→`tablet_dp`(13648)/`tablet_size`(13692)；OEM 白名单 0x29CEB4（`Lenovo;TB` 等 4 条 + `EEBBK;S/A/T/X/H`）。
- 上报：`sub_23DE84`（唯一 caller 0x23DA5C）输出 `DeviceType=%d|TabletInfo=%s|`(0x23DECC)，同段 `IsEmu=%d|EmuName=%s|`(0x23DF18)、`IsVAP=%d|VAPName=%s|`(0x23DFAC)。降级：七开关任一关即退化 `tablet_unknown`，`DeviceType` 照发（**B**）。

### 2.3 user_tag（用户标签）

- 单例 `sub_29B444`（0x158，`+0x4C=100`/`+0x50=1` 取自 `qword_994F0`，`+0x58` 起 256 B；init 0x29B508 用 `sub_29C34C(unk_97C25,5,&b)` 解 5 B），注册 0x27FBE4，name 16743，`W3=BIC W25,W21`（=!W21）；运行槽 +0x10=`sub_29B5A0`。
- 判据（**A**）：`LDRB [X0,#0x3B3]` 非 0 时查 `force_usertag_scan`(46557) 默认 **0**，关则 RET(0x29B79C)；再查 `user_tag` 默认 **0**，关则 RET(0x29B628) ⇒ 默认不跑。命中后 `sub_2336B0(&list)`→`sub_29B7B4`；score=100，逐节点 `sub_4C9214(node+0x54)` 命中则追加 `node+0x10` 名+`unk_93F25` 并减 `node[0x50]` 权重，末尾 `BIC W8,W8,W8,ASR#31` 钳非负；空结果填 5 B 解码常量（推断 `TAG;`）。
- 落盘/上报：缓存 `+0x58/+0x4C/+0x48`，`sub_29BB04` 落 `ano_uts_c2.dat`(0x29BD44)；`user_tag:%s%d`(0x29B754，id 14909)→`sub_4A54DC`→`sub_1F0368`。降级：关位与开关为「与」，任一关即静默。

### 2.4 ksat（Key Attestation）

- `sub_2AAA40`（平坦化）单例 `qword_55F5C0`，对象 `calloc(0x58)`+`sub_2AAB30`（`+0x48`word/`+0x4A`byte/`+0x4C`qword/`+0x54`byte=0），注册 0x27FD24，name 48607；vtable `off_5152B8`，运行槽 +0x10=`sub_2AAB88`，另有 +0x40=0x2AD898。
- 主流程：`0x1DB2FC`→`0x1F97A8`→`0x2AAE0C`→`att_vap`(0x2AAEE8,48630)→`att_cra_white`(0x2AB0C4,48704)→`att_svr`(0x2AB450,48796)→`0x4D1D38/0x4D1D3C`（KeyStore init/cleanup）。
- att_svr 判据：id 0xBE9C 默认 **0**（0x2AB478 `W2=WZR,W3=#1`），关闭返回 **-1**；开启 `sub_4D1D38(&h)`→`sub_4D2578(&h,&chain)`（失败 -1）→`sub_49F614`+`sub_49FD70(0x20230629)`→`sub_49FF34`。
- 证书链：0x4D2578→`0x4D2660 getCertificateChain`→`0x4D36B8` 存 DER；`0x4D2A24` 建 `KeyPairGenerator`(0x4D3088)/`KeyGenParameterSpec.Builder`(0x4D31CC，别名 `ANO_KEYSTORE_ALIAS_03_23`)；`setAttestationChallenge` 0x4D359C 无静态 caller（推断 JNI 表调用，**B**）。
- 规则/上报：`attest_cert_not_white`(48749)@0x2ABC04、`attest_cert_is_black`(48773)@0x2ABCC0；格式 `attp:`(0x2ABD5C,48366)/`atta:`(48374)/`attc:`(48382)；计数 `att_cert_cnt`(48720)/`att_vap_cert_cnt`(48640)；成果经 0x2A0494→`cert_crc` 模板(0x4CC9B0)、0x2AE0C4→`cert=%s|author=%s`(0x4CCA80) 进 info_publisher。
- 队列槽 +0x40=`0x2AD898`（thunk `SUB X0,X0,#0x48`）：gate `ctx+0x3B8`≠0 且 `unk_965B8` 解码开关（默认 0）开，`sub_2D0D30(ctx)` 取队列 `[+8]`，`sub_2CFFE8/0x2D0164` 弹节点进 `loc_2ACA20`（0x180 栈、36 case）→`0x2AD82C/0x2AD518`（**B**）。降级：att_svr 默认关⇒不外发 attestation；0x3B8 未置位则队列不消费。

### 2.5 pe_rep（上报策略）

- 单例 `sub_28F5C4`（0x50，`+0x48`dword=0），注册 0x280290，name 16916；vtable `off_514EF8`（+0x30=0x28FDA8 RET、+0x38=0x28FDAC、+0x40=0x28FDB0、+0x48=0x2907F4）。
- 运行槽 +0x40=`sub_28FDB0`：`LDRB [X19,#0x48]` 闸门→置 1→顺序 `0x28FE10→0x28FF1C→0x2900DC→0x290270(+0x290354)→0x2904AC→0x2905F4→0x290790`；`0x2907F4`＝`STRB WZR,[X0,#0x48];RET`。
- 判据全在共用链（2.6），本模块唯一字面量仅 `com.`(0x28FA8C) ⇒ 纯调度壳（**A**）。同一实现被 env_chk vtable 复用⇒两模块各跑一次同组检查并重复上报。

### 2.6 env_chk（环境总检）

- `calloc(0x50)`+`sub_28FD5C`（base `off_513108`、vtable `off_514F28`(+0x40=0x28FDB0)、`+0x48`byte=0），注册 0x2802E8，name 16483；运行槽与 pe_rep 共用 `0x28FDB0`。
- 共用链（各带开关）：`0x28FE10`→`env_rr:%d`(59816)/`nf_rr`(59808)=1；`0x28FF1C` 对临时路径 `fopen(w/r)`+`unlink`，失败经 `sub_4CC334`(33021) 记 `notwritable`/`notreadable`；`0x2900DC` `sigac`(49502，默认 ctx 位) 查信号 4/5/6/7/11/31 的 `sa_handler>0x1000`，`dl_iterate` 比对 `[base,base+size)`→`sub_290998`（名单含 `/system/`、`linker`、`libBugly`）；`0x290270` `secc`(=1，读 `Seccomp:`)→`secc: %d;%d;%d;%d;%d`(15390)→`sub_1F0148`；`0x290354` `stack_zero_cnt:%d`(621586)；`0x2904AC` `kmc`(默认 ctx 位)；`0x2905F4` `ptc`(=1)+`ptc_max`。
- 自有槽 0x293DA8（0x2bc）：解三段常量→`sub_294064`；`sub_230BD0` 取已装包集合，`sub_4DD77C` 等遍历已加载模块，`sub_489248` 求路径 hash 与内嵌 BST 比对+basename，命中→`sub_4CC2BC("app_name=%s",33007)`；旁证 `OpenTPHP err:%d`(612606)。
- 槽 0x2941B4→0x2941B8（0x458）：`%08X`(602233)+`VP_`(606369) 拼 VP 串（**B**）。

### 2.7 info_publisher（上报发布器）

- 单例 `sub_4CB94C`（`qword_568EB8`），对象 0xA0+`sub_4CBA04`：vtable `off_518EA0`、`+72` 容器、`*(WORD*)(+152)=0`（`+0x98/+0x99` 清零）、`e_hbeat`(0x9755E) 默认 1→`+0x99`；注册 0x27FFC4，name 31783。
- 三级管线：`0x4CCC44`（非空、len<=0xF5，组 code=1/id=10）→`0x4CBE5C`（判 `+0x99`，拼 `id=%d|%s`(0x916F6)）→`0x4CBEF0`（入口 `inst[152]!=0 || sub_4CD44C()!=0`；len<=0xFF；`sub_238320` 编码失败即弃；`%d|%s`(0x942C4)→`0x4CD428`；`inst[152]!=0` 时遍历监听者 `vf[0x18]`）。
- 通道：`0x4CD44C=*(BYTE*)(sub_4CD018()+112)`；`0x4CD118` 仅当 `[+112]!=0 && *(QWORD*)(a1+104)<=0x80` 才入队，随后 `[+113]!=0 && sub_4A2008(a1+56)!=0` 返回 -1 ⇒ **上限 128，满即静默丢弃**（**A**）。
- 内置字段（唯一 caller 0x4CBAF8）：`root=%d|x86=%d|apk_cnt=%d|adb=%d|machine=%s|sys_ver=%s|root_record=%d`(0x4CBB2C,32413)、`apk_name=%s|…|app_name_b64=%s`(0x4CBC24,32485)、`cert_md5=…|txt_seg_crc=0x%08x`(0x4CBDB4,32585)，另有 `info=%s`(32959)、`path=%s|permission=%s`(33021) 等共 13 模板。
- 扇入：`0x4CB94C` 共 32 处 xref（0x20C524、0x256A4C、0x28FF1C×2、0x293F50…）⇒ 全 SDK 唯一上报汇聚点（**A**）。降级：`e_hbeat` 关只去前缀；通道未就绪（`+112==0`）跳过后返回 0。

### 2.8 auto_defence3（运行时综合判定）

- `sub_258C50`（入口即 jumptable 分派 loc_258C54），注册 0x27FB78，name 49621；单例 `qword_55F2C0`；`+0x48` 链表头；生效 vtable 由 getter（0x258D54）写 `off_514298`，`+0x20=0x259210` 主判定，`+0x10=0x258E9C`(`gp3`)、`+0x48=0x259554`(`force_antibm`)。
- 主判定 0x259210（平坦化 7 case）：`ctx=sub_2DAD4C`；`sub_2BD8E4()->[+0x50]`；`attunlock1`(48390) 默认 1；`sub_23A114(ctx)` 位参与分支，另读 `0x71F1`(29169)、`sub_4CF408`、`sub_294B30/297A78`；9 开关 id：48390、29269(anti_blackmodule)、29288(anti_ida)、29299(anti_frida)、29312(anti_substrate)、29329(anti_xposed)、29358(anti_taichi)、31079(anti_profiler)、49766(anti_lose_jnienv)。
- 检测体：`0x258E9C`(`gp3` 24644/`strip_ext` 29747)、`0x259CE8`(`anti_bm:%s` 26541)、`0x25A0B4`→`0x25A1A8`(`ida:%d` 596088；读 `/proc/%u/status` 的 `TracerPid` 598119)、`0x259840` hook 名单（libxhook.so、libsandhook*.so、libhookzz.so、libwhale.so、libfake-linker-21…30.so）。降级：任一 `anti_*` 关即跳过该分支，阈值与名单全来自配置（**B**）。

## 3 小结

**证据强度**：info/tablet/user_tag/info_publisher 为 A；env_chk、pe_rep 检查链 A 但调度方 B；ksat 的 JNI 侧、`loc_2ACA20`、`sub_1F0148` 下游为 B。

**设计缺陷（仅描述，不涉及利用）**：

1. 能力面由默认值决定：`att_svr`、`user_tag`、`force_usertag_scan` 默认 0（0x2AB478、0x29B5E8、0x29B628）。
2. info 刷新窗口固定 7200 s（0x2DE01C-0x2DE03C），窗口内指纹不随环境更新。
3. 队列硬上限 128 且未就绪返回 0（0x4CD118），无重试语义，高负载静默丢数据。
4. pe_rep 与 env_chk 共用 `0x28FDB0`，同组检查重复执行并重复上报，闸门仅单对象幂等。
5. 规则与判据分离：`attest_cert_not_white`/`attest_cert_is_black`（0x2ABC04/0x2ABCC0）与 `anti_*` 名单（0x259840）全来自配置。
6. user_tag 分数钳非负（0x29B5A0 尾）使「0 分」与「未知」不可区分；tablet 七开关任一关即退化 `tablet_unknown` 而 `DeviceType` 照发。
