# partF：应用 / 进程 / 黑产类模块（8 个）

对象 `libs\libtersafe.so`（ACE/TSS SDK，AArch64，imagebase 0，strip）。以 `out/strings.tsv`、`allstr.tsv`、`ops.tsv` 的串偏移为锚点，`disasm` 逐块读平坦化代码；地址即文件偏移。

## 0. 注册框架与运行槽

`sub_27FAE4`(0x27FAE4) 为 40 个模块 `new(0x48/0x50/0x60)`→ctor→取名(`sub_4Exxxx(id)`)→`sub_222284(manager,obj,name,W3,W4)`；后者建 0x40 节点（`obj@+0x10`、`name[32]@+0x18`、`W3@+0x38`、`W4@+0x39`），`sub_2222F4` 插入 `manager+8` 链表。W3/W4 是 per-module 字节开关，非槽号；运行槽 = vtable 第 3 项(`+0x10`)。

## 1. 总览表

| 模块 | ctor | 运行槽（vtable/入口） | 职责 |
|---|---|---|---|
| `process` | `sub_293D58`（new 0x48 @0x2800AC） | 0x514F58[2] / `sub_293DA8` | 进程名匹配黑名单，报 `VP_`+8 位哈希 |
| `anti_virapp` | `sub_286F20`（工厂 `sub_286F80`，单例 qword_55F480） | 0x514DF8[2] / `sub_287004` | 反多开/分身，扫 `/data/data`、`.so` |
| `black_app` | `sub_29E460`（new 0x50 @0x27FD84） | 0x5150B8[2] / `sub_29E4B8` | 已装应用比对黑产名单，弹框+上报 |
| `collect_apk` | `sub_2B1DA4`（new 0x50 @0x280254） | 0x5153D8[2] / `sub_2B1DF0` | 采集 APK 元数据/证书，30 天、40 MB 阈值 |
| `anoscan` | `sub_29FAF8`（工厂 `sub_29FA2C`，qword_55F5A0） | 0x515188[2] / `sub_29FCA0` | 扫名字含 `GG` 的修改器，差集证书 MD5 |
| `trusted_scanner` | 工厂 `sub_2BD8E4`（qword_55F6A8，内联构造） | 0x515688[2] / `sub_2BDA10`（扩展槽 0x2BDEE4/0x2BDF3C） | 属性生成设备指纹，校验可信度 |
| `anti_cheat_open_id` | 内联 @0x27FE58（new 0x48） | 0x514D18[2] / `sub_28392C` | openid 一致性检查，失败按 crash 上报 |
| `HistoryOpenID` | 内联 @0x27FFD0（new 0x60） | 0x514CE8[2] / `sub_282B4C` | 维护"包名:应用名"缓存 `tdm_cache.dat` |

## 2. process

- 入口 `sub_293DA8`(0x293DA8)，扫描体 `sub_2941B8`；注册 0x2800C0，id 0x406D，`W3=1,W4=0`(0x2800D8)。
- 开关：`sub_294064` 解 9 字节键 **`9005.hi2`**（站 0x294088），`sub_22DA98(...,1,1)` 默认开。
- 判据：`sub_230BD0(type,&list)` 载名单（同 black_app）→`sub_4DD77C`/`sub_4DD7CC` 枚举进程（`+0`=pid、`+4`=comm）→每节点 `sub_4A47AC` 做 `strstr(进程名,node+0x14)`；上限 0x2710(10000)。
- 上报：名字经 `sub_4A21DC` 哈希，仅 `g[0x398]==0x9C` 用原名，否则 `%08X` 加前缀 **`VP_`**(0x294210)；字段 **`|%d:%s, attr:0X%08X`**(0x293E04)，`sub_4E5F10(0x11)`/`sub_4E5710` 上报。
- 降级：开关关/名单空即返回；异常只打印 `OpenTPHP err:%d`(0x293DDC)。

## 3. anti_virapp

- 入口 `sub_287004`；工厂 `sub_286F80`（qword_55F480）、ctor `sub_286F20`、vtable 0x514DF8；注册 0x27FC34，`W3=1,W4=1`（唯一 W4=1，推断独立线程）。
- 开关：`ava_filt`(0x9906D)→`obj[0x4D]`、`ava_pre_filt`(0x9486C)→`obj[0x4E]`；`simu_vap`(0x9508C)→`0x287A20`；id 0x5A7A→`0x287D6C`；id 0x71F1 总闸；id 0x7C38 取包名 `com.ace.gamesafe4`(0x98973)。
- 判据：`getpid()`→`sub_28751C` 用 **`/proc/%u`**(12413) 计数，<1 返回；`sub_4D4440` 读 `/proc/<pid>` 启动参数，`sub_2DB5C8` 与包名逐字节比对；白名单 `com.tencent.mm`(20794)、`com.tencent.mobileqq`(20811)、`com.google`(20834)（`sub_287594`）；扫 `/proc`、`/data/data/`(8602)、`/lib/`、`.so`、`.apk`（`sub_287664`/`sub_287A20`，串 `anti-virapp-lib` 20998）。
- 多开名单（0x288E70/0x289128/0x289234/0x2892C4/0x2893BC/0x289594）：`com.vmos`/`vm_vap_ext`、`com.vmos2`/`vm_vap2`、`com.vphonegaga.titan`/`vp_vap`、`com.excelliance.dualaid`/`da_vap`、`com.quxing.fenshen`/`qx_vap`、`com.bfire.da.nui`/`mc_vap`。
- 上报：`!vap_1:%s`(0x288434)、**`!vap_3:%s:%s`**(0x288BE0)、`vpp_crash`(29506)、`vap,gamestick`(21127，配 `com.tencent.gamestick` 20847)、`vap_2.5`(21396)、`mpshk`/`size_err`；收尾 `mem_ava`(58736)+`va:%d`(58746)；双检 `/data/data/%s/files/adt.s3.t`(0x288B04) 后才报。
- 降级：多道早退（0x71F1、`sub_294B30`、`sub_297A78`、白名单、无 `/proc` 权限），`obj[0x48]` 0→4。

## 4. black_app

- 入口 `sub_29E4B8`；ctor `sub_29E460`，vtable 0x5150B8；注册 0x27FD98，id 0xC1E5。先 `sub_4C7158()[+0x104]` 与 `this+0x4C` 比较去重（代数号），再置 `obj[0x48]=1`、`sub_230618(manager,&list)`、逐项 `sub_29E668`。
- 名单：`sub_230BD0`(0x230BD0) 用配置 id **0x2C9**（`sub_4E7348`→`sub_23088C`）；失败/空回退 `sub_230C78`(0x230C78) 内置 **64 条** = 62 包名/关键字 + 后缀 **`armbin`**(0x230DF8)、**`binarm`**(0x230E20)。节点 0x60：`+0x14` 名、`+0x58` 类型掩码。例：`cn.com.opda.gamemaster`(0x230D4C)、`com.cih.game_cih`(0x230E40)、`com.cyjh.gundam`(0x230FC0)、`com.cyjh.mobileanjian`(0x230FEC)、`com.dimonvideo.luckypatcher`、`com.keramidas.TitaniumBackup`、`net.aisence.Touchelper`、`com.github.shadowsocks`(0x231590)、`bin.mt.plus`(0x231644)。
- 判据：`sub_29E668` 取 `item[0]`=包名/路径、`item[0x28]`=类型；`sub_4A46C0` strcmp；子表项要求 `strlen(node+0x14)==0x20` 且 `sub_4A21DC` 哈希一致；`sub_4DEFD0` 白名单过滤。进程侧 `sub_4E2F30(name,mask)` 先 `node[0x58]&mask` 再 `strstr`，上限 10000，被 `gc_exists`(0x4E30AC)、`file_crc_eq2`(0x4E30B8) 复用。
- 上报/处置：`sub_29F060` 用 **`ano,drop:%s:%s`**(0x94886/15，站 0x29F0A0)，路径 `'@'`(0x40) 置换；弹框 `sub_1EE9F4`(0xC)、`sub_215BEC`/`sub_216078`；盒子 **`ano_box`**(0x734E) 经 `sub_22DA98(manager,"ano_box",flag,1)`；首次命中记 `obj[0x10]`=名、`[0x18]`=路径、`[0x20]`=类型、`[0x24]=1`，发事件 0x7C0D，再 `sub_46A5FC`/`sub_472AE8`/`sub_46CD24`；UI `Malware found on your phone. Please uninstall it before entering the game.(`(0x29F268)。
- 宿主命令：未 strip 的 `tss_sdk_ioctl`(0x1BCF84，88 项跳转表) 用 `strcmp` 匹配 **`CloseAntiBlackModule`**(0x1BDBB4)、**`NeedRequestApkList`**(0x1BE080)；0x1BE040 附近命中 `sub_4E5F10(0x44)` 报 `!cdc`(0x9684A) 并置 `manager[0x3CC]=1`。
- 降级：名单空 → `sub_4C99C4` 后返回 0；无应用管理器直接返回。

## 5. collect_apk

- 入口 `sub_2B1DF0`，`LDRB [X0,#0x48]` 一次性门闩；ctor `sub_2B1DA4`，vtable 0x5153D8；注册 0x280268，`W3=(sub_2399A8()&1)`。子阶段 `0x2B1E30`(AllApk)→`0x2B1F30`(阈值)→`0x2B223C`(i.9005)→`0x2B237C`(外置存储)。
- 开关：`sub_22DA98(manager,"collect_apk",0,1)`；子键 **`apk_time_diff`**、**`9003_cert_md5`**、**`9003_unsrc`** 各 `(...,1,1)`；**`i.9005`** 默认开；白名单 `ignore_white`(0x2B23AC)。
- 阈值：id **0x73F2**（`sub_4EC0B0`）默认 `0x278D00`(2592000 s=30 天)，非空 `atoi*0x15180`；id **0x7402**（`sub_4ED2AC`）默认 `0x2800000`(40 MB)，非空 `atoi<<20`；条件 `now-mtime>diff || size<max || crc<0`（0x2B213C–0x2B2164）。
- 上报：0x4CBC24 **`apk_name=%s|app_name=%s|app_ver=%s|sdk_ver=%s|app_name_b64=%s`**(32485)；0x4CBDB4 **`cert_md5=%s|apk_hash_1=0x%08x|apk_hash_2=0x%08x|txt_seg_crc=0x%08x`**(32585)；0x4CBB2C **`root=%d|x86=%d|apk_cnt=%d|adb=%d|machine=%s|sys_ver=%s|root_record=%d`**(32413)；名单项 `|%s:%s, attr:0X%08X`(0x9457E)。
- 扫描面：`/sdcard/Android/data`(0x2B24A4)+`%s/%s`(0x1D4A98)；`sub_4B841C` 解析 APK；`0x2B223C` 对黑名单用 `sub_2DC1D4` 判安装、`sub_2DC67C` 取版本、`node[0x58]` 掩码。
- 降级：开关关/无列表即返回；门闩保证只跑一次。

## 6. anoscan

- 入口 `sub_29FCA0`；工厂 `sub_29FA2C`（qword_55F5A0+pthread_once），ctor `sub_29FAF8`，vtable 0x515188；注册 0x27FCA8(id 0x1E5)。
- 开关：`sub_2A3CE4(0x965A0,7)` 解出 **`ano_fc`**(615840，站 0x29FCC4)；`sub_22DA98(manager,"ano_fc",0,1)`；特例 `manager[0x398]==0x9C` **跳过开关强制运行**。
- 判据：`sub_29FE80` 解 3 字节串 @0x973A2/@0x99091 得 **`GG`**/**`gg`**(619426/626833)，枚举应用记录（0x1F8 字节，名@+0x10、标志@+0x110），`strstr` 命中置 0x1000000；`sub_29FFC8` 取基线 **`ano2`**(615848)；`sub_2A005C` 做差集并用 **`ano_sys`**(601174)、**`ano_cfilt`**(602273) 过滤；`sub_2A0494` 算 **`ano_cert_md5`**(625792)。
- 上报/落盘：**`ano_box_%08x`**(0x2A0F10)+**`tss_ano.dat`**(0x22E798)；**`anocrash_all`**(29528)；`ano_hid_pat`(599157)、`ano_ignore_detect`(625806)；列表元素按 0x290/0x170/0x218 由 `sub_475CC8` 释放。

## 7. trusted_scanner

- 入口 `sub_2BDA10`；工厂 `sub_2BD8E4`（qword_55F6A8），vtable1 0x515688、vtable2 0x5156C8（多继承）；注册 0x27FEB8(id 0x79AE)。
- 开关：**`att_dev_flash`**(id 0xBE25，48677，站 0x2BDAE8；扩展槽 0x2BDEE4/0x2BDF3C 同引用)。
- 判据：`obj[0x28]` 有结果→`[0x51]=1` 返回；`sub_2DB8AC()&1` 早退；`sub_2AAA40()[+0x4A]` 取标志；`sub_2BDB2C(buf,0x40)` 生成指纹（`sub_4E6B78(0xBEA6)` 属性名+`sub_4CEE28` 读值+`sub_4EA6E0(0xBEDB)` 比对串）；`sub_4A54DC(dst,0x40,"a:%d;p:%s",flag,buf)`(613850)。
- 上报：`sub_1ECCB8(2,buf)`+`sub_4CC660(global,1,buf)`；开 `att_dev_flash` 进 `0x2BDE18`；收尾 `sub_2BDE78` 报 **`mem_dts`**(58700)/**`ul:%d`**(58710)。
- 降级：任一早退即不置位、不采集。

## 8. anti_cheat_open_id

- 入口 `sub_28392C`（`sub_282xxx` 跳转表 case 6）；内联 ctor 0x27FE58，vtable 0x514D18；注册 0x27FE90(id 0x7BB3)，`W3=BIC(1,sub_239BC8())`。
- 判据：`sub_283BB0(0x9788F,0xE)` 两次 XOR（密钥 0xE5 递增）得 **`cheat_open_id`**(14 字节含 NUL)；`sub_2DAD4C()` 取 manager，空则退出；`sub_23A114()` false 退出；`sub_23976C(manager,buf,0x40)` 取 openid，case2 用 `[X19+0x78]*6` 索引 `sub_1F524C` 与 `strlen` 比对；最多 5 轮，每轮 `sub_4B847C(1)` 睡 1 秒。
- 上报：不一致/失败走 case4：`sub_46A5FC`+`sub_4EB330(0x7382)`+`sub_46CD24(obj,明文,明文,事件,1)`，事件 **`cheat_openid_crash`**(0x285B6C，29570)。
- 降级：无 manager 或状态 false 返回；两路明文均为键名。

## 9. HistoryOpenID

- 入口 `sub_282B4C`；内联 ctor 0x27FFD0(new 0x60)，vtable 0x514CE8；注册 0x280010(id 0xC320)，`W3=BIC(1,sub_239BC8())`。
- 判据：`[X0+0x48]` 门闩；`sub_2DB600` 包名、`sub_2DB25C` 应用名任一空即返回；`sub_282BCC` 进 10 项跳转表(`jpt_282C34`@0x5324D0)；`sub_2832C0` 自旋等 `sub_1F524C`；按 `[obj+0x58]` 分支，case4 用 `sub_4E4B2C(buf,0x400)` 读 **`tdm_cache.dat`**(0x4E4B44) 交 `sub_283320`（魔数 **0x20230608**，坏项 `unlink`(0x2834BC)，同名去重，最多 0x10 条）。
- 上报：`sub_2837DC` 逐条 `sub_4ECBF0(0x30CC)` 取键、`sub_4E9F04(0xC320)`="**HistoryOpenID**"、`sub_4A54DC(buf,0x40,"%s:%s",key,val)`(0x1EDFD8，12492)→`sub_1F0148(buf,0,0)` 落盘/上报。
- 降级：包名/应用名缺失即返回；缓存损坏则删除重建。

## 10. 小结：证据强度与设计缺陷

证据：`process`、`black_app`、`collect_apk`、`anti_virapp` 高（名单/常量/调用链/上报格式齐备）；`anoscan`、`trusted_scanner`、`anti_cheat_open_id` 中（部分分支靠推断）；`HistoryOpenID` 最低（无上报串，状态机为推断）。

设计缺陷（只描述）：

1. 单次门闩：四模块用 `obj[0x48]` 一次性置位，运行期新增应用/换名单不重扫；`black_app` 靠 `[+0x104]` 代数号缓解。
2. 子串匹配误报大：`0x4E2F30`、`sub_293DA8` 用 `strstr`，短关键字 `binarm`/`armbin` 会误命中；`[0x58]&mask` 过滤弱。
3. 名单明文硬编码：64 条在 `.rodata`(0x230C78 起) 明文、无校验，改包名即绕过。
4. 弱脱敏：进程名默认只报 `VP_`+32 位哈希(0x294210)，可字典反推；是否用原名由 `g[0x398]` 决定。
5. 拼接无转义：`|%d:%s, attr:0X%08X`、`apk_name=%s|...` 直接拼名字，含 `|` 即破坏解析。
6. 默认开启：多处 `(...,1,1)` 默认 1（`ava_pre_filt`、`9003_*`、`i.9005`、`9005.hi2`），云控缺失仍全量采集。
7. 阈值过宽：`collect_apk` 默认 30 天/40 MB，且遍历 `/sdcard/Android/data`，长期留档外置 APK。
8. 多开检测靠固定包名：六组硬编码，改名即失效。
9. 降级静默：`trusted_scanner`、`anti_cheat_open_id` 早退无日志、无补偿上报。
10. 缓存无完整性：`tdm_cache.dat` 仅 4 字节魔数、无签名，可伪造。
