# 王者荣耀设备标记机制深度分析（ACE / QIMEI / TDM 三通道）

本文是对 `docs/qimei.md`、`docs/partD_devinfo.md`、`docs/main.md` 的延续与校正。所有地址默认指 `libtersafe.so`（5,598,144 B，MD5 E06344E0B5F6B09D13820C625FA3A123）或 `libqimei.so`（539,416 B，MD5 62BB50C92D64EB5160ECCE4CDFED63E5），除非另行注明。样本版本：王者荣耀 12.1.1.1，versionCode 1201010103。

---

## 1. 结论摘要

1. 游戏进程里同时存在三条独立上报通道，各自维护一份设备画像，互相之间没有代码级耦合，只在数据面（同一个 QIMEI）交汇：

| 通道 | 库 | 上报目的地 | 设备画像规模 | 判定者 |
| --- | --- | --- | --- | --- |
| ACE | libtersafe.so | `*.cschannel.anticheatexpert.com`（裸 TCP 443） | 17 槽 | 服务端 |
| QIMEI | libqimei.so | `https://snowflake.qq.com/ola/v2` | 12 维 + 注册 JSON 16 键 | 服务端（下发 q16/q36） |
| TDM | libTDataMaster.so | 运营配置的 TDM 路由 | 26 字段 | 运营侧 |

2. 真正承担"设备主键"职责的是 QIMEI 的 q16 / q36。它由服务端根据注册 JSON 计算并下发，客户端只做缓存（`A3` / `A153`），本地没有任何生成逻辑可以复现它。
3. ACE 的 17 槽画像是"硬件画像"：品牌、型号、ABI、CPU、内核、文件系统、inode、传感器、摄像头、电池、音量、USB、ADB、网络、应用列表、SDK 版本。它不直接构造主键，而是作为 q16 的旁证与封号证据。
4. ACE 还额外组装一个 fake token：`x:<xid>;q:<q16>;Q:<q36>;o:<oaid>`，再包上 `bt:<boot_id>;bd:<brand>`。这一串是 ACE 唯一直接引用 QIMEI 的位置，容器名是 `Fake_Token_TDM_info`（idx 51374），四个子键为 `xid`(51396)、`QiMaM`(51402)、`QIMEI36`(51410)、`OsEz`(51420)，组装函数 `0x2CCD20`。

   > **校正（12.1.1.1 复核）**：原文"来源是 TDM 写入的"缺少证据。`Fake_Token_TDM_info`、`QiMaM`、`OsEz` 三个名字在 12 个 `.so` 与 6 个 `.dex` 的明文中均为 **0 命中**，只存在于 libtersafe 的加密串表；`libTDataMaster.so` 的设备缓存只有 `tdm_cache.%d.dat`（文件偏移 `0x2E8524`），没有这三个键。实际写入点尚未定位（CFF 平坦化 + 间接调用）。另：槽 17 的取值顺序是 `ft_oaid` → `OsEz` → `fake_token_androidid`，`"Unknown"`(idx 34159) 为 OAID 的无效值哨兵，详见 `docs/devinfo_layers.md` §6.2/§6.3。
5. 刷机 / 恢复出厂 / 改机所能清除的只有本地缓存（SP + files 目录）；服务端仍然持有 `QIMEI ↔ openid ↔ 历史指纹` 三元组，任何一次"指纹漂移但 q16 不变"或"q16 变化但指纹全同"都会成为风控信号。
6. q16 的本地落盘形式是 16 字节二进制（base64 编码后写入 `files/com.tencent.qimei.sdk.QimeiSDK`），真机取出的 32 位 hex 是这 16 字节的十六进制展开。

---

## 2. ACE：17 槽设备画像

### 2.1 采集总控

设备信息采集总控在 `0x2C9D78`：`calloc(1, 0x400)` 分配 1024 B 缓冲区，`0x2CD090` 复位链表头，然后按固定顺序调用各采集器。

采集器统一签名 `f(ErrKey, env, buf, 1024, ErrKey)`，返回 0 表示失败。调用模板：

```
v23 = sub_2DB440(v22, v7, 1024);   // 采集
if (v23) v24 = v23; else v24 = v21; // 失败时用默认值
sub_2CA274(v23, a2, 1, v24);        // 入槽
```

最后一步 `0x2CA274` 做两件事：

- 把值里的 `=`（0x3D）和 `;`（0x3B）各加 29，变成 `Z` 和 `X`。这是防注入：上报串用 `;` 分隔、`=` 赋值，如果不转义，被采集到的进程名/路径就能伪造后续字段。
- 把 `{int slot; std::string value}` 挂到链表尾部。

### 2.2 槽位表

槽号 1–17，其中 7 空缺（历史遗留或保留位）。

| 槽 | ErrKey | 数据源 | 采集函数 | 输出格式 |
| --- | --- | --- | --- | --- |
| 1 | BrandErr | JNI `Build.BRAND` | 0x2429E0 | 原串 |
| 2 | ModelErr | JNI `Build.MODEL` | 0x249D68 | 原串 |
| 3 | ERR | JNI `Build.VERSION.SDK_INT` | 0x240508 | 十进制 |
| 4 | BatteryErr | `ACTION_BATTERY_CHANGED` | 0x2CA404 | `%s:%d`（technology:maxChargingCurrent） |
| 5 | GPUErr | `GLES10.glGetString` | 0x2CABF4 | GLES 版本串 |
| 6 | SysMaxVolumesErr | `AudioManager.getStreamMaxVolume` | 0x2CB06C | 十进制 |
| 8 | CameraErr | Camera2 特性 | 0x2CB31C | `%d:%s` |
| 9 | SensorErr | `SensorManager.getSensorList(TYPE_ALL)` | 0x2CBBFC | `%d:%d:%s` |
| 10 | KernelErr | `uname()` | 0x2CC02C | `%s,%s,%s` |
| 11 | FingerPrintErr | `Build.FINGERPRINT` | — | 原串 |
| 12 | BaseBandErr | `Build.getRadioVersion()` | — | 原串 |
| 13 | LibcInodeErr | `stat("/system/lib/libc.so").st_ino` | 0x2CC134 | `%d` |
| 14 | FileSystemErr | `statfs("/vendor/")` | 0x2CC1F0 | `%u:%u:%08x:%08x` |
| 15 | FileFirstTimeErr | 文件首见时间 | 0x2CC2F8 | `%llu` |
| 16 | AppInfoErr | 已装应用遍历 | 0x2CC358 | 包名哈希 |
| 17 | AndroidIdErr | `Settings.Secure.ANDROID_ID` | 0x2496E4 | 先哈希再 `%x` |

补充说明：

- **槽 3** 的 ErrKey 字面上就是 `ERR`（字符串表 off 49995），实际内容是 SDK_INT，属于命名复用。
- **槽 16** 的采集函数 `0x2CC358` 遍历已安装应用，把包名哈希与两个常量 `394722921`、`875655884` 比较，用于识别特定目标应用（常见于群控/多开环境）。
- **槽 17** 是全表唯一做哈希的槽：`0x2C8CBC` 在拼装时先调 `sub_489248`（CRC32）再以 `%x` 输出，所以 AndroidID 不会明文外发。这也是为什么抓包看不到 16 位 hex 的 AndroidID。
- 上层还有几个"聚合型"字段，不占槽位，但和槽一起上报：`IsRoot`、`IsEmu`、`IsVAP`、`OPC`、`CertHash`、`secc`、`tss_main`。它们的构造器分别在 `0x23DB04`、`0x23DF18`、`0x23DFAC`、`0x23E040`、`0x23E0C0`、`0x290270`、`0x2DF604`。

### 2.3 拼装与字段号

槽拼装在 `0x2C8CBC`：

```
for slot in list:
    snprintf(buf, 256, "%d=%s;", slot.id, slot.value)   // off 50159
```

槽 17 走单独分支（`0x2C8D7C`–`0x2C8DB0`），先哈希再按 `"%x"`（off 50396）输出。

拼好的串再经 `0x49F018` / `0x49F170` 追加进 protobuf 风格的流（wire type 2，长度前缀）。最终字段号由 `main.md` 6.2 的字段构造器表给出，与设备信息相关的主要是：

- 字段 10：`root=%d|x86=%d|apk_cnt=%d|adb=%d|machine=%s|sys_ver=%s|root_record=%d`
- 字段 11：`name=%s|size=%d|crc=0x%08x|root=%d`
- 字段 12：`name=%s|feature=%s|size=%d|mtime=%d|cert_md5_crc=0x%08x`
- 字段 17：dev_info 整串（17 槽）

字段 17 就是本节这条链的输出，明文形如 `1=HUAWEI;2=HMA-AL00;3=29;4=Li-ion:1500;...;17=deadbeef;`。

### 2.4 采集细节

**Build 字段**走 JNI，不用 `getprop`：

```
0x2CF61C -> 0x2CF3BC  FindClass
0x2CF488              GetStaticFieldID
'I'   -> 0x2CF4B0     GetStaticIntField
'L'/'[' -> 0x2CF488   GetStaticObjectField
```

native 只取五项：`BRAND`、`MODEL`、`HARDWARE`、`CPU_ABI`、`CPU_ABI2`。**没有** SERIAL、DEVICE、PRODUCT、BOARD、HOST、TAGS、TIME、INCREMENTAL、DISPLAY、MANUFACTURER。这一点很关键：ACE 不碰 SERIAL，因为从 Android 10 起普通应用拿不到，取它反而暴露 hook。

HARDWARE/ABI 合并成 `"%s,%s"`（`0x241384`），结果缓存在 `0x55F1F0`；BRAND、MODEL 分别缓存在 `0x55F258`、`0x55F250`。读缓存前会检查 `ctx+956` 的位掩码 `0x200` / `0x400` / `0x8`，未置位时回退 `getprop`（`0x4CEE28`）。位掩码的含义是"该字段已通过 JNI 成功取过"，失败后永久走 getprop 兜底。

**CPU** 在 `0x242490` 读 `/proc/cpuinfo`，解析三个键：`Processor`（`0x242740`）、`Hardware`（`0x2427B0`）、`model name`（`0x2427F8`），缓存到 `0x55F220`。

**文件系统** `0x2CC1F0` 对 `/vendor/` 调 `statfs`，输出 `"%u:%u:%08x:%08x"`（off 50220）：块大小、总块数、可用块数、空闲块数。带前缀的变体在 off 50238。这个值能区分"官方分区布局"和"改过分区的定制 ROM"。

**inode 指纹** `0x2CC134` 对 `/system/lib/libc.so` 取 `st_ino`，只输出十进制 inode 号。同一版本系统镜像的 inode 号是确定的，所以：

- 换机但同 ROM → inode 相同
- 同机刷不同 ROM → inode 变化
- 改了系统分区（Magisk 模块、debloat）→ inode 变化

这就是 `qimei.md` 第八节说的"inode 指纹历史"，也是刷机后被识别的主因之一。

**文件首见时间** `0x2CC2F8` 输出 `"%llu"`（off 50259），记录某个路径第一次被观测到的时间戳，用于判断"设备是否刚重置"。

**摄像头** `0x2CB31C` 取四个特性拼 `"%d:%s"`：`SENSOR_INFO_WHITE_LEVEL`、`CONTROL_AE_COMPENSATION_RANGE`、`SENSOR_INFO_MAX_FRAME_DURATION`、`SENSOR_INFO_PHYSICAL_SIZE`。模拟器/云手机通常返回空或 0。

**传感器** `0x2CBBFC` 用 `getSensorList(TYPE_ALL)`，拼 `"%d:%d:%s"`。同一个函数里出现了 `fake_token_sensor`（off 50024），说明传感器列表也是 fake token 的候选来源之一。

**USB / ADB**：`0x2CD864` 遍历 `/sys/bus/usb/devices`；`0x2CDCEC` 读 `service.adb.tcp.port` 判断 `wifi_adb`。

**网络**：`0x24F8A4` 直接 `popen("ip route get 8.8.8.8 2>&1")`，用 `sscanf` 抠出网关地址。不是读 `/proc/net/route`，因为后者会被改机工具伪造。

**seccomp**：`0x290270` 输出 `"secc: %d;%d;%d;%d;%d"`（off 15390），五个值来自 `prctl(PR_GET_SECCOMP)` 与 `/proc/self/status` 的 `Seccomp` 字段组合，用于识别"非标准沙箱/容器"。

**系统属性枚举**：`libtersafe.so` 的导入表里同时有 `__system_property_get`、`__system_property_find_nth`、`__system_property_read`。前两个的组合意味着 ACE 不只按名字读属性，还会**遍历全部系统属性**（`find_nth` 从 0 递增取）并与白名单比对。改机框架、云手机、定制 ROM 往往会在 `ro.*`、`persist.*`、`vendor.*` 里留下非标准键，这一条是比读单个属性更强的检测面。`libqimei.so` 只导入 `__system_property_get`，没有 `find_nth`，两者能力不对等。

### 2.5 fake token

fake token 是 ACE 设备标记里唯一直接引用 QIMEI 的部分。完整链路：

```
0x2CC6C4  取 17 槽的 fake token 值
0x2CCA7C  虚表 +0x60 取 OAID（256 B）
0x2CCD20  拼 "x:%s;q:%s;Q:%s;o:%s"
0x2CCE84  读 /proc/sys/kernel/random/boot_id
0x2CCF54  包 "td:%s;bt:%s;bd:%s"
0x2C9208  写入 0x200 缓冲，交给 0x1F3644
```

逐段说明：

**取值优先级**（`0x2CC6C4`）：

1. 先通过 `0x2CCA7C` 的虚表 `+0x60` 取 `ft_oaid`（off 58581）。非空且不等于 `"Unknown"`（off 34159）时输出 OAID。
2. 否则回落到 `fake_token_androidid`（off 50001）。
3. 若两者都没有，用空串。

**四元组**（`0x2CCD20`）：从 TDM 写入的 `Fake_Token_TDM_info`（off 51374）里取四个字段：

- `x` = xid
- `q` = QIMEI（q16）
- `Q` = QIMEI36
- `o` = OAID

格式串 `"x:%s;q:%s;Q:%s;o:%s"`（off 50303）。

**boot_id 与 brand**（`0x2CCF54`）：

- `bt` = `/proc/sys/kernel/random/boot_id` 的内容，每��开机都变，所以它只能做"会话级"关联。
- `bd` = Brand（`0x2DB440`）。

两个格式串并存：`"%s;bt:%s;bd:%s;"`（off 50325）与 `"td:%s;bt:%s;bd:%s"`（off 50343）。前者用于 17 槽，后者用于 `Fake_Token_TDM_info` 本身。从 `0x2CCF54` 的尾部可以看到它连续调了两次 `0x4A54DC`（`snprintf` 包装），第一次用 `0x4E80B8(0xc495)` 解出的格式串，第二次用 `0x4E94E8(0xc4a7)`，说明两条串都会生成，分别写入不同的缓冲。

**消费点**：`0x2CCF54` 的唯一调用者是 `0x2C9208`，其上下文是：

```
0x2C91E0  mov x3, x0
0x2C91E4  mov w4, #1
0x2C91E8  bl  0x2CC358        ; AppInfo 采集
0x2C91F0  add x0, sp, #0x10
0x2C91F4  mov w1, wzr
0x2C91F8  mov w2, #0x200
0x2C91FC  bl  0x50E0B0        ; memset
0x2C9200  add x1, sp, #0x10
0x2C9204  mov w2, #0x200
0x2C9208  bl  0x2CCF54        ; fake token -> buf
0x2C920C  and w0, w21, #1
...
0x2C9230  bl  0x1F3644        ; 构造事件对象
```

`0x1F3644` 的参数是 `(w0=w21&1, w1=w22, x2=x23, x3=x24, w4=w25, x5=x20, x6=x26, [sp]=x19)`，函数内部清零 0x658 字节结构体，填入常量与两个 0x40 的 `strncpy`，最后 `snprintf` 到 0x28C 偏移处（格式串 off `0xc4d1`），再 `0x1F4878` 入队。这就是 ACE 的"检测任务"对象：每个任务带一段上下文（品牌、fake token、app 信息）和一条格式串。

**云控开关**：`0x2C89D4` 处理 `force_fake_token`（off 46601），分发表在 `0x5168C8`，受 `ctx+953` 控制。也就是说 fake token 的强度是可远程调的：可以强制只上报原生值，也可以强制伪造值来钓鱼。

**17 槽里的 fake token**：`0x2CA214` 是 `0x2CC6C4` 的唯一调用者：

```
0x2CA1E0  mov x3, x0
0x2CA1E4  mov w4, wzr
0x2CA1E8  bl  0x2CC358        ; AppInfo
0x2CA1FC  mov w0, #0xCF06
0x2CA200  bl  0x4ED2AC        ; 解串
0x2CA208  mov x0, x20
0x2CA20C  mov x1, x21
0x2CA210  mov w2, #0x400
0x2CA214  bl  0x2CC6C4        ; fake token -> 1024 B
0x2CA218  mov x1, x19
0x2CA21C  mov w2, #0x11
0x2CA224  bl  0x2CA274        ; 槽 17
```

所以槽 17 的实际内容是 fake token，而 `partD_devinfo.md` 里把它记成 `AndroidIdErr` 是因为该槽的 ErrKey 字符串就是 AndroidID 相关（off 50001 的 `fake_token_androidid`），属于命名误导。

---

## 3. QIMEI：设备主键

### 3.1 类结构

`com.tencent.qimei` 包下的关键类：

| 类 | 职责 |
| --- | --- |
| `sdk.QimeiSDK` | 对外单例入口，`getInstance(appKey)` |
| `sdk.Qimei` | 数据对象，`f15474b`=q16、`f15475c`=q36 |
| `ai.e` | 单例实现，持有 appKey、监听列表、userId map |
| `ai.a` | 从 SharedPreferences 读缓存（`A3`/`A153`） |
| `ai.b` | 生命周期：判定是否需要重新注册 |
| `ai.c` | 注册 JSON 与内嵌 JSON 的构造 |
| `an.a` | Qimei 实例管理 |
| `au.a` | 组装 12 元素 `String[]` |
| `ae.a` | 12 个维度的统一取用入口 |
| `u.c` | 设备环境缓存（android_id、OAID、OZ、MODEL、kernel…） |
| `r.a` | 25 个属性名/键的 Base64+反转表 |
| `uin.U` | native 方法声明与包装 |

### 3.2 native 入口

`libqimei.so` 的 `JNI_OnLoad` 在 `0xa108`，注册表在 `.data` 的 `0x84058`，15 项，每项 24 字节 `{name, sig, fn}`：

| # | 名称 | 签名 | 地址 |
| --- | --- | --- | --- |
| 0 | r | `(ZIILjava/lang/String;I[Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;` | 0x256E8 |
| 1 | d | `(Ljava/lang/String;)[B` | 0x2A738 |
| 2 | e | `(Ljava/lang/String;Ljava/lang/String;)B` | 0x2A2A0 |
| 3 | n | `(Landroid/content/Context;Ljava/lang/String;[Ljava/lang/Object;)V` | 0x2ACB4 |
| 4 | m | `(I)Ljava/lang/String;` | 0x255E8 |
| 5 | z | `(Landroid/content/Context;)Ljava/lang/String;` | 0x3A818 |
| 6 | z2 | `(Landroid/content/Context;I)Ljava/lang/String;` | 0x3A8C8 |
| 7 | o | `()Ljava/lang/String;` | 0x2B920 |
| 8 | x | `(Ljava/lang/String;)Ljava/lang/String;` | 0x2B468 |
| 9 | u | `()Ljava/lang/String;` | 0x2B3BC |
| 10 | a | `(I[B[B[B)[B` | 0x2AD08 |
| 11 | p | `()Ljava/lang/String;` | 0x2B564 |
| 12 | b | `()Z` | 0x2B908 |
| 13 | r4 | `([BI[BI)[B` | 0x2B104 |
| 14 | w | `(Ljava/lang/String;)Z` | 0x475E8 |

`z` / `z2` / `o` 都是 `0x2B9D4` 的薄包装：`z` 传 `mode=0`，`z2` 传 `mode=3`，`o` 传 `mode=1`，结果通过 `0x22460`（`NewStringUTF` 包装）转成 jstring。

`x(String)` 是"按名字取设备值"的通用 getter。`0x2B468` 的流程是 `GetStringUTFChars` → `0x42110` → 释放 → `NewStringUTF`。`0x42110` 本身没有任何字符串引用，它通过 `.bss` 的 `0x85488` / `0x85490` 两个函数指针间接调用：

- `0x4227C`：`ldr x8,[0x85488]; ldr x0,[sp]; blr x8`，参数是 key，返回句柄。
- `0x42224`：`ldr x8,[0x85490]; ldur x0,[x29-8]; mov x1,xzr; ldr x2,[sp+0x10]; blr x8`，三参形态 `(pi, name=NULL, value)`。

这正是 `__system_property_find` + `__system_property_read` 的组合，所以 `0x42110` 就是 `getprop` 的平坦化封装。

`r.a` 的 25 条键里，12–18 全是 `ro.product.*` / `ro.build.host`，正好对应注册 JSON 的 `bod`/`brd`/`dv`/`firstLevel`/`manufact`/`name`/`package` 七个字段。

### 3.3 12 维 UserInfoType

`com.tencent.qimei.shell.sdkinfo.UserInfoType` 定义 12 个维度，索引直接用于 `r()` 的 `String[]`：

| 值 | 名称 | 内容 |
| --- | --- | --- |
| 0 | TYPE_APP_KEY | appKey |
| 1 | TYPE_NET_WORK_TYPE | 网络类型 |
| 2 | TYPE_SDK_VERSION | `2.1.2.126` |
| 3 | TYPE_APP_VERSION | 应用版本 |
| 4 | TYPE_CHANNEL_ID | 渠道 |
| 5 | TYPE_USER_ID_PARAM | 用户 ID 参数 |
| 6 | TYPE_OS_VERSION | `Android <RELEASE>,level <SDK>` |
| 7 | TYPE_Q16 | q16 |
| 8 | TYPE_Q36 | q36 |
| 9 | TYPE_MODEL | `Build.MODEL` |
| 10 | TYPE_PRE_AUDIT_STATE | 预审状态 `1`/`0` |
| 11 | TYPE_OZ | `z(context)` 的结果 |

`au.a.a()` 负责组装这个数组：先取当前 Qimei 填 [7]/[8]，再填 [10] 预审状态、[11] OZ，最后一次性填 [2]、[0]、[1]、[3]、[4]、[5]、[6]、[9]。

### 3.4 注册 JSON

`ai.c.a(String appKey)` 构造的注册 JSON，键就是协议字段号：

| 键 | 内容 |
| --- | --- |
| 1 | `ap.a(appKey).a()` |
| 2 | targetSdkVersion |
| 3 | `ap.a.h()`（策略控制） |
| 4 | `U.a(r.a.a(13))` = `ro.product.brand` |
| 5 | 空串 |
| 6 | 设备形态（`u.c.d()`：TV/WATCH/CAR/Pad/Phone） |
| 7 | `ae.g`（策略 o 时） |
| 8 | `ae.h`（策略 p 时） |
| 9 | `aVarA.a()` |
| 10 | `ae.i`（策略 q 时） |
| 11 | `ae.j`（策略 r 时） |
| 12 | `ap.a.c()?.b()` |
| 13 | `cVar.d()` |
| 14 | `c_f_uptimes`（历史启动时长） |
| 15 | `c_f_bootids`（历史 boot_id 列表） |
| 16 | 内嵌 JSON |

键名在源码里用 `com.tencent.connect.common.Constants` 的 `VIA_*` 常量，属于混淆残留。

内嵌 JSON（键 16）的字段：

| 字段 | 来源 |
| --- | --- |
| harmony | 反射 `com.huawei.system.BuildEx.getOsBrand` 是否为 `harmony` |
| clone | `Process.myUid() / 1000 != 0`（多开/分身） |
| containe | `u.c.c()`：容器检测串 |
| oz | `aVar.e()` |
| oz2 | 策略 u 时 `ae.k.a(10, ae.b)` |
| oo | 策略 v 时 `ae.k().a(9, ae.c)`，即 native `o()` |
| kelong | `ak.a.a()`（"客隆"检测） |
| ip | 本机 IPv4 |
| multiUser | `f.a.c(ctx)` |
| bod / brd / dv / firstLevel / manufact / name / package | `U.a(r.a.a(12..18))`，即 `ro.product.board` / `ro.product.brand` / `ro.product.device` / `ro.product.first_api_level` / `ro.product.manufacturer` / `ro.product.name` / `ro.build.host` |
| kernel | `U.c()`，即 native `u()` |
| pre | 应用 flags & 1 → 2；`getFilesDir` 以 `/system` 开头 → 1 |
| av / ch | 应用版本 / 渠道 |

`u.c.c()` 的容器检测值得单独记：扫描 `/` 下文件名形如 `init.*.environment.rc` 的文件取中间段，得到 `1#<name>`；再读 `/proc/self/mountinfo` 是否含 `/lxc_container/`，否则读 `/proc/self/cpuset` 是否含 `/docker` 且 mountinfo 含该 cpuset，得到 `2#lxc` 或 `2#docker`；两段拼接。这是给"云手机/容器"用的指纹。

### 3.5 请求与响应

native `r(...)` 不是"生成 QIMEI"，而是"发网络请求"。Java 侧调用形态：

```java
U.a(str, CMD.b(), requestJson, CMD.a())
```

`CMD` 是 `com.tencent.qimei.foundation.net.protocol.CMD` 枚举（APM / BEAT 等），`b()` 是命令号，`a()` 是类型。返回值是响应 JSON。

响应里的 `A3` → q16，`A153` → q36，由 `ai.a` 解析后写入 `Qimei.f15474b` / `f15475c`，同时由 `ab.e` 写进 SharedPreferences。

`ai.b.a()` 的生命周期：

1. 先 `an.a.e(appKey)` 取实例。
2. 若 `ak.a.a(appKey).a()` 为真（策略要求重置），把旧 q16/q36 交给 `ak.a.f15165e`，新建空 Qimei，调用 `U.a(str, "")`（即 native `e(str, "")`）拿到 `bA`，再 `f.a.a(str, bA)`，并清空 SP。
3. 否则从 SP 读（`ai.a.a`），为空则 `new Qimei()`。

### 3.6 本地落盘

| 位置 | 内容 |
| --- | --- |
| `files/com.tencent.qimei.sdk.QimeiSDK` | base64(16 B)，即 q16 的二进制形式 |
| `shared_prefs/QV1com.tencent.qimei.sdk.QimeiSDK108eeee72235004c.xml` | `tt`（32 hex）、`s_d`（加密种子）、`tn`（crypt=1）、appKey 1104466820、`t_s_t`、`a_i_t`、`is_first` |
| `shared_prefs/qm_global_sp.xml` | `c_f_bootids`（5 个历史 boot_id UUID）、`c_f_uptimes` |
| `app_tbs_64/core_share/libtbsqimei.so` | TBS 侧同名 SDK |
| `shared_prefs/device_id.vip.xml` | 设备 ID 缓存 |

SP 文件名规则来自 `aa.f`：`"QV1" + f15021e + com.tencent.qimei.ab.a.a(appKey)`。写入通过 `com.tencent.qimei.u.a.a(appKey, Runnable)` 串行化，避免并发覆盖。

`c_f_bootids` 这个设计很关键：它把历史上每一次开机的 boot_id 都记下来。boot_id 本身每次开机都变，但"历史列表"把设备生命周期串成一条链。恢复出厂会清 SP，但服务端已经存了上一次上报的列表。

### 3.7 为什么刷机无效

q16 由服务端计算，输入是注册 JSON（品牌、型号、board、device、first_api_level、manufacturer、name、host、kernel、容器、多开、harmony、预审状态…）。所以：

- **恢复出厂**：本地 q16 丢失，重新注册时提交同一套指纹，服务端大概率返回同一个 q16。
- **刷机**：指纹变化（kernel、inode、first_api_level、boot_id 列表清空），服务端会返回新的 q16 或走二次校验，但账号维度（openid）不变，服务端仍能把新旧 q16 关联到同一账号。
- **改机**：只能改 Java 层能读到的值（`Build.*`、`Settings.Secure`），改不了 `uname`、`/vendor` statfs、`libc.so` inode；这些恰好是 ACE 17 槽的内容，会与 QIMEI 上报的指纹形成交叉验证。

---

## 4. TDM：第三条通道

### 4.1 字段全集

`com.tdatamaster.tdm.device.DeviceInfoName` 定义 26 个字段：

`All`、`AllSyn`、`AndroidID`、`AppVersion`、`Brand`、`BundleId`、`CpuCore`、`CpuFreq`、`CPUName`、`DataSign`、`DeviceID`、`IDFA`、`MacAddr`、`Model`、`OAID`、`QIMEI36`、`QIMEI`、`ScreenHeight`、`ScreenWidth`、`SysVersion`、`TotalMem`、`TotalSpace`、`TuringTicket`、`UserAgent`、`UUID`、`xid`。

### 4.2 native 桥

`TDataMaster.java` 声明 20 个 native 方法：

`TDMInit`、`TDMEnableDeviceInfo`、`TDMEnableReport`、`TDMEnableHTTPProxy`、`TDMGetSDKVerision`、`TDMGetUID`、`TDMPause`、`TDMResume`、`TDMSetLogLevel`、`TDMSetRouteAddress`、`TDMSetUserAgent`、`TDMReportEvent`、`TDMReportBinary`、`TDMRealTimeReportEvent`、`TDMRealTimeReportBinary`、`TDMReportFileContent`、`TDMReportLogin`、`TDMReportLoginV2`、`TDMUploadBinaryByCOS`、`TDMUploadFileByCOS`。

公开的 `setDeviceInfo(String, long/String/boolean)` 全部转发 `DeviceInfoHolder.GetInstance()`，后者是纯 native 桥：

`AddDeviceInfoObserver`、`GetBooleanDeviceInfo`、`GetLongDeviceInfo`、`GetStringDeviceInfo`、`SetBoolDeviceInfo(String, boolean, int)`、`SetLongDeviceInfo(String, long, int)`、`SetStringDeviceInfo(String, String, int)`。

### 4.3 QIMEI 反射获取

`DeviceInfoCollect.GetQIMEIInfo(Context, str)`：

1. 反射 `com.tdatamaster.qimei.TDMQimei`，先 `GetInstance()`。
2. 再 `Init(Map)`，键：`TestMode`、`AppID`（`TDMUtils.GetBeaconAppId()`）、`APP_VERSION`、`Enable=true`。
3. 反射调用 `str` 指定的方法（`GetQimei` 或 `GetQimei36`）。
4. 用 `Proxy.newProxyInstance` 实现 `com.tdatamaster.callback.TDMBridgeCallback.OnResult(String name, int code, String data)`，按 `name` 写回 `mQIMEI` / `mQIMEI36`。

这条链说明 TDM 不直接调 libqimei 的 JNI，而是走 TDM 自带的 `com.tdatamaster.qimei` 封装（内部仍是 QimeiSDK）。所以同一个进程里存在两份 QIMEI SDK 实例：游戏侧（`com.tencent.qimei`）和 TDM 侧（`com.tdatamaster.qimei`），appKey 不同。

### 4.4 协议字段

`libTDataMaster.so` 里的 `tdm_` 前缀串 172 条，分三类：

- JNI：`tdm_set_string_device_info`、`tdm_get_string_device_info`、`tdm_initialize`、`tdm_report_event`…
- 协议：`tdm_platform`、`tdm_account`、`tdm_user_id`、`tdm_dev_uuid`、`tdm_app_id`、`tdm_app_ver`、`tdm_src_id`、`tdm_type`、`tdm_ver`、`tdm_event_name`、`tdm_event_time`、`tdm_network_type`、`tdm_operator`、`tdm_log_uuid`、`tdm_kv_total_count`
- 设备：`tdm_qimei` 0x2e61b5、`tdm_qimei36` 0x2e61bf、`tdm_android_qimei` 0x2e61cb、`tdm_android_oaid` 0x2e61e2、`tdm_android_imei` 0x2e61f3、`tdm_android_id` 0x2e6204、`tdm_android_xid` 0x2e6213、`tdm_serial_number` 0x2e1b7e、`tdm_android_user_agent` 0x2e8a2d

设备信息默认关闭：需要 `TDM_USER_DEVICE_INFO_ENABLE`（0x2e8b1a）为真，并调用 `TDMEnableDeviceInfo`（0x65f00）。这是隐私合规开关，实际游戏里由 `DeviceInfoCollect` 在初始化时打开。

### 4.5 ACE 侧的 TDM 数据入口

`libtersafe.so` 的明文串里有三条与 TDM 直接相关，且都不在加密表内：

| 偏移 | 字符串 |
| --- | --- |
| 0x97551 | `tdm_dev_info` |
| 0x91AAA | `tdm_report` |
| 0x96740 | `TotalMem:%d;FreeSpaceTDM:%d` |

三者分别被 `0x4C26D4`、`0x4C309C`、`0x4C2F00` 引用，集中在 `0x4C26xx`–`0x4C30xx` 这一段。`0x4C26C0` 附近的取用流程：

```
0x4C26C0  bl  0x2DAD4C        ; 取当前环境
0x4C26C4  bl  0x239BC8        ; 返回 bool，云控/能力判定
0x4C26C8  tbnz w0, #0, fail
0x4C26CC  bl  0x22D820        ; 取"数据提供者"对象
0x4C26D0  adrp x1, #0x97000
0x4C26D4  add  x1, x1, #0x551 ; "tdm_dev_info"
0x4C26D8  mov  w2, #1
0x4C26DC  mov  w3, #1
0x4C26E0  bl  0x22DA98        ; provider.get("tdm_dev_info", 1, 1)
```

`0x22DA98` 是一个平坦化的"按名字取值"中间层：先用 `0x22DB80` 在内部表里查名字，再 `0x22DC14` 调用对应实现，两个函数都由 `0x52A4A0` 的间接跳转表分发。`0x22D820` 同样用 `0x52A460` 的跳转表，返回同一个 provider 单例。

这条链解释了为什么 `partI_siblings.md` 说"五库与 ACE 无代码级耦合"却又能在同一条上报里看到 TDM 的字段：ACE 不链接 `libTDataMaster.so`，而是通过自己的 provider 抽象按名字请求数据；名字是明文，值由 TDM 在初始化时注册进去。

用 `readelf` 复核过依赖关系：`libtersafe.so` 的 `DT_NEEDED` 只有 `liblog/libc/libm/libdl`，既不链接 `libTDataMaster.so` 也不链接 `libqimei.so`，所以"数据面交汇、代码面隔离"这个判断成立。补充一点：`libtersafe.so` 里连 `TDataMaster`/`libqimei` 这类库名都不存在（主表 3,198 条与内联 875 条全部查过），因此它也不是通过 `dlopen` 去加载这两个库的——`0x4E11C8` 那个唯一的 dlopen 包装没有直接的 BL 调用者，库名参数始终没定位到。

### 4.6 MGPA 的 OAID 链

`com.ihoc.mgpa` 是游戏侧另一个上报 SDK。`gradish/o1.java` 的 OAID 获取：

1. 查 `c0.b()` 模块是否可用。
2. `c0.a(AppUtil.getAppContext(), new a())`。
3. 回调里 `i2 == d0.SUCCESS` 时 `SharedPrefUtil.put("OAID", str)` 并 `TDMReport.getInstance().setDeviceInfo("OAID", str)`。
4. 失败回退 `SharedPrefUtil.get("OAID")`。

错误码三态：`NO_DEVICE_TOKEN_MODULE`、`CLOUD_IS_CLOSE`、`VENDOR_NOT_SUPPORT`，重试 ≥3 次放弃。`IDType` 枚举 5 种：`UNKOWN`、`UDID`、`OAID`、`VAID`、`AAID`。

---

## 5. ACE 的 Java 面为什么看不到设备 ID

`com.tencent.tp.TssSdk` 的 native 方法只有 `getsdkantidata`、`hasMatchRate`、`init`、`onruntimeinfo`、`senddatatosdk`、`senddatatosvr`、`setappobject`、`setgamestatus`、`setsenddatatosvrcb`、`setuserinfo`、`setuserinfoex`。

`TssSdkInitInfo` 只有一个 `int game_id`；`TssSdkUserInfoEx` 只有 `entry_id`、`uin_type`、`uin_int`、`uin_str`、`app_id_type`、`app_id_int`、`app_id_str`、`role_id`、`world_id`。全是账号维度，没有任何设备 ID 入参。

所以 ACE 的 fake token 里 `q` / `Q` / `o` 三个值只能来自：

1. native 自己读 TDM 写入的 `Fake_Token_TDM_info`（off 51374）；
2. 或者云控下发。

这就解释了 `qimei.md` 第九节的"优先级"现象：ACE 不主动调 QIMEI SDK，它是被动消费 TDM 已经采好的值。

`l.java` 的凯撒 +5 解码也值得记一笔：`"vkk_fzt:"` → `"app_key:"`、`"bzo_mzkjmo_yvov"` → `"get_report_data"`、`"didodvgduz"` → `"initialize"`、`"ho:"` → `"mt:"`、`"dia_xg:"` → `"itf_cb:"`、`"hnbwjs:"` → `"msgbox:"`、`"cdyz_hnbwjs:"` → `"hier_msgbox:"`、`"kjk_rdi:"` → `"pop_win:"`。这是 ACE Java 层唯一的编码手段，强度等于零。

---

## 6. 标识稳定性层级

| 标识 | 生成源 | 重置条件 | 稳定性 |
| --- | --- | --- | --- |
| q16 / q36 | 服务端按注册 JSON 计算 | 指纹大幅变化时可能换发 | 高（跨刷机） |
| openid | 账号登录 | 换号 | 高（跨设备） |
| AndroidID | 系统随机，恢复出厂重置 | 恢复出厂 | 中 |
| OAID | 厂商服务，可重置 | 用户手动重置 | 低 |
| boot_id | 内核每次开机生成 | 每次开机 | 极低（会话级） |
| libc.so inode | 系统镜像 | 刷机/改分区 | 高（同 ROM 恒定） |
| /vendor statfs | 分区布局 | 改分区 | 高 |
| uname | 内核 | 刷内核 | 高 |
| c_f_bootids 列表 | 历史累积 | 清 SP / 恢复出厂 | 高（服务端另存） |

ACE 的 17 槽 + QIMEI 的注册 JSON 合起来，等于给每台设备建了一个"硬件哈希"；q16 是这个哈希在服务端的索引；openid 是账号索引。三者交叉，构成封号时的证据链。

---

## 6.5 客户端本地提示链（对"只采集不判定"的修正）

旧结论认为 ACE 客户端完全没有本地判定。两套字符串体系全量还原后，这个结论需要修正：内联字符串里有 6 条面向玩家的英文提示，说明这些检测项在客户端就会打断玩家，而不是静默上报后由服务端封禁。

| 文案 | 密文地址 | 触发引用点 | 语义 |
| --- | --- | --- | --- |
| root | 0x96243 | 0x28E7A8 | "Your device has been rooted…" |
| 解锁/篡改 | 0x96A6D | 0x2BDFE0 | "You are using an unlocked device…" |
| GPU Profiler | 0x977DA | 0x25FF4C | 调试器（GPU Profiler 工具）在运行 |
| AutoClicker | 0x9891E | 0x284B9C | 要求把滚动条拖到指定数字（交互式验证） |
| 模拟器 | 0xD917C | 0x29909C | 运行在 Android 模拟器里 |
| 恶意软件 | 内联串 | — | 要求先卸载再进游戏 |

`0x25FF14` 是这条链的消息拼装器：它把 `ICON:%s:`（0x9801C）、0x920BE2、GPU Profiler 文案（0x977DA）、0x9508AA 四条解到栈上，再用 `0x2DAD4C`（取上下文）、`0x2DB5C8`、`0x4A54DC`（snprintf）、`0x4A4998`（拼接）组织成一条消息。唯一调用者是 `0x25FE1C`：它先用 `0x4EB7B0(0x7967)` 解出名字、`0x4A46C0` 做 strcmp 匹配某个对象，命中后调用拼装器并返回 1。

需要注意证据等级：文案与拼装链是静态确凿的，但"命中后究竟是弹窗阻断、踢下线还是仅提示"取决于上层调用者的处置动作（kill / exit / 重连）。这一点需要动态验证。

---

## 7. 对抗视角的痕迹

如果目标是"在不改硬件的前提下换一个干净身份"，会踩到这些点：

1. 改 `Build.BRAND` / `MODEL` 只影响槽 1/2 与 QIMEI 的 `brd`，但 `ro.product.board`、`ro.product.device`、`ro.build.host` 仍在注册 JSON 里。
2. 改 `android_id` 只影响槽 17（且是哈希后的）与 QIMEI 的 `clone`/`ao`，不改变 q16 的其它输入。
3. 用 Magisk 隐藏 root 会改 `/system` 挂载与部分文件属性，可能改变 `libc.so` inode 或 `/vendor` statfs。
4. 云手机/容器会被 `containe`（`init.*.environment.rc`、`/lxc_container/`、`/docker`）直接命中。
5. 多开/分身会被 `clone`（`Process.myUid()/1000 != 0`）命中。
6. 只清 SP 不清 `files/com.tencent.qimei.sdk.QimeiSDK`，下次启动仍能读到旧 q16。
7. 清 SP 且清 files 后，`c_f_bootids` 变空，但服务端有上一次上报的副本。

---

## 8. 未解与待验证

1. 主字符串表已全量还原（`docs/tersafe_strings.md`，3,198 条），内联字符串也已还原（`docs/inline_strings.md`，875 条），两套合计约 4,073 条。`0x4E4A68` 返回 `0xFBCB0` 即主表基址，`0x4E4A7C` 返回的 `0x568FC4`（`.bss`）只是运行时明文缓存区，不是第二份表。
2. q16 的服务端算法不可见。客户端只有"注册 → 收 A3/A153 → 缓存"这一条路径。
3. `0x1F3644` 构造的事件对象（0x658 字节）字段语义未完全还原，只确认它携带 fake token 与一条格式串。
4. `0x45DF8` 的 `k%d:%s;` 编码器输入槽位表（每槽 128 字节）与 ACE 的 17 槽不是同一套，推测是 libqimei 内部用于上报的键值编码。
5. `TssSdk` 的 `tvc()` / `tvd()` / `tvm(String)` / `tvs()` 四个 native 不在 `0x84058` 的 15 项注册表里，注册路径未知。
6. `Fake_Token_TDM_info` 的提供方未定位：ACE 通过 provider 框架（`0x22D820` 单例、`0x22DA98(provider, key, 1, 1)` 能力查询、`0x22DC84` 按键取值）向运行时注册表要这个命名空间，四个子键是 `xid`/`QiMaM`(QIMEI)/`QIMEI36`/`OsEz`(OAID)。这些键在全部 16 个 `.so` 明文里都不存在，libTDataMaster 只有 `OAID`/`oaid`，说明提供方是运行期注册的。
7. 6 条本地提示文案命中后的实际处置动作（弹窗 / kill / 踢下线）未静态确认。
8. `0x2B9D4`（libqimei 的 60 KB 设备指纹采集总装函数）的最终输出格式仍未完整还原；已确认它是全部 q16/q36 形态的唯一入口，采集面覆盖属性、mountinfo/maps、inode、账号 openid、无障碍、LSPosed、模拟器/云手机。
9. ACE 是否 `dlopen("libTDataMaster.so")` 未证实：`0x4E11C8` 是唯一的 dlopen 包装，但没有直接的 BL 调用者（经函数指针/表引用），库名参数未能定位。

---

## 9. 动态验证脚本

`tools/hook_devinfo.js` 是针对本文结论的 Frida 脚本，覆盖四层：

| 层 | 目标 | 观察点 |
| --- | --- | --- |
| Java / QIMEI | `com.tencent.qimei.uin.U` 的 `z/z2/o/u/p/m/x` | 每个维度返回值（OZ、kernel、MODEL、getprop） |
| Java / QIMEI | `Qimei.getQimei16()` / `getQimei36()` | 缓存中的 q16/q36 |
| Java / TDM | `DeviceInfoHolder.SetStringDeviceInfo` / `GetStringDeviceInfo` | 谁在写 `Fake_Token_TDM_info`，写入时机 |
| Java / ACE | `TssSdk.getReportData()` / `ioctl(String)` | 上报原文（base64 前）与 ioctl 命令 |
| Native | `libqimei.so + 0x2B9D4` | `mode` / `mode2`，判断调用形态 |
| Native | `libtersafe.so + 0x2CCD20` / `0x2CCF54` | fake token 明文（`x:..;q:..;Q:..;o:..` 与 `bt/bd`） |

使用方式：`frida -U -f com.tencent.tmgp.sgame -l tools/hook_devinfo.js --no-pause`，进大厅后观察 `[qimei.*]`、`[tdm.*]`、`[ace.*]` 三类日志。native 偏移与本文一致（imagebase 0），若样本版本变化需重新用 `tools/bl_callers.py` 定位。

预期现象：

1. 冷启动后先出现 `[tdm.set] ...` 一串键值，其中包含 `QIMEI`、`QIMEI36`、`OAID`、`xid`、`AndroidID`、`DeviceID`、`UUID`。
2. 随后出现 `[qimei.U.o]` / `[qimei.U.z]` 等维度调用，最后 `[qimei.16]` / `[qimei.36]` 才非空（说明 q16 来自服务端响应，不是本地生成）。
3. `[ace.2ccd20.out]` 应能看到 `x:...;q:...;Q:...;o:...`，`[ace.2ccf54.out]` 能看到再加 `td:`/`bt:`/`bd:` 的完整串。
4. `[ace.report]` 的返回值是 `id=<字段号>|...` 的 Base64，解码后与 `main.md` 6.2 的字段表对应。

## 10. 附录：地址速查

### ACE（libtersafe.so）

| 地址 | 作用 |
| --- | --- |
| 0x2C9D78 | 设备采集总控 |
| 0x2CD090 | 链表复位 |
| 0x2CA274 | 入槽 + `=`/`;` 转义 |
| 0x2C8CBC | 17 槽拼装 |
| 0x2CC358 | 已装应用采集 |
| 0x2CC6C4 | fake token 17 槽 |
| 0x2CCA7C | OAID 虚表 +0x60 |
| 0x2CCD20 | `x/q/Q/o` 组装 |
| 0x2CCE84 | boot_id |
| 0x2CCF54 | `td/bt/bd` 包装 |
| 0x2C9208 | fake token 消费点 |
| 0x1F3644 | 事件对象构造 |
| 0x2C89D4 | `force_fake_token` |
| 0x242490 | `/proc/cpuinfo` |
| 0x2CC02C | `uname` |
| 0x2CC1F0 | `statfs("/vendor/")` |
| 0x2CC134 | `libc.so` inode |
| 0x2CC2F8 | 文件首见时间 |
| 0x290270 | seccomp |
| 0x2CD864 | USB 遍历 |
| 0x2CDCEC | wifi_adb |
| 0x24F8A4 | `ip route get` |
| 0x4D3088 | Key attestation 密钥生成 |
| 0x2AB450 | attestation 上报 |

### QIMEI（libqimei.so）

| 地址 | 作用 |
| --- | --- |
| 0x84058 | JNI 注册表（15 项） |
| 0x2B9D4 | 设备指纹总装（mode 0/1/2/3） |
| 0x42110 | `getprop` 封装 |
| 0x42110 → 0x85488/0x85490 | `__system_property_find` / `read` |
| 0x45DF8 | `k%d:%s;` 编码器 |
| 0x2B468 | `x(String)` |
| 0x3A818 | `z(Context)` → OZ |
| 0x2B920 | `o()` |
| 0x256E8 | `r(...)` 网络请求 |
| 0x6CFA4 | 字符串表（9469 B，398 条） |

### 字符串表偏移（libqimei.so，已解）

| 偏移 | 内容 |
| --- | --- |
| 0x1418 | `lvcwmSYVr2Axv1gn`（ChaCha20 key 前半） |
| 0x142C | `Zs0ntDqG2jyhKN0c`（ChaCha20 key 后半） |
| 0x12D8 | `ro.product.model` |
| 0x02FE | `ro.product.brand` |
| 0x1289 | `content://settings/secure/` |
| 0x12CA | `android_id` |
| 0x12BC | `GET_secure` |
| 0x1403 | `k%d:%s;` |
| 0x140E | `k10:%d` |
| 0x0B67 | `1,Telephony,getDeviceId;2,Telephony,getSubscriberId;...` |
| 0x24F5 | `Syzs` |
| 0x113F | `deviceUniqueId` |
