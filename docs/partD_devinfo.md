# libtersafe.so 设备信息采集、伪造检测与反自动点击分析

## 总览

设备信息由 0x2C9D78 统一调度 16 个采集槽（编号 1–17，7 号空缺；brand/model/sdk_int/battery/gpu/volume/camera/sensor/kernel/fingerprint/baseband/libc inode/statfs/文件首见时间/已装应用/androidid），每槽失败即回填 `*Err` 字符串，最终由 0x2C8CBC 拼成 `"槽号=值;...;"`（17 号槽只发哈希）。伪造检测分两路：Key attestation（0x4D3088/0x4D31CC 生成带 challenge 的 AndroidKeyStore RSA 密钥，0x4D2660 取证书链，0x4D2310 校验包名，0x2AB450 以 type=9 上报由服务端复核）与 fake token（OAID/QIMEI/xid/ANDROID_ID 与 boot_id、Brand 交叉比对）。反自动点击在 JS 侧开关驱动下，用 512 个触摸间隔样本做 500 桶直方图，算主桶占比，超阈值（默认 70%）即报警并写 `/sdcard/sdk/enable.log`。

## 一、采集总控与错误键

0x2C9D78(a1=env, a2=上报结构)：`calloc(1,0x400)` 取 1024 字节值缓冲，先 0x2CD090 复位链表，再顺序调用各采集器，签名统一为 `f(ErrKey, env, buf, 1024, ErrKey)`，**返回 0 表示失败**，调用点把返回值与 ErrKey 二者择一交给 0x2CA274：

```
v23 = sub_2DB440(v22, v7, 1024);        // 1 号槽：Brand
if (v23) v24 = v23; else v24 = v21;     // 失败则 v24 = "BrandErr"(off 52805, site 0x2C9F50)
sub_2CA274(v23, a2, 1, v24);            // 槽号 1
```

槽号实测为 1–6、8–17（7 号空缺），与 Err 键一一对应：1 BrandErr、2 ModelErr、3 "ERR"(off 49995，失败文案)、4 BatteryErr、5 GPUErr、6 SysMaxVolumesErr、8 CameraErr、9 SensorErr、10 KernelErr、11 FingerPrintErr、12 BaseBandErr、13 LibcInodeErr、14 FileSystemErr、15 FileFirstTimeErr、16 AppInfoErr、17 AndroidIdErr。**Err 键即"失败原因字符串"，被当作该槽的值原样进入上报**，因此服务端看到 `5=GPUErr` 就知道 GPU 采集失败而非空值。

3 号槽不是 Err，而是 SDK_INT：0x2CA39C→0x2DB578→0x240508，后者用 `android/os/Build$VERSION`（site 0x23FF30）+ 字段 `SDK_INT`（0x2406D8）走 JNI 取 int，`sub_4A54DC(buf,1024,"%d",v)`。

0x2CA274 还会把值里的 `=`(0x3D) 与 `;`(0x3B) 各 +29 转成 `Z`/`X`（防分隔符注入），再挂入 `{int slot; std::string}` 链表。

这套设计的意图很明确：Err 键与真实取值共用同一槽位，服务端无需额外的"缺字段"分支，只要看到取值等于自己下发的 Err 文案，就能区分"采集失败"与"字段为空/被隐藏"。因此每个采集器的第 1、5 参数都填同一个 ErrKey，失败路径 `return a4` 与成功路径写缓冲互斥，调用点再用返回值是否为 0 做二选一。16 个槽的调用顺序固定（1→6、8→17），脚本化的采集链一旦被 inline hook 打断，最可能的表现就是某槽直接变成 Err 文案或整体缺失，这也是该 SDK 自查完整性的一种副产品。

## 二、上报拼装

0x2C8CBC 遍历上述链表，逐槽 `"%d=%s;"`（off 50159，site 0x2C8DB8）；**第 17 槽例外**：`if (v16 == 17)` 时先 `sub_489248(value,len)` 求哈希，再用 `"%x"`（off 50396）输出（0x2C8D7C–0x2C8DB0），即 AndroidID 不明文外发。整串再经 0x49F018/0x49F170 追加进 protobuf 式流。17 槽单独哈希的意义在于：AndroidID 是明文最敏感的标识，明传会被中间人/日志侧直接收割，而服务端只需比对哈希是否与历史一致即可完成"同机判定"，同时保留了对改机（ID 变化→哈希变化）的识别能力；哈希函数 0x489248 为定长摘要，因此该槽在报文里的长度恒定，也便于服务端做定长解析。其它模块用同风格 `key=value|`：0x23DE84 `"DeviceType=%d|TabletInfo=%s|"`（off 51858）、0x4CBB2C `"root=%d|x86=%d|apk_cnt=%d|adb=%d|..."`（off 32413）。

## 三、Build / CPU / 内核 / 文件系统 / seccomp

Build 走统一 JNI 取静态字段：0x2CF61C→0x2CF3BC 先 `FindClass`（函数表 +0x30），`sub_2CF488` 用 `GetStaticFieldID`（+0x480=1152）后按类型分派——`'I'` 走 `GetStaticIntField`（+0x4B0=1200），`'L'/'['` 走 `GetStaticObjectField`（+0x488=1160，0x2CF4F4）；`ExceptionCheck` 在 +0x720，异常清理在 +0x88。三处实现：0x2429E0 取 `BRAND`（0x242AD8），0x249D68 取 `MODEL`（0x24A030），0x241384 依次取 `HARDWARE`/`CPU_ABI`/`CPU_ABI2`（0x241438/0x2414D0/0x241524），再 `sub_4A54DC(v29,128,v37,HARDWARE,CPU_ABI)` 合并（格式串由 `&unk_92043` 解密，推测 `"%s,%s"`）。三者缓存于 qword_55F258/55F250/55F1F0，读取前查 `ctx+956` 位掩码（0x200/0x400/0x8，置位直接跳过），失败回退 `getprop`（0x4CEE28）。

需要强调：全量字符串索引中**不存在** `SERIAL`/`DEVICE`/`PRODUCT`/`BOARD`/`HOST`/`TAGS`/`TIME`/`INCREMENTAL`/`DISPLAY`/`MANUFACTURER` 这些 Build 静态字段名，native 侧只取 BRAND、MODEL、HARDWARE、CPU_ABI、CPU_ABI2 五项；`RADIO` 以 `getprop("gsm.version.baseband")` 替代（12 号槽），`FINGERPRINT` 也走 `getprop("ro.build.fingerprint")`（11 号槽）。这说明指纹的主体在 Java 层组装，native 只补齐与内核/文件系统相关的低层字段。

- CPU：0x242490 读 `/proc/cpuinfo`（site 0x2425B0），解析 `Processor`(0x242740)、`Hardware`(0x2427B0)、`model name`(0x2427F8)，按 `:` 切分取右值，缓存 qword_55F220。
- 内核：0x2CC02C `uname(&s)` 后 `"%s,%s,%s"`（off 50209），即 sysname/release/version。
- 文件系统：0x2CC1F0 `statfs("/vendor/")` → `"%u:%u:%08x:%08x"`（off 50220），另有带前缀 `"%s:%u:%u:%08x:%08x"`（off 50238）。
- LibcInode：0x2CC134 对 `system/lib/libc.so` 做 stat，取 `v14[1]`（st_ino）以 `"%d"` 输出。
- 文件首见时间：0x2CC2F8 `"%llu"`（off 50259）。
- AppInfo：0x2CC358 遍历已装应用（0x2DBBC0），用 0x489248 对包名哈希并与常量（394722921、875655884 等）比对计数。
- seccomp：0x290270 组串 `"secc: %d;%d;%d;%d;%d"`（off 15390）：SDK_INT、`/proc/self/status` 的 `Seccomp:`（0x290E0C）、`prctl(21)`（0x290FC4）、`prctl(39)`（0x291058）、固定 0。

## 四、GPU / 电量 / 音量 / Camera / Sensor

- GPU 0x2CABF4：`getSystemService("activity")` → `getDeviceConfigurationInfo()` → `getGlEsVersion()` → `"%s"`。全库无 `glGetString`/EGL 采集串，**只取 GLES 版本号**。
- 电量 0x2CA404：注册 `ACTION_BATTERY_CHANGED`，取 `EXTRA_TECHNOLOGY`/`EXTRA_MAX_CHARGING_CURRENT`，格式 `"%s:%d"`。
- 音量 0x2CB06C：`getStreamMaxVolume` → `"%d"`。
- Camera 0x2CB31C：`getCameraIdList()`，逐个 `getCameraCharacteristics(id)` 取 `SENSOR_INFO_WHITE_LEVEL`、`CONTROL_AE_COMPENSATION_RANGE`、`SENSOR_INFO_MAX_FRAME_DURATION`、`SENSOR_INFO_PHYSICAL_SIZE` 并 `toString()`，拼 `"%d:%s"`。
- Sensor 0x2CBBFC：`getSensorList(TYPE_ALL)`，逐项 `getMinDelay()`+`toString()` 拼 `"%d:%d:%s"`；同函数出现 `fake_token_sensor`（off 50024），传感器清单参与伪造校验。

## 五、USB / ADB / 网络

- USB 0x2CD864：`EXTRA_PLUGGED` 与 `BATTERY_PLUGGED_USB` 比对（0x2CDC38）。
- ADB 0x2CDCEC：`getprop("service.adb.tcp.port")` 命中即标 `wifi_adb`（0x2CDD08）。
- 网络 0x24F8A4：`popen("ip route get 8.8.8.8 2>&1")`，再 `sscanf("8.8.8.8 via %s dev")` 取网关，用于网络环境/代理判定。
- 校正：0x24EBD4、0x280C3C 的 `tencent/leidian/nox/bluestacks/mac` 与 `*_tp` 是**模拟器指纹标签表**，不是 MAC 地址采集。

## 六、Key attestation

0x4D3088 `KeyPairGenerator.getInstance("RSA","AndroidKeyStore")`；0x4D31CC 构造 `KeyGenParameterSpec.Builder(ANO_KEYSTORE_ALIAS_03_23, PURPOSE_SIGN)`，链式 `setSignaturePaddings("PKCS1")`→`setDigests("SHA-256","SHA-1")`→`setAttestationChallenge(byte[])`（0x4D359C）→`setKeySize`→`build`；0x4D2A24 执行 `initialize(spec)`+`generateKeyPair()`。0x4D2660 再 `KeyStore.getInstance("AndroidKeyStore").load(null)`，`getCertificateChain(alias)` 逐张 `getEncoded()`，用 0x4D36B8（GetArrayLength/GetByteArrayElements+memcpy）取出 DER，存入 0x818 字节链表节点（0x4D37B4）。0x4D2BE8 是对 `getCertificate(alias)` 的单证书版本。

判定：0x4D2578 返回码 0 成功、2 上下文空、4 生成密钥失败、5 生成后复验失败；0x4D1D3C 要求证书块 ≥0x64 字节，再 0x4D2238 解析、0x4D2310 校验包名（`"NULL"`/`"UnknownPackage"`，0x4D2378）并把结果位写入 `*a7`。0x2AB450 在配置开关 `att_svr`（off 48796）打开时把证书链序列化（0x49F614/0x49FE88）加密后以 **type=9** 包（vtable+232）上报，因此 challenge/证书字段的最终判据在服务端，本地规则名 `attest_cert_not_white`/`attest_cert_is_black`（0x2ABC94/0x2ABD20）即黑白名单判据。

## 七、Fake token 与唯一标识

17 号槽 0x2CC6C4 先取全局对象 `ft_oaid`（off 58581），经 0x2CCA7C 走虚表 +0x60 取 256 字节字符串；**非空且 ≠ `Unknown`（off 34159）就用 `"%s"` 输出 OAID**，否则回落到 `fake_token_androidid`（off 50001）对象。另一路 0x2CCD20 从 `Fake_Token_TDM_info`（off 51374）取 xid/QIMEI/QIMEI36/OAID，拼 `"x:%s;q:%s;Q:%s;o:%s"`（off 50303）；0x2CCF54 再包一层 `"%s;bt:%s;bd:%s;"`（off 50325）与 `"td:%s;bt:%s;bd:%s"`（off 50343），其中 `bt` 为 `/proc/sys/kernel/random/boot_id`（0x2CCE84），`bd` 为 Brand（0x2DB440）——**token、boot_id、Brand 三者交叉比对**，改机后 token 与 boot_id/品牌不自洽即暴露。0x2C89D4 是云端规则动作 `force_fake_token`（off 46601，分发表 0x5168C8），受 `ctx+953` 控制，命中后强制走伪造 token 分支。IMEI 无直接 TelephonyManager 调用，由 Java 层以 `imei_ex`（0x2C35DC）传入（0x2C3118）。

AndroidID 的明文读取另有独立路径 0x2496E4：常量池加载 `android/provider/Settings$Secure`，再 `getString(ContentResolver, "ANDROID_ID")`（site 0x249A7C，内联标记 `AndroidID` 于 0x24971C），结果缓存后供上层使用。推测该值与 17 槽的 `fake_token_androidid` 做一致性比对，用于发现"OAID 与 ANDROID_ID 不同源"的伪造组合。

优先级可归纳为：OAID（`ft_oaid`，非空且非 `Unknown`）> `fake_token_androidid`（含 ANDROID_ID）> QIMEI/QIMEI36（0x2CCD20，多用于 TDM 侧信道）；全库检索不到 gsf id / advertising id 采集串。三者最终都与 boot_id、Brand 组成交叉校验三元组，任一环节被改机工具篡改都会出现"标识内部不自洽"。

## 八、反自动点击

控制面：0x2B4B94 解析 Java 下发命令 `RecordTouchEnable/Start/Stop`（off 15288/15308/15327），按 `:` 切分取参数，置 `ctx+10237`/`ctx+10238`，参数拷入 `ctx+10332`（64 字节）；同族命令 `start_anti_auto_clicker2`（0x2B4A0C，off 15261）。0x285B40 反射 `com/tencent/tp/TouchListenerProxy` 取单例，0x285E74 调 `setOnTouchListener` 挂钩 View 触摸。

采集：`ctx+112` 起 0x800 字节 = 512 个 int32 间隔（初始 0xFF），`ctx+104` 为样本数，`ctx+96` 为基准时间。

判定 0x2840B8：需 `ctx+2184` 使能且 `ctx+2169==0`（未报过），计数器 `ctx+2164` 对周期 `ctx+2172` 取模为 0 且 `ctx+2168` 采样中才评估；先 `memset` 500 个 int 直方图，0x284220 填充——要求样本 >31，`res=ano_touch_reg`（off 41624，默认 10，非法取 10），`bucket = interval/res`，`hist[bucket]++`（0x284294–0x2842B4）。阈值取 `ano_touch_thres`（off 41553），0x2841AC–0x2841C0 做区间钳制：`SUB W9,W0,#0x65`（thres-101）、`MOV W8,#0x46`（70）、`CMN W9,#0x33`、`CSEL W21,W8,W0,CC`，即**仅当阈值落在 [50,100] 时采用原值，否则统一回落 70**。0x284340 找最大桶：`v11=max/total; v4=v11*100.0`，写日志 `"rate:%.2f,grp:%d,tll:%d"`（off 41598，0x284468）——`grp` 是主间隔桶号（即主导间隔≈grp×res 毫秒），**`tll` 是总样本数而非双击间隔**；随后 `if (rate > thres) 0x284544`（0x2841F8）。

处置 0x284544：`ano_det_cnt`（off 41539，默认 3）为命中次数门限，累计达门限且未报过则拼 `"rate:%.2f,hit:%d,name:%s"`（off 41571），`name` 由 0x2846E0 生成（含 `adb`/`clk_adb` 标记），交 0x1EFA48 上报；再读 `click_alert`（off 42181）走云端上报，并置 `ctx+2169=1` 一次性封口。旁路日志 0x284E68 以 `"%s/%s"` 拼 `/sdcard/sdk/enable.log`，最多写 10 次（`ctx+2180`），并有 `rand()%1000==517` 的概率跳过。

另外 0x1BCF84 命令表中存在 `CloseDevInfoCollect:`/`CloseDevInfoCollectEx:`（off 46402/46448），宿主可整体关闭设备采集。

从工程角度看，反自动点击是一套"云控开关 + 本地统计 + 云端复核"的结构：`ano_touch_thres`/`ano_touch_reg`/`ano_det_cnt` 三个键都从配置对象读取并带缺省值（70/10/3），意味着阈值可在不发版的情况下由服务端调整；命中后除 0x1EFA48 的即时上报外，还要再读 `click_alert` 才决定是否上云，形成两级过滤，降低误报带来的带宽与封禁成本。`/sdcard/sdk/enable.log` 的 10 次写入上限与 `rand()%1000==517` 的抽样旁路，则是为了在用户设备上留下可回收的取证痕迹，同时避免频繁 IO 被检测工具发现。

## 九、结论与局限

采集面"窄而精"：只取 Build/CPU/uname/statfs/seccomp/相机与传感器清单、网关地址这类**环境一致性证据**，没有 IMEI/MAC 的直采路径，说明其目标不是广谱画像而是判定"这台机器是否被改过"。伪造检测走双轨——key attestation 把证书链（含 challenge）以 type=9 上送、由服务端用 TEE 根证书复核，本地只做包名校验与黑白名单标记；fake token 则把 OAID/ANDROID_ID/QIMEI 与 boot_id、Brand 交叉绑定，两条轨都很难靠单点 hook 绕过（推测）。反自动点击本质是**低置信度信号的累积**：单次只记录 rate/grp/tll，要连续命中 `ano_det_cnt` 次才上报告警，阈值全部云控，因此误报成本低、对抗者需长期维持类人节奏才能规避（推测）。

局限：OLLVM 控制流平坦化使 0x2C9D78、0x2840B8 等函数无法稳定反编译，本文结论主要来自 disasm、字符串解密点与调用关系三方印证；凡标「推测」处均未做动态验证，尤其 0x241384 的拼接格式串、0x2CCA7C 的虚表取值语义。

## 十、采集项/上报键对照表

| 槽/键 | 采集项 | 实现地址 | 数据来源与格式 |
|---|---|---|---|
| 1 | Brand | 0x2429E0 | Build.BRAND，失败 `BrandErr` |
| 2 | Model | 0x249D68 | Build.MODEL，失败 `ModelErr` |
| 3 | SdkInt | 0x2CA39C/0x240508 | Build$VERSION.SDK_INT，`%d` |
| 4 | Battery | 0x2CA404 | 技术:最大充电电流，`%s:%d` |
| 5 | GPU | 0x2CABF4 | getGlEsVersion，`%s` |
| 6 | MaxVolume | 0x2CB06C | getStreamMaxVolume，`%d` |
| 8 | Camera | 0x2CB31C | 4 个 CameraCharacteristics，`%d:%s` |
| 9 | Sensor | 0x2CBBFC | getMinDelay+toString，`%d:%d:%s` |
| 10 | Kernel | 0x2CC02C | uname → `%s,%s,%s` |
| 11 | Fingerprint | 0x4CEE28 | getprop ro.build.fingerprint |
| 12 | BaseBand | 0x4CEE28 | getprop gsm.version.baseband |
| 13 | LibcInode | 0x2CC134 | libc.so st_ino，`%d` |
| 14 | FileSystem | 0x2CC1F0 | statfs(/vendor/)，`%u:%u:%08x:%08x` |
| 15 | FileFirstTime | 0x2CC2F8 | `%llu` |
| 16 | AppInfo | 0x2CC358 | 包名哈希匹配计数 |
| 17 | AndroidId/OAID | 0x2CC6C4 | OAID 优先，否则 ANDROID_ID；上报仅 `%x` 哈希 |
| — | Build 组合 | 0x241384 | HARDWARE,CPU_ABI |
| — | CPU | 0x242490 | /proc/cpuinfo Processor/Hardware |
| — | secc | 0x290270 | `secc: %d;%d;%d;%d;%d` |
| — | USB/ADB | 0x2CD864/0x2CDCEC | EXTRA_PLUGGED、wifi_adb |
| — | 网关 | 0x24F8A4 | ip route get 8.8.8.8 |
| — | fake token | 0x2CCD20/0x2CCF54 | `x:q:Q:o` + `bt`(boot_id)+`bd`(Brand) |
| — | attestation | 0x4D2578/0x2AB450 | 证书链，type=9 上报 |
| — | 点击统计 | 0x284340/0x284544 | `rate/grp/tll`、`hit/name` |
