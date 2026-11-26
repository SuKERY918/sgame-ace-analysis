# 王者荣耀 12.1.1.1：五个"疑似安全库"的归属与 ACE/TSS 耦合分析（partI）

对象：`libsaf.so`、`libTDataMaster.so`、`libqimei.so`、`libckguard.so`、`libencrypt.so`（均 arm64 ELF，`.symtab` 全部不存在＝已 strip）。方法：pyelftools 解析 ELF，capstone 扫 `.text` 的 `BL` 并按 `.rela.plt` 还原导入名（得出谁调用 dlopen/popen/ptrace/socket），IDA 取函数级证据，全文检索 `tersafe|anticheat|cschannel|frida|xposed|magisk|ptrace|TracerPid|substrate`（五库命中 0）。

## 0. 总览

| 库 | 大小(B) | MD5 | 已定义导出 | JNI_OnLoad | 归属 | 与 ACE 关系 | 风险 |
|---|---|---|---|---|---|---|---|
| libsaf.so | 1,805,128 | 2e286a32… | 2846（`saf*` 162 + `al*` 16） | 无 | OpenAL Soft 1.22.2 改名 | 无关（纯音频） | 无关 |
| libTDataMaster.so | 4,082,392 | f346fb17… | 111 | 0x6d624 | 腾讯 TDM 上报 SDK | 数据面上游（采集 + 读 TSS 目录） | 中 |
| libqimei.so | 539,416 | 62bb50c9… | 11（实质仅 0xa108） | 0xa108 | 腾讯 QIMEI 指纹 SDK | 数据供给（经 Java `GetQIMEI` 喂给 TDM） | 中 |
| libckguard.so | 18,080 | 61517eff… | 11（3 JNI + OnLoad） | 0x11d8 | 腾讯视频 TVK CKeyGuard | 无 | 低 |
| libencrypt.so | 9,920 | 8723ceec… | 11（2 JNI + 2 TEA） | 无 | 腾讯 TGA/Mina OICQ-TEA | 无关 | 无关 |

## 1. 结论

五个库都不是 ACE/TSS 本体，也没有与 libtersafe 的代码级耦合：`libsaf` 是改名后的 OpenAL Soft 音频库，`libTDataMaster` 是腾讯 TDM（数据大师）通用上报 SDK，`libqimei` 是 QIMEI 设备指纹 SDK，`libckguard` 是腾讯视频 TVKPlayer 的 CKey 授权校验，`libencrypt` 是 QQ/TGA 网络层的 OICQ-TEA。交集只在数据面：TDM 采集 OAID/QIMEI/IMEI/序列号/位置，并按 `tss_tmp/`、`ano_tmp/` 这套与 TSS 相同的目录约定读 `comm.dat`、`tss_ano.dat`；QIMEI 经 Java `GetQIMEI` 把标识交给 TDM。检测、云控（`nj./tyf.cschannel.anticheatexpert.com`）与 443 自有协议只存在于 libtersafe。

## 2. 与 ACE 是否同源：逐项检查

| 检查项 | 结果 |
|---|---|
| DT_NEEDED 含 libtersafe | 五库全无；分别为 saf: libdl/liblog/libm/libc；TDM: libz/liblog/libm/libstdc++/libdl/libc；qimei: libandroid/liblog/libz/libm/libdl/libc；ckguard: liblog/libz/libc/libm/libstdc++/libdl；encrypt: liblog/libz/libc/libm/libdl |
| dlopen libtersafe/libTPCore | saf/ckguard/encrypt 无 dlopen 导入；TDM 全 `.text` 无 dlopen 调用点；qimei 仅 0x41f00 通用 `dlopen`+`dlsym`+`dlclose` 取符号包装 |
| `anticheatexpert`/`cschannel` | 0 次（五库） |
| `tersafe` 字样 | 0 次（五库） |
| 443 自有 TCP | saf/ckguard/encrypt 无 socket 导入；TDM 内置 libcurl+OpenSSL 走 HTTPS；qimei 有 socket/connect/epoll 但无硬编码 host |
| `tss_` 命名 | 仅 TDM：`tss_tmp/comm.dat` 0x2e9d1f、`tss_tmp/tss_ano.dat` 0x2e9d30、`ano_tmp/tss_ano.dat` 0x2e9d44 |

qimei 的字符串几乎全经加密表下发，故"无字面量"不能反证"无检测"；只能确认它无 ACE 云控常量、未加载 tersafe。TDM 的 `tss_` 只出现在文件名，不构成对 TSS 导出符号的引用。

## 3. libsaf.so —— 改名后的 OpenAL Soft

- SONAME `libsaf.so`；dynsym 3032 项（2846 已定义、184 未定义）；无 JNI_OnLoad、无 socket/ptrace 导入。
- 身份：`OpenAL Community` 0x13a7b0、`1.1 ALSOFT 1.22.2` 0x13a7c1、`OpenAL Soft` 0x13a7d3、`/etc/openal/alsoft.conf` 0x13ead6。
- 改名：`al*`→`saf*`、`alc*`→`safc*`，162 个 `saf*` 导出（`safcOpenDevice` 0x7d59c、`safSourcePlay` 0x71aa4、`safGetString` 0x77e18、`safcDestroyContext`）；残留 16 个未改名 `al*`（`alMapBufferSOFT` 0x5d7c0、`alAuxiliaryEffectSlotPlayvSOFT` 0x5a228）；内部 C++ 符号仍是 OpenAL 的 `_ZN10ALCcontext…`、`_ZN2al9allocator…`、`PPhaseResampler::init`。
- 无检测、无采集、无网络；`TSS`/`ACE` 字节命中全来自 C++ 符号与音频常量。风险：**无关**。

## 4. libTDataMaster.so —— 腾讯 TDM 上报 SDK

- SONAME `libTDataMaster.so`；`.text` 0x4d150（0x2932e4）、`.rodata` 0x2e0440（0x504a5）；dynsym 325（111 已定义、212 未定义）；JNI_OnLoad 0x6d624；内置 libcurl/OpenSSL/zlib（`# Netscape HTTP Cookie File` 0x2eb4d8、`SSL: certificate subject name '%s' does not match target host name '%s'` 0x2ef350）→ HTTPS 上报，与 ACE 的 443 裸 TCP 不同。
- 归属：导出全为 `Java_com_tdatamaster_tdm_TDataMaster_*`：`TDMInit` 0x64998、`TDMReportEvent` 0x64bd4、`TDMRealTimeReportEvent` 0x65400、`TDMReportLoginV2` 0x660ac、`TDMUploadFileByCOS` 0x667cc、`TDMSetRouteAddress` 0x65f68、`TDMEnableDeviceInfo` 0x65f00、`TDMEnableReport` 0x649d4、`TDMEnableHTTPProxy` 0x65f34、`TDMSetUserAgent` 0x66f24、`TDMGetUID` 0x64a04、`setAppDir` 0x8ff20；C API `tdm_report_event`/`tdm_real_time_report_kv_event`/`tdm_upload_binary_by_cos`；GCloud 插件 `_Z20RegisterGCloudPluginv` 0x6cec4 与导出类型 `_ZTVN6GCloud6Plugin12PluginReportE`。构建路径泄露：`/Users/bkdevops/DevopsAgent/agent/workspace/p-9df4cdec05f242e39586807895cf0514/src/Project/TDM/Source/…`（0x9c750 一带）、NDK `/usr/local/android-ndk-r10e/…` 0x2f79b8。
- 上报地址不写死：`TDMSetRouteAddress` 0x65f68 把 Java 串写入 `ITDataMasterV4` 的 vtable+96（0x66020），默认路由来自游戏配置。
- 隐私开关：键 `TDM_USER_DEVICE_INFO_ENABLE` 0x2e8b1a，判定函数 sub_9C4D4 0x9c4d4，日志 `is enable device info: %d` 0x9c75c；未开启打印 `* Notice :` 0x2e8bb4、`* TDM will report without device info` 0x2e8bbf、`* please call EnableDeviceInfo(true) after user agreed privacy agreement` 0x2e8be5 —— 默认不上报设备信息，需用户同意后显式开启。
- 采集字段：`tdm_qimei` 0x2e61b5、`tdm_qimei36` 0x2e61bf、`tdm_android_qimei` 0x2e61cb、`OAID` 0x2e61dd、`tdm_android_oaid` 0x2e61e2、`tdm_android_imei` 0x2e61f3、`tdm_android_id` 0x2e6204、`mac_addr` 0x2e18fd、`latitude` 0x2e1945、`longitude` 0x2e194e、`tdm_serial_number` 0x2e1b7e、`cpu_name` 0x2e199a、`space_total`/`space_avail` 0x2e1982/0x2e198e、`tdm_dev_uuid` 0x2e09cc、`tdm_network_type` 0x2e0a2a、`tdm_operator` 0x2e0a3b、`GetMSDKOpenid` 0x2e17f5。
- 与 QIMEI：sub_99B88 在 0x99cb8 反射调用 Java `GetQIMEI` 0x2e8a11，签名 `(Landroid/content/Context;)Lcom/tdatamaster/tdm/device/DeviceInfo;` 0x2e8880（helper sub_95E08）——不 dlopen libqimei，由 Java 层回传。
- 与 TSS（最实质一条）：sub_B15D4 0xb15d4 按序探测 `ano_tmp/comm.dat` 0x2e9d0e → `tss_tmp/comm.dat` 0x2e9d1f → `comm.dat` → `tss_ano.dat` → `tss_tmp/tss_ano.dat` 0x2e9d30 → `ano_tmp/tss_ano.dat` 0x2e9d44；`tss_`/`ano_` 目录名与 TSS（libtersafe 的 `tss_*` 命名）同源，二者共用落盘约定（推断：TDM 是 TSS/ACE 的通用上报通道，旧目录名保留兼容）。
- 非检测：`/proc/%d/maps` 0x2e840f 仅出现在 sub_91D7C 0x91d7c（GCloud::Plugin::PluginReport 侧），配 sub_920BC 0x920bc 的 `%lu-%lu %4s %*x %*x:%*x %*d %n` 0x2e841d 解析，用于枚举模块上报；`prctl(16=PR_GET_NAME)` 0xad87c（sub_AD850）只取进程名；全库无 `ptrace`/`TracerPid`/`frida`/`xposed`/`magisk`/`root`/`emulator` 字面量，也无 fork/execl/kill/ptrace 调用点。
- 风险：**中**（采集面宽、与 TSS 共享目录，但属通用上报 SDK 且带隐私开关）。

## 5. libqimei.so —— 腾讯 QIMEI 设备指纹 SDK

- SONAME `libqimei.so`；NEEDED `libandroid/liblog/libz/libm/libdl/libc`；BIND_NOW；dynsym 130、已定义 11（10 项为链接器符号），唯一实质导出 `JNI_OnLoad` 0xa108；`.text` 0x9340（0x63774），IDA 识别 1307 函数。
- 归属：`JNI_OnLoad` 0xa108 在 0x47e40/0x47e48 收尾；注册类 `com/tencent/qimei/uin/U` 0x70121（FindClass 0x47dc4、RegisterNatives 0x47e28，JNIEnv 偏移 1720），方法表 0x84058 共 15 项，方法名压成 1–2 字符（`r` `d` `e` `n` `m` `z` `z2` `o` `x` `u` `p` `b` `r4`），签名可读：`r`=`(ZIILjava/lang/String;I[Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;` 0x70139、`z`=`(Landroid/content/Context;)Ljava/lang/String;` 0x70222、`z2`=`(Landroid/content/Context;I)Ljava/lang/String;` 0x70253、`n`=`(Landroid/content/Context;Ljava/lang/String;[Ljava/lang/Object;)V` 0x701c8、`m`=`(I)Ljava/lang/String;` 0x7020a；另有 `com.tencent.mtt` 0x6f77c、`ts.qq.com` 0x703f0。
- 加固（与 libtersafe 同风格、实现不同）：sub_1EFB8 0x1efb8 按 ID 取串，表基 `qword_84340`、表尾 `unk_6CFA4`、ID 上限 9469（`if (a2 <= 9469)` 0x1f050），全库 280 处调用；控制流平坦化（`JNI_OnLoad` 用 324038292/-1485884695/2056318286 等常量分派，sub_47CA4 同）。与 libtersafe 的 0x90EC0 双层加密表属同一设计思路（推断：同一加固工具链），但表结构与常量不同。
- 防篡改哨兵：`plzdontcrackme856c91firstInstallTime` 0x6f62f 被 sub_256E8（0x26674、0x26680）引用；前半为哨兵、后半为采集键 `firstInstallTime`，静态改串会令该函数行为异常。
- 采集面：`signatures` 0x6f8d8、X.500 OID `2.5.4.3`/`2.5.4.10` 0x6f914/0x6f91c（解析证书 CN/O）、`ro.build.version.sdk` 0x6f767、`java/net/NetworkInterface` 0x6f9a5、`getStackTrace` 0x6fa3e、`currentActivityThread` 0x6fa80、`open_id` 0x6fb01/`wxOpenId` 0x6fb1d/`qqOpenId` 0x6fb26、`/data/data/%s/files/%s` 0x6f656、`/dev/urandom` 0x6f5ed。
- 跨进程取标识：sub_3FC28 0x3fc28（0x16b8 字节）走隐藏 API 直连 provider——`acquireProvider` 0x6fc4a、`(Landroid/content/Context;Ljava/lang/String;IZ)Landroid/content/IContentProvider;` 0x40468、`writeInterfaceToken` 0x3ffc8、`transactNative` 0x40d78、`getAttributionSource` 0x40d08、`readBundle` 0x40354、`readException` 0x40338、`settings` 0x41220，配 `android/app/ActivityThread` 0x40aec（推断：取 OAID/AAID/ANDROID_ID）。
- shell 检查：`popen` 唯一调用点 0x42b80（sub_4297C 0x4297c），`popen(cmd,"r")` 后 `fgets`+`strstr` 比对 sub_1EFB8(4375, 5113) 解出的串；上层 sub_23968 用 `%s && %s %s` 0x23eac、`%s %s` 0x23f94 拼命令。命令片段在加密表内（推断：属性/进程/多开类检查，非 ACE 式 hook 扫描）。
- 其它：`/proc/self/maps` 0x6fe49 存在但无直接 xref（推断由加密表或计算偏移引用）；ChaCha20 常量 `expand 32-byte k` 0x6cf80、Base64 表 0x6cadf/0x6cf3a、`/dev/random` 0x6f5fa；sub_41F00 0x41f00 为通用 `dlopen`+`dlsym`+`dlclose` 包装，未见加载 tersafe。
- 风险：**中**（指纹采集 + 加固 + shell 检查，但无 ACE 云控/无符号级耦合）。

## 6. libckguard.so —— 腾讯视频 TVKPlayer CKeyGuard

- SONAME `libckguard.so`；BIND_NOW；dynsym 30、已定义 11，实质 4 个导出：`Java_com_tencent_qqlive_tvkplayer_vinfo_ckey_CKeyGuard_sGuardInit` 0xef8、`..._sGuard` 0x1014、`..._sVersion` 0xee4、`JNI_OnLoad` 0x11d8；`.text` 0xad0（0x1c54）。
- 归属：Java 包名 `com.tencent.qqlive.tvkplayer.vinfo.ckey.CKeyGuard`（导出名即证据）——腾讯视频 TVKPlayer 的 CKey 校验；`JNI_OnLoad` 0x11d8 仅 `__android_log_print(4,"guardsover","V1.0.001")`（0x121c）后 `GetEnv(…,0x00010004)` 并返回 0x00010004（JNI_VERSION_1_4）。
- 行为：`sGuardInit` 0xef8 取 `getpid()`（0xf6c）→ sub_127C 0x127c 读 `/proc/%u/cmdline`（0x12d0 snprintf、0x12e0 fopen、0x1300 fread，去换行与非可打印字符）写 `unk_14120`；sub_1B64 0x1b64 反射 `getPackageManager`→`getPackageName`→`getPackageInfo`→`sourceDir` 写 `unk_14020`。`sGuard` 0x1014 把入参 byte[] 拷入 1024 字节栈缓冲，调 sub_1F90 0x1f90（大端长度分组摘要/MAC：`*(_DWORD*)&v117[1]=bswap32(a1)` 0x2004、`v117[3]=bswap32(v12)>>16` 0x203c，含 `rand()` 与常量表 `xmmword_2A30`），输入为"数据 + sourceDir + cmdline"，失败输出 `snprintf("0x%x")` 0x114c，成功转 Java String（vtable+1408）。
- 证书链：`GET_SIGNATURES` 0x2839、`signatures` 0x2869、`X.509` 0x2930、`java/security/cert/CertificateFactory` 0x28c2、`generateCertificate` 0x2960、`getPublicKey` 0x29cb、`toString` 0x2a05 —— 取 APK 签名证书公钥参与校验。
- 无网络、无 ptrace、无 dlopen、无 root/模拟器/文件黑名单；唯一环境读取是 cmdline 与 APK 路径，用于绑定安装实例（防重打包），属 DRM/授权。风险：**低**。

## 7. libencrypt.so —— TGA/Mina 的 OICQ-TEA

- SONAME `libencrypt.so`；BIND_NOW；dynsym 21、已定义 11；无 JNI_OnLoad；`.text` 0x890（0xf88）；全库仅 21 条字符串（除导入名/SONAME/`Android` 0x1824 外无业务串、无日志、无域名）。
- 导出：`Java_com_tencent_tga_net_encrypt_MinaNetworkEngine_native_1encrypt` 0x8cc、`..._native_1decrypt` 0xa60、`QtOicqEncrypt` 0xc08（1184 B）、`QtOicqDecrypt` 0x10a8（1756 B）。
- 算法：`native_1encrypt` 0x8cc 用 JNIEnv+1472 GetByteArrayElements、+1368 GetArrayLength、+1536 Release，调 `QtOicqEncrypt(0, src, len, dst, out, &outlen)`，`if (outlen >= 0x10000) outlen = -1`（0x9bc）；`QtOicqEncrypt` 0xc08 按 `a3+10` 估输出（QQ TEA 头：1 B 标志 + 2 B 随机 + 2 B 长度 + 填充），块循环在 0xe80：`v55 ^= prev_cipher` 后 sub_1784 做 16 轮 TEA，结果链式传给下一块（`v21 = v24`）——OICQ-TEA 的 CBC 变体。
- 纯算法库：无检测、无采集、无网络；`MinaNetworkEngine` 指向 TGA（腾讯游戏加速器）网络层。风险：**无关**。

## 8. 检测逻辑盘点

| 能力 | libsaf | libTDataMaster | libqimei | libckguard | libencrypt |
|---|---|---|---|---|---|
| root / su / 模拟器 / 属性黑名单 | 无 | 无 | 无字面量；shell 命令在加密表（推断） | 无 | 无 |
| frida / xposed / magisk / substrate | 无 | 无 | 无字面量；`/proc/self/maps` 0x6fe49、`getStackTrace` 0x6fa3e（推断查注入） | 无 | 无 |
| ptrace / TracerPid | 无 ptrace 导入 | 无 | 无字面量 | 无 | 无 |
| 文件/模块枚举 | 无 | `/proc/%d/maps` 0x2e840f（上报用） | `/proc/self/maps`、`/data/data/%s/files/%s` | `/proc/%u/cmdline` 0x2761 | 无 |

五库都不存在 ACE 那类"扫描 + 云控下发 + CloseXxxScan 开关"的检测体系；唯一有主动检查能力的是 libqimei（shell + maps + 栈回溯），目的是保护自身指纹结果不被篡改。

## 9. 数据采集面与合规

- TDM：OAID/IMEI/ANDROID_ID/QIMEI/QIMEI36/序列号/MAC/经纬度/CPU/存储/网络/运营商/MSDK OpenID（地址见 §4）；默认关闭，靠 `TDM_USER_DEVICE_INFO_ENABLE` 0x2e8b1a + `TDMEnableDeviceInfo` 0x65f00 显式开启，未开启打印隐私提示 0x2e8be5。
- qimei：安装时间、签名证书、系统版本、网卡/IP、宿主包名（`com.tencent.mtt`）、开放 ID、跨进程 provider 取值；未见隐私开关，采集时机由 Java 层决定（推断）。
- ckguard：进程 cmdline + APK 路径 + 签名证书公钥，属安装实例标识。

## 10. 混淆与加固对比（相对 libtersafe）

| 特征 | libtersafe | libqimei | libTDataMaster | libckguard | libencrypt | libsaf |
|---|---|---|---|---|---|---|
| 字符串加密表 | 0x90EC0 双层加密 | 0x1efb8 + 表 0x84340（ID 0–9469） | 无（明文） | 无 | 无（21 条） | 无 |
| 平坦化 | 有 | 有（状态机常量分派） | 无 | 无 | 无 | 无 |
| 反篡改哨兵 | 有 | `plzdontcrackme856c91` 0x6f62f | 无 | 无 | 无 | 无 |
| 导出面 | 71 个 `tss_*` | 仅 JNI_OnLoad | 111 个 Java/C API | 4 个 | 4 个 | 2846 个 |

只有 libqimei 与 libtersafe 共享"加密串 + 平坦化 + 哨兵"的加固风格；TDM/ckguard/encrypt 基本裸编译，libsaf 是第三方开源库改名。

## 11. 汇总表

| 库 | 归属 | 与 ACE 的关系 | 风险 |
|---|---|---|---|
| libsaf.so | OpenAL Soft 1.22.2（al→saf、alc→safc） | 无（纯 3D 音频，无网络/采集） | 无关 |
| libTDataMaster.so | 腾讯 TDM 上报 SDK，含 GCloud 插件 | 数据面上游：采设备字段、按 `tss_tmp/` 读 TSS 缓存、经 Java `GetQIMEI` 取 QIMEI；无云控、无 tersafe 依赖 | 中 |
| libqimei.so | 腾讯 QIMEI 指纹 SDK（`com/tencent/qimei/uin/U`） | 数据供给；加固风格与 tersafe 同源（推断） | 中 |
| libckguard.so | 腾讯视频 TVKPlayer CKeyGuard | 无（DRM/授权；cmdline + APK 路径 + 证书公钥） | 低 |
| libencrypt.so | 腾讯 TGA/Mina OICQ-TEA | 无（纯加解密，零业务串） | 无关 |
