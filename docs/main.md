# 王者荣耀（Honor of Kings）12.1.1.1 反作弊 SDK 逆向分析报告

分析对象：`王者荣耀_12.1.1.1.apk` 内置的 ACE/TSS 反作弊 SDK（`libtersafe.so` 及其配套库）
分析方式：静态逆向（IDA Pro + Capstone + PyElfTools 自建工具链），无动态运行
报告日期：2026-11-26

---

## 1. 结论摘要

1. **客户端只采集、判定在服务端。** 全库没有任何"本地直接封号/杀进程/删文件"的反制逻辑：所有命中都走统一的"事件 + 字段上报"通道（`sub_1F2640` / `sub_1F0148` / 上报容器），最终由服务端 ACE 判定。这与旧分析的结论一致，本轮给出了完整的代码证据链（第 9 章）。
2. **检测面 = 41 个特征模块 + 9 项具名检查任务 + 101 条云控规则算子 + 88 路 ioctl 命令。** 41 个模块由 `0x27FAE4` 统一构造注册（经 `.rela.dyn` 重定位调用，无代码 xref），覆盖 Root、模拟器、云手机、Hook、调试、设备伪造、黑产应用、包扫描、反自动点击等；9 项检查任务由 `0x27019C` 注册进 `ctx+16`（4.9），任务名同时就是云控开关名。
3. **三族"关闭开关"是最大的结构性弱点。** 游戏/云控可通过文本命令在运行期关闭五类检测（`CloseUserTagScan` / `CloseEmulatorScan` / `CloseAntiProfiler` / `CloseCloudPhoneScan` / `CloseAntiBlackModule` → `ctx+0x3B3..0x3B7`），还可用 `CloseDevInfoCollect:<hex>` 按位关闭任意设备信息采集项（`ctx+0x3BC` 位图）。这是"检测可被绕过"的第一现场：绕过不需要改一行代码，只需要发一条命令。
4. **全字符串加密 + 全函数控制流平坦化 + 运行时代码保护（libtprt） + 热更新检测模块** 构成四层静态对抗：字符串表 2868 条记录用 100 个不同参数的解密封装；内联串 945 条用第二套编码；关键函数（init、ioctl、注册表、云手机判定等）全部平坦化成状态机；`libtprt.so` 提供 OBJ_VM 与 inline-hook 表（`g_tprt_pfn_array` 里直接是 ARM64 指令字节）；而加密器、`ischeatpacket`、`get_report_data`、甚至 `JNI_OnLoad` 本体都可以被运行时下载的 `files/libtersafeupdate2.so` 接管（`qword_55E8E0` 就是它的函数表，删除该 so → 发包直接退回明文）。
5. **检测能力集中在"环境指纹"而非"行为"。** 设备信息 17 槽（Build 5 字段、GPU 只取 GLES 版本、Camera/Sensor/USB/内核/属性目录）、Root 15 项、云手机 6 位聚合、Frida 7 路、Xposed/Substrate 名单、GP3/GP4/GP6 内存与调试对抗、Key Attestation、时间序列反自动点击。判定的"证据"几乎都是可被改机工具伪造的静态特征——因此 SDK 同时采集"自洽性"证据（fake token 的 `x/q/Q/o` 交叉校验、boot_id、证书 MD5、代码段 CRC）。
6. **自校验是"抽样 + 可配置"，不是全覆盖。** `various_opcode` 单次只验 20 槽中的 1 槽、`opcode_scan` 只在差异页 ≤10% 时才崩溃、`cert3` 的唯一硬判据是证书 MD5（可被 `official_cert_md5` 为空或 `cal_cert_md5` 关闭短路）、`cc2` 的路径拼接存在系统性缺陷、`elf_hook_scan` 运行槽是 `RET` 空桩、`shell_checker` 没有特征库。换句话说，改代码/换 so 的"被发现概率"高度依赖采样与时序，而不是确定性判定。
7. **真正属于 ACE 的只有两个库。** APK 里 130 多个 so 中，反作弊相关只有 `libtersafe.so`（检测主体）与 `libtprt.so`（OBJ_VM/代码保护）；`libTPCore-master.so` 是录屏组件，`libsaf` 是改名后的 OpenAL Soft，`libTDataMaster` 是 TDM 上报 SDK、`libqimei` 是 QIMEI 指纹 SDK、`libckguard` 是腾讯视频的 CKey DRM、`libencrypt` 是 OICQ TEA——后五个与 ACE 无代码级耦合（3.4 节）。
8. **真机验证的结果（第 12 章）**：`ano_tmp` 里的 `ob_x`/`ob_cs2`/`comm` 每次启动都会被重新拉取（删除后 35 秒内原样恢复、MD5 一致）；其中 `a32/a64.dat` 是**签名的原生代码模块**（RSA-2048 + MD5，运行期验签通过后在堆内存里被 `libtprt` 装载执行），意味着**新检测逻辑可以随云控下发而不改 `libtersafe.so`**；注入后进程会在 8–65 秒内以 `free()` 非法指针自杀（不是 `kill`），且 root 也读不了进程内存。
9. **唯一被完整打通的明文通道**：ACE 的上报/下发走**裸 TCP**，端口 443 只是伪装（全库无 SSL 导入）。抓包中唯一非 TLS 的流，其目的地 `117.89.177.167` 正是内置主机名 `nj.cschannel.anticheatexpert.com` 的解析结果——静态分析与真机观测在同一点闭环。

---

## 2. 样本与方法

### 2.1 样本

| 文件 | 大小 | MD5 | 说明 |
|---|---|---|---|
| `libtersafe.so` | 5,598,144 | `e06344e0b5f6b09d13820c625fa3a123` | 检测主体（本报告核心） |
| `libtprt.so` | 1,829,288 | `5bcc75d7e371d1c1df190737bf607f83` | 运行时代码保护，仅导出 unwind 接口 |
| `libTPCore-master.so` | 6,729,808 | `e805973aa79263b6e749058eada881ab` | 录屏/分享（ffmpeg），非反作弊 |
| `libTDataMaster.so` | 4,082,392 | `f346fb17bfa09f305a738f4d3e958b38` | 数据上报辅助（未展开） |
| `libqimei.so` | 539,416 | `62bb50c92d64eb5160ecce4cdfed63e5` | 设备标识（OAID/QIMEI） |
| `libsaf.so` | 1,805,128 | `2e286a328f1abe7e7a18c05b0abb51e1` | 未展开 |
| `libckguard.so` | — | `61517eff18b414604907d5d3df2d3bdf` | 未展开 |
| `libencrypt.so` | — | `8723ceecbd169ecd432ad2de39b91dab` | 未展开 |
| `libmain.so` | — | `88288bdf102713b0a7d5d41c377102fd` | 游戏入口壳 |

APK 共 1567 个 entry，`lib/` 下 144 个 so（arm64 134 + armeabi-v7a 10）。

### 2.2 分析方法

`libtersafe.so` 被 strip（无 `.symtab`），只保留 `.dynsym`（288 项，其中 217 项为 libc 导入、71 项为本库导出）。函数边界用 `.eh_frame_hdr` 恢复：

- `.eh_frame_hdr` 头 `01 1b 03 3b`，`eh_frame_ptr` 为 sdata4 pcrel（0x1FCE8 → `.eh_frame` 0x12BF20），`fde_count = 0x3F9C = 16284`；表从偏移 12 开始，每项 `(sdata4 loc, sdata4 fde)`，`loc` 以 0x10C234 为 datarel 基准。
- 得到 16284 个函数起始地址（0x1B6C20..0x50DE6C）。IDA 报 17780 个函数，差额是无 unwind 信息的小函数/桩。

字符串体系（本报告 80% 结论的入口）有两套：

| 体系 | 规模 | 编码 | 解密位置 |
|---|---|---|---|
| 主字符串表 | 2868 条记录（明文 60586 字节内） | 记录格式 `[key][len^key][cipher][check]`，`p[j]=c[j]^((k+j mod 2^32 递推)&0xFF)`，参数 (E,C) 共 98 组 | 100 个解密封装函数（0x4E64D0..0x4ED3CC），每函数固定一组 (E,C)，索引由调用方 `MOV W0,#imm` 传入 |
| 内联字符串 | 945 条 | `p[i]=c[i]^((k+i)&0xFF)`，k 每解码器固定（0x8A/0x91/0xC6/0xE8/0xAB…） | 262 个内联解码器，调用点 992 处 |

调用图：`out/cg.json`（12434 个函数）+ `out/calls.pkl`（58551 条内部调用、7236 条导入调用）+ `out/pltmap.pkl`（PLT→符号）。所有结论均可用 `tools/look.py`、`tools/xref.py`、`tools/icall.py` 复现。

---

## 3. 组件与协作

### 3.1 libtersafe.so 的真实构成

- `DT_NEEDED` 只有 `liblog / libc / libm / libdl`。**没有** libc++、没有网络库、没有 JNI 之外的运行时。
- 导出 71 个符号：`tss_sdk_init/ioctl/encryptpacket/decryptpacket/ischeatpacket/setuserinfo(_ex)/setgamestatus/rcv_anti_data/regist_tss_info_receiver/gen_session_data/set_token/wait_verify/dec_tss_info`、`tss_get_report_data(1..4)`、`tss_del_report_data(1..4)`、`tp2_*` 系列、`TssSDKInit/InitEx/SetUserInfo(WithLicense)/OnPause/OnResume/GetReportData(1..4)/DelReportData(1..4)/OnRecvData/OnRecvSignature/RegistInfoListener/Ioctl/IoctlOld/Free/ForExport`、`GetTssExportFunc2`、`JNI_OnLoad`、`TssJavaMethod_SendCmd`。
- 注意：`tss_enable_get_report_data` 等"看起来是导入"的符号其实是**本库导出**（default visibility），PLT 调用是符号预占而非外部依赖——这一点纠正了旧分析中"存在外部依赖"的猜测。

### 3.2 libtprt.so：OBJ_VM 与二进制混淆恢复运行时

- 规模：11117 个函数、镜像 0x1C2E50；版本串 `4.0.9.33667_cn`（0x16AA70，18 处引用）。`dynsym` 151 项，**defined 仅 8 个**。
- 导出：`unwind_xx_info_query` 0xE7CB4、`unwind_xx_ioctl` 0xE7CF0、`JNI_OnLoad` 0x6B594、`g_tprt_pfn_array` 0x1B7160（.data）、`g_tprt_ori_array` 0x1BF230（.bss，运行期填原函数指针）。
- 功能开关就在版本串后面：`"  __ENABLE_OBJ_VM__"`（0x16AA7F）与 `"  __ENABLE_BINOBF_RECOVER__"`（0x16AA93）——"对象虚拟机"与"二进制混淆恢复"。libtersafe 的 `ob_normal.zip / ob_normal_ver.zip / ob_normal_64.zip`（§4.3 的 `ob_normal` 模块）正是喂给这套 VM 的代码包。
- 它装载的到底是什么（2026-11-26 的 blob 专项分析修正）：`sub_1528B0(obj, payload, secname, name, out)` 是 `.img` 模块的解析器（要求段名含 `.img`），`sub_151FF8` 负责符号绑定（未知符号整段拒装），`sub_15321C(obj, 0x10000) + 0xFFC0` 划出 64 KB 的转发地址空间。段载荷解密后是**带逐字混淆的 ARM64 原生代码模块**（可解出 `stp x28,x19,[sp,#-0x20]!`、`b`、`ret` 等合法指令，导入表含 `_Znwm/_ZdaPv/memset`），所以"OBJ_VM"更接近**装载器 + 符号解析 + 调用转发**，而不是逐条解释字节码。详见 §12.10 与 `partJ_blob.md`。
- 导出函数只是 VM 入口壳：`unwind_xx_ioctl` 0xE7CF0 先按 `cmd==1/2` 用 `CSEL` 选出两个常量，再从 `.data` 的 `off_1B6FF0` 跳转表派发；`JNI_OnLoad` 0x6B594 同样先引用两个开关串、`GetEnv`，末尾 `BR X9` 间接跳转（两者都被平坦化）。
- 代码不在 `.text`：`.tptext`（0x16A928，0x148 字节）是独立可执行段；`g_tprt_pfn_array`（0x1B7160，在 .data）里存的是 **ARM64 指令字节**（首项 `A9A9CA3C` = `STP X28,X18,[X17,#0x98]`），`g_tprt_ori_array` 在 .bss 保存被替换前的原函数指针 —— 这是"inline hook 表 + 代码镜像"的组合，不是普通数据数组。
- 自带解压与编码：`.rodata` 有 `invalid distance code`、`unknown zip result code`（zlib inflate 错误串）与标准 Base64 字母表（0x174E5C），用于把加密代码/数据还原进内存——这解释了"文件里搜不到检测逻辑"的原因。
- **反向依赖**：`.rodata` 0x13635C 处连续三条字符串 `libtersafe.so`、`TssSDKIoctl`、`TssSDKIoctlOld` —— tprt 知道怎么 dlopen tersafe 并直接调它的 ioctl。即"保护运行时 → 反作弊 SDK"存在反馈通道，tprt 检出异常可以回灌给 tersafe，而不是另开一套上报。
- 能力面（导入）：`socket/connect/getaddrinfo/sendto/recvfrom/select`、`fork/execv/kill/sigaction`、`mmap/mprotect/madvise`、`dlopen/dlsym/dladdr`、`symlink/rename/mkdir` —— 可改内存、可起子进程、可自行发包。
- tersafe 对它的用法（懒加载，双路径）：
  - `sub_238E70`：`sub_23D5E4(&unk_977AF,8,buf)` 取开关 → `byte_55F151` 单次 → `sub_22D820()+sub_22DA98()` 判启用 → `dlopen("libtprt.so", RTLD_LAZY)` → `dlsym("unwind_xx_ioctl")` 存 `[ctx+976]`。
  - `sub_2BA5FC`：`dlopen("tprt"/"libtprt.so")` → `dlsym("unwind_xx_info_query")` 存 `[ctx+72]`，失败即 `dlclose`。
- 结论：libtprt 不是"顺手带的反调试库"，而是**装载并运行云端下发模块的运行时**：磁盘上只有 VM 入口与混淆代码，真正的检测模块（`.img`）运行期从 `ano_tmp` 读入、验签、解密、绑定符号后执行。对分析的直接含义——tersafe 只用到它的 unwind 接口，**libtprt 缺失时相关检查静默降级**（找不到指针就不查，不报错），这也解释了"删掉 libtprt.so 能降低一部分检出"。

### 3.3 libTPCore-master.so：与反作弊无关

`dynsym` 4803 项（4502 defined），NEEDED 含 `libz/libEGL/libGLESv2/libOpenSLES/libandroid/libjnigraphics`，大量 `av_*/ff_*/sws_*` 符号 → 游戏内录屏/分享组件。分析 ACE 时可排除。

### 3.4 伴生库的真实身份（`libsaf`/`libTDataMaster`/`libqimei`/`libckguard`/`libencrypt`）

APK 里另有五个体积不小、容易被误当成"反作弊组件"的 so。逐个验过后结论一致：**没有一个是 ACE/TSS 本体，与 `libtersafe.so` 也没有代码级耦合**。

| 库 | 真实身份 | 关键证据 |
|---|---|---|
| `libsaf.so` | 改名后的 **OpenAL Soft 音频库** | `1.1 ALSOFT 1.22.2`(0x13a7c1)、`/etc/openal/alsoft.conf`(0x13ead6)、16 个残留 `al*` 符号（如 `alMapBufferSOFT` 0x5d7c0）；NEEDED 只有 `libdl/liblog/libm/libc` |
| `libTDataMaster.so` | 腾讯 **TDM 上报 SDK** | `TDMSetRouteAddress`(0x65f68) 路由由 Java 注入、库内无域名；上报走内置 libcurl/OpenSSL（`SSL: certificate subject name '%s' does not match target host name '%s'` 0x2ef350）；采集字段 `tdm_android_oaid`(0x2e61e2)、`tdm_android_imei`(0x2e61f3)、`tdm_serial_number`(0x2e1b7e)、`latitude`(0x2e1945)；默认关闭，需 `TDM_USER_DEVICE_INFO_ENABLE`(0x2e8b1a) + `TDMEnableDeviceInfo`(0x65f00)，未开启时打印 `* please call EnableDeviceInfo(true) after user agreed privacy agreement`(0x2e8be5) |
| `libqimei.so` | 腾讯 **QIMEI 指纹 SDK** | 注册类 `com/tencent/qimei/uin/U`(0x70121)、方法表 0x84058（15 项、方法名压成 `r/z/z2/n/m`）、串解密器 `sub_1EFB8`（表基 `qword_84340`、ID 上限 9469）、哨兵串 `plzdontcrackme856c91firstInstallTime`(0x6f62f)、`popen` 唯一调用点 0x42b80、`acquireProvider`(0x6fc4a)/`transactNative`(0x40d78) 跨进程取标识 |
| `libckguard.so` | 腾讯视频 TVKPlayer 的 **CKey 授权（DRM）** | 仅 4 个导出；`sGuardInit`(0xef8) 读 `/proc/%u/cmdline`(0x2761) + 反射取 `sourceDir`；`sGuard`(0x1014) 做摘要/MAC；配 `GET_SIGNATURES`/`getPublicKey` 防重打包；无网络 |
| `libencrypt.so` | TGA/Mina 的 **OICQ TEA** | 全库仅 21 条字符串；`QtOicqEncrypt`(0xc08) 走 16 轮 TEA 的 CBC 变体 |

- 全文检索 `tersafe|anticheat|cschannel|frida|xposed|magisk|ptrace|TracerPid|substrate` 在这五个库里**命中 0**；`DT_NEEDED` 中也没有 `libtersafe`；capstone 扫 `libTDataMaster` 全 `.text` 无 `dlopen` 调用点，`libqimei` 唯一的 `dlopen` 只是 0x41f00 的通用 `dlopen`+`dlsym` 取符号包装。
- 唯一的真实交汇点在**数据面**：`libTDataMaster` 的 `sub_B15D4`(0xb15d4) 按序探测 `ano_tmp/comm.dat`(0x2e9d0e) → `tss_tmp/comm.dat`(0x2e9d1f) → `tss_tmp/tss_ano.dat`(0x2e9d30) → `ano_tmp/tss_ano.dat`(0x2e9d44)，`tss_`/`ano_` 目录名与 `libtersafe` 的 `tss_*` 命名同源（推断：TDM 被当作通用上报通道，旧目录名留作兼容）；QIMEI 则是 Java 侧反射 `GetQIMEI`(0x2e8a11) 回传，不是 `dlopen libqimei`。
- `libqimei` 是五个库里唯一带加固与主动检查的：注册类压缩方法名、9469 项串表、平坦化常量（324038292/-1485884695/2056318286）、`plzdontcrackme…` 哨兵、`popen` 拼命令自检——风格与 `libtersafe` 同源（推测同一加固工具链），但表结构与常量完全不同，且它的产物是"设备指纹"而非"作弊判定"。

**结论**：分析 ACE 只需 `libtersafe.so` + `libtprt.so` 两个文件；其余库属于"周边 SDK"，它们和 ACE 的关系是"同属一个 App 的不同 SDK"，不是"ACE 的组成部分"。

---

## 4. SDK 框架

### 4.1 初始化流程（`tss_sdk_init` @0x1BF4D0）

函数被平坦化成"比较常量 + 跳转"的状态机（入口处即 `mov w8,#0xc07b; movk w8,#0x61ca,lsl#16; cmp w8,w26; b.ge ...`）。按实际调用顺序还原：

1. `sub_20E9FC()` → `pthread_once` 构造 264 字节任务对象（vtable `off_513AD8`、`+128=1800` 超时/周期、`+16=0x80000` 即 512KB 线程栈）→ `sub_4CD664(cfg)` 启动后台任务线程（一次性，受 `ctx+8` 保护）。
2. `tss_enable_get_report_data()`（PLT 调用自身导出）→ 打开上报数据通道。
3. `sub_4ED2AC(1198)` → 解密字符串表 idx 1198（版本/标识串），结果存栈上 `v19`。
4. `sub_4E5034(buf, 1024)` → 以字符串表 idx 1184 为格式串，把 `1024` 格式化进 `buf`（`sub_4EC2F0(1184)` → `sub_4A4998`）。
5. 校验 `byte_55E3E8`（初始化闸门）与入参 `a1 != 0`（回调/上下文），任一不满足走 **`getpid()` + `kill(pid, 9)` 自杀分支**（0x1BFC10/0x1BFC18）。
6. `byte_55E8D4` 判定：为 0 视为"被篡改/异常"，同样落入异常路径；正常路径将其置 1。
7. `sub_2DAD4C()` 取全局上下文 → `sub_239BC0(ctx)`（初始化模块表/锁）→ `sub_4E5284(ctx)`（初始化调试开关 'D'）→ `sub_4E5850(ctx)`（初始化配置）。
8. `memset` 清缓冲 → `sub_4E78DC(idx)`（**通用字符串解密例程**，即 `p=c^(k+j)`、`k=(k+j)^0x12+3` 的参考实现，全库 30 处调用）→ `sub_4A54DC`（vsnprintf 风格格式化，515 处调用）→ `tp2_sdk_ioctl(...)`（把控制权交给命令层）。

结论：初始化本身不跑任何检测，只建上下文、起线程、开上报；检测由被注册的 41 个模块在各自时机执行。

### 4.2 全局上下文与关键偏移

上下文由 `sub_2DAD4C()` 惰性创建（全局单例）。逆向中反复命中的偏移：

| 偏移 | 含义 | 证据 |
|---|---|---|
| `+0x3AC` | 外部接管模块指针（`tss_sdk_ioctl` 首查 `[+0x3AC]`，非空则走接管 stub） | 0x1BCF84 入口 |
| `+0x3B3` | 关闭 UserTag 扫描 | `CloseUserTagScan` → `STRB #1` |
| `+0x3B4` | 关闭模拟器扫描 | `CloseEmulatorScan` |
| `+0x3B5` | 关闭反性能分析（AntiProfiler） | `CloseAntiProfiler` |
| `+0x3B6` | 关闭云手机扫描 | `CloseCloudPhoneScan` |
| `+0x3B7` | 关闭黑产模块扫描 | `CloseAntiBlackModule` |
| `+0x3BC` | 设备信息采集**位掩码**（32 位，按位关闭采集器） | `CloseDevInfoCollect:<hex>` → `ORR` |
| `+956` | 采集掩码的只读副本（各采集器读它） | `*(_DWORD*)(ctx+956)` |
| `+72` | `unwind_xx_info_query` 函数指针 | `sub_2BA5FC` |
| `+976` | `unwind_xx_ioctl` 函数指针 | `sub_238E70` |
| `+926` | frida_scan 门控字节 | 0x2A9040 |
| `+333` | 云手机品牌命中"防重报"标志 | 0x2B9D98 |
| `+2169` | 反自动点击一次性封口 | 0x284544 |
| `+8` | 线程已启动标志 | `sub_4CD664` |
| `+0x50` | 外接模块的 `get_report_data` 槽 | `tss_get_report_data` |
| `+132` | job 的 `sc_dlp` 派生布尔 | 0x20EEB0 |
| `+133` | job 一次性初始化标志 | 0x20EE2C |
| `+104` / `+112` | 触摸采样计数 / 512 个 `int32` 间隔缓冲（0x800 字节） | 0x2840B8 |
| `+10237` / `+10238` | `RecordTouchEnable` 开关 / 采样状态 | 0x2B4B94 |
| `+0x70` / `+0x74` | GP6 通道号（-1/1）/ 错误码 | 0x268C14/0x269B64、0x269658 |
| `+1032` / `+1040..1048` | module2 的模块大小 / Zygisk 校验字段 | 0x2AFD4C |
| `+0x84` | `txt_seg_crc`（`opcode_scan` 写入的 `.text` 段 CRC，取反存储） | 0x28E140 |
| `+940` | "本进程内校验已在进行"标志（重入保护） | 0x2A96AC |
| `+120` | 轮转计数器（`*(ctx+120)&7` 选槽组） | 0x2A9704 |
| `+0xD4` / `+0xD8` | `info` 上次采集的 uid / 时间戳（2 小时窗口判据） | 0x2DE01C |
| `+76` | `cert3` 行为码（0/2/4/5 → 不同上报路径） | 0x2AE0C4 |
| `+0x48` | `pe_rep`/`env_chk` 共用的"本轮已执行"复位位 | 0x2907F4 |

### 4.3 41 个特征模块（`0x27FAE4` 注册）

`0x27FAE4` 本身**没有任何代码 xref**：它只通过 `.rela.dyn` 的 `R_AARCH64_RELATIVE`（`r_offset=0x514C40`, `addend=0x27FAE4`）被写进 `.data.rel.ro` 的函数指针槽，再由上层表驱动调用。这种"重定位即注册"的手法使静态交叉引用完全失效。

注册函数 `sub_222284(ctx, obj, name, enabled, flag2)`：栈上构造 0x40 字节节点 `{obj; name[32]; enabled; flag2}`，`sub_2222F4` 追加到 `ctx+8` 的 vector。名称走两套解密（表格 idx 或内联 0xAB 递增 XOR）。**`enabled`/`flag2` 只是 per-module 字节开关（`+0x38`/`+0x39`），不是运行槽**；真正的运行槽是对象 vtable 的第 3 项。

上表由 `tools/regs2.py` 机械抽取：在 `0x27FAE4..0x280440` 扫到 **40 个 `BL sub_222284` + 1 个尾调用 `B sub_222284`（0x280318）= 41 次注册**（站点 `0x27FB84..0x280318`），对每个站点回溯"构造调用 → 名字解密调用（`MOV W0,#idx` + `BL 0x4Exxxx`）"序列得到 ctor 与名字索引，再用 2868 条字符串表逐条校验名字。三个名字不走解密器而由内联 0xAB 解码写入栈缓冲：`SP+0x08`=`inf_sca`(8B)、`SP+0x10`=`win_data_sync`(14B)、`SP+0x38`=`sdt_chk`(8B)。`file`/`wb_new_sync`/`anti_cheat_open_id`/`HistoryOpenID` 四个模块共用基座 `sub_1DB038(obj, flag)`（8 组三元组初始化 + 环形小表写入），差异只在传入的 vtable。

| # | 模块名 | 构造 | 职责 |
|---|---|---|---|
| 1 | `auto_defence3` | `sub_258C50()` | 自动防御（运行时综合判定） |
| 2 | `antiemulator` | `sub_294B30` | 模拟器检测（QEMU 后门、品牌位图） |
| 3 | `tablet` | `sub_29C3AC` | 平板/设备形态 |
| 4 | `user_tag` | `sub_29B444` | 用户标签（读 `ctx+0x3B3`） |
| 5 | `info` | `sub_2DDE78` | 设备信息汇总 |
| 6 | `anti_virapp` | `sub_286F80` | 反病毒/风险应用 |
| 7 | `ob_normal` | `sub_1D9050` | 常规混淆数据通道 |
| 8 | `opcode_scan` | `sub_28D9A0` | 指令/opcode 扫描（名字由 `sub_28DB54` 提供） |
| 9 | `anoscan` | `sub_29FA2C` | ANO 扫描（自定义检测框架） |
| 10 | `FakeToken` | `sub_2C8984` | 伪造 token 检测 |
| 11 | `ksat` | `sub_2AAA40` | 密钥/证书证明（attestation） |
| 12 | `file` | `sub_1DB038` | 文件完整性（清单来自 `comm.dat`） |
| 13 | `black_app` | `sub_29E460` | 黑产应用名单（64 条内置） |
| 14 | `wb_new_sync` | `sub_1DB038` | 白名单同步 |
| 15 | `anti_clicker` | `sub_283C10` | 反自动点击（触摸序列） |
| 16 | `anti_clicker2` | `sub_2B37B4` | 反自动点击（第二套） |
| 17 | `anti_cheat_open_id` | `sub_1DB038` | OpenID 反作弊 |
| 18 | `trusted_scanner` | `sub_2BD8E4` | 可信扫描器（属性指纹） |
| 19 | `inf_sca` | `sub_29A600` | 信息扫描（Binder 直连 PackageManager） |
| 20 | `win_data_sync` | `sub_250F64` | 窗口数据同步（内联名） |
| 21 | `wb_daemon` | `sub_280404` | 白名单守护进程（ACE Keeper） |
| 22 | `cc2` | `sub_2829A8` | APK 中央目录 CRC 与磁盘 `.so` 比对 |
| 23 | `gp5` | `sub_260BC0` | GP5 保护（线程名/调试） |
| 24 | `info_publisher` | `sub_4CB94C` | 上报发布器（观察者挂接点） |
| 25 | `HistoryOpenID` | `sub_1DB038` | 历史 OpenID（`tdm_cache.dat`） |
| 26 | `frida_scan` | `sub_2A6940` | Frida/注入检测（第 7.3 节） |
| 27 | `various_opcode` | `sub_2A9370` | 自身 `.text` 随机槽哈希校验 |
| 28 | `cs_vm` | `sub_2ADCC0` | 云端虚拟机数据（`tss_cs2.dat`） |
| 29 | `process` | `sub_293D58` | 进程扫描（64 条名单） |
| 30 | `module2` | `sub_2AEEA8` | 模块/ELF 检测（maps 逐行） |
| 31 | `anti_root` | `sub_28E530` | Root 检测（第 7.1 节） |
| 32 | `elf_hook_scan` | `sub_28EA9C` | ELF 钩子扫描（运行槽为 `RET` 空桩，见 7.3） |
| 33 | `shell_checker` | `sub_2BA160` | 壳/加固状态回传（无特征库） |
| 34 | `cert3` | `sub_2AE04C` | 签名证书校验（`official_cert_md5`） |
| 35 | `live` | `sub_2AC258` | 直播/投屏环境（对象 0x120，vtable `0x5152E8`） |
| 36 | `cps_new` | `sub_2B5138` | 云游戏/串流 |
| 37 | `cps_new3` | `sub_2B5138` | 云游戏第三套（名字 idx 54795，vtable `0x515590`） |
| 38 | `collect_apk` | `sub_2B1DA4` | 已装 APK 采集（30 天 / 40 MB 阈值） |
| 39 | `pe_rep` | `sub_28F5C4` | 上报策略 |
| 40 | `sdt_chk` | `sub_2BE348` | 安全数据校验（名字由内联 0xAB 解码写入栈缓冲 `var_8`） |
| 41 | `env_chk` | `sub_28FD5C` | 环境总检（名字 idx 16483） |

`enabled` 实参有 1 / 0 / `(cfg&1)==0` / `(v34&1)` / `(v58&1)` 五种形态 → 部分模块默认关闭，由云控配置决定是否启用。

### 4.4 命令面

**数字命令**：`tss_sdk_ioctl`（0x1BCF84，0x11E8 字节）是 88 分支跳转表（`cmd` 1..88，`jpt_1BD084` 位于 .rodata 起始 0x90EC0，`sdata` 相对 0x1BD078）。其中有独立处理器的 cmd：1-10、14-18、23-28、30-42、46、47、49、51、54、56、58-60、70、72-77、79、88；其余（11-13、19-22、29、43-45、48、50、52、53、55、57、61-69、71、78、80-87）落默认分支 0x1BD7C4，转 `sub_1CA680(cmd,a1..a4)` 扩展实现。

`tools/cmds.py` 把跳转表与"每个 case 内解密出的字符串"机械对齐，可直接看出各命令的语义（完整输出可重跑该脚本）：

| cmd | 处理地址 | 可识别字符串 / 行为 |
|---|---|---|
| 5 | `0x1BD5FC` | `shell_crash` |
| 47 | `0x1BD718` | `gcloud_connector_t` |
| 54 | `0x1BD194` | `OpenMrpcsBridge` / `MrpcsBridgeCmd` / `CloseMrpcsBridge`（`sub_4EBF90(0xABCD)`） |
| 56 | `0x1BD0F0` | 命令自描述表 `ms_va` / `\|` / `name` / `desc` |
| 58 | `0x1BD2E0` | `\|` / `name`（`sub_4E89A8(0x85)`） |
| 77 | `0x1BD0BC` | `open_log`（`sub_4EA5C0(0xD712)`） |
| 4/5/88 | — | 先检查入参字符串首字节 |
| 6/15/16/77 | — | 先 `sub_22D820()` 取配置管理器 |
| 7 | `0x1BD49C` | `sub_489248(0x521510, 0x140)` 清一块全局缓冲 |
| 42 | `0x1BD2B8` | `sub_4E5284`/`sub_4E5810` 并置全局=1 |
| 11-13 等 41 个 | `0x1BD7C4` | 统一转文本命令解析器（见下） |

**文本命令**（ioctl 尾部 0x1BD7FC..0x1BE12C，参数为字符串）共 22 类，是 SDK 的真实控制面：

| 命令 | 作用 |
|---|---|
| `IsEnabled` / `IsEnabled_1:` / `IsEnabled_0:` | 查询/设置某检测开关，`%d` 写回 |
| `CloseUserTagScan` | 关用户标签（`ctx+0x3B3`），调试别名 `!cuts` |
| `CloseEmulatorScan` | 关模拟器（`+0x3B4`），别名 `!ces` |
| `CloseAntiProfiler` | 关反性能分析（`+0x3B5`），别名 `!cap` |
| `CloseCloudPhoneScan` | 关云手机（`+0x3B6`），别名 `!ccps` |
| `CloseAntiBlackModule` | 关黑产模块（`+0x3B7`），别名 `!cbm` |
| `CloseDevInfoCollect:<hex>` / `...Ex:` | 按位关设备采集（`+0x3BC`），调试别名 `!cdic:%x` |
| `OpenMrpcsBridge` / `MrpcsBridgeCmd:` / `CloseMrpcsBridge` | 模块下发桥（0xABCD/0xABDF/0xABF0） |
| `ilc_open_pipe` / `ilc_close_pipe` / `ilc_recv_pipe` / `ctl:ilc_open_pipe` | ILC 管道通信 |
| `regist_mtp_info_receiver` | 注册 MTP 信息回调 |
| `dec_tss_info:` / `SetSecToken:` / `SetHWDevice` | 解密信息/安全 token/硬件设备号 |
| `CountryCode:` / `CountryCode:CN` / `SetLocaleId:` | 地区/语言 |
| `UserAgreedPS` | 隐私协议（写 `u_a_ps`） |
| `CDNHost:` / `SetChannelHost:` / `SetChannelBuiltinIp:` | 通道/域名/内置 IP |
| `GetSdkAntiData` / `StartSecScan` / `NeedRequestApkList` | 取反作弊数据/启动扫描/请求下发 APK 列表 |
| `AddTouchEvent:` / `AddAnoTouchEvent:` | 注入触摸样本（反自动点击的输入源） |
| `Logout` / `EnableGameReport` / `EnabledConnector:` / `InvokeCrash:` / `IsEmulator2` / `OpenVerificationLog` | 杂项控制 |

**关键结论**：五个 `Close*Scan` 与 `CloseDevInfoCollect` 的处理逻辑完全同构——先 `sub_4E5284(); sub_4E5F10(ctx,0x44)` 判"是否调试态"（字符 `'D'`），是则额外用 `sub_4E5710(ctx,"!cuts"/"!ces"/"!cap"/"!ccps"/"!cbm")` 记别名；然后 `sub_2DAD4C()` 取上下文、`STRB #1` 置位。也就是说：**这套 SDK 主动提供了一条"官方后门"式的检测开关**，开关值只存在内存里，不做任何校验、不区分调用者身份。任何能调到 `tss_sdk_ioctl` 的代码（游戏本体、云控下发、甚至被注入的模块）都能关掉检测。

### 4.5 包加密（`tss_sdk_encryptpacket` @0x1B9D54 / `decryptpacket` @0x1BA0D4）

- 包结构：`{+4 buf, +12 len, +16 out_buf, +24 inout_len}`。
- 若 `qword_55E8E0 == 0`（外部接管模块缺失）→ **直接返回 `-146739396`（0xF741234C）**，即旧分析所说的"明文发包"。这不是加密失败，而是"没有加密器"的显式退化。
- 否则若 `[[qword_55E8E0]+56]` 非空 → 调用外部模块的加密器；否则走内置 `sub_4889F4`。
- `sub_4889F4`：`sub_508180(32800)` 分配 0x8020 上下文 → 清零 → `sub_488AA0()` 初始化 → `sub_488BF0(ctx,out,&len)` 加密 → `sub_508230` 释放。**内置加密是 32KB 状态机的自定义算法，不调用任何标准密码库**（无 EVP/AES/SM4 导入），静态还原成本高，但它的存在与否只影响"包是否可读"，不影响检测逻辑。

### 4.6 热更新检测模块 `libtersafeupdate2.so`（`qword_55E8E0` 的真身）

这一节是本轮最重要的架构修正：所谓"外部接管模块"不是玄学句柄，而是**运行时从 app 私有目录加载的热更新 so**。

- **加载器**：`TryInitProxyFunc` @ `0x1D4334`（0x730 字节，IDA 只能读成 1666 行平坦化状态机），全库仅 `JNI_OnLoad` 的 `0x1D6410` 调用一次。
- **目标路径**：`/data/data/%s/files/libtersafeupdate2.so`（字符串表 33441；另有 33485/5557 的 `%s/libtersafeupdate2.so` 模板与内联串 615624 的 `/data/data/%s/files/`）。
- **APK 里没有它**：已核对 APK 的 1567 个 entry，`lib/` 下只有 `libtersafe/libtprt/...`，无 `libtersafeupdate2.so`、`assets/` 里也没有 → 它是**运行时下载**到 `files/` 的（下载通道见 5.4：`down.anticheatexpert.com` 的 `iedsafe/Client/android/8899/71C1E6D7/`，或 mrpcs 模块下发）。
- **流程**（已按指令确认）：拼路径 → `sub_4CF408` 判存在（`stat==0 || access==0`）→ `dlopen` → `dlsym("GetTssExportFunc2")`（名字由 `sub_4E888C(0x1538)` 解密）→ `BLR X0` → `STR X0,[qword_55E8E8]`、`STR X19,[qword_55E8E0]`、`STR #1,[X19]`；任一步失败则 `dlclose(qword_55E900)` 并清空。
- **状态串**：`Leave TryInitProxyFunc(3)`（`0x983A5`，26 字节），密钥为 `0xC6` 起始递增 XOR——与模块注册表用的 `0xAB`、`sub_210418` 用的 `0xE5` 并列，是第三把内联解码钥匙。
- **`JNI_OnLoad` @0x1D63D4 的真实顺序**：
  1. `sub_2D0D30`/`sub_2D0D94`：缓存 `JavaVM`。
  2. 若 `g_AllTssExportFunc`（`0x521738`，首字为"已加载"标志，成功加载后由 `STR #1` 置 1）为 0：`RegisterNatives` 注册 `com/tss/gamedemo/Game`（3 个方法：init/onPause/onResume，类名字符串 3164 解出）与第二个类（`qword_55E910`，11 个方法）。`com/tss/gamedemo/Game` 是腾讯 SDK 里遗留的 **demo 类名**，真机游戏并不使用它——真正的 JNI 入口是 `TssJavaMethod_SendCmd`。
  3. **`TryInitProxyFunc(0)`**：尝试加载热更新模块。
  4. 若 `qword_55E8E0` 非空且 `[qword_55E8E0+112]` 非空 → **`return [+112](vm,reserved)`，把整个 `JNI_OnLoad` 交给更新模块**，静态库不再做任何注册。
  5. 否则读云控键 `gcloud`（`sub_4E82F8(49827)`，默认 1）决定是否初始化 GCloud 连接器（`sub_2D15F0/0x2D1628/0x2D1738`），最后 `sub_1D94E8`/`sub_1DA020` 初始化，返回 `0x10004`（JNI 1.6）。
- **`qword_55E8E0` 的语义**：`GetTssExportFunc2()` 返回的**函数表对象**（`[0]=1` 为已初始化标志）。53 处 xref 都是读它的槽位：

| 槽位 | 用途 | 读取者 |
|---|---|---|
| `+0x38` | 包加密 | `tss_sdk_encryptpacket` @0x1B9D54 |
| `+0x48` | `ischeatpacket` 判定 | `tss_sdk_ischeatpacket` @0x1B90E0 |
| `+0x50` | `get_report_data` | `tss_get_report_data(1..4)` |
| `+0x70` | `JNI_OnLoad` 接管 | `JNI_OnLoad` @0x1D63D4（注：IDA 把 `+112` 显示为字节偏移，`112 = 0x70`） |

- **缺失时（删掉 `libtersafeupdate2.so`）的真实后果**（已按 `0x1B9D54` 反编译确认，纠正我此前"内置兜底"的说法）：
  - `encryptpacket`：`qword_55E8E0 == 0` → **直接返回 `-146739396`，内置 `sub_4889F4` 根本不会被调用**。也就是说，热更新模块缺失 = SDK 完全不加密发包。内置 32 KB 状态机只在"模块存在但 `[+56]` 为空"时才跑。
  - `get_report_data`：走 `sub_1F8248` 的内置退化路径。
  - `JNI_OnLoad`：不接管，静态库自行注册（即表里那 3+11 个方法）。
  - `init`：继续，只是加密/判定能力降级。

**结论**：静态 `libtersafe.so` 是"桥 + 内置兜底"，真正可被腾讯服务端替换的检测/加密实现放在 `files/libtersafeupdate2.so`。只逆静态 so 会漏掉这一层；而删掉它会让发包退回**完全明文**（服务端可观测，属高噪声手段，但确实是一条明确的失效路径）。

### 4.7 对外 API 的真实分层

导出的 71 个符号并不是 71 个独立实现，而是三层壳：

```
tss_sdk_*（稳定 ABI）  →  tp2_*（v2 实现层）  →  外部模块 qword_55E8E0  /  内置实现
```

| API | 地址 | 实际行为（已反编译） |
|---|---|---|
| `tss_sdk_setuserinfo` | 0x1BBB58 | 唯一外部调用是 PLT `tss_sdk_setuserinfo_ex` + `memset` → 旧接口转发到 `_ex` |
| `tss_sdk_setuserinfo_ex` | 0x1BC31C | 调 `0x20C030/0x20C194`（参数解析）、`sub_2DAD4C`（取 ctx）、`0x23958C/0x239670/0x239680`（写入用户信息槽）、`sub_4E5284`（载配置） |
| `tss_sdk_setuserinfo_with_license` | 0x1BCCB4 | 同上族，带 license 字段 |
| `tss_sdk_ischeatpacket` | 0x1B90E0 | `[qword_55E8E0+0x48]` 非空则 `return ext_is_cheat(pkt) & 1`，否则 `return 0`——**它只是把"这包是否作弊"的判断权交给外部模块**，自身不做判定 |
| `tss_get_report_data(1..4)` | 0x1B9790 / 0x1BEE10 / 0x1C4C50 / 0x1C55A4 | 取 `[qword_55E8E0+0x50]` 或内置 `sub_1F8248` |
| `tss_sdk_encryptpacket` / `decryptpacket` | 0x1B9D54 / 0x1BA0D4 | 见 4.5 |
| `tss_sdk_dec_tss_info` | 0x1C1188 | `memset` → `sub_4E6820` 解密 → `sub_4A54DC` 格式化 `"dec_tss_info:%s"` → `tp2_sdk_ioctl` → `tp2_free_anti_data` |
| `tss_sdk_regist_tss_info_receiver` | 0x1BFE4C | `memset` → `sub_4E78DC` 解串 → 格式化 `"regist_mtp_info_receiver:%p"` → `tp2_sdk_ioctl` |
| `tss_sdk_gen_session_data` | 0x1C4628 | 函数体内 **无任何 BL**（1460 字节纯状态机）→ 只读写上下文/缓冲，不调用外部函数 |
| `tss_sdk_set_token` | 0x1C4130 | 同上（1272 字节，无 BL） |
| `tss_sdk_wait_verify` | 0x1C4BDC | 116 字节，无 BL → 读一个上下文标志后返回（推测是"服务端校验是否完成"的轮询点） |
| `tss_sdk_setgamestatus` | 0x1BB274 | `sub_4E5284` + `0x4C7158/0x4C7220/0x4C7308/0x4C7374/0x4C7280/0x4C73DC`（状态 setter 簇）+ 一次 `blr` |
| `tss_sdk_rcv_anti_data` | 0x1BA454 | `0x20AD74/0x20B2C0`（下发数据处理）+ 一次 `blr` |

**结论**：SDK 的 API 层是"薄壳 + 委托"。真正的检测逻辑全部在 41 个模块与规则引擎里；API 只负责把外部输入写进上下文、把上下文里的证据取出来交给调用方。这也解释了为什么旧分析在 `tss_sdk_init` 里看到的几乎都是"初始化脚手架"——检测不在初始化里。

### 4.8 执行引擎：job 对象、run 状态机与全局开关

- **线程对象**：`tss_sdk_init` 第一步 `sub_20E9FC` 用 `pthread_once` + `sub_508180(264)` 构造 264 字节 job：`*job = off_513AD8`（vtable）、`+128 = 1800`、`+16 = 0x80000`（512 KB 线程栈），交给 `sub_4CD664` 一次性起线程 → `0x4CD6F0`（通用线程包装：`pthread_attr_setdetachstate(1)`、最多 3 次 `pthread_create`、把任务名登记进 `qword_568F10` 表并以 `dword_568F18/F1C` 计数）→ 回调 vtable `+0x10`。
- **vtable 解析**：`off_513AD8` 在 `.data.rel.ro` 中内容为 0，必须读 `.rela.dyn`（21940 条 `R_AARCH64_RELATIVE`）才能还原：`+0=0x20EB90`、`+8=0x20EB94`、`+0x10=0x20EEB0`（主循环 `run`）、`+0x28=0x2102AC`、`+0x30=0x2102BC`、`+0x38=0x20F76C`、`+0x40=0x20F90C`、`+0x48=0x2102EC`。
- **`run` @0x20EEB0 每轮四步**：
  1. 解三个云控键：`sub_210418`（密钥 `0xE5` 起递增 XOR）解出内联串 `0x93B61`(8B)=`sc_idle`、`0x953BE`(7B)=`sc_dlp`；`sub_4EAB58(31863)` 得 `report_bk`。
  2. `sub_22DA98(cfg, 键, 默认, 强制)` 逐个读取：`report_bk`(默认 0)、`sc_idle`(默认 0)、`sc_dlp`(默认 1)，`sc_dlp` 结果 AND 1 写入 `job+132`。
  3. 一次性初始化 `sub_20EE2C`（`job+133` 为标志；内部 `0x20EBB8/0x20EBFC/loc_20EC24`）。
  4. 读全局单例 `sub_4C7158()`（272 字节，`+256` 初值 1、`+258/+260/+264` 初值 0，`pthread_once 0x4C71CC`，18 处引用）→ `sub_4C7488()` 只返回 `+256` 字节；随后 `qmemcpy(v14,"QKF*[KF*",8)` 与 `LDR X8,[X26,W8,SXTW#3]; BR X8` 组成平坦化状态分派（表索引由 `(state+8)^state` 与 `(alt+10)^alt` 二选一，`X26` 为状态表基址）。
- **语义**：`report_bk` 是"后台回传"总闸，`sc_idle`/`sc_dlp` 是扫描节奏与 DLP 子开关，`0x4C7158+256` 是运行期可写的上报开关。这些开关全部来自云控，客户端没有硬编码的"必检测"路径——这是 8.1 节结论的第二层证据（第一层是 `Close*Scan` 命令）。
- **配置读取 API**（`sub_22DA98` @0x22D98，232 字节）：`v13[0]=0` 作默认 → `sub_22DB80(cfg,key,&v13)` 取值（返回 0 表示命中）→ 命中且"强制"则用解析值，否则 `sub_22DC14/sub_22DC84(cfg,key)` 再取一层（-1 判未配置）→ `sub_238000()` 取默认 → 最终 `a3 & 1` 返回布尔。全库 `sub_22DA98` 有 300+ 调用点，是"一检测一开关"的物理体现。

### 4.9 检查任务表（`ctx+16`）与位掩码

除了 4.3 的模块表（`ctx+8`），还有第二张表：**检查任务表**（`ctx+16`）。

- **注册器** `0x27019C`：本身没有代码 xref，只由 `.data.rel.ro` 的槽 `0x514A20`（`R_AARCH64_RELATIVE`，与上次的热更新/模块表同一套表驱动模式）间接调用。它依次调用各任务的工厂函数拿到对象，再用 `sub_224F78(ctx, obj, 位, 0, 名称, 1)` 追加。
- **节点结构**（`sub_224F78` 造栈上临时记录，`sub_224FE4` 分配 72 字节节点插入双向链表，链表头在 `ctx+16`、计数在 `ctx+24`）：`+0` 对象指针、`+8` 位掩码、`+12` 保留、`+16` 名称（32 字节拷贝，`sub_4A4A20`）、`+48` 两个标志字节。
- **九个任务**（名称来自字符串表，工厂与位如下）：

| 位 | 任务名 | 工厂 | 名称 idx |
|---|---|---|---|
| 1 | `ScanEmulator` | `sub_270364` | 51955 |
| 2 | `ScanVirApp` | `sub_271A40` | 51970 |
| 4 | `ScanOpcode` | `sub_27D870` | 51983 |
| 8 | `ObjExtensionEngine` | `sub_27E880` | 52022 |
| 16 | `ScanRoot` | `sub_2718B4` | 51944 |
| 64 | `Attester` | `sub_27DD90` | 51996 |
| 128 | `ScanCert` | `sub_27EB3C` | 52054 |
| 256 | `ScanTablet` | `sub_27F694` | 52065 |
| 512 | `S2BuiltinObj` | `sub_27F91C` | 52078 |

  位 `32` 空缺（未注册任何任务），因此这是一张 10 位编码、实占 9 位的任务号表。

- **名称即开关名**：`0x271958`（Root 检查入口）先 `sub_22D820()` 取配置管理器，再 `sub_4E9608(51944)` 解出 `ScanRoot`，然后 `sub_22DA98(cfg,"ScanRoot",1,1)` 判开关，命中且 `[obj+8]==0` 时才调 `sub_2BAEE0`（4.3/7.1 的 15 项 Root 表）。→ **任务名、云控键名、日志/上报里的检查名是同一个字符串**，这也是为什么 `ScanRoot/ScanEmulator/ScanCert/ScanTablet/Attester` 这些名字在注册处和开关读取处各出现一次（`db.json` 里 `n=2`）。
- **意义**：客户端不是"硬编码一串检测按顺序跑"，而是"按表注册一批具名检查项，每项有自己的位号与同名云控键"。这既方便云端逐项开关（8.1），也解释了为什么同一份 so 在不同账号/不同时间表现出的检测项数量会不同。

---

## 5. 云控与配置

### 5.1 配置文件

SDK 从自身数据目录读取一组本地配置/缓存文件（路径由 `sub_218870` 拼接：`sub_4E5284()+sub_4E5F10(ctx,19)` 判测试态 → 选内联串 55641（`…/%s/test/config5.dat`）或 55663（`%s/config5.dat`）→ `sub_216C00` 取目录 → `sprintf` → `sub_4C6CEC(path,"rb")` → `sub_49F41C` 取长度，要求 ≥10 字节）：

| 文件 | 推测用途 |
|---|---|
| `config5.dat` / `config2.dat` / `config3.dat` (+`.xml`) | 主配置（开关、规则、阈值） |
| `cloud_feature.xml` | 云控特征下发 |
| `tcjcfg.dat` / `tss_tcj.dat` / `tss_cs2.dat` | 通道/CS 配置 |
| `tss_ano.dat` | ANO 扫描模块配置 |
| `tss_up_flag.dat` | 上报开关 |
| `tss_fap_info.dat` / `tss_dev_info.dat` / `tss_flag_info.dat` | 已装包/设备/标志缓存 |
| `comm.dat` / `comm.zip` / `sig5` | 名单下发包与签名 |
| `mrpcs_abort.dat` | 下发中断标记 |

配置访问 API 族：`sub_4E5284()`（载入）、`sub_4E5F10(ctx, key)`（按单字符键查布尔项，如 `'D'`=调试态、`19`=测试态）、`sub_4E5710(ctx, name)`（置位/记录）。全库的"云控开关"判定最终都落到这几个函数，因此**改控配置比改代码更容易**。

### 5.2 云控规则引擎（本地表达式解释器）

这是本 SDK 架构上最值得注意的一层：**服务端下发的不是"结果"，而是"规则表达式"，由客户端本地解释执行**。

- **算子注册**：`sub_4E3CAC`（649 行）把 101 个算子登记进全局表（懒初始化 `sub_4C91D8`，表指针 `qword_568E98`）。每条记录在栈上构造 0x30 字节 `{name_ptr@0, 0@8, handler@0x10, ...}`，`name` 由 `MOV W0,#<strtab_off> + BL 解密器` 得到，`handler` 由 `ADR X8, sub_XXXX` 给出。完整表见 `out/ops.tsv`。
- **算子分类**（节选，括号为字符串表偏移）：
  - 字符串/数值：`add`(0x4E3C10)、`stricmp`(0x4E118C)、`stristr`(0x4E1194)
  - 设备：`model_eq`(0x4E2660)、`model_contains`、`brand_contains`、`property_get`(0x4E2088)、`is_simulator_cpu`(0x4E397C)、`is_x86_env`(0x4E3A50)
  - 文件：`file_exists`(0x4E1680)、`file_crc_eq`(0x4E1448)、`file_md5_eq`(0x4E15D4)、`file_sha1_eq`(0x4E1810)、`file_crc_eq2`(6994)、`file_crc_not_eq2`(7009)、`folder_writable`、`get_files_dir`(0x4E3534)、`del_file_if`(6743)
  - 进程/模块：`process_exists`(0x4E2798)、`root_process_exists`(0x4E2894)、`module_exists`(0x4E29C8→6864)、`is_mem_readable`(0x4E3ACC→7386)
  - 应用/证书：`apk_installed`(0x4E21BC)、`is_root`(0x4E22F0)、`cert_md5_eq`(0x4E334C)、`malware_exists`(0x4E342C)、`hidden_malware_exists`(0x4E3758→7594)
  - 环境/时间：`datetime_range`、`week_day`、`is_adb_over_usb_enabled`、`is_touch_result_bt`(0x4E35BC)、`max_user_watches_lt`、`is_update_cdn_ok`(7807)、`is_cs_channel_ok`(7826)
  - 上报动作：`report_qos_if`、`report_str_qos_if`(6773)、`ModuleBase`(7990)、`ReportQosIf`(8003)、`CallObjVM`(8017)
- **表达式求值器** `sub_4C9214`（0x77C 字节）：`malloc` 工作区 → 去空格/去反斜杠/处理引号 → 按字符分类分词，识别 `! != " # $ ' .`、数字、`: ; % * / & && ( ) , + - < <= = > >=` ，分别调 `sub_4C99D0/sub_4C9D0C/sub_4CA458/sub_4CA548/sub_475CC8/sub_4CA730`。
- **调用者**（xref 显示是各检测模块，不是单一调度器）：`0x228D3C`、`0x2454D4`（两处）、`0x296E1C`、`0x29B5A0`、`0x2ADE04`（frida 区）、`0x2B7EB8`（云手机区，435 行平坦化状态机，按条件类型 `a2+16` 分派）、`0x2D1DF0`。
- 语义结论（**推断，有代码结构支撑**）：服务端可用规则表达式动态组合上述算子（例如"存在 magisk 且 apk 证书 MD5 不等于白名单 → 上报"），客户端只负责求值并上报结果。这让 SDK 的检测策略可在不发版的情况下改变，也让静态分析看到的"名单/阈值"只是默认值。

### 5.3 名单下发

`OpenMrpcsBridge(0xABCD)` / `MrpcsBridgeCmd(0xABDF)` / `CloseMrpcsBridge(0xABF0)` 三个命令构成"模块下发桥"；配套证据：

- `0x219D84` 日志格式 `"dl custom, name:%s, len:%d, crc:%08x, channel:%d"`（0x219F70）。
- `comm.dat` / `comm.zip` / `sig5` / `mrpcs_abort.dat` 文件族 → "下发 + 验签 + 通知 + 中断恢复"。
- 名单型检测（黑产包名、so 名单等）都实现了"外部文件优先、内置常量兜底"：`0x230BD0` 先读 `comm.dat`，失败回退内置 `0x230C78` 的 64 条；`0x231824` 同法取 `0x231998` 的 21 条。

**第二条通道：原生检测模块。** 除名单/配置外，`ano_tmp` 里还会落 `ob_x.zip` / `ob_cs2.zip`，内含 `a32.dat`/`a64.dat` 与各自 `.sig`。它们不是配置，而是**签名的原生代码包**：外层是 `magic 0x20220118` 的段表，每段一个 `.img` 模块（段名即模块名，如 `detect_live_app`、`obj_uid_check`、`qxk`），由 `libtprt` 在运行期解析、验签（RSA-2048+MD5）、解密后装载执行。真机上删掉这三个 zip 再启动，35 秒内会原样重新拉回（MD5 一致），证明它是**每次启动都走的常规下发**而非一次性缓存。结构细节见 §12.10 与 `partJ_blob.md`。

### 5.4 服务器与通道

| 字符串/来源 | 内容 |
|---|---|
| 0x1F860C | `game_host`、`tyf.cschannel.anticheatexpert.com`、`nj.cschannel.anticheatexpert.com` |
| 0x1F8898 | 16 个内置 IP（`180.109.156.92`、`36.155.240.19`、`153.3.50.229`、`119.45.69.203` …）作为域名解析失败时的直连兜底 |
| 0x216080 | `down.anticheatexpert.com`、`dl.putdl.com`、`dl.timedl.com`（下载 CDN） |
| 0x281D50 | `ACE Keeper`、`acekeeper.anticheatexpert.com`（守护/Keeper 通道） |
| 0x222504 | `down.anticheatexpert.com/iedsafe/Client/android/8899/71C1E6D7/`（模块下载路径） |

传输层有两套：**上报走 libtersafe.so 自带的裸 TCP 客户端**（`sub_4CDD80` 建连 / `sub_201DB8` 握手 / `sub_202A00` 组包，端口 443，详见 6.4），libtersafe 里**没有** HTTP 实现（导入只有 socket 族）；**下载/名单/热更新 so 只给 URL 模板、由 Java 层去取**——`https://%s/gamesafe/mobile/%s/%08X`（0x216C00）与 `https://down.anticheatexpert.com/iedsafe/Client/android/8899/71C1E6D7/donot_delete_me`（0x222504）。包体由 4.5 节的加密器处理。

### 5.5 云控开关矩阵（配置键 → 读取点）

用 `out/allstr.tsv` 的内联串反查其所属函数，得到 833 个小写键名候选（`out/config_keys.tsv`），其中与检测强相关的 130 余个如下。读取语义见 4.8 节的 `sub_22DA98`。

| 键 | 读点 | 作用 |
|---|---|---|
| `report_bk` | 0x20EEB0 | 后台回传总闸（`run` 每轮读，默认 0） |
| `sc_idle` / `sc_dlp` / `sc_protect` | 0x20EEB0 / 0x20EEB0 / 0x2267A8 | 扫描节奏、DLP 子开关（默认 1）、保护扫描 |
| `ano_touch_thres` / `ano_touch_reg` / `ano_touch_period` / `ano_record_cnt` / `ano_record_scale` | 0x2840B8 / 0x284220 / 0x283FF0 / 0x283FF0 / 0x283FF0 | 反自动点击的阈值、分桶粒度、采样周期、记录条数/比例（7.5） |
| `ano_det_cnt` / `click_alert` / `click_capt` | 0x284544 / 0x284544 / 0x284544,0x284A4C,0x284E10 | 判定次数门限、告警是否上云、点击采样开关 |
| `force_emu_scan` | 0x270464、0x294F90 | 强制模拟器扫描 |
| `force_cp2_scan` | 0x2B5194 | 强制云手机扫描 |
| `force_antiprofiler` / `force_antibm` / `force_usertag_scan` | 0x25EC24 / 0x259554 / 0x29B5A0 | 强制开对应模块（与 `Close*Scan` 相反方向） |
| `force_fake_token` | 0x2C89D4 | 强制走伪造 token 分支 |
| `force_apk_collect` | 0x20C1EC、0x20F94C、0x2454D4、0x2DBBC0 | 强制 APK 收集 |
| `force_hb` / `force_qia` / `force_r2` / `force_built_in_ip` | 0x1F8E64 / 0x246198 / 0x2236D8 / 0x1FA5A0 | 心跳与通道强制项 |
| `ScanRoot` / `ScanEmulator` / `ScanVirApp` / `ScanOpcode` / `Attester` / `ScanCert` / `ScanTablet` / `S2BuiltinObj` | 0x271958（各自入口） | 4.9 检查任务表的同名开关，**任务名 = 键名**，缺省 1；`Close*Scan` 命令则是同一批检查的运行期强制关闭 |
| `unlock_root` | 0x2BAEE0 | Root 扫描总开关（默认 0） |
| `ksu_mtp` | 0x2BCF44 | KernelSU MTP 检测 |
| `zygisk` / `zygisk_module` / `zygisk_module_entry` / `zygisk_anonymous` | 0x2A34DC / 0x2AFD4C / 0x2AFD4C,0x2BD038 / 0x2BD038 | Zygisk 系列 |
| `attunlock1..4` | 0x259210 / 0x25680C / 0x2A9040 / 0x253F08 | 四个"解锁/放行"总闸（`attunlock3` 即 frida_scan 总开关） |
| `att_svr` / `att_dev_flash` / `att_vap` / `attest_cert_not_white` / `attest_cert_is_black` | 0x2AB450 / 0x2BDA10,0x2BDE18,0x2BDEE4,0x2BDF3C / 0x2AAEE8 / 0x2ABC04 / 0x2ABCC0 | 密钥证明、设备完整性 |
| `gp3` 及 `gp3_*`（14 个） | 0x2578BC…0x2A9040 | 调试对抗分组开关（xposed/taichi/ida/fri/fork/traced/cs/ext/incompat…） |
| `gp4` 及 `gp4_*`（15 个） | 0x265EFC…0x26844C | maps/pagemap 巡检分组开关（ignore/mr/no_root/nonblock/pagemap_ig/w3/vap_2…） |
| `gp5` / `gp5_crash` | 0x27FAE4 / 0x261320,0x46CD24 | GP5 组 |
| `cp_comm` / `cp_kvm` | 0x2B54C8 / 0x2B5A5C | 云手机聚合、KVM 检测 |
| `official_cert_md5` | 0x2AE0C4 | 官方证书期望值（完整性对比） |
| `ano_sys` / `ano_cfilt` / `ano_fc` / `ano_icon` / `ano_time` / `ano_tip_pkg` / `ano_cert_md5` / `ano_hid_pat` / `ano_ignore_detect` | 0x2A005C…0x2A2B84 | anoscan 的系统项/过滤/图标/时间/证书/隐藏模式 |
| `anocrash_all` | 0x2A09E0 | ANO 崩溃全量上报 |

**结论**：几乎每个检测都能被一个云控键单独关掉，且 `force_*` 与 `unlock_*` 的默认值多为 0（关）。这既是灰度/风控可调的工程设计，也是最直接的攻击面——改一个键即可让对应检测整体失效（详见 8.1）。

---

## 6. 上报管线

### 6.1 三段式结构

```
字段构造器（20+ 个 0x4CBB2C..0x4CCE1C）
   → "k=v|k=v|…" 文本（≤245 字节）
   → sub_4CCC44 → 项 {1, 0xA, len, payload}
   → sub_4CBE5C 包装成 "id=%d|payload"
   → sub_4CBEF0：sub_238320 混淆(344B) → 观察者链表回调 vtable+24(observer,id,str)
```

- `sub_4CCC44(item)`：长度 ≤0xF5 时 `memcpy` 到 246 字节项，构造头 `{1, 0xA}`。
- `sub_4CBE5C`：`sprintf("id=%d|%s")`，容器 `+152` 标志决定是否带 payload。
- `sub_4CBEF0`：写入前 `sub_238320(str, buf, 344)`（混淆/编码）；`sub_4CD44C()!=0` 时再 `sprintf("%d|%s")` → `sub_4CD428`（日志）；容器 `+152` 置位时遍历观察者（`sub_4CC018` 取表、`sub_4CBAB4` 释放），对每个观察者调 `vtable+24`。
- **线上编码（已完全还原）**：`sub_238320` 用固定 36 字节密钥 `"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"`（字符串表 30548，`sub_4E9A88(30548)` 取）对明文做**逐字节循环 XOR**（`s[i] = key[i % 0x24] ^ plain[i]`），再经 `sub_48A710` 做**标准 Base64**（字母表 `A-Za-z0-9+/`，`0xE2774`）。
  即单条上报项的线上形态是：
  ```
  base64( xor( "id=<字段号>|<k=v|k=v|…>", "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" ) )
  ```
  这是**混淆而非加密**：密钥硬编码在静态库里，任何抓包者都能解开；它的作用只是防止明文关键字被网络层/日志层直接匹配。
- 观察者本身是带 vtable 的对象（`+0x18` = on_item 回调），链表遍历由 `sub_4CC018` 收集、`sub_4CBAB4` 释放；容器 `+152`/`+153` 两个标志分别控制"是否外发"与"是否启用 id 包装"。

### 6.2 字段 schema（已还原的格式串）

头部 8 字节常量 `{类型, 字段号}` 由各构造器从 `.rodata` 直接加载（`ADRP+LDR D0`），再交给 `sub_4CBE5C` 拼成 `id=<字段号>|<payload>`。已解析出的字段号：

| 构造器 | 字段号 | 格式串 |
|---|---|---|
| 0x4CCC44（经 0x4CBB2C） | 10 | `root=%d\|x86=%d\|apk_cnt=%d\|adb=%d\|machine=%s\|sys_ver=%s\|root_record=%d` |
| 0x4CBC24 | — | `apk_name=%s\|app_name=%s\|app_ver=%s\|sdk_ver=%s\|app_name_b64=%s` |
| 0x4CBD08 | — | `files_dir=%s\|sd_dir=%s\|lib_dir=%s` |
| 0x4CBDB4 | — | `cert_md5=%s\|apk_hash_1=0x%08x\|apk_hash_2=0x%08x\|txt_seg_crc=0x%08x` |
| 0x4CCCCC / 0x4CCD3C | 12 | `name=%s\|feature=%s\|size=%d\|mtime=%d\|cert_md5_crc=0x%08x` |
| 0x4CCE1C / 0x4CCE74 | 1 | `seq=%u\|pid=%d\|time=%ld` |
| 0x4CCBA4 / 0x4CCBF8 | 11 | `name=%s\|size=%d\|crc=0x%08x\|root=%d` |
| 0x4CCB1C / 0x4CCB64 | 7 | `rate=%d\|reason=%s` |
| 0x4CC9B0 / 0x4CCA24 | — | `name=%s\|feature=%s\|cert_crc=0X%08X\|size=%u\|install_t=%lu\|is_custom=%d` |
| 0x4CC76C / 0x4CC7F0 | 5 | `name=%s\|feature=%s\|cert_md5=%s\|fake_cert=%d` |
| 0x4CC83C | 6 | 同上（第二个构造点） |
| 0x4CC90C / 0x4CC96C | 3 | `reason=%s\|root=%d\|cert=%s` |
| 0x4CCA80 / 0x4CCADC | 21 | `cert=%s\|author=%s` |
| 0x4CC660 / 0x4CC6B4 | 23 | `is_unlock=%d\|reason=%s` |
| 0x4CC334 / 0x4CC37C | 15 | `path=%s\|permission=%s` |
| 0x4CC2BC | 16 | `app_name=%s` |
| 0x4CC3BC | 9 | `info=%s` |
| 0x4CC434 | 19 | `name=%s`（包/文件类） |
| 0x4CC4AC | 20 | `name=%s`（第二类） |
| 0x4CC6F4 | 8 | `name=%s`（第三类） |
| 0x4CC528 / 0x4CC5E0 / 0x4CCD8C | — | 头部由间接方式构造，未解析 |

聚合型字段（由各模块直接拼装，不经上述构造器）：

| 位置 | 内容 |
|---|---|
| 0x23DB04 | `IsRoot=%d\|RootReason=%s\|IsNeedReqApkList=%d\|` |
| 0x23DF18 | `IsEmu=%d\|EmuName=%s` |
| 0x23DFAC | `IsVAP=%d\|VAPName=%s` |
| 0x23E040 | `OPC=%08x` |
| 0x23E0C0 | `CertHash=%s\|DST=%04x\|PkgNamesCnt=%d\|PkgNames=%s` |
| 0x290270 | `secc: %d;%d;%d;%d;%d` |
| 0x2DF604 | `tss_main:%s,0x%lx` |
| 0x26B360 | `err=%d\|all_wp=%d\|all_bp=%d\|used_wp=%d\|used_bp=%d`（GP3） |
| 0x2B0174 | `!%s, size:%d, crc:%08x, t:%s`（module2） |

### 6.3 API 遥测

`sub_4C3510(kind=1, api_id 0..6)` 对 7 个 API 各注册一次 `"monitor"` 事件，事件名即 API 名（表偏移 33682/33695/33715/33731/33748/33770/33792）：`TssSDKInit`、`TssSDKSetUserInfo`、`TssSDKOnPause`、`TssSDKOnResume`、`TssSDKGetReportData`、`TssSDKDelReportData`、`TssSDKOnRecvData`，每个最多记 3 次（`dword_568E0C/E08/E10`）。另有一组内部事件：`tss_sdk_init_start`(0x4C2FDC)、`tss_sdk_init_finish`(0x4C3300)、`tss_connect_count`(0x4C33A4)、`tss_heart_beat`(0x4C3498)。

**用途**：判断"API 是否按预期被调用"。如果游戏被改造（例如跳过 `TssSDKInit`、不调 `OnPause`、`GetReportData` 调用次数异常），服务端在遥测层就能看出来——这是比环境检测更隐蔽的一层完整性校验，且**完全无法通过改机绕过**。

### 6.4 外发通道（libtersafe.so 自带 TCP 客户端）

上报项并不总是交给游戏 Java 层转发：本库内部就有一整套 socket 客户端与自定义协议栈，只有在配置/环境不允许时才降级为回调宿主。链路如下：

| 阶段 | 函数 | 关键细节 |
|---|---|---|
| 选主机 | `sub_1F860C(out,cap)` | 先解两把配置键（`unk_913CA` 7B、`unk_917F4` 8B，`sub_200760`）；若布尔开关 `game_host`（字符串表 701）为真 → 用内置串 60040 = `nj.cschannel.anticheatexpert.com`；否则 `sub_22DFD0(cfg,key,buf,255)` 从云控取 |
| 解析 | `sub_4CE6C4(host,443,&list,0)` | `getaddrinfo` 包装，端口 **443**（同族还有 `0x4CE43C/0x4CE75C/0x4CE964`） |
| 建连 | `sub_4CDD80(host,port,nonblock)` | `sub_4CDEF8`=`socket()`、`sub_4CDF68` 设超时、`sub_4CDFEC`=`connect()`；主机名含 `:` 走 `AF_INET6`（`inet_pton(10,…)`，28B sockaddr），否则 `AF_INET`（16B） |
| 握手 | `sub_201DB8` | 把 fd 存入连接对象后依次 `sub_201E9C`（发连接请求）→ `sub_201F34(&fdset,&len)` → `sub_201FDC` → `sub_202078` → `sub_202190(…,256B)`；任一步失败即 `sub_4CDEC8` 关 fd |
| 组包 | `sub_202A00` → `sub_202C8C` → `sub_202E30` | `sub_202A00` 申请 4096 缓冲；`sub_202E30` 构造 32834 字节包：魔数 `0x010A0023`、`[+24]/[+28]` 双序号、`[+16]` 64 字节会话标识、`[+64]` 16 位长度、`[+66]` 起为 payload，再交 `sub_1FE7D0` 加密 |
| 发送 | `sub_2015EC(conn,seq,data,len)` | 序号 `[+136]` 自增；`sub_489248` 算 CRC32；按 **4096 字节分片**（`(len>>12)+1`，上限 `0x10` 片），逐片写头+校验+数据 |

连接对象是标准 C++ 对象，vtable 在 `.data` 的 `0x5264B8..0x526510`（12 项，由 `.rela.dyn` 的 `R_AARCH64_RELATIVE` 填入 `0x202A00..0x202C60` 之间的扁平化片段）；`sub_2015EC` 的唯一调用者就是 vtable 里那一项，说明"发送"是对象方法而不是散落调用。

**两个值得记录的判断：**

1. **端口 443 但没有 TLS**。全库无 `SSL_*`/`EVP_*`/`mbedtls`/`BoringSSL` 导入，握手是自研二进制协议，包体再经 `sub_1FE7D0` 做两段封装（`sub_4B8F54` 处理头部、`sub_4B9DDC` 处理载荷，两段长度之和写回 `+4` 的 16 位字段）。选 443 更像是对流量识别/中间设备的伪装，而不是真的走 HTTPS。
2. **主机名可被云控改写**。`game_host` 为真时用内置 `nj.cschannel.anticheatexpert.com`，为假时取配置值——也就是说服务器地址本身是下发内容，抓包看到的域名不一定是判定链路。

### 6.5 上报项从内存到网络（串起来看）

```
字段构造器 → "k=v|…"（≤245B）
  → sub_4CCC44 项头 {类型=1, 字段号}
  → sub_4CBE5C "id=<字段号>|<payload>"（容器 +152 决定是否外发、+153 决定是否包 id）
  → sub_238320 逐字节循环 XOR（密钥 "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"）
  → sub_4CBEF0 交观察者 vtable+24(observer, 类型, base64串)
  → [native 通道] sub_202A00/sub_202E30 组包（魔数 0x010A0023、序号、64B 会话 id）
  → sub_2015EC 4096B 分片 + CRC32
  → TCP → <host>:443（默认 nj.cschannel.anticheatexpert.com）
```

---

## 7. 检测项逐类

### 7.1 Root / 解锁 / Zygisk / KernelSU

唯一入口 `0x271958`：读云控开关 `ScanRoot`（默认 1）→ `0x2BAEE0` 扫描 → 结果写单例 `qword_55F3C0` 的 `+9 IsRoot`、`+10 RootReason`，`+8` 标记已扫，**只跑一次**。

`0x2BAEE0` 驱动 `.data.rel.ro 0x515600` 的 15 项函数表（`+0x78` 为 0），签名 `int fn(char*, size_t)`，任一返回 1 即停止；末尾查开关 `unlock_root`（默认 0）。

| 检测项 | 地址 | 手法 |
|---|---|---|
| su 路径 | `0x2BB3B0` | 14 个目录（`/data/local`、`/sbin`、`/su/bin`、`/system/xbin`、`/cache`…）逐个拼 `/su`，用**自实现 faccessat**（`0x4B8420` → `__NR_faccessat=48`、`AT_FDCWD=-100`）判存在，绕开 libc `access/stat` hook |
| Root 包名/文件 | `0x2BB764` | 20 条（magisk、kernelsu、Superuser.apk、daemonsu、99SuperSUDaemon…）逐条 faccessat，循环 20 次，函数内无 getprop |
| PATH 污染 | `0x2BAFD8` | 解密 `getenv("PATH")` 按 `:` 拆分，逐目录拼 `/su` |
| ro.debuggable | `0x2BBF64→0x2BC054` | 读属性，`atoi==1` 判 Root |
| 扩展计数 | `0x2BBA00` | 配置项 `root_ext_cnt` 做阈值 |
| 解锁状态 | `0x2BDB2C` | `ro.boot.flash.locked`、`ro.boot.vbmeta.device_state`（含 unlock）、`ro.boot.verifiedbootstate ≠ green`，配 `att_dev_flash` |
| Zygisk 文件 | `0x2BCAE8` | 开关 `ksu_files`，faccessat 五个特征：`/system/zygisk_magic`、`lib{,64}/libzygisk_loader.so`、`libzygisk_injector.so` |
| Zygisk 匿名映射 | `0x2BD038` | 解析 `/proc/self/maps`（`0x4DCD28`，格式 `%zx-%zx %c%c%c%c %x %x:%x %u %s`），映射名 `== zygisk_module_entry` 且命中 `"/memfd:jit-cache (deleted)"` → `zygisk_anonymous` |
| KSU MTP | `0x2BCF44` | 开关 `ksu_mtp`：`prctl(167,0xDEADBEEF,1,page)` + `mincore` 判页被内核写脏 |
| AP 内核 | `0x2BCDC4` | 开关 `ap_ker`：`prctl(45,page,-1)` |
| Zygisk 栈残留 | `0x2BC4CC` | 从 maps 取 `[stack]` 栈顶，前 1000 字节内 `memcmp("MAGISK_INJ_1")` → `residual_env` |
| KSU 挂载 | `0x2BCC38` | `/proc/self/mounts` 查 `zygisksu` → `ksu_mounts` |
| SELinux 上下文 | `0x2BC678` | 读 `/proc/self/attr/prev` |
| mount ns | `0x2BC87C` | `fstatat("/proc/self/ns/mnt", AT_SYMLINK_NOFOLLOW)` 比对字段（`magic_delta`） |

**完整性/证书**（Root 模块之外，属"官方包校验"）：

- `0x4CBDB4` 拼 `cert_md5/apk_hash_1/apk_hash_2/txt_seg_crc`（`txt_seg_crc` 取自安全上下文 `v4+132`，即 `.text` 段 CRC）。
- `0x4D8DF4 cal_cert_md5`（默认开，zip 解析 `0x4D8F44/0x4D90A0`）。
- `0x2AE0C4` 用 `official_cert_md5` 期望值比对，不匹配按 `cert_crash` 上报 `cert=%s|author=%s`。
- 上报聚合 `0x23DA5C`，含 `IsRoot`(0x23DB04) 与 `CertHash|DST|PkgNames`(0x23E0C0)。

### 7.2 模拟器 / 云手机 / 多开

**模拟器品牌位图**（`0x280688`）：`TencentAoYYB=512`、`Tencent=2`、`Win=1`、`LeiDian=4`、`Nox=8`、`XiaoYao=16`、`BlueStack=32`、`Google=64`、`Mac=128`；标签表 `0x280C3C`（`nox_tp`/`bluestacks_tp`/`leidian_tp`…）直接作为 `EmuName` 上报。

**QEMU 后门探测**（`0x27B110`）：栈上就地解密 11 段密文，逐段向"设备"`write` 探测；其中 19 字节为 `"pipe:qemud:sensors"`——QEMU 的传感器后门管道，写入长度 `== 期望+1` 即判命中。这是少数不依赖属性/文件名的"硬"模拟器证据。

**云手机 6 位聚合**（`0x2B54C8`）：写 `{+0 valid, +4 bitmap, +8 name[64]}`，默认名 `"UnKnownYun"`，门控命令 `cp_comm`。

| bit | 检测 | 地址 |
|---|---|---|
| 0 | KVM | `0x2B5A5C`：三重门控（`cp_kvm`、白名单 `0x2B62BC`、版本上限 `sub_2DB578>32`）后才查 `/sys/module/kvm` 与 `parameters/halt_poll_ns` |
| 1 | Rockchip | `0x2B6500`：11 条路径（`init.rockchip.rc`、`/sys/module/rockchip_*`、`librockit.so` 等）；`0x2B5B00` 注入 `RK_ADEPT_DEVICE_TYPE`/`rk3588_docker` 标记 |
| 2 | gemini 属性 | `0x2B5B9C`：17 条 `ro.*`，标记由调用方注入（`0x2B54C8` 传 `gemini`） |
| 3 | 属性目录 | 遍历属性名空间（`__system_property_find_nth` @0x4D7B9C） |
| 4 | CPH 属性/库 | `0x2B6040`：21 条 `com.cph.*`/`ro.com.cph.*`/`ro.hardware.fps.cph` 与 `"none"` 比较；`0x2B5EA8`：12 条 `/system/lib{,64}/libCPH*.so` 存在性 |
| 5 | cloudphone 字面量 | `0x2B6AC4`：`"cloudphone"` 匹配 `sys.prop.writewifissid`、`wifi_name` 与 4 条 `ro.product.*.model` |

品牌判定 `0x2B9D98`：互斥掩码（RedFinger/ZYYun 需 `v13&1`，ShuangZiXinYun `&2`，LeiDianYun `&0x20`；DuoDuoYun 需 `~v13&0x39`，XiaoDiYun `~v13&0x33`），命中拼 `"cp23:%d,%s,%s"`，事件 `cloud3_err4`，置 `+333` 防重报。

**x86 / 翻译层**：`0x2975B8`（`ro.enable.native.bridge.exec`、`ro.dalvik.vm.isa.arm`、`libhoudini.so`）、`0x297EDC`（`ro.dalvik.vm.isa.arm64`、`x86_64`）。

**多开**：`0x28C914`（24 条虚拟多开 stub Activity：`com.bly.dkplat`、`com.lody.virtual`、`com.excean.dualaid`、`com.vmos.app`、`com.qihoo.magicmutiple`、`com.bfire.da.nui`…）与 `0x28CD40`（12 条 taptap 系）。

### 7.3 Hook / 注入 / Frida / Xposed / Substrate

`frida_scan` 总控 `0x2A9040`（虚表 `0x5151C0`，`[+8]=0x2A9040`），总开关 `attunlock3`（偏移 48416），门控 `(cfg&1) || ([cfg+80]&v8) || *(ctx+926)!=0`。命中统一出口：`sub_1F2640(706, tag)`（`MOV W8,#0x41` + `sub_4A4A20(msg+0x20C,tag,0x40)`）与 `sub_1F0148(str,0,0)`（事件码 `0x100002342`）。**`sub_1F0148` 是事件派发，不删文件；`0x2A6AE0` 不产生主动反制。**

| 路径 | 地址 | 手法 |
|---|---|---|
| frida-server 文件 | `0x2A6AE0` | 先判诱饵路径 `/data/local/tmp/12re.34frida.56server78`（27374，**已反编译确认**）：存在则 `return 0`（判为干净）；不存在才依次查 27431 `/data/local/tmp/re.frida.server`、27465 `/system/bin/frida-server`、27492 `/data/local/tmp/frida-server`，任一存在则 `return 1` 并 `sub_1F0148(path,0,0)` 上报 |
| 端口探测 | `0x2A6FEC` | 连 27042/27043；`loc_2A6BAC` 连 `127.0.0.1` 后按响应字 `"REJECTED"` 判定 |
| ART 跳板 | `0x2A880C` | `dlopen("libart.so")` → `dlsym("_ZN3art9ArtMethod12PrettyMethodEb")` → 检查 `*(u32*)addr == 0x58000050`（`LDR X16,#8` inline hook 跳板魔数）→ `fri_art` |
| 线程名 | `0x2A8B64→0x2A88B0` | 遍历 `/proc/self/task`，读 `comm`，比对 `gum-js-loop`/`gmain`/`gdbus`/`pool-frida` → `fri_thr` |
| JIT memfd | `0x2A8C6C` | 内联 XOR（`unk_D9618`，6 轮）还原 `"fri_me"`，匹配 `/memfd:jit-cache (deleted)`——Frida QuickJS JIT 的匿名映射 |
| maps 扫描 | `0x2A80C0` | `"/data/local/tmp/"` 前缀直接命中；`strstr("frida")` + 名单（`libfrida-gadget.so`、`frida-agent-32/64.so`、`frida_agent_main`、`FRIDA_AGENT_1.0`），先 `sub_489248` 哈希去重 |
| Xposed | `0x25C090` | 扫描器（`sub_4DCC88→sub_4DCD28→strstr→sub_4DCCEC`）；名单 `0x25C52C`（`app_process32/64_xposed`、`libxposed_art.so`、`XposedBridge.jar`）、`0x25C7A4`（`de.robv.android.xposed.installer`）、`0x25C9D0`（`EdHooker_`/`SandHookerNew_`） |
| Substrate | `0x25DAF4` | `MSHookFunction`/`MSJavaHookClassLoad`/`MSJavaHookBridge`/`MSJavaHookMethod`/`MSCloseFunction`；`0x25E210`（`libsubstrate.so`/`libsubstrate-dvm.so`）；`0x25D740`（`anti_substrate`） |
| IDA 痕迹 | `0x25B824` | `/data/local/tmp/android_server(64)` 经 `sub_4CF408` 命中，`byte_55F2E0` 保证只报一次；前置一条内联 23 字节**诱饵路径**（密钥 0xF2 递增 XOR） |
| 模块扫描 | `0x2AEEFC→0x2AEF80` | `getpid`→maps 逐行，`"["` 过滤、`"/"` 必含，`sub_2AFEB4` 白名单子串，`filter_by_uid(52170)` 比 `stat+24` 与基准 uid，`chk_elf_header2(329)` 核对；命中进 `0x2B012C` 上送 `!%s, size:%d, crc:%08x, t:%s` |
| Zygisk 模块名 | `0x2AFD4C` | 校验 `+1048/+1040/+1044` 非零、`+1032>0x1000`，开 `zygisk_module`(20238) 后在 `zygisk_module_entry`(20254) 上做 0x3FFE 滑窗 `memcmp`，命中写 `zgkm.dat`(20305) 模板 |
| 反 PLT/GOT hook | `0x2D9DB0`/`0x2DA1E0` | 解析 `.dynsym`+`.rel(a).plt`，按符号名**改写自身 GOT 槽** |
| 私有指针表 | `0x28EAF4` | `strcmp` 链（`"open"`/`"read"`/`"write"`）取 `0x51C4C0(open_ptr)`/`0x51C4C8(read_ptr)`，全程不走自身 PLT |
| 代码段采样 | `various_opcode` 0x2A9674 | 20 槽随机采样，`s[v12+12] ^ 0xACC9725E` 与实测比对 |

**注意**：`elf_hook_scan` 模块（ctor `0x28EA9C`，虚表 `0x514EC8`）的运行槽 `0x28EAF0` 是**单条 `RET` 空桩**——本版本仅注册占位，真正的 ELF/inline 判定由 `module2` 与 `various_opcode` 承担。

### 7.4 调试对抗与内存保护

**不做 `PTRACE_TRACEME`、不用 PEEKDATA/POKEDATA**（与旧分析的猜测不同）。`ptrace` 导入桩 `0x50E6F0`，17 个调用点只用 `ATTACH(0x10)/DETACH(0x11)/CONT(7)/SYSCALL(0x18)/SETOPTIONS(0x4200)/GETREGSET(0x4204)/SETREGSET(0x4205)`——它是"反向调试器"，而不是"自我反调试"。

| 设施 | 地址 | 机制 |
|---|---|---|
| 迷你调试器 | `0x2623D4` | `ATTACH` → `waitpid(__WALL)` → `SETOPTIONS=14(TRACEFORK\|VFORK\|CLONE)` → 512 槽 pid 表 → `CONT`；事件循环 `0x2625E8` 用 `waitpid(-1, __WALL\|WUNTRACED)` 走 `off_52F440` 跳转表 |
| 致命信号解绑 | `0x2626C0` | 位掩码 `0x129D0`（SIGILL/ABRT/BUS/FPE/SEGV/PIPE/STKFLT）→ `DETACH` 清槽；`0x262AF0`：`kill(pid,19)`→`waitpid`→`DETACH`→`kill(pid,18)` |
| GP6 syscall 代理 | `0x269658` | 读 `NT_PRSTATUS`(272B) 判魔数 `0xBEEF00AD`，命中回写寄存器，用 `NT_ARM_SYSTEM_CALL(0x404)` **改写 syscall 号**，`PTRACE_SYSCALL` 单步，上限 0x10000 次——代执行/跳过 syscall，不杀进程 |
| TracerPid 三路互证 | `0x263D58` / `0x25A5EC` / `0x25AB10` | `/proc/%u/status` 的 TracerPid；`/proc/%d/stat` 第 4 字段 `T/t`；`/proc/%d[/task/%d]/wchan` 里 `memmem("ptrace_stop")`；结果缓存 `dword_55F344`，并 `prctl(PR_SET_DUMPABLE,1)` 让 GP6 可附着 |
| GP3 硬件断点 | `0x26B25C` | 命令串 `atoi` 取 pid → `ATTACH` → `NT_ARM_HW_WATCH(0x403)`/`NT_ARM_HW_BREAK(0x402)`（`GETREGSET` 264B，`buf[0]=dbg_info`）→ `DETACH` → 上报 `err/all_wp/all_bp/used_wp/used_bp` |
| GP6 服务 | `0x268EE4`/`0x269EFC` | 反射 `Intent` → `setAction("ioctl")` → `setPackage("%s.%s")` → `startService`（`com.ace.gshell.GP6Service`），16 条命令 `GP6_Open/Read/ReadMemory/GetRegister/GetHWBPStat/Dladdr/VMFunc0/VMFunc1`；双通道 `ace_gp6`/`ace_gp6_c` |
| memtrap | `0x2537A8`/`0x253E50` | **页状态巡检**（非 SIGSEGV）：每页 `mmap` → 第 4 页起 `prctl(PR_SET_VMA, ANON_NAME, "memtrap_name")` → `mprotect(PROT_EXEC)`；轮询命中 `mem_trap`，同页最多 5 次 |
| GP4 maps/pagemap | `0x266E54` | 一次读 8160 字节 maps，过滤 `(perm&0x29)!=0 && (perm&0x40000000)==0`，路径匹配 `mem`/`pagemap`，红黑树去重 + 3 秒限频；`perm&1`→`0x253CD0`，`perm&0x20`→memtrap；上报器 `loc_267080` 持 `pagemap/kwrite/mem_trap_no_root/gp4_cs/gp4_2` |
| mincore 反 hook | `0x2F1950` | 按 `byte_53B9F8` 在 libc `mincore` 与 `sub_345360`（`svc __NR_mincore`）间切换；特征搜索走自带"libc 子集"函数指针表（15 项，`0x37048C`） |
| 上报封装 | `0x262E18` | `[len:4][payload][time&0xFF]`，`MOV W8,#0x7D1(2001)`，`malloc(0x1000)` + 序列化 + `sub_24E314` 投递 |
| inotify 自保护 | `0x3F5070` | `inotify_init` + `fcntl(F_SETFL,O_NONBLOCK)` + `inotify_add_watch` |
| mrpcs 下发桥 | `0x219D84` | `"dl custom, name:%s, len:%d, crc:%08x, channel:%d"` |

`PR_SET_VMA` 共 7 处（`0x253CB8/0x31BD28/0x367EFC/0x367F30/0x440008/0x463584/0x469378`），**无 `PR_SET_PTRACER`**（说明它不打算让自己被调试器附着，而是自己去附着别人）。

### 7.5 设备信息采集、伪造检测、反自动点击

**采集总控** `0x2C9D78` 调度 16 个槽（1-6、8-17，7 空缺），签名 `f(ErrKey, env, buf, 1024, ErrKey)`，任一步失败即返回，失败原因（`5=GPUErr` 等）本身就是上报字段。序列化 `0x2C8CBC` 逐槽 `"%d=%s;"`；第 17 槽（AndroidID）例外：`sub_489248` 求哈希后 `"%x"`，**不明文外发**；`0x2CA274` 把值内 `'='/';'` 各 +29 变 `'Z'/'X'` 防分隔符注入。

- JNI 偏移链 `0x2CF3BC/0x2CF488`：`FindClass=+0x30`、`GetStaticFieldID=+0x480`、`GetStaticObjectField=+0x488`、`GetStaticIntField=+0x4B0`、`ExceptionCheck=+0x720`。
- Build 只取 5 字段：`BRAND`(0x2429E0)、`MODEL`(0x249D68)、`HARDWARE/CPU_ABI/CPU_ABI2`(0x241384)；`FINGERPRINT`/`RADIO` 由 `0x4CEE28` 读属性补齐；**全库无 SERIAL/DEVICE/PRODUCT/BOARD/HOST/TAGS/DISPLAY/MANUFACTURER**。
- GPU 只取 GLES 版本（`0x2CABF4`：`getSystemService("activity")→getDeviceConfigurationInfo()→getGlEsVersion()`）；全库无 `glGetString`/EGL 采集。
- Camera `0x2CB31C` 取 4 个 SENSOR_INFO；Sensor `0x2CBBFC` 取 `getMinDelay()+toString()`，含 `fake_token_sensor`。
- 内核侧：`uname`→`"%s,%s,%s"`(0x2CC02C)；`statfs("/vendor/")`→`"%u:%u:%08x:%08x"`(0x2CC1F0)；`libc.so st_ino`；`secc` 五元组(0x290270) = SDK_INT、`/proc/self/status` 的 `Seccomp`、`prctl(21)`、`prctl(39)`、固定 0。
- USB/ADB：`0x2CD864` 比较 `EXTRA_PLUGGED` 与 `BATTERY_PLUGGED_USB`；`0x2CDCEC` 读 `service.adb.tcp.port` 标 `wifi_adb`；`0x24F8A4` `popen("ip route get 8.8.8.8")` 取网关。
- 采集掩码 `ctx+0x3BC` 的实际位分配（逐采集器反汇编）：`0x240FB8→bit1`、`0x241188→bit2`、`0x241384→bit3`（HARDWARE）、`0x242088→bit4`、`0x241B3C→bit6`、`0x2421DC→bit7`、`0x2429E0→bit9`（BRAND）、`0x24338C→bit0`；其余被花指令混淆。这意味着 `CloseDevInfoCollect:200` 能精确停掉 BRAND 一项，而服务端只看到"该字段缺失"。

**Key Attestation**：`0x4D3088` `KeyPairGenerator("RSA","AndroidKeyStore")` → `0x4D31CC` `Builder(ANO_KEYSTORE_ALIAS_03_23)` + `setSignaturePaddings("PKCS1")` + `setDigests` + SHA-256/SHA-1 + `setAttestationChallenge`(0x4D359C) → `0x4D2660` `getCertificateChain→getEncoded` → `0x4D36B8` 存 DER（0x818 节点）；返回码 0/2/4/5；`0x2AB450` 在 `att_svr` 开关下以 `type=9` 上报，本地规则 `attest_cert_not_white`/`attest_cert_is_black`。

**注意默认姿态**：`ksat` 的主链是 `att_vap`(48630) → `att_cra_white`(48704) → `att_svr`(48796)，其中 `att_svr` 默认值为 **0**，关闭时 `0x2AB450` 直接返回 -1——也就是说**正式包里 attestation 默认不工作**，要云端把 `att_svr` 打开才启用（"先本地校验、再云端开启"的两级闸门）。`setAttestationChallenge`(0x4D359C) 没有静态调用者，推断由 JNI 方法表回调（B 级结论）。

**伪造 token**：`0x2CC6C4` 取 `ft_oaid` → `0x2CCA7C`（虚表 `+0x60`，256B），非空且 ≠ `"Unknown"` 输出 OAID，否则回落 `fake_token_androidid`；`0x2CCD20` 拼 `"x:%s;q:%s;Q:%s;o:%s"`；`0x2CCF54` 包 `"%s;bt:%s;bd:%s;"`——`bt=` `/proc/sys/kernel/random/boot_id`(0x2CCE84)、`bd=Brand`。**三者不自洽即暴露改机**；`0x2C89D4 force_fake_token` 在分发表 `0x5168C8` 里强制走伪造分支（用于"诱捕"，把伪造值主动送给服务端）。

**反自动点击**：`0x2B4B94` 解析 `RecordTouchEnable/Start/Stop` 置 `ctx+10237/10238`；`0x285B40` 反射 `com/tencent/tp/TouchListenerProxy` 取单例，`0x285E74` `setOnTouchListener`；采样缓冲 `ctx+112` 起 0x800 字节 = 512 个 int32 间隔、`ctx+104` 为样本数；统计 `0x2840B8/0x284220/0x284340`：500 桶直方图、`bucket=interval/res`（`ano_touch_reg` 默认 10）、`rate=max/total*100`、日志 `"rate:%.2f,grp:%d,tll:%d"`；阈值 `ano_touch_thres` 仅在 `[50,100]` 生效否则 70；处置 `0x284544` 以 `ano_det_cnt`（默认 3）为门限拼 `"rate:%.2f,hit:%d,name:%s"`（`name` 含 `adb`/`clk_adb`），交 `0x1EFA48`，读 `click_alert` 决定是否上云，置 `ctx+2169` 一次性封口；旁路写 `/sdcard/sdk/enable.log`（≤10 次，`rand()%1000==517` 抽样跳过——用于"看起来像随机漏报"）。

### 7.6 黑产/文件/包

- 黑名单判定 `0x4E2F30` **不走 PackageManager**：`sub_4DD77C` 开 `/proc`、`sub_4DD7CC` 逐 pid，`sub_4A47AC` 对进程名 `strstr`，再与类型掩码 `(v9[11]&a2)` 联合——因此"改包名"无效，但"改进程名"有效（见 8.2）。
- 名单双源：`0x230BD0` 先读 `comm.dat`，失败回退内置 `0x230C78` 的 64 条（`bin.mt.plus`、`com.speedsoftware.rootexplorer`、`com.cyjh.gundam`、`com.cyjh.mobileanjian`、`com.dimonvideo.luckypatcher`、`org.sbtools.master`、`gamehacker`、`com.github.shadowsocks` …）；`0x231824`/`0x231998` 21 条 so/框架串（`libsubstrate`、`libooenv`、`libooSpeeder`、`libxxAndroidLoader`、`libxxdvm`、`libxxghost`、`libhelpertool`、`libhhmsypy` …）；`armbin`/`binarm` 作后缀片段。
- `/proc/self/fd` 扫描 `sub_274AB8`：遍历 fd，`readlink /proc/self/fd/%s` 与 `/proc/self/./fd/%s`，按 `.apk/.so/.dex/cache/maps` 过滤；`sub_2748D8` 用 `/proc/self/maps` + `/proc/self/fd/%d`；由 `sub_274864`（0x74B 分发器）调用 → 抓"已加载模块背后文件被删/落在 cache"这类 dump/hook。
- **哈希基础设施**：`0x489248`（整块 CRC32，初值 `0xFFFFFFFF`+final 取反）、`0x489284`（带种子续算）、`0x4892B4`（文件 CRC，4096 字节分块、最多 1000 次重试），查表 `dword_E2270`（标准 `0xEDB88320` 多项式表）。`0x489248` 有 148 处调用，覆盖 `file_crc_eq` 算子、`apk_hash_1/2`、AndroidID 哈希与名单去重——**全库没有 MD5/SHA 的自实现**，这两类只出现在上报字段名里（值由 Java 侧算好传入）。

- `process` 模块（入口 `0x293DA8`，扫描体 `0x2941B8`，注册 `0x2800C0`）：开关键 `9005.hi2`（默认开，`sub_294064` 解），逐 pid `strstr(comm)` 比对 64 条名单，pid 上限 `0x2710`；命中名先 `sub_4A21DC` 哈希，仅当全局 `g[0x398]==0x9C` 时上报明文，否则 `VP_`+`%08X`，字段 `|%d:%s, attr:0X%08X`（`0x293E04`）。
- `black_app` 模块（入口 `0x29E4B8`，注册 `0x27FD98`）：名单走配置 id `0x2C9`，缺失时回退 `0x230C78` 明文 64 条；命中除弹框外还发 `ano,drop:%s:%s`（`0x94886`）与事件 `0x7C0D`。
- `collect_apk` 模块（入口 `0x2B1DF0`，注册 `0x280268`）：一次性门闩后依次 AllApk → 阈值 → `i.9005` 名单 → `/sdcard/Android/data`；阈值 id `0x73F2` 默认 `0x278D00`（30 天）、id `0x7402` 默认 `0x2800000`（40 MB）。三套上报模板分别是 `0x4CBC24`（apk_name/app_name/…b64）、`0x4CBDB4`（cert_md5/apk_hash_1/2/txt_seg_crc）、`0x4CBB2C`（root/x86/apk_cnt/adb…）。

### 7.7 代码段完整性与签名校验

这一组模块的共同点是**校验对象都是 ACE 自身**，而不是游戏或系统库——它们防的是"有人改了 libtersafe.so 或重打包 APK"。

- **`various_opcode`**（注册 `0x280054`，运行槽 `0x2A93EC` → worker `0x2A9674`）：校验对象确认是**自身 `libtersafe.so` 的 `.text`**，不是 `libil2cpp`/`libGameCore`。单次只验 20 个采样槽中的 1 个：`v11 = sub_1F524C(ctx+6*(*(ctx+120)&7)+72)`、槽号 `v12 = v11 % 0x14`；`sub_1B6CE4(s)` 把 20 个静态期望值填进 `s[12..31]`，与内存哈希 `sub_2A9C18`、文件哈希 `sub_2A9E28` 比对。
  - 上报条件：`s[v12+12] ^ 0xACC9725E != 内存哈希` → 以 `"%08x%08x%08x"` 发事件（键 idx 40127 = `various_opcode`）。
  - 崩溃条件（更严）：`内存哈希 != 文件哈希 && 两者都非 0 && sub_2DB8AC(ctx)&1==0 && (sub_23A114(ctx)&1 || sub_2DB888(ctx)&1)` → 取 `crash_various_opcode`(idx 40144，默认 1) 后 `sub_46CD24(crash_ctx, 30819, key, 29629, 1)`。
  - 也就是说"内存里是 A、磁盘上是 B"（典型的内存补丁）才可能触发崩溃；单纯改磁盘文件只上报。
- **`opcode_scan`**（注册 `0x27FC78`，运行槽 `0x28DC98`）：对自身 `.text` 做**全量逐页 CRC32**（`sub_489248`/`sub_489284`）+ `memcmp`（`sub_4A4690`）；差异页号与前 5 个差异 dword 由 `0x28E188` 用 `sub_1EF554(ctx, 10, offset, 文件值, 内存值)` 记录；崩溃判定在 `sub_28E364(total_pages, diff_pages, …)`，条件是 `total_pages >= 100 && diff_pages >= 1 && 100*diff_pages/total_pages <= 10`，再要求 `sub_23A0B0(ctx,0,0)==0` 且云控键 `opcode_crash`(29629，默认 1) 为真，最后 `sub_46CD24(crash, 30819, "…", 29629, 1)`。**改多了反而不崩**（只上报）。校验后的整段 CRC 取反写入 `ctx+0x84`，即汇总字段 `txt_seg_crc` 的来源。
- **`cert3`**（注册 `0x280194`，运行槽 `0x2AE0C4`）：唯一的硬判据是**证书 MD5**——`0x4D8DF4` 对自身 APK 计算（开关 `cal_cert_md5`，id 40203，默认开），与 `official_cert_md5`(id 59921) 及 `cert_cnt`(16843)/`cert_%d`(40262) 列表比对；不匹配按 `cert_crash`(16830) 崩溃，行为码写入 `[ctx+76]`；结果由 `0x4CBDB4` 汇总成 `cert_md5|apk_hash_1|apk_hash_2|txt_seg_crc`。注意"`white_mode` 打开"或"`official_cert_md5` 为空"都会让这条判定整体失效。
- **`cc2`**（注册 `0x27FF58`，运行槽 `0x282B4C`）：`0x487694`/`0x487798` 解析 APK **中央目录**取出各 `.so` 条目的 CRC/size，`0x282E04` 对 `nativeLibraryDir/<条目名>` 的实际文件重算 CRC32（`0x4892B4`）比对——检测"APK 内 so 与安装后 so 不一致"（即换 so 重打包）。`cc2_force` 默认 1、`cc2_x86` 默认 0；失配发 `"cc2"` 事件。实现上疑似有系统性路径拼接缺陷（`"%s/%s"` 把 `nativeLibraryDir` 与 zip 条目全名直接拼，条目带 `lib/arm64-v8a/` 前缀时 `access` 必然失败），属设计缺陷而非可主动利用的漏洞。
- **`shell_checker`**（注册 `0x28016C`，`sub_2BA160`，运行槽 `0x2BA1CC`）：**没有壳特征库、也不校验代码段**；只把 Java 侧传入的 `apk_path/shell_ver/check_state/debugger/s_open_id/time_magic/chk_err_%d` 回传发布，另外探测 `/sdcard/sdk/enable.log`（`0x2BA7F4`，含 1/1000 随机命中）并解析 `acecrh.dat`（`0x2BA960`）。
- **`file`**（注册 `0x27FD28`，运行槽 `0x29B194`）：按配置键 `comm.dat`（id 713）取 32 条路径清单，只查存在性与 `stat` 属性，事件头 `0x60000233B`，格式 `"|%s:0x%08x, from_c:%d"`；**不做内容哈希**。

`elf_hook_scan`（ctor `sub_28EA9C`，虚表 `0x514EC8`）的运行槽 `0x28EAF0` 是单条 `RET` 空桩——本版本只注册不干活，实际 ELF/内存判定由上述 `module2`、`various_opcode`、`opcode_scan` 分担。

### 7.8 设备画像、账号与上报汇聚

这一组模块本身"不做判定"，负责把上下文加工成可上报的画像，是服务端判定的原材料供应商。

- **`info`**（`sub_2DDE78`，运行槽 `+0x30 = sub_2DDFDC`）：**只有当 `uid != ctx+0xD4` 或距上次采集 ≥ `0x1C20`（7200 s）时才重采**——即设备指纹有 2 小时陈旧窗口，换机/换环境/装包在窗口内不会体现。随后串行调 15 个采集器；采集位串由 `sub_2DE288` 以 `dst[i]=src[i]^(0xBE+i)`（7 字节）解出，格式 `inf_cl:1|%d|%d|%d|%08x`（`0x2DE394`），4 个开关（`0x13B`/`0x8D`/`0x9A`/`0xAB`）默认全开。自身不发报，交 publisher 以 `info=%s` 发布。
- **`tablet`**（`sub_29C3AC`，注册 `0x27FBC4`，**`W3=0`**）：不轮询，由任务表 `0x27019C` 的 `ScanTablet`(`0x27F7A8`) 触发；七层带开关判据（`tablet_certain`(13353)/`tablet_unknown`/`tablet_model`(13383)/`tablet_prop`(13398)/`tablet_layout`(13456)/`tablet_dp`/`tablet_size`），OEM 白名单在 `0x29CEB4`（Lenovo/EEBBK），出口 `DeviceType=%d|TabletInfo=%s|`。
- **`user_tag`**（`sub_29B444`，运行槽 `+0x10 = 0x29B5A0`）：仅当 `ctx+0x3B3` 有效且 `force_usertag_scan`(46557) 或 `user_tag` 为开时运行——**两者默认均为 0**；score 从 100 递减、`BIC W8,W8,W8,ASR#31` 钳非负，落 `ano_uts_c2.dat`(`0x29BD44`)，上报 `user_tag:%s%d`(`0x29B754`)。
- **`ksat`**（`sub_2AAA40`，对象 `calloc(0x58)`，运行槽 `+0x10 = 0x2AAB88`）：见 7.5 的"注意默认姿态"。
- **`pe_rep`**（`sub_28F5C4`，注册 `0x280290`）与 **`env_chk`**（`calloc(0x50)+sub_28FD5C`，注册 `0x2802E8`）：**两者共用同一实现 `0x28FDB0`**（虚表 `off_514EF8`/`off_514F28` 的 `+0x40` 都指向它），因此同组检查（`secc:` 五元组、信号 handler 落点 `sigac`、`/proc` 文件可读写 `path=%s|permission=%s`、`stack_zero_cnt`、`kmc`、`ptc/ptc_max`）会被**各执行一次、各上报一次**。`pe_rep` 本体只有一个字面量 `com.`(`0x28FA8C`)，是纯调度壳。
- **`info_publisher`**（`sub_4CB94C`，注册 `0x27FFC4`）：三步管线 `0x4CCC44` → `0x4CBE5C` → `0x4CBEF0`（观察者 `vf[0x18]`）；底层队列 `0x4CD118` **上限 128 条，超出即静默丢弃（返回 -1 且不重试）**，就绪位 `+112==0` 时又直接返回 0，调用方无法区分"成功"与"丢弃"。`0x4CB94C` 共 32 处 xref，是**全 SDK 唯一的上报汇聚点**。
- **`auto_defence3`**（`sub_258C50`，注册 `0x27FB78`）：实际 vtable 由 getter `0x258D54` 写为 `off_514298`，主判定 `+0x20 = 0x259210`（平坦化 7 case），读 9 个 `anti_*` 开关（48390/29269/29288/29299/29312/29329/29358/31079/49766）；检测体包括 `gp3`(24644)、`anti_bm:%s`(26541)、`ida:%d`(596088，读 `TracerPid`)、hook 名单（`libxhook.so`…`libfake-linker-2x.so`，`0x259840`）。

**注册标志 ≠ 实际能力**：`tablet` 的 `W3=0`、`user_tag` 的 `W3=!W21` 说明它们默认不进运行序列；而真正是否启用还叠了模块内开关的默认值（`att_svr`=0、`user_tag`=0、`force_usertag_scan`=0）。只看注册表会高估能力，必须结合模块内默认值。

---

## 8. 结构性弱点与绕过面

> 本章只描述"检测逻辑自身的设计缺陷"，不含任何绕过实现。所有条目都能在上文找到对应地址。

### 8.1 官方开关就是最直接的绕过面

五类检测（用户标签、模拟器、反性能分析、云手机、黑产模块）与设备采集位图，都提供了**运行期开关命令**，且：

1. **无鉴权、无签名、不校验调用者**：`tss_sdk_ioctl` 是导出函数，任何能拿到 `libtersafe.so` 句柄的代码（游戏本体、注入的 so、甚至 Java 侧反射）都能调用。
2. **开关只在内存**：`ctx+0x3B3..0x3B7` 与 `+0x3BC` 是普通字节/位图，无副本校验、无周期性回读。
3. **调试态别名**：`!cuts/!ces/!cap/!ccps/!cbm/!cdic:%x` 说明这些开关本来就是给内部调试用的——它们被保留到了正式版。
4. **`IsEnabled` 查询接口**：可以反查"当前哪些检测开着"，为定向关闭提供地图。

结论：**检测的"开关面"比"检测面"更容易攻击**。这类命令的存在意味着 ACE 的威胁模型里，"游戏客户端本身"是可信的——一旦攻击者能执行代码（而这正是外挂的前提），这个假设就失效了。

### 8.2 检测逻辑的静态弱点（逐条）

| # | 弱点 | 位置 | 说明 |
|---|---|---|---|
| 1 | 进程名匹配用 `strstr` | `0x4E2F30` | 黑产名单比对的是 `/proc/<pid>/comm`，改 `comm`（`prctl(PR_SET_NAME)`）即可规避；包名改了没用，进程名改了有用 |
| 2 | 属性读取依赖 libc | 全库 | 所有 `__system_property_get` 都可被 PLT/GOT hook；SDK 只在 mincore/特征搜索等少数点做了"直 syscall"备份（`0x2F1950`、`0x37048C`），属性路径没有 |
| 3 | 诱饵短路 | `0x2A6AE0` | 已反编译确认：先判 `/data/local/tmp/12re.34frida.56server78`（27374，去掉数字即 `re.frida.server`，是 27431 真实路径的"带数字变体"），**存在即 `return 0` 判干净**，三条真实路径（27431/27465/27492）不再检查；只有诱饵不存在时才继续。反向利用：在目标机创建这个空文件，即可让 frida-server 文件检测整体失效；同时它也是给分析者的陷阱——手工 `touch` 一个"看起来像 frida"的文件，反而看到"未检测到" |
| 4 | faccessat 路径固定 | `0x2BB3B0`/`0x2BB764` | 自实现 syscall 绕过了 libc hook，但探测的 14 个目录/20 个文件是编译期常量，可用 mount namespace/overlay 隐藏 |
| 5 | maps 只看字符串 | `0x2BD038`/`0x2A80C0` | 通过 `memfd_create` + 重命名、或 unlink 后保留映射，可让路径不含 `frida`/`zygisk` 字样 |
| 6 | GP3/GP6 需要附着 | `0x26B25C`/`0x269658` | `ptrace(ATTACH)` 受 SELinux、`hidepid`、`PR_SET_DUMPABLE=0` 限制；被检测进程只要关掉 dumpable 就能让 GP3/GP6 失败（而失败在 SDK 里通常只记"无结果"，不是"命中"） |
| 7 | 反自动点击是统计阈值 | `0x284340` | 500 桶直方图 + `rate` 阈值，随机化间隔/加抖动即可把 `rate` 压到阈值下；`rand()%1000==517` 的抽样跳过还主动制造漏报 |
| 8 | attestation 依赖 TEE | `0x4D3088` | 模拟器/云手机没有可用 TEE，返回码 2/4/5 本身就是特征——这对防守方是好事，但也意味着"能拿到真机证书"的设备可复用证书链（服务端需绑定 `setAttestationChallenge` 随机数才能防重放） |
| 9 | 规则本地求值 | `0x4C9214` | 云控表达式的求值结果是一个普通返回值，hook 求值器或篡改算子表（`qword_568E98`）即可让所有规则恒为 false |
| 10 | 上报可被截断 | `0x4CBEF0` | 观察者链表是普通内存结构，`+152` 标志位控制"是否带 payload"；清掉标志或摘掉观察者，上报就"合法地"变空 |
| 11 | 自校验范围有限 | `0x4CBDB4` / `0x28E140` | `txt_seg_crc`（`ctx+0x84`）在 `0x28E140` 由 `STR W19,[X0,#0x84]` 写入，值经 `MVN` 取反，与 CRC32 的 final `~` 一致（反向定位到 0x28DC.. 的大平坦化函数）；覆盖范围只是单一段，`libtprt.so` 与 `.data.rel.ro`（模块表指针所在）都不在内 |
| 12 | 名单可被替换 | `0x230BD0` | 外部 `comm.dat` 优先于内置名单；能写数据目录就能替换名单（虽然服务端可用 `sig5` 验签，但验签失败时的行为是"回退内置"，不是"上报异常"） |
| 13 | 热更新模块决定加密 | `0x1D4334` / `0x1B9D54` | 加密器来自 `files/libtersafeupdate2.so`：文件不存在 → `qword_55E8E0 == 0` → `encryptpacket` 直接返回 `-146739396`（明文），内置 `sub_4889F4` 不会被调用。删掉这个 so 即可让发包"裸奔"（服务端可观测，但确是一条单点失效路径） |
| 14 | 更新模块可被替换 | `0x1D4334` | `dlopen` 路径由 `/data/data/%s/files/` 拼成，so 内容无签名校验、`dlsym` 只按名字取 `GetTssExportFunc2`；能写 `files/` 就能用同名 so 提供**全假**的加密/上报/ischeatpacket 实现，且 `JNI_OnLoad` 会被它完全接管 |
| 15 | 代码段校验只抽 1/20 槽 | `0x2A9674` | `various_opcode` 单次只验 20 个采样槽中的 1 个（槽号由 `sub_1F524C` 的返回值决定），且期望值是 `XOR 0xACC9725E` 的静态常量——改一处非采样槽的代码，需要被抽中才会暴露 |
| 16 | 逐页 CRC 崩溃窗口窄 | `0x28E364` | `opcode_scan` 仅当"总页 ≥ 100 且差异页 ≥ 1 且差异页 ≤ 10%"时崩溃；改动页数超过 10% 只上报不崩，而"改多处"恰恰是真实补丁的形态 |
| 17 | 证书判定可被配置短路 | `0x2AE0C4` | `cert3` 唯一的硬判据是 `official_cert_md5` 比对；该键为空、`cal_cert_md5`(40203) 关闭、或 `white_mode` 打开，都会让重签名检测整体失效 |
| 18 | cc2 路径拼接缺陷 | `0x282E04` | 用 `"%s/%s"` 拼 `nativeLibraryDir` 与 zip 条目全名（条目含 `lib/arm64-v8a/` 前缀），`access` 必然失败、整条跳过——换 so 重打包在多数情况下不会被 `cc2` 抓到 |
| 19 | 壳/加固检测无实体 | `0x2BA160` | `shell_checker` 没有特征库、不校验代码段，只回传 Java 侧字段；壳检测实际依赖服务端与 `opcode_scan`/`various_opcode` |
| 20 | 设备指纹有 2 小时陈旧窗口 | `0x2DDFDC` | `info` 仅在 `uid` 变化或距上次 ≥7200 s 时重采；窗口内的换机/改机/装包不会反映到上报里 |
| 21 | 上报队列静默丢数据 | `0x4CD118` | 队列上限 128 条，溢出返回 -1 不重试；就绪位 `+112==0` 时直接返回 0，调用方无法区分"已发"与"丢弃"——高频命中项会把后续证据挤掉 |
| 22 | 两个模块重复执行同一检查 | `0x28FDB0` | `pe_rep` 与 `env_chk` 的 `+0x40` 指向同一实现，`secc`/`sigac`/文件权限等被各跑一次、各报一次，属冗余而非增益 |
| 23 | attestation 默认关闭 | `0x2AB450` | `att_svr`(48796) 默认 0，关闭时 `0x2AB450` 直接返回 -1；只有云端显式打开才走 Key Attestation，静态看到的"证书链检测"在默认配置下并不生效 |
| 24 | 多项画像默认关闭 | `0x29B5A0`/`0x27FBC4` | `user_tag`（`user_tag`/`force_usertag_scan` 默认 0）、`tablet`（注册 `W3=0`）在默认配置下不进入运行序列——"41 个模块"不等于"41 项检测常开" |

### 8.3 为什么客户端不做主动反制

全库没有"检测到作弊就杀进程/删文件/封号"的路径（唯一的 `kill(getpid(),9)` 在 `tss_sdk_init` 的异常分支，用于自杀而非攻击）：

- 误杀成本：ACE 覆盖大量机型/ROM，任何本地硬反制都会带来大量客诉。
- 取证需要：封号需要"证据链"，本地删掉痕迹反而破坏证据。
- 法律与合规：客户端主动破坏用户设备（删文件、杀进程）风险极高。

因此它选择了"**采集—上报—服务端判定**"的架构，并把"是否关闭检测"做成可下发的开关（运营/灰度需要）。这套设计在工程上是合理的，但它把"检测是否生效"的最终控制权交给了**运行时命令面**，而命令面没有鉴权。

---

## 9. "判定在服务端"的完整证据链

| 证据 | 位置 |
|---|---|
| 无封禁/删除/杀进程逻辑 | 全库唯一 `kill` 语义是 init 自杀与 GP 调试器控制（`0x262AF0` 的 SIGSTOP/SIGCONT）；`sub_1F0148` 是事件派发，不删文件 |
| 命中统一出口是"上报" | `sub_1F2640(706, tag)` + `sub_1F0148(str,0,0)`（事件码 `0x100002342`）+ 上报容器 `sub_4CBEF0` |
| 字段语义是"证据" | `name/feature/size/mtime/cert_md5/crc/time/pid/seq` 全部是取证字段，无"处置指令" |
| API 遥测 | 7 个 `TssSDK*` monitor 事件 + `tss_sdk_init_start/finish/connect_count/heart_beat` → 服务端据此判断 SDK 是否被完整调用 |
| 云控规则下发 | 101 条算子 + 表达式解释器 `0x4C9214` → 策略（阈值、名单、组合条件）在服务端 |
| 服务器基础设施 | `*.cschannel.anticheatexpert.com`、`acekeeper.anticheatexpert.com`、16 个内置 IP、CS 通道 + `libTDataMaster.so` |
| Keeper 守护 | `0x281D50` 的 `ACE Keeper` 通道，独立于主通道，用于"检测 SDK 自身是否存活" |

**判罚链条**（据代码结构与字符串推断）：

```
游戏启动 → tss_sdk_init → 41 模块按云控配置执行 → 命中项写入上报容器（id=%d|k=v|…）
        → 0x238320(36 字节 XOR) → 0x48A710(Base64) → 观察者 vtable+0x18
        → sub_2015EC 分片(4096B + CRC32) → sub_202A00 组包(魔数 0x010A0023)
        → 裸 TCP:443 → nj/tyf.cschannel.anticheatexpert.com
        → 服务端 ACE 风控（规则/名单/模型）→ 判定 → 封禁/观察/放行
```

`encryptpacket`（`0x1B9D54`）走的是**另一条路**：它加密的是"游戏/SDK 之间的业务包"，不是上报包——上报包在到达 TCP 层之前只做了 XOR+Base64 混淆（6.1）。这一点容易混淆，旧分析把两者当成同一条链。

客户端在链条中的角色是"传感器 + 执行器（关开关）"，不是"裁判"。

---

## 10. 与旧分析的差异（勘误）

| 旧结论 | 本轮结论 | 证据 |
|---|---|---|
| 检测到异常置 `byte_55E8D4=0`、`qword_55E8E0=NULL` | `byte_55E8D4` 是"初始化完成"标志：全库仅 4 处引用（都在 `tss_sdk_init`），唯一的写是 0x1BFDA4 的 `STRB #1`，**没有任何地方把它清 0**；`qword_55E8E0` 不是"句柄"而是**热更新模块 `libtersafeupdate2.so` 导出的函数表**（见 4.6），53 处调用先查它 | `0x1BF4D0` 反编译 + 0x55E8D4 的 xref，`0x1B9D54` 入口，`0x1D4334` |
| 存在约 20 秒周期监控线程 | 全库 sleep/nanosleep 站点 16 处，无固定 20 秒轮询；只有 6 处 `pthread_create`，任务由 `0x4CD6F0` 命名调度 | `icall.py pthread_create`、`disp.py` |
| 字符串表长度 66948 | 密文表止于约 60586，尾部是明文 `.rodata`（C++ typeinfo） | 解密 DFS 定界 |
| 有 `PTRACE_TRACEME` 反调试 | 无 TRACEME；ptrace 用于**反向调试**（ATTACH 外部进程、GP3 硬件断点、GP6 syscall 代理） | `0x50E6F0` 桩的 17 个调用点 |
| 有悬浮窗检测 | 未发现悬浮窗/无障碍检测；有"直播/投屏"(`live`) 与"云游戏"(`cps_new*`) 模块 | 模块表 |
| 特征模块 40 个 | **41 个**：40 次 `BL sub_222284` + 1 次尾调用 `B sub_222284`(`0x280318`)；且 `tablet`/`user_tag`/`att_svr` 等默认不启用 | `tools/regs2.py` + `0x27FAE4` 反编译 |
| 规则算子 101 条 | **101 条唯一算子**成立（子代理报的 86 项是子集），完整表 `out/ops.tsv` | `0x4E3CAC` 反编译 + `ops.py` |
| 关闭命令 `CloseCloudPhoneScan → +0x3B5` | 正确为 `+0x3B6`；`+0x3B5` 属 `CloseAntiProfiler` | `0x1BDB80/0x1BDB98` |
| GPU 采集走 `getDeviceConfigurationInfo` | 正确，且只取 GLES 版本字符串；无 EGL/glGetString | `0x2CABF4` |
| 字符串表 2,868 条、98 组 (E,C)、密文止于约 60,586 | **3,198 条**、99–101 组、最后一条非空记录止于 60,947；记录格式 `[key][len^key][cipher][check]`，尾字节校验 `(check^cs^key)==0xFF`。旧表漏掉了 `ft_oaid`(58,581)、`AndroidIdErr`(52,998) 等尾部记录 | `docs/tersafe_strings.md`、`docs/strings.tsv` |

---

## 11. 附录

### 11.1 关键地址索引

| 功能 | 地址 |
|---|---|
| SDK 初始化 | `0x1BF4D0` |
| 包加密/解密 | `0x1B9D54` / `0x1BA0D4` |
| 校验是否作弊包 | `0x1B90E0` |
| 命令分发（88 路） | `0x1BCF84` |
| 文本命令解析 | `0x1BD7FC..0x1BE12C` |
| JNI_OnLoad | `0x1D63D4` |
| 模块注册表 | `0x27FAE4`（经 `.rela.dyn 0x514C40` 调用） |
| 检查任务表 | `0x27019C`（经 `.rela.dyn 0x514A20` 调用）→ `sub_224F78`/`sub_224FE4` |
| 算子注册表 | `0x4E3CAC`（表指针 `qword_568E98`，懒初始化 `0x4C91D8`） |
| 表达式求值器 | `0x4C9214` |
| 上报字段构造器 | `0x4CBB2C..0x4CCE1C` |
| 上报容器 | `0x4CCC44` / `0x4CBE5C` / `0x4CBEF0` |
| 配置路径生成 | `0x218870` |
| Root 总入口 | `0x271958` → `0x2BAEE0`（15 项表 `0x515600`） |
| 模拟器品牌位图 | `0x280688`（标签 `0x280C3C`） |
| 云手机聚合 | `0x2B54C8` |
| frida_scan 总控 | `0x2A9040`（虚表 `0x5151C0`） |
| 设备采集总控 | `0x2C9D78` |
| 反自动点击 | `0x283C10` / `0x2B37B4` / `0x284544` |
| 迷你调试器 | `0x2623D4` |
| GP6 服务 | `0x268EE4` / `0x269EFC` |
| GP3 硬件断点 | `0x26B25C` |
| GP4 maps/pagemap | `0x266E54` |
| memtrap | `0x2537A8` |
| libtprt 加载 | `0x238E70` / `0x2BA5FC` |
| 热更新模块加载 | `0x1D4334`（`GetTssExportFunc2`），`JNI_OnLoad` `0x1D63D4` |
| 模块注册表 | `0x27FAE4`（41 项）/ `sub_222284` 节点构造 |
| 代码段校验 | `0x2A9674`（various_opcode）/ `0x28DC98`（opcode_scan）/ `0x2AE0C4`（cert3）/ `0x282B4C`（cc2，比对在 `0x282E04`） |
| 上报编码 | `0x4CBE5C`（`id=%d\|…`）→ `0x238320`（36 字节 XOR）→ `0x48A710`（Base64） |
| TCP 客户端 | `0x4CDD80`/`0x201DB8`/`0x202A00`/`0x2015EC` |
| 字符串表基址 | `0xFBCB0`（`sub_4E4A68`），缓存表 `sub_4E4A7C` |

### 11.2 产物与复现

```
report/
  main.md              本报告
  partA_root.md        Root / 完整性
  partB_emu.md         模拟器 / 云手机 / 多开
  partC1_hook.md       Hook / 注入 / Frida
  partC2_antidbg.md    调试对抗 / 内存保护
  partD_devinfo.md     设备采集 / 伪造 / 反自动点击
  partE_integrity.md   代码段完整性（various_opcode/opcode_scan/cert3/cc2/file/shell_checker）
  partF_apps.md        应用与进程（process/black_app/collect_apk/anoscan/…）
  partG_account.md     设备账号与上报（info/tablet/user_tag/ksat/pe_rep/env_chk）
  partH_misc.md        云游戏/守护/白名单（live/cps/wb/cs_vm/ob_normal…）
  partI_siblings.md    伴生库身份（libsaf/libTDataMaster/libqimei/libckguard/libencrypt）
  partJ_blob.md        下发 blob 格式（a64/a32 段表、.img 原生模块、RSA-2048 验签、comm.dat 名单）
out/
  strings.tsv          2868 条主表字符串（offset/len/refcount/string）
  allstr.tsv           3997 条（主表 + 内联，含所属函数与调用点）
  func_strings.txt     876 个函数→字符串摘要
  ops.tsv              101 条规则算子（唯一名）
  config_keys.tsv      833 个云控配置键候选
  db.json              offset→{s,n,funcs,sites}
  cg.json / calls.pkl  调用图（12434 函数 / 58551 内部调用）
  funcstarts.pkl       16284 个函数起始地址（.eh_frame_hdr）
  strtab.bin           66948 字节密文表
dyn/
  ano_tmp_full/        从真机 /data/data/.../files/ano_tmp 拉回的 113 个运行期文件
  unpack/              解包后的 comm.dat / sig4 / sig5 / a32.dat / a64.dat / 各 .sig
  redownload/          删除后重新下发的副本（与原件 MD5 一致）
  ace.pcap             启动流量抓包（唯一非 TLS 流的 ACE 通道）
  hook3..hook10.js     检测函数 patch 脚本
  hook_ioctl.js        命令面观测（ioctl 命令号 / 上报项）
  hook_text.js         文本命令 + 扩展命令观测
  pcap2.py             抓包解析（SLL2）
  f17..f21.py          attach / spawn / 生命周期观测驱动
tools/
  look.py              字符串/函数查询（主入口）
  xref.py              调用者/被调用者
  icall.py             按导入名找调用点
  disp.py              按结构体偏移找读取者
  adrp.py / adrp2.py   按数据地址找引用者（后者支持任意 ELF）
  regs.py / regs2.py   抽取 41 次模块注册的 (名字, ctor)
  cmds.py              88 条 ioctl 命令 → 处理地址 → 字符串
  blob.py              blob 容器/段表/.img 头/comm 名单/验签（`info|img|names|comm|mrpcs|verify`）
  relocs_show.py       打印 R_AARCH64_RELATIVE 的 addend（还原 vtable）
  merge.py             重建 allstr.tsv
  ops.py / jtab.py / pltsym.py / dyninfo.py / ...
```

复现示例：

```
python tools\look.py -f 0x2bb764          # 该函数引用的字符串
python tools\xref.py 0x2C9214 in          # 谁调用了表达式求值器
python tools\icall.py ^pthread_create$    # 所有线程创建点
python tools\disp.py 0x3bc                # 谁读取了采集掩码
```

---

## 12. 动态验证（真机，2026-11-26）

静态分析的每一条"应当如此"，都应当在真机上被观测证实或修正。本章记录在一台已 root 的一加 Ace6 上，对 `com.tencent.tmgp.sgame` 12.1.1.1 所做的运行期实验。

### 12.1 环境与方法

| 项目 | 值 |
|---|---|
| 设备 | 一台 arm64 真机，Android 17 / SDK 37 |
| root | KernelSU，`su -c id` → uid=0，SELinux 域 `u:r:ksu:s0` |
| 游戏 | `com.tencent.tmgp.sgame` 12.1.1.1（versionCode 1201010103），targetSdk 30 |
| 安装路径 | `/data/app/~~9usLw8j-oA0N9e5dq1Fldg==/com.tencent.tmgp.sgame-mh1xM5-K32eIJDV1j7JpZg==` |
| 工具 | `adb` 37.0.1；`frida-server` 17.26.2（`/data/local/tmp/frida-server`，`adb forward tcp:27042`）；`tcpdump`（系统自带） |
| 原则 | 不修改 APK、不修改 `/data/app` 下的 so；所有观测用 root 权限 + 只读手段 + 进程内钩子 |

三次基线观测（不带任何钩子）确认：游戏在无注入时可正常进入 Unity 大厅并长时间运行；这说明后续所有异常都来自注入或钩子，而非游戏自身不稳定。

### 12.2 运行期下发物证

`/data/data/com.tencent.tmgp.sgame/files/ano_tmp/` 在每次启动时被写入（121 个条目，其中上百个是 0 字节的 `ms_XXXXXXXX_XXXXXXXX_tmp.dat` 占位）。有效载荷：

| 文件 | 大小 | 说明 |
|---|---|---|
| `comm.zip` | 33011 | 内含 `comm.dat` 69731 + `sig4` 256 + `sig5` 256 |
| `ob_x.zip` | 18408 | 内含 `a32.dat` 18259 / `a64.dat` 16970 及各自 `.sig` 256 |
| `ob_cs2.zip` | 96183 | 内含 `a32.dat` 118582 / `a64.dat` 117291 及各自 `.sig` 256 |
| `mrpcs.data` | 31582 | mrpcs 通道数据 |
| `mrpcs_MVM.data` / `mrpcs_com.data` | 23810 / 266 | mrpcs 变体 |
| `config2.dat.e70c5b81` / `config3.dat.da6c7231` | 460 / 496 | 云控配置（带内容哈希后缀） |
| `mn_cache.dat` | 2849 | 141 条模块名缓存（`libtprt.so`、`libBeacon.so.*`、`libckguard.so` 等） |
| `kvcache8.dat` | 180 | 上报字段缓存（`mem_ava`、`va:4`、`mem_dts`、`ul:1`、`nf_rr`、`env_rr:0`） |
| `ano_ksh.dat` | 119 | 包名 + 64 位十六进制摘要（SHA256 形态） |
| `atti_obv.dat` / `adc0.dat` / `cpcah.dat` | 174 / 1239 / 255 | attestation、采集、云手机缓存 |
| `tersafe.update` | 4 | `5a7ac517`（热更新标记/版本） |

已用 `tar` 打包拉回本机（`D:\workspace\ACE\dyn\ano_tmp_full`，113 个文件），并解包到 `dyn/unpack`。

**重下发实验**：把 `ob_x.zip`/`ob_cs2.zip`/`comm.zip` 三个文件从 `ano_tmp` 里删掉，然后重启游戏；35 秒后三个文件**全部重新出现**，且与删除前的副本 **MD5 完全一致**（`ob_x` C64AC70C7ECC、`ob_cs2` 9DEBDC0E125A、`comm` 6DE7F7499763）。这证明：这些载荷是 SDK 在每次启动时主动拉取的（不是安装包自带、也不是一次性缓存），且服务端当前对同一版本客户端返回的是同一份内容。

**格式判读（已由 blob 专项分析修正）**：`comm.dat` 头是 `u32BE 3 + "tlf\0"`，记录流是内存态解压后的 `[u32BE len][len 字节]` 条目（详见 12.10 与 `partJ_blob.md`）；`a64.dat` 的头 8 字节为 `magic 0x20220118（大端）+ 段数`，随后是 `[u32BE namelen][段名 36-XOR][u32BE paylen][S 盒变换的载荷]` 的段表 —— 段名解出 `acp.img`、`cse.img`、`detect_live_app.img` 等，载荷是**带逐字混淆的 ARM64 原生模块**（不是 VM 字节码）。`0x83` 占 42% 只是因为它是 S 盒对 `0x00` 的像，并非填充。

**可解部分**：36 字节密钥 `0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ` 循环异或即可解出 `mn_cache.dat`（141 条 so 名）、`ano_ksh.dat`（包名 + 摘要）、`kvcache8.dat`（上报字段名）。这说明缓存类文件用的是**轻量混淆**，而不是包加密。

### 12.3 装载与验签实测

在 `libtersafe.so` 的 `0x1D7268`（读文件 + 验签）下钩，启动后可观测到两次连续调用：

```
[blob] a64.dat / a64.sig      →  [verify] ret = 1
[blob] a64.dat / a64.sig      →  [verify] ret = 1
```

即：**a64.dat 与 a64.sig 确实在运行期从 `ano_tmp` 读取，且 `sub_4CB458` 验签通过（返回 1）**；两次调用对应两条装载通道（`ob_x` 与 `ob_cs2` 两套包各自携带一份）。这与静态分析中"两把内嵌 RSA 公钥、比对 16 字节"完全吻合。

同时 `/proc/<pid>/maps` 中**没有** `libtersafeupdate2.so`，也没有任何 `ob_*`/`a64` 文件的映射 —— blob 是读进堆内存后交给 VM 的，不以文件形式 mmap，因此"按 maps 找可疑 so"抓不到它。

### 12.4 上报实测

在容器写入函数 `0x4CBEF0` 与编码函数 `0x238320` 下钩，大厅阶段（约 60 秒）共捕获 12 条明文，全部形如 `id=<字段号>|<k=v|...>`：

```
id=1|sdk_ver=7.7.50.28931          ← 字段 3，SDK 版本
id=1|seq=0|pid=26315|time=1795692807   ← 字段 2，心跳，每 20 秒一条，seq 自增
id=1|seq=1|pid=26315|time=1795692827
id=1|seq=2|pid=26315|time=1795692847
id=9|info=foo                      ← 字段 1，字面量 "foo" 的健康检查项
```

三点结论：

1. **上报项确实是文本 key=value 拼接**，与静态分析一致；`id=` 前缀由容器写入时加，字段号与格式串一一对应。
2. **大厅阶段上报极少**：只有心跳、SDK 版本、一条 `info=foo`。所有 root/模拟器/Hook/完整性检测项都没有上送 —— 因为它们要等到游戏下发 `StartSecScan` 等命令后才运行（见 4.4 的命令面），大厅阶段并没有触发。
3. `info=foo` 是一条**硬编码字面量**，推测是链路健康检查/自测项；它同时也说明：服务端看到的"info"字段并不总是真实采集值。

### 12.5 云控键实测（启动阶段）

在配置读取函数 `0x22DA98` 下钩并去重，启动 60 秒内实际被读取的键（顺序即读取顺序）：

```
gcloud, gcloud_regist, no_tshe, CSReconnect, cs3, force_hb, tdm_report, sec_path,
win_fea_sync, mrpcs1, e_hbeat, scan1, antiemulator, ve_rsa_new, ve_rsa_his,
ten_by_rsa, tenao_by_rsa, yyb_by_rsa, yyx_by_rsa, qq_by_rsa, scan_x86,
scan_x86_by_mem, sx_rel, am_cnt, allow_xbl, mrsen_th, ce_bad, x86_mem_failed,
x86_sys_scan, ss_c_a_e, property_get, tdm_dev_info, qos_filt, user_tag, mt2_evt,
gp4_2, anti_ts2, ts2_timejudge, interface_test, report_bk, sc_idle, sc_dlp,
mem_trap2, mt2_ko, random_trap, pagemap_trap, memtrap_name, self_sys, gs_dl,
cache_cus_fea, ext_cdn_first, screenshot, mp_lf_nwthrd, nw_stp_pnts, mvm_bk_proc,
mvm_bk_task, dl_by_ver, mrmoni_th, mrmoni_fb, mrmoni_fc, ms_use_jni_get_apk_version,
MrpcsActiveSig, reset_gs_chann, is_en_ds, cs_pkg_init, ObfQos, mt_sar2, req_custom,
force_apk_collect, cs_speed_ctl, apk_permission, rcv_by_main, use_lf_aphash2, enc_r3,
force_r2, cs_ipv6, test_cs_ip_ext, game_host, game_bip, port_80, GameVipCS,
ForceGameVip, force_built_in_ip, cs2.hb.start, tcj, tcj_encrypt, mt2_no_r,
attunlock4, mt2_no_root
```

这张表比静态枚举更有价值：它给出了**真实存在的键名**（静态分析里很多键名是解出来的字符串，未必都被读取），也印证了"几乎每个检测面都有一个独立开关"（`mt2_*`/`mem_trap*`/`pagemap_trap`/`attunlock4`/`force_apk_collect`/`scan_x86*` 等）。

### 12.6 反注入实测

| 实验 | 结果 |
|---|---|
| 不注入，仅启动 | 正常运行，无崩溃 |
| `frida-server` attach 后执行**空脚本**（`create_script("")`） | 8–20 秒内进程死于 `F libc: Invalid address 0x.... passed to free: value not allocated`（SIGABRT） |
| 先 patch 14 个检测函数（frida 文件/端口/maps/art/线程名/memfd、various_opcode、opcode_scan、cert3、TracerPid 三路、root 扫描） | 存活延长到 60–65 秒，随后仍死 |
| patch 上述 14 个 + blob 装载链（`0x1D7064`/`0x1D7418`/`0x1D90BC`/`0x1DA584`/`0x26EA68`） | 存活 60–65 秒，仍死 |
| 钩 `kill`/`tgkill`/`raise`/`abort`/`pthread_kill`/`_exit` | 全程**没有**捕获到 sig 9/15 的 kill 调用；死亡不是这些 API 触发的 |

**结论**：ACE 的反注入处置是"让进程自己 `free()` 一个非法指针而 abort"，不是 `kill`。这解释了为什么静态分析里看不到 `kill(getpid(),9)` 的显式路径被执行 —— 它走的是另一条自毁路径（`free` 一个页对齐的非法地址）。而这种处置**无论注入方式如何都会触发**：即使把所有已知检测函数都 patch 成 `return 0`，进程仍在约 1 分钟后死亡，说明还有一条未定位的判定路径（可能在 libtprt 的 OBJ_VM 里，或在 blob 装载后由 VM 执行）。

另一个实测到的加固点：**root 读不了自身进程内存**。`/proc/<pid>/mem` 一律返回 `EIO`，`/proc/<pid>/status` 显示 `TracerPid: 0`，说明 ACE 在初始化后把进程设成 non-dumpable（`prctl(PR_SET_DUMPABLE,0)`），即使 root 且有 `CAP_SYS_PTRACE` 也无法 `pread` —— 这直接封死了"dump 内存找密钥"的常规路线。

**一处必要的保留**：只挂 `free` 记录脚本的那次运行活过了 55 秒，并且进程是在 `detach` 之后才消失——也就是说存活时间在 8–65 秒之间波动，与注入方式、钩子数量、detach 时机都相关，并不是一个硬定时器。`free` 钩子还抓到大量 libtprt 自身释放页对齐指针的调用（如 `0xb400007531755000`，调用栈全在 `libtprt.so!0x127e30/0x140574`），属于正常分配器行为；真正致命的那次 `free` 没有被捕获到（发生在脚本 detach 之后），所以"自杀"是**行为层面的强证据**，但具体指令地址仍未定位。

匿名可执行区里还能看到 `[anon:ano_sg_2]`（36 KB，`rwxp`）这类 ACE 命名的映射，推测是 VM 的代码/数据页；由于内存不可读，未能进一步取证。

### 12.7 网络实测

用设备自带 `tcpdump` 抓 45 秒启动流量（5801 个包、153 条 TCP 流），其中**只有一条不是 TLS**：

```
10.0.0.2:50658  ->  117.89.177.167:443    20442 字节（上行）
117.89.177.167:443 ->  10.0.0.2:50658    751068 字节（下行）
```

上行首部：`01 00 00 00 2a 07 00 00 00 00 83 1b 0e da 00 00 0a 11 ...`，下行首部：`01 00 00 00 32 08 00 00 00 01 83 1b 0e da 00 00 0a 11 62 18 08 6b ...`；两个方向都反复出现 8 字节标签 `83 1b 0e da 00 00 0a 11`，之后是随机字节。

**端点归属已闭环**：在设备上解析 `nj.cschannel.anticheatexpert.com`，得到的正是 `117.89.177.167`（`ping` 实测，TTL 52）；`tyf.cschannel.anticheatexpert.com` 解析为 `175.27.10.218`，`acekeeper.anticheatexpert.com` 解析为 `0.0.0.1`（已废弃）。也就是说，抓包里那条唯一明文 TCP 流的目的地，**就是静态分析中内置的 `nj.cschannel.anticheatexpert.com`**（字符串表 60040），说明本次连接走的是"内置主机名"路径，而不是云控下发的主机。

**这也与静态分析完全对上**：ACE 的传输是"裸 TCP + 自定义二进制帧"，端口写 443 只是为了伪装成 HTTPS（全库无 SSL/TLS 导入）。其余 152 条流都是标准 TLS（`16 03 03` 开头），属于游戏登录、CDN、TDM 等其它组件。

由于载荷是二进制密文（不是 12.4 里那种 `base64(xor(...))` 的文本项），要还原内容需要实现 `sub_4889F4 → sub_489050` 那套包编解码；本次只做到"确认通道与帧结构"，未做解密。

### 12.8 动态结论与局限

**被证实的**：

1. 云端下发的检测载荷**真实存在**且每次启动都会被重新拉取：删掉 `ob_x.zip`/`ob_cs2.zip`/`comm.zip` 后重启，35 秒内原样恢复且 MD5 与删除前一致（见 12.2 的"重下发实验"）。
2. a64 原生模块是**签名的原生代码容器**（每段一个 `.img`，RSA-2048+MD5 验签），运行期验签通过后被读入内存、由 `libtprt` 装载与绑定符号执行，不以文件形式映射；其结构与可逆向性见 12.10。
3. 上报是 `id=<n>|k=v|...` 文本项 + `base64(xor(...))`，大厅阶段只有心跳/版本/`info=foo`。
4. 反注入是**自杀式 `free`**，且存在一条未被 patch 覆盖的判定路径；root 无法读进程内存。
5. ACE 的 C2 是**明文 TCP 443**，可被抓包与中间人分析。

**局限**：

- 所有实验都停留在 Unity **大厅**阶段。检测模块要等游戏下发 `StartSecScan`/`NeedRequestApkList` 等命令后才运行，因此本次没有观测到 root/模拟器/Hook/完整性这几类实际上报项；要覆盖这些，需要在真机对局中抓取，或直接实现包解密。
- 反注入的具体判定点未定位（patch 了 14 个已知函数仍会死），需要结合 blob VM 的逆向或内存取证才能确定。
- 未修改 APK、未替换 so，因此"改包后服务端如何判罚"没有被验证。

### 12.9 调用面实测（大厅阶段）

在 `tss_sdk_ioctl`（`0x1BCF84`）入口钩住命令号，观察游戏在启动到大堂的 60 秒内实际下发了哪些命令（不同次运行的调用顺序略有差异，下表为一次典型运行的统计）：

| 命令号 | 次数 | 备注 |
|---|---|---|
| 24 | 17 | 最高频，`sub_4B682C(a1,a2,a3,a4)` 直通 |
| 58 | 7 | 处理器 `0x1BD2E0` |
| 88 | 6 | 处理器 `0x1BD78C`（查字符串首字节） |
| 10 | 3 | **带字符串参数**：`files_dir=/storage/emulated/0/Android/data/com.tencent.tmgp.sgame…` |
| 16 / 18 | 各 3 | 先取配置上下文 |
| 28 | 3 | 要求第 4 参 ≥8 |
| 34 / 35 / 36 | 各 1 | `0x1BD25C` / `0x222F14+0x22325C` / `0x222F14+0x223DBC` |
| 51 / 53 | 各 2 | — |
| 2 / 7 / 81 / 86 | 各 1–3 | 7 会清 `0x521510` 的 0x140 字节缓冲；86 落默认分支转扩展命令 |

两点结论：

1. **大厅阶段只用了最基础的 15 类命令**，其中 `cmd 10` 把应用外部目录 `files_dir` 直接告诉 SDK（决定云控/下发物写到哪里）。
2. **没有任何字符串命令**（`CloseEmulatorScan`/`CloseCloudPhoneScan`/`CloseDevInfoCollect`/`StartSecScan` 等）被下发 —— 说明这五个"关闭检测"开关和扫描启动命令都不是启动期行为，而是等待游戏在登录/对局阶段按云控指示下发。这也解释了 12.4 里"大厅只上送心跳"的现象。

同一次实验中，进程在注入后约 35 秒死亡；而另一次只挂 `free` 记录脚本的运行存活超过 55 秒、并在 `detach` 后随即消失。多次测量的存活时间为 **8–65 秒且不稳定**，因此"注入后约 1 分钟必死"只能作为定性描述，不宜当作精确阈值。

### 12.10 下发 blob 的结构与能力（对 12.2/12.3 的修正与补充）

对拉回的 blob 做纯静态逆向（完整过程见 `partJ_blob.md`，工具 `tools/blob.py`），得到比我最初的"VM 字节码"判断更准确的结构：

**容器**：`u32BE magic 0x20220118` + `u32BE 段数` + 每段 `[u32BE 名字长][名字（36 字节密钥循环 XOR）][u32BE 载荷长][载荷（S 盒 pt=T[ct^0x23]，T 在 libtersafe+0x9A240）]` + 尾部再写一次 magic。四份文件的段表精确闭合到 `EOF−4`。同一张 S 盒（前 8 字节 `ab e4 7f a8 46 24 58 9d`）在 `libtersafe.so` 里出现两次（`0x9A240`、`0xD963C`）、在 `libtprt.so` 里出现一次（`0x173C36`）：libtprt 的 `sub_13C3F0` 用它解载荷、`sub_125198` 用 36 字节密钥解段名。两个库共用同一套编解码，这也解释了为什么 tersafe 侧只看得到"读文件 + 调用"——真正的解析在 tprt 里。

| 包 | 段（即云端下发的模块名） |
|---|---|
| `ob_x`（4 段） | `acp`、`auto_clicker_proxy4`、`close_tprt_hb_debug`、`win_vm_wb` |
| `ob_cs2`（5 段） | `cse`、`detect_live_app`、`enum_apk_r`、`obj_uid_check`、`qxk` |

**段载荷 = `.img` 原生模块**：头魔数 `0x20220623`，随后是四张表（函数/导入/两处保留）、代码区、尾部元数据；导入表里出现 `memset`、`_Znwm`、`_ZdaPv`、`_Znam`、`_ZdlPv` 等 C++ 符号，代码区能解出合法 ARM64 指令（如 `0x99be4ffc ^ 0x30000000 = 0xa9be4ffc`，即 `stp x28,x19,[sp,#-0x20]!`），说明它是**按架构编译的原生代码**，只是对每字的顶部做了扰动、并留有 `??123456` 形态的待重定位占位。装载解析在 `libtprt.so` 的 `sub_1528B0`，符号绑定走 `sub_151FF8`（未知符号则整段拒装），`sub_15321C(obj,0x10000)+0xFFC0` 提供 64 KB 的转发地址空间。

**a32 与 a64 是同一份源码的两份编译产物**：同名段在两种架构下的字节相同率只有 10.9%–37.9%，但段名、表结构、尾部元数据完全一致。

**签名是 RSA-2048**：`sub_489F10` 是 64×32 位 limb 的 Montgomery 模幂（指数 `0x10001`），模数在 `0x547860`/`0x547A68` 两把 key 里（各 520 字节：`nwords=64`、key id、256 字节模数、Montgomery 常量）。签名 256 B 解出后是 `00 ‖ MD5(data) ‖ 00×240`，比较 `m[1:17]` —— 与静态看到的 `memcmp(&v11[1],v13,16)` 完全一致。实测 **5 个文件 / 6 份签名（`comm` 的 `sig4`、`sig5` 分别计）全部能被第二把 key 验证通过**（第一把未命中任何样本，疑为轮换备用钥）；`comm.sig4` 与 `sig5` 逐字节相同，是同一签名复用到两个槽位。

**这意味着什么**：云端下发的不只是开关和名单，**可以下发新的检测逻辑本身**，而且是签名的原生代码模块 —— 新增检测项无需更新 `libtersafe.so`。同时它**只有完整性、没有机密性**：容器变换与 S 盒都是固定的，blob 可以离线还原、静态分析（本节与 `partJ_blob.md` 就是这么做出来的）。这既是我能把它讲清楚的原因，也是它结构上的固有弱点。

`comm.dat` 则承载**名单**：内存态解压后逐条 `[u32BE len][36-XOR 的字符串][u32 id]`，36 个相位全扫可捞出 971 条路径、329 个包名、40 个 so 名，覆盖模拟器（`libhoudini.so`、`libhyzm.so`、`mumu-configs`、`com.mumu.launcher`）、虚拟触控/手柄（`com.xiaoji.virtualtouchutil`、`com.chaozhuo.gameassistant`、`com.handjoy.goplay` 等）、注入框架（`com.saurik.substrate`、`com.topjohnwu.magisk`、`bin.mt.plus`、Frida 的 `catch_.me_.if_.you_.can_`）。`mrpcs*.data` 是第三条独立通道（外层 ZIP/deflate，内层格式未定），暂未见检测语义。

## 13. 结论

1. 王者荣耀 12.1.1.1 的反作弊是**"云控策略 + 客户端传感器"**的经典架构：客户端负责采集环境特征（41 个模块、17 槽设备信息、5 族 Hook/调试对抗），按云控规则做轻量求值、把证据打包上报；判定与处罚全部在服务端。
2. 检测的工程完备度很高：三层字符串加密、全函数平坦化、重定位注册、外部模块接管、运行时代码保护（libtprt）、自实现 syscall、反 PLT hook、诱饵路径、随机化漏报。静态分析成本极高——本报告能给出完整地址表，依赖的是自建的解密器与调用图工具链，而非 IDA 的自动分析。
3. 但它的**控制面是脆弱的**：五类检测开关 + 采集位图 + `IsEnabled` 反查，全部通过无鉴权的导出函数暴露，且只存在内存里。对攻击者而言，"关掉检测"比"对抗检测"便宜得多。
4. **自校验是概率性的**：`various_opcode` 单次抽查 20 槽中的 1 槽、`opcode_scan` 只在差异页 ≤10% 时崩溃、`cc2` 存在路径拼接缺陷、`shell_checker` 无特征库、`att_svr` 默认关闭。真正确定性的只有证书 MD5（`cert3`）与"API 是否被调用"的遥测。
5. 检测与反制的边界划在服务端，客户端保持"只观察不动手"。这既是法律与体验上的正确选择，也意味着**客户端的任何完整性缺失（API 未调用、字段缺失、开关被关）都必须由服务端识别**——API 遥测（7 个 monitor + init/connect/heartbeat 事件）就是为此设计的最后一道防线。
6. 架构上最值得注意的单点是**热更新模块**：`files/libtersafeupdate2.so` 一个文件同时决定了"包加密是否存在"、"`ischeatpacket` 是否有人实现"、"上报数据从哪来"，甚至能接管 `JNI_OnLoad`。它是这套 SDK 的"能力开关"，也是唯一的"单文件失效点"——静态分析 `libtersafe.so` 得到的只是"桥 + 内置兜底"，真实能力要连这个 so 一起看。
7. 热更新之外还有**第二条扩展通道**：`ano_tmp` 里以 `ob_x`/`ob_cs2` 形式落盘的 `a32/a64.dat` 是签名的**原生代码模块**（每段一个 `.img`，段名如 `detect_live_app`、`obj_uid_check`、`qxk`），由 `libtprt` 装载与绑定符号。也就是说，**新增检测项可以随云控下发而完全不改 `libtersafe.so`**——这解释了为什么静态分析里"41 个模块"看起来是全集，而运行期能力仍可能是超集。真机实验证明这些包每次启动都会被重新拉取（删除后 35 秒内原样恢复、MD5 一致）。
8. 与"下发能力"形成反差的是**下发机密性的缺失**：容器（`0x20220118` + 36 字节密钥 XOR + S 盒）和签名（RSA-2048，明文 `00‖MD5‖00×240`）都只保护完整性，不保护内容；blob 可离线还原、静态逆向。这条通道既是分析者的突破口，也是它结构上的固有弱点。


