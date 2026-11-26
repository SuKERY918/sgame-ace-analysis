本报告静态逆向 libtersafe.so 的 Root 与完整性校验。Root 侧由 sub_2BAEE0 驱动 0x515600 的 15 项检查表，覆盖 su 路径、Root 包名、ro.debuggable、SELinux、mount namespace、Zygisk/KernelSU 与栈残留标记；结果写入单例（+9=IsRoot、+10=Reason）并由 0x23DB04 上报。完整性侧由云控开关驱动 APK/证书哈希与 .text 段 CRC，失败按 cert_crash 等标签上报。字符串均以 0xD973C 密钥流解出。

## 1. Root 检测总览

唯一入口是 **sub_271958**（0x271958）：先取引擎单例（sub_22D820），用 sub_4E9608(51944) 解出开关名 `ScanRoot`，调用 `sub_22DA98(ctx,"ScanRoot",1,1)`——这是云控开关读取器（带默认值，返回 1 表示开启）；开关为真且状态结构 `+8`（已扫描标志）为 0 时，调用 **sub_2BAEE0(reason_buf, &state+10, 128)**，把返回值写入 `state+9`（IsRoot），最后置 `+8=1`。即检测是**懒加载、只跑一次**，且整个 Root 扫描可被云端 `ScanRoot` 关闭（默认开）。

sub_2BAEE0（0x2BAEE0）是扫描驱动：栈上 `char buf[128]` 清零后，先直接调用第 0 项 0x2BAFD8(buf,128)；随后 `ADRL X22, off_515600`，循环 14 次 `LDR X8,[X22+X21*8+8]; MOV X0,SP; MOV W1,#0x80; BLR X8`，任一返回 1 即停止并把 buf 经 sub_4A4A20（strlcpy）拷入出参；最后取全局上下文 sub_2BD8E4()，若 `[ctx+0x50]` 非 0 则 `sub_22DA98(ctx,"unlock_root",0,1)`，其返回值与命中结果按位或后返回。

15 项检查表位于 .data.rel.ro **0x515600**（+0x78 为 0 结束），签名统一为 `int fn(char *reason, size_t len)`：

| # | 函数 | 云控开关名（解密所得） | 判据摘要 |
|---|---|---|---|
| 0 | 0x2BAFD8 | 无 | getenv("PATH") 逐目录拼 `/su` → faccessat |
| 1 | 0x2BB3B0 | 无 | 14 个固定目录 + `/su` → faccessat |
| 2 | 0x2BB764 | 无 | 20 个包名/文件路径 → faccessat |
| 3 | 0x2BBA00 | 无 | 配置值 `root_ext_cnt` → atoi 比较 |
| 4 | 0x2BBDBC | 无 | JNI 取 PackageInfo，`TST flags,#0x40`（GET_SIGNATURES） |
| 5 | 0x2BBF64 | 无 | `ro.debuggable` → atoi == 1 |
| 6 | 0x2BC190 | `zygisk_module` | faccessat(`zgkm.dat`) |
| 7 | 0x2BC4CC | `zygisk_stack` | 栈顶 1000 字节内查 `MAGISK_INJ_1` |
| 8 | 0x2BC678 | `sec_context` | 读 `/proc/self/attr/prev` |
| 9 | 0x2BC87C | `magic_delta` | fstatat(`/proc/self/ns/mnt`) 比对 |
| 10 | 0x2BCAE8 | `ksu_files` | 5 个 zygisk 文件 → faccessat |
| 11 | 0x2BCC38 | `ksu_mounts_ext` | `/proc/self/mounts` 含 `zygisksu` |
| 12 | 0x2BCDC4 | `ap_ker` | prctl(45, page, -1) + mincore 探页 |
| 13 | 0x2BCF44 | `ksu_mtp` | prctl(0xDEADBEEF,1,page) + mincore |
| 14 | 0x2BD038 | `zygisk_anonymous` | `/proc/self/maps` 含 `zygisk_module_entry` |

## 2. 路径与包名清单（检查 1、2、10）

检查 1（0x2BB3B0）在序言里解密 14 条目录串入栈（[SP]…+0x68），再内联解出格式串 `"%s/%s"`（0x2BB4A0 起，XOR 0xD9742+i）与 `"su"`（0x2BB528 起，XOR 0xD973F+i），对每个目录 `sub_4A54DC(buf,0x200,"%s/%s",dir,"su")` 后调 `sub_4B8420(buf,0)`。sub_4B8420 是自实现 syscall 分发 thunk（→0x4B73CC，`v5(48,-100,path,0,0)` 即 `faccessat(AT_FDCWD,path,F_OK,0)`，48=__NR_faccessat、-100=AT_FDCWD），**绕开 libc 的 access/stat hook**。返回 0 视为存在。目录清单：`/data/local`、`/data/local/bin`、`/data/local/xbin`、`/sbin`、`/su/bin`、`/system/bin`、`/system/bin/.ext`、`/system/bin/failsafe`、`/system/sd/xbin`、`/system/usr/we-need-root`、`/system/xbin`、`/cache`、`/data`、`/dev`。全部为密文表常量，运行时解密到栈，非常量拼接（仅 `%s/%s` 是拼接）。

检查 2（0x2BB764）把 20 条串各自独立解密到 `[SP]…[SP+0x98]`，`CMP X27,#0x14` 循环 20 次逐条 faccessat：`/data/data/com.topjohnwu.magisk`（表中重复出现两次）、`/data/data/com.noshufou.android.su`、`/data/data/com.noshufou.android.su.elite`、`/data/data/eu.chainfire.supersu`、`/data/data/com.koushikdutta.superuser`、`/data/data/com.thirdparty.superuser`、`/data/data/com.yellowes.su`、`/data/data/com.kingroot.kinguser`、`/data/data/com.kingo.root`、`/data/data/com.smedialink.oneclickroot`、`/data/data/com.zhiqupk.root.global`、`/data/data/com.alephzain.framaroot`、`/data/data/com.zachspong.temprootremovejb`、`/data/data/com.ramdroid.appquarantine`、`/system/app/Superuser.apk`、`/system/etc/init.d/99SuperSUDaemon`、`/dev/com.koushikdutta.superuser.daemon`、`/system/xbin/daemonsu`、`/data/data/me.weishu.kernelsu`。该函数内**没有** getprop 调用；`__system_property_get` 只出现在下一项 0x2BBF64 的 0x2BC054。

检查 0（0x2BAFD8）补充了 PATH 维度：从 `0x99820` 取 4 字节 + `'/'` 组成 5 字节密文，与 K[5..9] 异或得 `"PATH"`；它构造 `std::vector<std::string>`（构造/析构可见 0x49EBB0）后按 `:` 拆分，逐个 `dir + "/su"` 做 faccessat——与检查 1 的固定目录表互补。

## 3. Zygisk 与 KernelSU 专项

**0x2BCAE8（ksu_files）**：解密 10 字节开关名（0x2BCB1C 起，XOR K[10+i]）为 `ksu_files`；开关开则依次解密并 faccessat 五个路径：`/system/zygisk_magic`、`/system/lib/libzygisk_loader.so`、`/system/lib/libzygisk_injector.so`、`/system/lib64/libzygisk_loader.so`、`/system/lib64/libzygisk_injector.so`；循环 `CMP v8,#4` 命中即把该路径 strlcpy 进 reason 并返回 1。

**0x2BCC38（ksu_mounts_ext）**：开关名 15 字节（XOR K[15+i]）= `ksu_mounts_ext`；随后解出 18 字节路径（xmmword_9A160，XOR K[18+i]）`/proc/self/mounts`，并以 9 字节串（XOR K[9+i]）`zygisksu` 交给 sub_2BD36C(path,needle) 做包含匹配；命中即上报 reason `ksu_mounts`。

**0x2BCF44（ksu_mtp）**：先取 sub_2BD5F0() 得到一页匿名可写内存（`mmap(0,pagesize,3,0x22,-1,0)`+`madvise(4)`+`mincore`，用于确认页初始未驻留），再通过 syscall thunk 调 `prctl(167, 0xDEADBEEF, 1, page, 0, &out)`（167=__NR_prctl），随后 `mincore(page)`：若返回 0 且 `vec[0]==1`（页被内核写脏）则判 root，reason `ksu_mtp`。0xDEADBEEF 是 KernelSU 内核态命令魔数，此检测利用“内核模块响应 prctl 并回写用户页”这一副作用。

**0x2BCDC4（ap_ker）**：同一套页探测，但 prctl 命令号为 45：`prctl(45, page, -1)`，mincore 命中即上报 `ap_ker`；调用前还要求 `sub_2CDE1C()` 为假（未检测到 adb）且 `[sub_2AAA40()+74] != 0`（全局开关）。

**0x2BC4CC（zygisk_stack）**：解密 13 字节开关名 `zygisk_stack`；sub_2BD1F4() 打开 `/proc/self/maps`，逐行解析（格式 `'%zx-%zx %c%c%c%c %x %x:%x %u %s'`，0x4DCD28），找到名字为 `[stack]` 的映射并取 `start+size` 作为栈顶；随后对 `[栈顶-1000, 栈顶)` 调 sub_4DC8F8 校验可读，再在该窗口内 `memcmp` 查找 13 字节特征 `MAGISK_INJ_1`（第二段密文，XOR K[13+i]），命中上报 `residual_env`。

**0x2BD038（zygisk_anonymous）**：开关名 `zygisk_anonymous`；打开 `/proc/self/maps` 后最多遍历 100000 行，条件为行结构 `[262]!=0 && [261]!=0 && [258] > 0x1000`，再用 `strcmp(line, "/memfd:jit-cache (deleted)")` 二次确认；随后重新遍历并解码 `zygisk_module_entry`（20 字节），要求映射名长度等于该串长度（v14[258]）且内容逐字节相等，命中即上报 `zygisk_anonymous`。这是对 Zygisk 注入模块在 maps 中匿名映射的定点识别（字符串常量 `/memfd:jit-cache (deleted)` 与 `zygisk_module_entry` 均为密文表项）。

## 4. 启动状态与系统属性

**0x2BDB2C** 是独立的“设备解锁/启动状态”检查（不在 15 项表内）：`memset` 输出缓冲后，依次 `sub_4CEE28(prop,buf,64)` 读属性（相当于 getprop），`sub_4A2190` 规范化，再比较：
- `ro.boot.flash.locked`：`sub_4A47AC(value, "unlock")`（strstr）命中则把原值 `sub_4A4998` 追加到输出并加分隔符 `unk_93714`；
- `ro.boot.vbmeta.device_state`：同样与 `"unlock"` 做包含匹配；
- `ro.boot.verifiedbootstate`：与 `"green"` 做 `sub_4A46C0` 精确比较，**不相等**即追加原值。
返回 `*a1 != 0`（有任何一项异常即 1）。即判定条件为：`flash.locked`/`vbmeta.device_state` 含 `unlock`，或 `verifiedbootstate != green`（orange/yellow/red 全部命中）。上层用 `"a:%d;p:%s"`、标签 `att_dev_flash` 组织上报，并配 `"ICON:%s:"`、`"%sWarning"` 弹出解锁警告文案（“You are using an unlocked device that is compromised or modified…”）。

**0x2BBF64** 项单独读 `ro.debuggable`（14 字节密文，0x2BC04C 处 `__system_property_get(name, SP+0x20)`，name 由 qword_99708/99710 解出），`atoi(value)` 后 `CMP W0,#1`，等于 1 即判 root。

**0x2BBA00** 项不读系统属性，而用 `sub_22DFD0(ctx,"root_ext_cnt",buf,0x200)` 取配置字符串（13 字节密文：`root_ext_cnt`），`atoi` 后按阈值比较，属于云控可调的“外部 Root 计数”判据。

## 5. /proc 相关

| 路径 | 读取点 | 匹配内容 |
|---|---|---|
| `/proc/self/maps` | 0x4DCC88 打开、0x4DCD28 逐行解析，被 0x2BD1F4 与 0x2BD038 复用 | `[stack]`（取栈顶）、`/memfd:jit-cache (deleted)`、`zygisk_module_entry` |
| `/proc/self/mounts` | 0x2BCC38 内联解密后经 0x2BD36C 打开/匹配 | `zygisksu` |
| `/proc/self/ns/mnt` | 0x2BC87C 内联解密（18 字节，xmmword_99C40）后 `fstatat(AT_FDCWD,path,&st,AT_SYMLINK_NOFOLLOW=0x100)` | stat 成功且字段比较异常（st_ino/st_dev 关系）；`magic_delta` 是其开关名 |
| `/proc/self/attr/prev` | 0x2BC678 内联解密 21 字节（密钥按 15 回绕）后 `fopen(path,"r")` 读取 | SELinux 前一个安全上下文；`sec_context` 开关；同时用 `sub_2BD2B0(23,33,...)` 做区间值校验 |
| `/proc/self/status` | 0x290E0C 处引用 | 归属 TracerPid/调试检测部分，与 Root 表分离 |

值得注意：所有 /proc 访问都走自实现的 open/read 包装（0x4DCC88/0x4DCD28/0x4DCEEC），不经过 libc 的 fopen 符号，增加 hook 成本。

## 6. 完整性校验与签名链

**汇总格式**在 0x4CBDB4：`"cert_md5=%s|apk_hash_1=0x%08x|apk_hash_2=0x%08x|txt_seg_crc=0x%08x"`。四个值来自安全上下文对象 `v2=sub_2DAD4C(...)`：`v4=sub_2DB678(v2)` 取证书信息结构（`v2+2209` 已初始化则直接返回，否则 `sub_241660(0,0)` 走 JNI 采集），`sub_2DB724(v4)` 两次分别取 apk_hash_1/apk_hash_2，`*(uint32_t*)(v4+132)` 即 **txt_seg_crc**。0x4CBAF4 顺序拼接四条诊断串：`root=%d|x86=%d|apk_cnt=%d|adb=%d|machine=%s|sys_ver=%s|root_record=%d`（0x4CBB2C）、证书三元组（0x4CBDB4）等，说明 CRC/哈希属于“设备指纹”而非仅本地判定。

**证书 MD5**：0x4D8DF4（cal_cert_md5）先查云控开关 `cal_cert_md5`（默认 1，结果缓存于 byte_568F44，一次性初始化用 byte_568F48 原子标志），开则解析 APK（sub_4D8F44 / sub_4D90A0 为 zip 解析），把证书条目链入 `a3` 列表，返回 0/2/4 等状态码；`*a4=1` 表示“已命中/已确认”。

**官方证书比对**：0x2AE0C4 用 `sub_22DFD0(ctx,"official_cert_md5",buf,64)` 取内置期望值（空则退化为空串 `unk_92AD3`），再用开关 `white_mode`（默认 0）决定比对模式；遍历已安装应用（sub_2AE390/sub_2AE3F0），对每项用 `sub_4A46C0(expected, item+20)` 比较证书 MD5，不等则执行 `sub_1EE0C4`（上报回调）、`sub_2AE8A4`、`sub_1F2344`，并按 `cert_crash` 标签以格式 `"cert=%s|author=%s"`（0x4CCA80）上报。另见 0x2A0494 的 `ano_cert_md5`、0x2B1F30 的 `9003_cert_md5`/`9003_unsrc`、0x2C3118 设备信息键 `cert_md5`。

**签名字段采集**：0x23E0C0 经 `sub_27DD90()`/`sub_27E450(ctx, hash, 128, names, 512, &dst, list, 128)` 走 JNI 取证书哈希、签名类型 DST、包名数量与列表，格式 `"CertHash=%s|DST=%04x|PkgNamesCnt=%d|PkgNames=%s|%s|"`。JNI 侧签名链在 0x23FC70/0x240038/0x241B3C 等函数：`getPackageManager` → `getPackageInfo`（字符串常量分别在 0x23F548/0x23FD74）→ 取 `signatures` 字段（0x241D88）；0x2451BC 还直接使用 `IPackageManager$Stub`/`TRANSACTION_getPackageInfo`/`GET_SIGNATURES` 常量，属 Binder 直调兜底。

**失败处置**：未见硬编码“期望 CRC 常量”参与本地阻断；`txt_seg_crc` 与 `apk_hash_1/2` 是**上报值**，是否判定由云控规则决定——0x4E3CAC 维护 101 个条件名到处理码的映射，含 `file_crc_eq`、`file_crc_eq2`、`file_crc_not_eq2`、`inner_apk_file_crc_eq2`、`apk_crc_eq`、`apk_crc_not_eq`、`inner_apk_crc_eq`、`cert_md5_eq`、`cert_md5_not_eq`、`root_process_exists`、`is_root`、`module_exists`、`apk_9015_eq` 等（同函数还定义 `add/stricmp/stristr` 等条件算子）。因此完整性失败主要是“打标签 + 上报”，由服务端下发处置（推测：命中后由云控指令触发踢下线/二次验证）。

## 7. 上报字段与聚合

0x23DA5C 是设备信息聚合器，按序调用各字段拼接函数，任一返回非 0 即整体失败（-1）：0x23DB04 → `IsRoot=%d|RootReason=%s|IsNeedReqApkList=%d|`；0x23DBB0 → `CDN=%d|`；0x23DC34 → `Arch=%s|SysVer=%s|ModelB64=%s|ApkNameB64=%s|IsAllowApkList=%d|`；0x23DF18 → `IsEmu=%d|EmuName=%s|`；0x23DFAC → `IsVAP=%d|VAPName=%s|`；0x23E040 → `OPC=%08x|`；0x23E0C0 → `CertHash=…`；0x23E1B0 → `RFC=%08x|`。每个函数最终都走 `sub_49F51C(a2, s, strlen(s))` 把串追加到上下文缓冲。

各字段来源：`IsRoot`/`RootReason` 来自单例 qword_55F3C0（0x2718B4 创建，vtable off_514A70），sub_2719D8(obj,buf,128) 在未扫描时先调虚表 `+16` 触发扫描，再 strlcpy `obj+10` 的 reason 并返回 `obj[9]`；`IsNeedReqApkList` 推测来自 Java 层 `NeedRequestApkList` 开关（0x1BCF84 处 SDK 接口名，0x1BE080 解密点），控制是否索要应用列表；`IsEmu/EmuName` 由模拟器扫描模块填充（同文件 0x2B9D98 处含 RedFinger/DuoDuoYun/LeiDianYun 等云机品牌与 `cloud3_err4`、`cp23:%d,%s,%s`）；`CertHash/DST/PkgNames` 来自 JNI 签名采集。

## 8. 云控开关

SDK 命令/接口名集中在 0x1BCF84 的字符串组（0x1BE080 起解密）：`NeedRequestApkList`、`StartSecScan`、`CloseEmulatorScan`、`CloseUserTagScan`、`CloseCloudPhoneScan`、`CloseAntiProfiler`、`CloseDevInfoCollect`、`CloseAntiBlackModule`、`IsEmulator2`、`OpenVerificationLog`、`SetSecToken`、`EnableGameReport` 等。其中与 Root 直接相关的是 **`ScanRoot`**（0x271958，默认开，控制整轮扫描）与 **`unlock_root`**（0x2BAEE0 末尾，默认 0，命中后决定是否附加“解锁”处置）；每项子检测又有独立开关，形成两级门控：`ScanRoot` → 逐项 `ksu_files`/`ksu_mtp`/`ksu_mounts_ext`/`zygisk_anonymous`/`zygisk_stack`/`zygisk_module`/`magic_delta`/`sec_context`/`ap_ker`。完整性侧开关为 `cal_cert_md5`（默认 1）与 `white_mode`（默认 0），另有 `official_cert_md5` 期望值由云端下发。开关读取统一走 sub_22DA98(ctx,name,default,strict)，未命中配置时返回默认值，因此断网时 Root 扫描默认仍然执行。

## 9. 关键结论

1）Root 判定是“15 项检查的函数指针表 + 命中即停”，全部判据落在文件存在性（自实现 faccessat）、属性值、/proc 内容与内核 prctl 副作用四类，未使用 `which su`、`id`、`Runtime.exec` 等 shell 手段。2）对 Zygisk/KernelSU 的覆盖明显强于传统 Root 检测：既查文件与 mounts 明文特征，也查匿名映射名与栈上 `MAGISK_INJ_1` 残留，还用 prctl 魔数探测内核模块。3）完整性校验本身不阻断，只产出 `cert_md5/apk_hash_1/apk_hash_2/txt_seg_crc/CertHash` 五类指纹，配合 101 条云控条件名做服务端裁决。4）所有敏感字符串均为运行时解密（0xD973C 密钥流 + 逐项偏移），且关键 syscall 走内部 thunk 表，静态特征少、hook 面窄。
