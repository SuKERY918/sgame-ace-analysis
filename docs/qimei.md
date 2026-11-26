# 《王者荣耀》QIMEI SDK（libqimei.so）彻底分析


> 说明：文中出现的 QIMEI 实测值（`q16`、`tt`）已按设备唯一标识脱敏处理，仅保留前缀；其余字符串、地址、常量均为样本真实内容。

样本：`/data/app/~~9usLw8j-oA0N9e5dq1Fldg==/com.tencent.tmgp.sgame-mh1xM5-K32eIJDV1j7JpZg==/lib/arm64/libqimei.so`
大小 539,416 B；版本随王者 12.1.1.1 下发。分析方式：纯静态（IDA 式反汇编 + pyelftools + capstone），关键结论用 unicorn 在进程外执行验证，全程未进入游戏进程（规避 ACE 反调试）。

---

## 一、结论速览

1. **QIMEI 的字符串表已经完全解开**。9469 字节的加密块被解析为 **398 条**独立字符串，加密是「每条记录 3 字节头 + 单字节变种 XOR」，算法三行可复现（见第三节）。
2. 398 条字符串构成了 SDK 的**全部检测与采集词汇表**：root/su、Magisk、Xposed/LSPosed/Epic/Substrate/Frida/Riru/Zygisk、模拟器与云手机、群控与自动化工具（按键精灵、触摸精灵、minitouch、scrcpy、appium、来喜/小薇）、代理、无障碍、Widevine、文件系统 inode 指纹、腾讯系账号 openid 等。
3. **280 个静态引用点**全部定位，可按函数还原「哪个函数查哪一类东西」（附录 B 给出完整映射文件）。
4. QIMEI 的组装核心在 `0x2b9d4`：以两段 16 字节常量拼成 32 字节密钥（ChaCha20 参数），按模式取 `ro.product.model`、`ro.product.brand`、`android_id` 等字段拼装，另有 4 组 32 位十六进制常量（`0x13440` 起，经 `0x13878` 解成 16 字节）参与。
5. 设备标记之所以「刷机恢复出厂也没用」，根因不在本地文件，而在**服务端用 QIMEI + 腾讯账号 openid 建立的设备图谱**；本地只缓存 q16（`files/com.tencent.qimei.sdk.QimeiSDK`）与加密种子（`shared_prefs/...QimeiSDK*.xml` 的 `s_d`/`tt`/`tn`）。

---

## 二、样本结构与入口

| 段 | 地址 | 大小 |
|---|---|---|
| .text | 0x9340 | 0x63774 |
| .rodata | 0x6cac0 | 0x666d |
| .data.rel.ro | 0x81390 | — |
| .data | 0x84000 | — |
| .init_array | 0x81330 | 10 项 |
| JNI_OnLoad | 0xa108 | 316 B（唯一实质导出） |

- `.init_array`：`0x95e4, 0x9600, 0x9920, 0x997c, 0x9c9c, 0x9fbc, 0x9fd8, 0x9ffc, 0xa040, 0xa09c`
- 方法注册表在 `.data` 的 `0x84058`，15 项 × 24 B（`{name, sig, fn}`），由 `JNI_OnLoad → 0x47ca4 → 0x47d8c` 调用 `JNIEnv[215]`（偏移 1720）即 `RegisterNatives` 完成注册。
- 15 个 native 与 Java 侧 `com.tencent.qimei.uin.U` 一一对应（`r/d/e/n/m/z/z2/o/x/u/p/b/r4/w`），初始化入口 `U.a(Context,String,String)`：`System.loadLibrary("qimei")` → `n(context, appKey, 回调对象数组)`。

---

## 三、字符串表：格式与解密（核心成果）

### 3.1 表的加载

`sub_1EE04`（0x1ee04）是惰性初始化，等价于：

```c
void init_table(void) {
    void *p = malloc(0x24fd);          // 9469
    memcpy(p, rodata + 0x6cfa4, 0x24fd);
    *(void **)0x84340 = p;             // .bss 全局指针
}
```

即「字符串表」= 文件偏移 **0x6cfa4** 起 **9469 字节**，运行时被复制到堆并在原地解密。

### 3.2 记录格式

```
[u16 len][u8 key][len 字节密文]
```

### 3.3 解密算法

```c
plain[i] = cipher[i] ^ ((key + i * 0x53) & 0xff);   // i = 0..len-1
```

- 每条记录用**自己的 key 字节**做种子，步进 `0x53`（83），与位置线性相关；
- 398 条记录从偏移 0 依次首尾相接，**正好消耗 9469 字节**，无剩余、无空洞 → 格式判定成立；
- 用 unicorn 在进程外直接调 `sub_1EFB8(0, off)` 取回的内容与静态解出的结果逐条一致（例：`off=0 → "libc.so"`、`0x12ca → "android_id"`、`0x1eb → "/proc/self/maps"`）。

### 3.4 取串 API

```c
const char *get_str(uint32_t off);   // sub_1EFB8；off < 0x24fd
```

调用约定：`mov w1, #off; bl 0x1efb8`（`w0` 为占位立即数，函数内不使用）。函数原地解密该记录并返回 `table + off + 3`，因此**同一字符串只需解一次**。

复现脚本：`_qdec.py`（表解析）、`_qd2.py`（导出全表）、`_quse.py`（引用点映射）。

---

## 四、398 条字符串的功能分布

| 分类 | 条数 | 代表性内容 |
|---|---|---|
| 文件与设备路径 | 69 | `/proc/self/maps`、`/proc/%d/mem`、`/proc/self/mountinfo`、`/system/bin/app_process`、`/mnt/sdcard` |
| Android 属性 | 39 | `ro.build.fingerprint`、`ro.debuggable`、`ro.secure`、`ro.kernel.qemu`、`persist.vmos.root.enable`、`service.adb.root` |
| 模拟器与云手机 | 33 | `qemu.sf.fake_camera`、`androVM`、`genymotion`、`microvirt`、`droid4x`、`nox`、`ttVM`、`vmos`、`/lxc_container/`、`/docker`、`virtio` |
| Root 与 SU | 30 | `su`、`/su/bin/`、`/system/xbin`、`/system/bin/.good-job/.`、`/system/bin/.spapa/.`、`magisk`、`Superuser.apk`、`test-keys`、`bamenshenqi` |
| 系统库与 syscall | 29 | `libc.so`、`libart.so`、`__system_property_get`、`fstatat64`、`inotify_add_watch`、`__statfs64` |
| 文件系统指纹 | 25 | `/data/system/locksettings.db`、`/data/system/procstats`、`Inode:`、`Links:`、`Modify:`、`Blocks:` |
| 自动化与群控 | 19 | `minitouch`、`minicap`、`scrcpy`、`appium`、`mobileanjian`（按键精灵）、`TouchSprite`、`laixi.jar`、`xiaowei.jar` |
| 账号与 openid | 16 | `LoginInfoManager`、`MSDKLogin`、`wechat_open_id`、`new_qq_zone_open_id`、`KaraokeAccountManager`、`Syzs` |
| Hook 与注入框架 | 15 | `XposedBridge`、`LSPosed-Bridge`、`libepic.so`、`libsubstrate.so`、`frida-agent`、`riru_`、`zygisk_lsposed`、`EdHooker_` |
| 网络与 MAC | 14 | `socksProxyHost`、`http.proxyHost`、`tun0`、`ppp0`、`/sys/class/net/%s/address`、`mmcblk0/device/cid` |
| 无障碍与窗口 | 11 | `ACCESSIBILITY_SERVICE`、`getEnabledAccessibilityServiceList`、`SurfaceView`、`setSecure` |
| 加密与密钥 | 9 | `expand 32-byte k`、`lvcwmSYVr2Axv1gn`、`Zs0ntDqG2jyhKN0c`、4×MD5、RSA-2048 公钥 |
| 反调试与进程 | 9 | `TracerPid`、`ptrace_stop`、`/proc/self/wchan`、`getStackTrace` |
| 反射与进程内钩子 | 9 | `artMethod`、`mInstrumentation`、`mH`、`mCallback`、`setAccessible` |
| JNI 与类名 | 9 | `com/tencent/qimei/uin/U`、`android/os/SystemProperties`、`android/provider/Settings$Secure` |
| DRM 与 Widevine | 4 | `AMediaDrm_createByUUID`、`AMediaDrm_getPropertyByteArray`、`libmediandk.so` |
| 其它 | 58 | 电池/CPU 节点、`Hardware :`、`logcat -v brief`、`/com.lbe.parallel/`（平行空间）、`/base.apk` |

完整清单（偏移 + 字符串 + 静态引用次数）见附录 A，同一份数据也导出为 `QIMEI_strings.txt`。

几点值得单独说明：

- **`1,Telephony,getDeviceId;2,Telephony,getSubscriberId;3,SystemProperties,get;4,WifiInfo,getMacAddress;5,Settings$Secure,getString;6,WifiInfo,getSSID;7,WifiInfo,getBSSID;`**（0x0b67）是一张「敏感 API 清单」，用于逐个检查这些方法是否被 hook（方法入口字节对比）。
- **`/data/system/*` 的 25 条 + `Inode:/Links:/Modify:/Blocks:` 格式串**：SDK 对系统目录做 `stat/statvfs`，采集 inode 号、硬链接数、mtime、块数——这是典型的「文件系统指纹」，恢复出厂后这些值会整体变化，但服务端已留有旧值。
- **`/dev/__properties__`、`__system_property_read`**：绕过 libc 的 `__system_property_get`，直接读属性区，防 hook。
- **`rirud`、`riru_`、`riru64_`、`zygisk_lsposed`、`riru_lsposed`**：同时覆盖 Magisk 系（Riru/Zygisk）与 LSPosed。
- **`Syzs`**（0x24f5，表尾最后一条）：腾讯「神谕/手Q」相关标识，属账号体系探测。

---

## 五、280 个引用点：哪个函数在查什么

静态扫描 `bl 0x1efb8` 共 **280** 处，其中 279 处能从前序 `mov w1, #imm` 取到偏移（1 处为运行时计算）。按「调用点 → 偏移 → 字符串」聚合后（完整见 `QIMEI_string_usage.txt`），密度最高的几个函数：

| 函数 | 角色 | 典型字符串 |
|---|---|---|
| `0x24004` | 文件系统/挂载/指纹采集 | `/data/system/locksettings.db`、`/data/dalvik-cache`、`/data/media`、`/cache`、`/mnt` |
| `0x2b9d4` | **QIMEI 组装核心** | `lvcwmSYVr2Axv1gn`、`Zs0ntDqG2jyhKN0c`、`ro.product.model`、`ro.product.brand`、`android_id`、`content://settings/secure/` |
| `0x13440` | 密钥材料装载 | 4 个 32 位 MD5 常量 + `Ql9nXK6f…`(256 B) |
| `0x25138` | RSA 加密 | `MIIBIjANBgkqhki…`（RSA-2048 公钥） |
| `0x297c8` | 随机源 | `/dev/urandom`、`7148575929` |
| `0x2b844` | 进程权重 | `/proc/self/oom_adj` |
| `0x2ba28`/`0x2ba40` | 组装分支 | 两段 16 字节 key |

引用次数为 0 的那些字符串（约 119 条）不是死代码：它们由表驱动/循环取值（例如按索引数组批量取路径、批量比对属性），或以 `w1` 运行时计算后调用，静态立即数扫描看不到。

---

## 六、QIMEI 的生成与加密

`0x2b9d4` 是主组装函数（栈帧约 0x1c90 字节，控制流平坦化），结构可辨：

1. `get_str(0x1418)` / `get_str(0x142c)` 取两段 16 字节常量 `lvcwmSYVr2Axv1gn`、`Zs0ntDqG2jyhKN0c`，交给 `0x11004`（std::string 赋值）→ 拼接后即 **ChaCha20 的 32 字节密钥**（.rodata 里存在 `expand 32-byte k`，与之配套）。
2. 按第三参数 `w3` 分支：`0`、`1`、`>=2` 三种拼装模式；`w3==1` 走 `ro.product.model`（0x12d8）分支，`>=2` 走 `ro.product.brand`（0x2fe）分支，`0` 走内部/缓存分支。
3. `w3>=2` 分支里出现 `content://settings/secure/` + `android_id`（0x12ca）+ `GET_secure`(0x12bc) —— 即通过 `ContentResolver` 读取 `Settings.Secure.ANDROID_ID`。
4. `0x13440` 一侧把 4 个 32 位十六进制常量（`a7aff789…`、`353c9fc8…`、`ff802003…`、`b8221969…`）各解成 **16 字节**（`0x13878 → 0xa618(dst, src, 16)`），另有 `Ql9nXK6f…` 的 **256 字节** base64 块——这些都是密钥/种子材质的候选集，与「按 appKey 选择不同密钥组」的实现吻合。
5. `0x25138` 使用 RSA-2048 公钥（`MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A…`，标准 X.509 SubjectPublicKeyInfo 的 base64），典型用途是**包裹会话密钥**（信封里的 `crypt` 字段）。
6. 摘要/编码：自定义 Base64 表（`;0123456789ABCDEF` 与 `.rodata` 0x6cf3a 的另一张表），配合 ChaCha20 输出，最终形成 `q16`/`q36` 与上报体。

> 说明：以上是对函数结构与常量用途的判定，未做逐指令还原；`q16`/`q36` 的精确字节序（哪些字段、什么顺序做摘要）需要继续跟进 `0x256e8`（`r()`）与 `0x3a818`（`z()`）两处，已在第七节列为未完成项。

设备侧实测的落盘值（与算法对得上）：

- `files/com.tencent.qimei.sdk.QimeiSDK`：base64 → `00938824XXXXXXXXXXXXXXXXXXXXXXXX`（32 个十六进制字符 = 16 字节，即 q16 本体）
- `shared_prefs/QV1com.tencent.qimei.sdk.QimeiSDK108eeee72235004c.xml`：
  - `tt=94001FF8XXXXXXXXXXXXXXXXXXXXXXXX`（32 hex）
  - `s_d`（加密种子）、`tn`（`crypt=1`，appKey 1104466820）
  - `t_s_t=1795691670442`（服务端时间戳）、`a_i_t=1795329243472`、`is_first=false`
- `qm_global_sp.xml`：`c_f_bootids`（5 个历史 boot_id UUID）+ `c_f_uptimes`
- `app_tbs_64/core_share/libtbsqimei.so`、`device_id.vip.xml`

---

## 七、上报协议与数据流

- 信封字段（.rodata）：`crypt`/`params`/`nonce`/`sign`/`extra`/`code`/`data`/`body`/`sever`/`local`/`type`/`msg`/`net`。
- 上报端点（Java 侧 `com.tencent.qimei.x.b`，`k5` 回调）：默认 `https://snowflake.qq.com/ola/v2`，测试环境 `https://test.snowflake.qq.com/ola/v2`；POST + `Content-Type: application/json`，连接 30s / 读 10s，禁止重定向，返回 `{"is","bd","ic","rc","em"}`；错误码 452/199/451/499 分别对应非 2XX、SecurityException、ConnectException、其它。
- 事件通道（`com.tencent.qimei.q.b`）：`k1 sendSample` → 事件 `x8`，`k2 sendError` → 事件 `x9`，键 `"6"/"7"/"8"`。
- 本地写入 `files/com.tencent.qimei.sdk.QimeiSDK` 与 `shared_prefs`，并在启动时与 `c_f_bootids` 对齐。

---

## 八、为什么「刷机 + 恢复出厂」清不掉设备标记

设备标记是**服务端图谱**，不是本地文件：

1. **QIMEI 作为主键**：首次注册时服务端把 QIMEI 与设备画像绑定；此后同一台机器重新生成的新 QIMEI 会被「硬件锚点」关联回旧记录（AAID/VAID 由系统 provider 维护、IMEI/MEID 在 modem 分区、序列号在 bootloader 区、部分设备 MAC 出厂烧录）。
2. **腾讯账号维度**：`open_id`/`wxOpenId`/`qqOpenId`、`LoginInfoManager`、`MSDKLogin`、`getLastLoginUserInfo`、K歌/QQ音乐的账号类——同一账号在不同设备上的登录记录会合并。
3. **文件系统指纹**：`/data/system/*` 的 inode、mtime、链接数在恢复出厂后整体变化，但服务端历史记录仍在；这解释「换了新指纹仍被认出来」。
4. **DRM/Widevine**：`AMediaDrm_createByUUID` 取 Widevine 设备唯一 ID（`getPropertyByteArray`），该 ID 在 TEE 内生成，刷机不变。
5. boot_id（`/proc/sys/kernel/random/boot_id`）每次重启变，属于「会话级」而非「设备级」。

---

## 九、与 ACE 的关系

- ACE 的 fake token 优先级：**OAID（`ft_oaid`）> ANDROID_ID > QIMEI/QIMEI36**，组装成 `x:%s;q:%s;Q:%s;o:%s`，再包 `bt:<boot_id>;bd:<Brand>`。
- 也就是说：只要 OAID 可用，ACE 侧首选的是 OAID（ColorOS 的 `com.heytap.openid` provider 提供）；QIMEI 是兜底。**但 QIMEI SDK 自身仍会把 q16/q36 上报给腾讯侧**，两条链在服务端可交叉。
- 对本机（一加 Ace6，KernelSU + Zygisk Next + HMM/HMA，无 Shamiko/SusFS）：QIMEI 侧的检测面主要在「环境类字符串」，即 root/hook/模拟器/群控/代理/无障碍——本机已通过 ACE 的同类检测，QIMEI 侧判定基本同理。

---

## 十、对抗视角：哪些能改，哪些改不了

**可改（本地）**

- 属性类：`ro.debuggable`、`ro.build.tags`、`ro.kernel.qemu` 等（resetprop 或 Zygisk 模块）；
- 路径类：`su`、`/system/xbin/su`、Magisk 目录、`zygisk_*`（KernelSU/Shamiko/SusFS 卸载命名空间）；
- 注入痕迹：`/proc/self/maps` 里的 `libepic.so`、`frida-agent`、`LSPosed-Bridge` 等；
- 自动化/群控：`/data/local/tmp/minitouch` 等文件、`/dev/input/event0` 访问；
- 代理与无障碍：`socksProxyHost`、`accessibility_enabled`。

**基本改不了**

- QIMEI 的服务端登记（一旦绑定）；
- TEE key attestation（真实 BL 状态在 TEE 内，软件层只能改「上报值」）；
- Widevine 设备 ID；
- IMEI/MEID/序列号（只读分区 + modem）；
- 账号维度的登录历史。

结论：本地隐藏只能降低「当场被判为异常环境」的概率，无法清除已有设备标记；要换设备身份，等价于换一台机器。

---

## 附录 A：字符串全表（398 条，按功能分类）

## 附录 A：字符串全表（398 条，按功能分类）

### 加密与密钥（9 条）

| 偏移 | 字符串 | 引用点 |
|---|---|---|
| 0x012d | `/dev/__properties__` | 0 |
| 0x1418 | `lvcwmSYVr2Axv1gn` | 1 |
| 0x142c | `Zs0ntDqG2jyhKN0c` | 1 |
| 0x145a | `MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApLEpcsiHA/PE4MKl… (c4c65a7c)` | 1 |
| 0x15e6 | `Ql9nXK6f3xXGykFE7J3bwxrdkcy2BM2zMGlioKumcmdsI8PlOcWBl5EpBBXc… (71209dee)` | 1 |
| 0x1742 | `a7aff789b8ec69e1454f2689fbb89bdf` | 1 |
| 0x1766 | `353c9fc8b84b5882b00591dae8e81cc4` | 1 |
| 0x178a | `ff802003f67f55be8b535a97b01b459d` | 1 |
| 0x17ae | `b8221969c27a8019d533b139ade71bcc` | 1 |

### Root 与 SU（30 条）

| 偏移 | 字符串 | 引用点 |
|---|---|---|
| 0x08be | `nox` | 1 |
| 0x0d41 | `com.soft.apk008v` | 0 |
| 0x0d55 | `com.qxq.shenqi` | 0 |
| 0x0d67 | `bamenshenqi` | 0 |
| 0x0d9a | `/system/app/Superuser.apk` | 0 |
| 0x0db7 | `ro.build.tags=` | 0 |
| 0x0dc9 | `test-keys` | 0 |
| 0x0dd6 | `/sdcard/Android/data/com.topjohnwu.magisk` | 0 |
| 0x0e03 | `type su` | 0 |
| 0x1a30 | `su.white_list.1` | 1 |
| 0x1a43 | `persist.sys.bd.su_white_list.1` | 1 |
| 0x1a65 | `ro.x8.support_dev_ashmem` | 1 |
| 0x1b6b | `/.magisk/` | 1 |
| 0x1b78 | `magisk` | 2 |
| 0x1c71 | `/ueventd.titan.rc` | 1 |
| 0x1c86 | `/system/etc/init.titan.sh` | 1 |
| 0x1ca3 | `/x8.prop` | 1 |
| 0x1cc4 | `su` | 1 |
| 0x1cca | `/sbin/` | 1 |
| 0x1cd4 | `/su/bin/` | 1 |
| 0x1cf8 | `/data/local/xbin/` | 1 |
| 0x1d46 | `/system/bin/failsafe/` | 1 |
| 0x1d5f | `/system/xbin/` | 1 |
| 0x1d70 | `/system/sd/xbin/` | 1 |
| 0x1d84 | `/system/usr/we-need-root/` | 1 |
| 0x1db5 | `/magisk/.core/bin/` | 1 |
| 0x1de1 | `/system/bin/.good-job/.` | 1 |
| 0x1dfc | `/system/bin/.spapa/.` | 1 |
| 0x1e39 | `/data/data/n/bstk/` | 1 |
| 0x1e58 | `/system/xbin/nox` | 1 |

### Hook 与注入框架（15 条）

| 偏移 | 字符串 | 引用点 |
|---|---|---|
| 0x0b16 | `disableHooks` | 0 |
| 0x0b26 | `sHookedMethodCallbacks` | 0 |
| 0x0b40 | `de.robv.android.xposed.XposedBridge` | 0 |
| 0x0c12 | `libepic.so` | 1 |
| 0x0c20 | `/libsubstrate.so` | 0 |
| 0x0c34 | `/libfrida-loader.so` | 0 |
| 0x0c4b | `/libfrida-agent.so` | 0 |
| 0x0c61 | `rirud` | 0 |
| 0x0c6a | `riru_` | 0 |
| 0x0c73 | `riru64_` | 0 |
| 0x0c7e | `/EdHooker_` | 0 |
| 0x0c9e | `LSPosed-Bridge` | 0 |
| 0x0e4a | `xposed` | 0 |
| 0x2437 | `zygisk_lsposed` | 1 |
| 0x2449 | `riru_lsposed` | 1 |

### 模拟器与云手机（33 条）

| 偏移 | 字符串 | 引用点 |
|---|---|---|
| 0x04a6 | `qemu.sf.lcd_density` | 0 |
| 0x07b5 | `/sys/bus/virtio` | 0 |
| 0x07c8 | `/sys/module/virtio_net` | 1 |
| 0x07e2 | `/sys/module/virtio_pci` | 1 |
| 0x07fc | `/sys/class/virtio_pt/virtiopt` | 1 |
| 0x081d | `/sys/devices/virtual/virtio_pt/virtiopt` | 1 |
| 0x0848 | `/sys/class/virtio_pt` | 1 |
| 0x0860 | `/dev/virtiopt` | 1 |
| 0x0871 | `/sys/bus/pci/drivers/virtio-pci` | 1 |
| 0x0894 | `guopan` | 1 |
| 0x089e | `ttVM` | 1 |
| 0x08a6 | `microvirt` | 1 |
| 0x08b3 | `droid4x` | 1 |
| 0x08c5 | `androVM` | 1 |
| 0x08d0 | `51mnq` | 1 |
| 0x08e4 | `ro.genymotion.version` | 1 |
| 0x08fd | `androVM.vbox_dpi` | 1 |
| 0x0911 | `qemu.sf.fake_camera` | 1 |
| 0x0928 | `ro.kernel.qemu` | 1 |
| 0x0995 | `/system/bin/%s-vbox-sf` | 6 |
| 0x09af | `/data/data/com.microvirt.market` | 1 |
| 0x09d2 | `/system/app/ldAppStore/ldAppStore.apk` | 1 |
| 0x09fb | `/system/priv-app/LDAppStore/LDAppStore.apk` | 1 |
| 0x0a29 | `/system/app/MOMOStore/MOMOStore.apk` | 1 |
| 0x0a50 | `/system/app/AntStore/AntStore.apk` | 1 |
| 0x0a75 | `/system/bin/nemuVM-nemu-sf` | 1 |
| 0x0a93 | `/system/app/phoenixvip/phoenixvip.apk` | 1 |
| 0x0ad8 | `/lxc_container/` | 1 |
| 0x0aeb | `/docker` | 1 |
| 0x0b0b | `Androws` | 1 |
| 0x0d8c | `/vmos.prop` | 0 |
| 0x19fe | `persist.vmos.root.enable` | 1 |
| 0x1a1a | `vmos.camera.enable` | 1 |

### 自动化与群控（19 条）

| 偏移 | 字符串 | 引用点 |
|---|---|---|
| 0x0ee3 | `/dev/input/event0` | 0 |
| 0x0ef8 | `/sdcard/com.cyjh.mobileanjian` | 0 |
| 0x0f19 | `/sdcard/TouchSprite/lua` | 0 |
| 0x0f34 | `/sdcard/Android/data/com.nx.nxprojit` | 0 |
| 0x0f94 | `minitouchagent` | 0 |
| 0x0fa6 | `minicapagent` | 0 |
| 0x0fb6 | `scrcpy` | 0 |
| 0x0fc0 | `/data/local/tmp/minitouch` | 0 |
| 0x0fdd | `/data/local/tmp/minicap` | 0 |
| 0x0ff8 | `/data/local/tmp/tc/mobileagent` | 0 |
| 0x101a | `/sdcard/eagleeye` | 0 |
| 0x102e | `/data/local/tmp/scrcpy-server.jar` | 0 |
| 0x1053 | `/data/local/tmp/yyds.py` | 0 |
| 0x106e | `/sdcard/Android/data/io.appium.settings` | 0 |
| 0x1099 | `/data/local/tmp/hulu/scrcpyTouch.apk` | 0 |
| 0x10c1 | `/sdcard/Android/data/com.aibot.client` | 0 |
| 0x10ea | `/data/local/tmp/agent` | 0 |
| 0x1103 | `/data/local/tmp/laixi.jar` | 0 |
| 0x1120 | `/data/local/tmp/xiaowei.jar` | 0 |

### 反调试与进程（9 条）

| 偏移 | 字符串 | 引用点 |
|---|---|---|
| 0x0257 | `/proc/%d/mem` | 0 |
| 0x0267 | `/proc/%d/mounts` | 0 |
| 0x027a | `/proc/self/wchan` | 0 |
| 0x028e | `/proc/self/status` | 0 |
| 0x0ea3 | `ptrace_stop` | 0 |
| 0x0eb2 | `TracerPid` | 0 |
| 0x0ebf | `exit` | 0 |
| 0x0ec7 | `kill` | 0 |
| 0x0ecf | `java/lang/System` | 0 |

### DRM 与 Widevine（4 条）

| 偏移 | 字符串 | 引用点 |
|---|---|---|
| 0x1151 | `libmediandk.so` | 0 |
| 0x1163 | `AMediaDrm_createByUUID` | 0 |
| 0x117d | `AMediaDrm_getPropertyByteArray` | 0 |
| 0x119f | `AMediaDrm_release` | 0 |

### 网络与 MAC（14 条）

| 偏移 | 字符串 | 引用点 |
|---|---|---|
| 0x056e | `wifi.interface` | 0 |
| 0x0ce7 | `http.proxyHost` | 1 |
| 0x0cf9 | `http.proxyPort` | 1 |
| 0x0d0b | `https.proxyHost` | 1 |
| 0x0d1e | `https.proxyPort` | 1 |
| 0x0d31 | `tun0` | 1 |
| 0x0d39 | `ppp0` | 1 |
| 0x11b4 | `/sys/block/mmcblk0/device/type` | 0 |
| 0x11d6 | `/sys/block/mmcblk0/device/name` | 0 |
| 0x11f8 | `/sys/block/mmcblk0/device/cid` | 0 |
| 0x1228 | `freeifaddrs` | 0 |
| 0x1237 | `getifaddrs` | 0 |
| 0x1245 | `/sys/class/net/%s/address` | 0 |
| 0x1262 | `/sys/devices/virtual/net/%s/address` | 0 |

### 文件系统指纹（25 条）

| 偏移 | 字符串 | 引用点 |
|---|---|---|
| 0x13b7 | `Inode: ` | 1 |
| 0x13c2 | `Links: ` | 1 |
| 0x13cd | `Modify: ` | 1 |
| 0x13d9 | `ID: ` | 1 |
| 0x13e1 | `Blocks: ` | 1 |
| 0x13ed | `Inodes: ` | 1 |
| 0x13f9 | `File: ` | 1 |
| 0x1828 | `/data/system/job` | 1 |
| 0x183c | `/data/dalvik-cache` | 1 |
| 0x1852 | `/data/system/locksettings.db` | 1 |
| 0x1872 | `/data/system/inputmethod` | 1 |
| 0x1898 | `/data/app-lib` | 1 |
| 0x18a9 | `/data/system/recoverablekeystore.db` | 1 |
| 0x18d0 | `/data/system/graphicsstats` | 1 |
| 0x18ee | `/data/system/sensor_service` | 1 |
| 0x190d | `/data/system/last-header.txt` | 1 |
| 0x192d | `/data/system/sync` | 1 |
| 0x1942 | `/data/system/netstats` | 1 |
| 0x195b | `/data/media` | 1 |
| 0x196a | `/data/system/procstats` | 1 |
| 0x1984 | `/data/system/notification_log.db` | 1 |
| 0x19a8 | `/data/resource-cache` | 1 |
| 0x19c0 | `/data/lost+found` | 1 |
| 0x19d4 | `/data/ss` | 1 |
| 0x19e0 | `/data/system/uiderrors.txt` | 1 |

### 账号与 openid（16 条）

| 偏移 | 字符串 | 引用点 |
|---|---|---|
| 0x1f08 | `com/tencent/msdk/login/LoginInfoManager` | 1 |
| 0x1f33 | `()Lcom/tencent/msdk/login/LoginInfoManager;` | 1 |
| 0x1f7a | `()Lcom/tencent/msdk/api/LoginRet;` | 1 |
| 0x1f9f | `com/tencent/gcloud/msdk/api/login/MSDKLogin` | 1 |
| 0x1fce | `getLoginRet` | 1 |
| 0x1fdd | `()Lcom/tencent/gcloud/msdk/api/login/MSDKLoginRet;` | 1 |
| 0x2013 | `com/tencent/qqmusic/business/user/UserHelper` | 1 |
| 0x2043 | `loadAuthUserFromMain` | 1 |
| 0x205b | `()Lcom/tencent/qqmusic/business/user/AuthUser;` | 1 |
| 0x208d | `wechat_open_id` | 1 |
| 0x209f | `new_qq_zone_open_id` | 1 |
| 0x20b6 | `com/tencent/karaoke/module/account/KaraokeAccountManager` | 1 |
| 0x2107 | `()Lcom/tencent/karaoke/module/account/KaraokeAccountManager;` | 1 |
| 0x2147 | `getActiveAccount` | 1 |
| 0x2188 | `Lcom/tencent/component/account/Account$Extras;` | 1 |
| 0x24f5 | `Syzs` | 1 |

### 无障碍与窗口（11 条）

| 偏移 | 字符串 | 引用点 |
|---|---|---|
| 0x22ec | `ACCESSIBILITY_SERVICE` | 1 |
| 0x2305 | `accessibility` | 1 |
| 0x2316 | `android/view/accessibility/AccessibilityManager` | 2 |
| 0x2356 | `ENABLED_ACCESSIBILITY_SERVICES` | 1 |
| 0x2378 | `enabled_accessibility_services` | 1 |
| 0x239a | `getEnabledAccessibilityServiceList` | 2 |
| 0x23df | `android/view/SurfaceView` | 1 |
| 0x23fb | `android/view/Window` | 2 |
| 0x2412 | `setFlags` | 1 |
| 0x241e | `addFlags` | 1 |
| 0x242a | `setSecure` | 1 |

### 反射与进程内钩子（9 条）

| 偏移 | 字符串 | 引用点 |
|---|---|---|
| 0x21d8 | `java/lang/reflect/Executable` | 2 |
| 0x21f8 | `artMethod` | 2 |
| 0x2459 | `getDeclaredField` | 3 |
| 0x246d | `(Ljava/lang/String;)Ljava/lang/reflect/Field;` | 3 |
| 0x249e | `setAccessible` | 3 |
| 0x24af | `mInstrumentation` | 1 |
| 0x24c3 | `android.app.Instrumentation` | 1 |
| 0x24e2 | `mH` | 1 |
| 0x24e8 | `mCallback` | 1 |

### Android 属性（39 条）

| 偏移 | 字符串 | 引用点 |
|---|---|---|
| 0x02e6 | `ro.build.version.sdk` | 0 |
| 0x02fe | `ro.product.brand` | 1 |
| 0x0312 | `ro.product.device` | 2 |
| 0x0327 | `ro.product.oem` | 1 |
| 0x0339 | `ro.product.model=` | 0 |
| 0x034e | `ro.product.brand=` | 0 |
| 0x0363 | `ro.product.name=` | 0 |
| 0x0377 | `ro.product.device=` | 0 |
| 0x038d | `ro.product.manufacturer=` | 0 |
| 0x03a9 | `ro.product.cpu.abi=` | 1 |
| 0x03c0 | `ro.build.version.sdk=` | 0 |
| 0x03d9 | `ro.build.version.release=` | 0 |
| 0x03f6 | `ro.build.fingerprint=` | 0 |
| 0x040f | `ro.build.date.utc=` | 0 |
| 0x0425 | `ro.build.host=` | 0 |
| 0x0437 | `ro.secure=` | 0 |
| 0x0445 | `ro.debuggable=` | 0 |
| 0x0457 | `ro.hardware` | 0 |
| 0x0466 | `ro.revision` | 0 |
| 0x0491 | `ro.sf.lcd_density` | 0 |
| 0x04bd | `gsm.sim.state` | 0 |
| 0x04ce | `gsm.operator.alpha` | 0 |
| 0x04e4 | `gsm.operator.iso-country` | 0 |
| 0x0500 | `gsm.operator.numeric` | 0 |
| 0x0518 | `gsm.sim.operator.alpha` | 0 |
| 0x0532 | `gsm.sim.operator.iso-country` | 0 |
| 0x0552 | `gsm.sim.operator.numeric` | 0 |
| 0x0590 | `adb_enabled` | 1 |
| 0x059f | `development_settings_enabled` | 1 |
| 0x05bf | `service.adb.tcp.port` | 0 |
| 0x05d7 | `service.adb.root` | 1 |
| 0x05eb | `stay_on_while_plugged_in` | 0 |
| 0x0af6 | `sys.tencent.model` | 1 |
| 0x1219 | `ro.serialno` | 0 |
| 0x12d8 | `ro.product.model` | 1 |
| 0x1808 | `anykey` | 0 |
| 0x1a9c | `ro.package.name` | 1 |
| 0x1adc | `ro.setupwizard.mode` | 1 |
| 0x1e6c | `sys_ext.root_manage.enable` | 1 |

### JNI 与类名（9 条）

| 偏移 | 字符串 | 引用点 |
|---|---|---|
| 0x17e8 | `getInstance` | 0 |
| 0x17f7 | `getSdkVersion` | 0 |
| 0x1812 | `Ljava/lang/String;` | 0 |
| 0x215b | `()Lcom/tencent/component/account/Account;` | 1 |
| 0x2205 | `android/provider/Settings$Secure` | 6 |
| 0x223f | `()Landroid/content/ContentResolver;` | 4 |
| 0x2266 | `(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;` | 2 |
| 0x22b1 | `(Landroid/content/ContentResolver;Ljava/lang/String;I)I` | 3 |
| 0x23c0 | `android/os/SystemProperties` | 2 |

### 系统库与 syscall（29 条）

| 偏移 | 字符串 | 引用点 |
|---|---|---|
| 0x0000 | `libc.so` | 0 |
| 0x000b | `libandroid_runtime.so` | 0 |
| 0x0024 | `libart.so` | 0 |
| 0x0031 | `libdvm.so` | 0 |
| 0x003e | `__system_property_get` | 0 |
| 0x0057 | `__system_property_find` | 1 |
| 0x0071 | `gettimeofday` | 0 |
| 0x0081 | `open` | 0 |
| 0x0089 | `read` | 0 |
| 0x0091 | `chdir` | 0 |
| 0x009a | `fstatat64` | 0 |
| 0x00a7 | `fstat64` | 0 |
| 0x00b2 | `munmap` | 0 |
| 0x00bc | `inotify_init1` | 0 |
| 0x00cd | `inotify_add_watch` | 0 |
| 0x00e2 | `inotify_rm_watch` | 0 |
| 0x00f6 | `lseek64` | 0 |
| 0x0101 | `mmap64` | 0 |
| 0x010b | `lseek` | 0 |
| 0x0114 | `__statfs64` | 0 |
| 0x0122 | `__mmap2` | 0 |
| 0x0475 | `/libdvm.so` | 0 |
| 0x0483 | `/libart.so` | 0 |
| 0x094b | `/system/app/Launcher/lib/x86/libmaa.so` | 1 |
| 0x1314 | `stat` | 2 |
| 0x1440 | `__system_property_read` | 1 |
| 0x1af3 | `.so` | 2 |
| 0x1eb4 | `libwebviewchromium.so` | 1 |
| 0x1ecd | `libmediaext.so` | 1 |

### 文件与设备路径（69 条）

| 偏移 | 字符串 | 引用点 |
|---|---|---|
| 0x0144 | `/dev` | 0 |
| 0x014c | `/proc` | 0 |
| 0x0155 | `/etc` | 1 |
| 0x015d | `/system` | 0 |
| 0x0168 | `/mnt/sdcard` | 1 |
| 0x0177 | `/system/build.prop` | 0 |
| 0x018d | `/proc/uptime` | 0 |
| 0x019d | `/system/bin/app_process` | 0 |
| 0x01b8 | `/proc/cpuinfo` | 0 |
| 0x01c9 | `/proc/version` | 0 |
| 0x01da | `/proc/meminfo` | 0 |
| 0x01eb | `/proc/self/maps` | 1 |
| 0x01fe | `/proc/self/cmdline` | 1 |
| 0x0214 | `/proc/self/mountinfo` | 1 |
| 0x022c | `/proc/self/cpuset` | 0 |
| 0x0241 | `/proc/self/oom_adj` | 1 |
| 0x02a3 | `/proc/sys/kernel/random/boot_id` | 2 |
| 0x02c6 | `/proc/sys/kernel/random/uuid` | 0 |
| 0x0616 | `/sys/devices/system/cpu` | 0 |
| 0x0660 | `/sys/class/switch/h2w/state` | 0 |
| 0x067f | `/sys/class/power_supply` | 0 |
| 0x0719 | `/proc/ioports` | 0 |
| 0x072a | `/sys/devices/virtual/pp` | 0 |
| 0x0745 | `/sys/devices/virtual/switch` | 0 |
| 0x0764 | `/sys/devices/system/cpu/cpu0/cpufreq` | 0 |
| 0x078c | `/sys/devices/virtual/misc/android_adb` | 0 |
| 0x093a | `/etc/xcpuinfo` | 1 |
| 0x0e0e | `/data/data/` | 1 |
| 0x0e1d | `/data/app/` | 1 |
| 0x0e2b | `/data/user/` | 0 |
| 0x0e3a | `/data/local/` | 1 |
| 0x0f5c | `/storage/emulated` | 2 |
| 0x0f71 | `/storage/emulated/0` | 2 |
| 0x1304 | `/dev/urandom` | 1 |
| 0x1322 | `/mnt` | 1 |
| 0x132a | `/data/data` | 1 |
| 0x1338 | `/data/user` | 1 |
| 0x1346 | `/system/etc` | 1 |
| 0x1355 | `/storage/emulated/0/Android/data` | 1 |
| 0x1379 | `/storage/emulated/0/Android` | 1 |
| 0x1398 | `/storage/emulated/0/tencent` | 1 |
| 0x188e | `/cache` | 2 |
| 0x1b21 | `/system/` | 1 |
| 0x1b9f | `/system/framework/` | 1 |
| 0x1bb5 | `/system/lib` | 1 |
| 0x1bc4 | `/system/vendor/lib` | 1 |
| 0x1bda | `/vendor/lib` | 1 |
| 0x1be9 | `/apex/com.android.` | 1 |
| 0x1bff | `/apex/com.google.mainline.` | 1 |
| 0x1c1d | `/product/lib` | 1 |
| 0x1c2d | `/system/product/lib` | 1 |
| 0x1c44 | `/system_ext/lib` | 1 |
| 0x1c57 | `/system/system_ext/lib` | 1 |
| 0x1caf | `/proc/self/mounts` | 1 |
| 0x1ce0 | `/data/` | 1 |
| 0x1cea | `/data/bin/` | 1 |
| 0x1d0d | `/data/local/bin/` | 1 |
| 0x1d21 | `/system/bin/` | 1 |
| 0x1d31 | `/system/bin/.ext/` | 1 |
| 0x1da1 | `/cache/` | 1 |
| 0x1dac | `/dev/` | 1 |
| 0x1dcb | `/system/bin/.ext/.` | 1 |
| 0x1e14 | `/data/data/bin/` | 1 |
| 0x1e27 | `/data/data/in/` | 1 |
| 0x1ea1 | `/my_product/lib` | 1 |
| 0x1edf | `/system/app/HwWebview/lib` | 1 |
| 0x1efc | `/odm/lib` | 1 |
| 0x21ba | `/mnt/asec/` | 1 |
| 0x21c8 | `/mnt/expand/` | 1 |

### 其它（58 条）

| 偏移 | 字符串 | 引用点 |
|---|---|---|
| 0x0580 | `ANDROID_ROOT` | 0 |
| 0x0607 | `Hardware	: ` | 0 |
| 0x0631 | `cpuinfo_max_freq` | 0 |
| 0x0645 | `cpuinfo_min_freq` | 0 |
| 0x0659 | `cpu` | 0 |
| 0x069a | `battery/capacity` | 0 |
| 0x06ae | `battery/status` | 0 |
| 0x06c0 | `ac/online` | 0 |
| 0x06cd | `usb/online` | 0 |
| 0x06db | `battery` | 0 |
| 0x06e6 | `Charging` | 0 |
| 0x06f2 | `Discharging` | 0 |
| 0x0701 | `Not charging` | 0 |
| 0x0711 | `Full` | 0 |
| 0x08d9 | `generic` | 2 |
| 0x0975 | `Hardware    :` | 1 |
| 0x0986 | `placeholder` | 1 |
| 0x0abc | `init.` | 1 |
| 0x0ac5 | `.environment.rc` | 1 |
| 0x0b67 | `1,Telephony,getDeviceId;2,Telephony,getSubscriberId;3,System… (037da184)` | 0 |
| 0x0c8c | `.jar (deleted)` | 0 |
| 0x0cb0 | `logcat -v brief` | 0 |
| 0x0cc3 | `socksProxyHost` | 1 |
| 0x0cd5 | `socksProxyPort` | 1 |
| 0x0d76 | `/com.lbe.parallel/` | 0 |
| 0x0e54 | `/base.apk` | 0 |
| 0x0e61 | `/com.tencent.` | 0 |
| 0x0e72 | `/com.android.` | 0 |
| 0x0e83 | `/com.google.` | 0 |
| 0x0e93 | `/com.huawei.` | 0 |
| 0x0f88 | `Access: ` | 1 |
| 0x113f | `deviceUniqueId` | 0 |
| 0x1289 | `content://settings/secure/` | 1 |
| 0x12a7 | `_track_generation` | 0 |
| 0x12bc | `GET_secure` | 2 |
| 0x12ca | `android_id` | 2 |
| 0x12ec | `tmpA03` | 1 |
| 0x12f6 | `7148575929` | 1 |
| 0x131c | `-f` | 1 |
| 0x1403 | `k%d:%s;` | 1 |
| 0x140e | `k10:%d` | 1 |
| 0x17d2 | `qimei/sdk/QimeiSDK` | 0 |
| 0x1a81 | `x.host.vm_camera_enable` | 1 |
| 0x1aaf | `vm.camera.status` | 1 |
| 0x1ac3 | `android.host.adb.port` | 1 |
| 0x1afa | `%lx-%lx %s %*x %x:%x %*d %s` | 2 |
| 0x1b19 | `r-xp` | 0 |
| 0x1b2d | `%*s %*s %*s %s %*d %*d` | 1 |
| 0x1b47 | `%s %s %*s %*s %*d %*d` | 1 |
| 0x1b60 | `/share ` | 1 |
| 0x1b82 | `/ /data ` | 1 |
| 0x1b8e | `%*d %*d %d:%d` | 1 |
| 0x1e4f | `/res/` | 1 |
| 0x1e8a | `storage.cloud.model` | 1 |
| 0x1f62 | `getLastLoginUserInfo` | 1 |
| 0x20f2 | `getAccountManager` | 1 |
| 0x2229 | `getContentResolver` | 4 |
| 0x2349 | `isEnabled` | 2 |


## 附录 B：工具与产物

| 文件 | 作用 |
|---|---|
| `_qdec.py` | 按 `[u16 len][u8 key][cipher]` 解析并解密整张表 |
| `_qd2.py` | 导出 398 条字符串 → `QIMEI_strings.txt` |
| `_quse.py` | 扫描 280 个 `bl 0x1efb8` 引用点 → `QIMEI_string_usage.txt` |
| `_report.py` | 生成附录 A 的分类表 |
| `_emu.py` | unicorn 进程外执行框架（PT_LOAD 映射、重定位、桩函数、TLS） |
| `_trace.py` | 跟踪取串函数对表的读写，验证「原地解密」 |
| `_findcallers.py` | 定位解密/上报函数的调用者 |

## 附录 C：未完成项

1. `q16`/`q36` 的精确拼装顺序：需继续跟 `0x256e8`（`r()`）与 `0x3a818`（`z()`）。
2. 4 个 MD5 常量与 `Ql9nXK6f…` 256 B 块的具体角色（密钥组选择 vs 校验）。
3. `0x2b9d4` 三种模式的完整伪代码（控制流平坦化，需逐块还原）。
4. 上报体的 ChaCha20 计数器/nonce 布局与 `sign` 生成规则。
