## 总览

libtersafe.so 把环境异常拆成两套体系：**IsVAP**（云手机/开发板/虚拟多开）与 **IsEmu**（模拟器品牌）。云手机由 0x2B54C8 汇总 6 个位标志写入 `{valid, bitmap, name[64]}`，再交 0x2B9D98 命名上报；模拟器由 0x280688 取机型串做 `strstr`，产出 1~512 位图并映射为 `*_tp` 标签。x86 走属性链 0x2975B8/0x297EDC，回填 `prop:x86`。黑名单不走 PackageManager，而是遍历 `/proc` 对进程名做 `strstr`。最终由 0x23DA5C 串成 `IsEmu/EmuName/IsVAP/VAPName/OPC` 上报。

## 云手机（cloud phone）检测

**判据一：com.cph.* 属性族。** 0x2B6040 逐条 `sub_4CEE28` 读 21 个属性，值参与 `sub_2B6764` 匹配（该基元内部 `memset(s,0,0xFF)` 后 `sub_4CEE28(a2,s,255)`，长度 ≤0 直接返回 0）：

```
com.cph.bandwidth_limit / bluetooth_mac / bluetooth_name / cg_type / encode_type /
mainkeys / media_engine.version / network.type / network.type_name /
cme.use_uinput / disable_fb_permission
ro.com.cph.as.changed / cloud_app_engine / mac_address / non_root /
notification_disable / remote_input_method / sfs_enable / toast_enable / vpn.changed
ro.hardware.fps.cph
```

函数体为 `_QWORD v10[21]`，先判 `v10[0]`，再以 `v1 != 21` 收口扫完 `v10[1..20]`；基准值 `v0 = sub_4EB7B0(52474)`（`none`），每条走 `sub_2B6764(v0, v10[i], v0)`，命中即跳 `LABEL_12` 返回 `v4 < 0x14`。语义是「属性可读且值不等于 `none`」——正常机型读这些属性长度为 0，`sub_2B6764` 直接返回 0；云手机则能读到具体值。属性读取走 0x4CEE28，它是带完整性门控的 `__system_property_get` 包装（先 `sub_22DA98(..., "property_get"(0x97199), 1)` 校验再调用）。

**判据二：CPH 私有媒体库。** 0x2B5EA8 对 12 条路径做 `sub_4CF408`（access/stat）存在性判定，任一存在即真：`/system/lib{,64}/libCPHIvmiAudio.so`、`libCPHMediaEngine.so`、`libCPHMediaServer.so`、`libCPHTurboVideoEngine.so`、`libCPHVideoEngine.so`、`libCPHVmiAudioRecord.so`。

**判据三：cloudphone 字面量。** 0x2B6AC4 用 `cloudphone`（offset 58302）匹配 6 条属性值：`sys.prop.writewifissid`、`wifi_name`、`ro.product.odm.model`、`ro.product.product.model`、`ro.product.system.model`、`ro.product.system_ext.model`。

**判据四：gemini 机型指纹。** 0x2B5B9C 对 17 条 `ro.*` 属性做匹配，标记由调用方传入：0x2B54C8 传 `gemini`（offset 55777），0x2B5B00 传 `rk3588_docker`。属性含 `ro.build.product/flavor/fingerprint/description`、`ro.product.{device,name,odm.*,system.*,vendor.*}`、`ro.odm/vendor/bootimage.build.fingerprint`、`ro.bd.product.model`、`ro.system.build.fingerprint`。`gemini` 是腾讯云手机机型代号，命中即判云手机。

**判据五：属性系统目录异常。** 0x2B5D70 打开 `/dev/__properties__/`（offset 55846），`readdir` 最多 100000 项，对文件名先 `sub_489248` 求哈希去重（红黑树 set），仅新项取 `sub_4B841C` 尺寸并维护最小值，收尾 `LODWORD(v0) = v2 > 0x5F5E100`（160000000）。即「目录下所有属性文件尺寸都 >160MB」才成立——正常设备属性文件仅百 KB 级，该分支用于识别属性系统被镜像/容器替换的环境（命中条件苛刻，「推测」）。

**品牌命名与上报。** 0x2B9D98 以位图 `v13 = *((_DWORD*)a2+1)` 为门控，掩码决定了「哪种底层特征才能认哪个品牌」：

| 品牌 | 掩码条件 | 含义 |
|---|---|---|
| RedFinger / ZYYun | `v13 & 1` | 必须命中 KVM |
| ShuangZiXinYun | `v13 & 2` | 必须命中 Rockchip |
| LeiDianYun | `v13 & 0x20` | 必须命中 cloudphone 属性 |
| DuoDuoYun | `~v13 & 0x39` | bit0/3/4/5 全不命中 |
| XiaoDiYun | `~v13 & 0x33` | bit0/1/4/5 全不命中 |
| VMOSYun | 无掩码 | 恒判定 |

命中后 `sub_4A54DC(v37, 256, "cp23:%d,%s,%s"(58401), bitmap, a2+8)` 拼装，事件名 `cloud3_err4`（58387），`sub_474EF4` 上报，并置 `*(_BYTE*)(v5+333)=1` 防重报。结构默认名 `UnKnownYun`（55869）。

## Rockchip / 开发板 / 容器

0x2B6500 对 11 条路径做存在性判定，循环上限 11、返回 `v3 < 0xA`：`init.rockchip.rc`、`/sys/module/rockchip_{hdmirx,rga,charger_manager,performance,pwm_remotectl}`、`/sys/module/rockchipdrm`、`/system/lib{,64}/librockit.so`、`/system/lib{,64}/librknnhal_bridge.rockchip.so`。

0x2B5B00 先读 `RK_ADEPT_DEVICE_TYPE`（56379）走 0x2B6320 判定，再 `sub_2B6500() || sub_2B6684()`，最后用 `rk3588_docker`（56402）匹配 17 条属性——RK3588 开发板上跑 Docker 容器的典型指纹。

0x2B5A5C（KVM）门控为云控命令 `cp_kvm`（58427），三道排除后判定：`sub_2B62BC()` 命中则跳过；`sub_2DB578(sub_2DAD4C()) > 32`（API level >32，即 Android 13+）跳过；随后要求 `/sys/module/kvm`（55786）与 `/sys/module/kvm/parameters/halt_poll_ns`（55804）同时存在，最后 `sub_4B7AA8` 成功读到 `halt_poll_ns` 内容才 `return 1`。Android 13+ 普遍内置 kvm 模块，故用版本上限规避误报。

## 模拟器品牌识别

0x280688 是品牌位图生成器：先 `sub_23A0B0(ctx, v36, 64)` 取机型/品牌串，再按顺序判定并写入 `*(_DWORD*)(a1+192)`：

- `strcmp(v36,"TencentAoYYB")==0` → **512**；`strstr` 命中顺序：`Tencent`→**2**、`Win`→**1**、`LeiDian`→**4**、`Nox`/`NOX`→**8**、`XiaoYao`→**16**、`BlueStack`→**32**、`Google`→**64**、`Mac`→**128**。

对应标签在 0x280C3C：`tencent_yyb_tp`、`tencent_tp`、`win_tp`、`leidian_tp`、`nox_tp`、`xiaoyao_tp`、`bluestacks_tp`、`google_tp`、`mac_tp`——即 `EmuName` 的取值集合。

**QEMU 管道探测。** 0x27B110 在栈上就地解密 11 段密文（`sub_27BCF8(&unk_xxxx, len, buf)`），其中 19 字节段即 `pipe:qemud:sensors`（site 0x27B190），云控门控后 `v4 = sub_4B8488(v28, 2, 0)` 打开设备（O_RDWR），逐段 `write` 探测命令，最后以「写入字节数 == 期望长度+1」判定 `v27`，返回是否命中。这是 goldfish/qemu 传感器后门探测。

**处置动作。** 0x29904C 引用 `It is found that you are running in an Android emulator. Please resume the game after returning to physical de...`（889212）、`Exit`、`ICON:%s:`、`%sWarning`、`Netease`，即弹窗并退出游戏。

## x86 / houdini / 指令集

0x2975B8 三级属性判定，任一成立 `return 1`：

```
ro.enable.native.bridge.exec == "1"          → 1   (45952 / "1" 46138)
ro.dalvik.vm.isa.arm        == "x86"         → 1   (45983 / 46142)
ro.dalvik.vm.native.bridge  == "libhoudini.so" → 1 (46033 / 46073)
```

0x297EDC 是 64 位补充：读 `ro.dalvik.vm.isa.arm` 若等于 `x86`、或读 `ro.dalvik.vm.isa.arm64`（46166）若等于 `x86_64`（46191），走 `LABEL_19`：`sub_4A54DC(a2, a3, "prop:%s"(46156), v23, ...)` 把 `prop:x86` / `prop:x86_64` 写进输出缓冲并 `return 1`——这正是 `EmuName` 的「属性类」命名来源。函数内 `if (v13 != 2) abort();` 属 OLLVM 平坦化的死分支。

上层 0x270760 引用 `scan_x86`、`scan_x86_by_mem`、`x86_sys_scan`、`am_cnt`、`sx_rel`、`ce_bad`、`.so`、`/dev/`，是「按内存/按系统扫描 x86 痕迹」的调度器，`am_cnt` 累计命中数。

## 虚拟多开（VAP）

**静态 stub 表。** 0x28C914 在 `atomic_load(&byte_55F530)` 保护下填充 `qword_55F488[21]`，每项是 `name=<包名>|cls_name=<stub Activity>`；随后按 `|` 分割（`sub_4A1504(...,"|",0)`），取 `name`/`cls_name` 两键（`sub_4A1714`），各拷 64/128 字节后 `sub_233E0C` 追加进结果容器，`++v6 == 21` 结束。21 条覆盖 `com.lody.virtual`、`com.morgoo.droidplugin`、`com.lbe.doubleagent`、`com.polestar.clone`、`info.red.virtual`、`com.vmos.app`（`android.os.VmosForkAppManager`）、`com.vmos.pro`、`com.excean.*`、`com.qihoo.magic*`、`com.bly.dkplat` 等。

**运行期反射链。** 0x28C378 用 JNI 逐跳取 ClassLoader 后 `loadClass` 探测：

```
android/app/ActivityThread.currentActivityThread()        (2101/2130/2154)
→ mInstrumentation : Landroid/app/Instrumentation;        (5147/5166)
→ getClassLoader() : Ljava/lang/ClassLoader;              (39355/39372)
→ loadClass(String) : Ljava/lang/Class;                   (5095/5107)
```

0x28CB8C 对每个候选类名做 `sub_2CE3A4(a2, a3, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;")`，成功即 `v19 = 1`——即「主进程 ClassLoader 里能加载出沙箱 stub 类」= 运行在虚拟多开内。0x233C90 负责把 0x230C78 系列黑名单转成待查类名容器。

**taptap / 4399 系。** 0x28CD40 12 条：`com.play.taptap.application.AppGlobal`、`ui.SplashAct`、`service.TapService`、`com.taptap.CallbackActivity`、`meta.core.client.stub.ShadowActivity `（含尾空格）、`ShadowService`、`core.meta.metaapp.fC.TACE`、`com.pm.api.AppManagerHelper`、`CpuBitMode`、`Logger`、`4399_clzs`、`meta_clzs`。

## 作弊 / 辅助 / 加速器黑名单

**内置表。** 0x230C78 把 64 条包名逐个 `sub_4E8418(off)` 解密、`sub_1DB394` 构造成 libc++ `std::string` 写入 96 字节项（3 字段 × 32 字节，项内名字在 +20、标志位在 +88）。名单含 `bin.mt.plus`、`com.cyjh.gundam`、`com.cyjh.mobileanjian`、`com.dimonvideo.luckypatcher`、`org.sbtools.master`、`org.sbtools.gamespeed`、`gamehacker`、`com.scriptelf`、`com.huluxia.gametools`、`com.kascend.chushou.lu`、`com.keramidas.TitaniumBackup`、`com.github.shadowsocks`、`com.bige0.shadowsocksr`、`co.solovpn`、`com.speedsoftware.rootexplorer`，以及租号/代练/加速器类 `com.wuba.zhuanzhuan`、`com.jym.mall`、`com.jj.jiasu`、`com.speed.chick`、`com.bdkj.LightningGameRental`。另有 `armbin`(12460)、`binarm`(16972) 两个后缀片段同表下发。

**覆盖机制。** 0x230BD0 先 `sub_23088C("comm.dat"(713), a2, "comm.dat")` 尝试从外部配置加载；成功且非空则直接用外部名单，否则 `sub_230C78` 用内置表兜底。列表每项 96 字节，`sub_475CC8(ptr, 96)` 释放可反证。

**使用方法（关键）。** 0x4E2F30 是规则引擎里的检查函数：

```
v5 = sub_239A64(sub_2DAD4C(a1));          // 取上下文/uid
sub_230BD0(v5, v14);                      // 取名单
v6 = sub_4DD77C();                        // calloc(1,0x210) + opendir("/proc")
while ((v8 = sub_4DD7CC(v6)) != 0) {      // readdir 解析 pid
  v10 = v8 + 1; v11 = *v8;
  while (((_DWORD)v9[11] & a2) == 0       // 项标志 & 类型掩码
      || sub_4A47AC(v10, (char*)v9 + 20) == 0   // strstr(进程名, 项名)
      || sub_4DD8E8(v11) == 0) { v9 = *v9; }
  v12 = 1;                                // 命中
}
```

即**遍历 /proc 全进程，对进程名做子串匹配**（`sub_4A47AC` 为 strstr），配 `a2` 类型掩码过滤条目类别；整个过程不调用 PackageManager，因此改包名/隐藏应用无效，但换进程名即可绕过。

**so / 框架黑名单。** 0x231824 从 `comm.dat` 路径迭代器逐项取路径（每项 65 字节 = 64 字符串 + 1 字节是否有后继），失败则 `sub_231998` 填内置 21 条：`/system/`、`/dev/`、`com.ijinshan.duba`、`com.lbe.security`、`com.qihoo`、`com.android.vndk`、`com.huawei.webview`、`com.google.android.webview`、`WebViewGoogle`、`dalvik`、`hook`、`libhelpertool`、`libhhmspy`、`libooenv`、`libooSpeeder`、`libsubstrate`、`libxxAndroidLoader`、`libxxdvm`、`libxxghost`，另挂 `com.google.android.trichromelibrary`(25034)、`com.android.chrome`(40043)。其中 `libsubstrate`（Cydia Substrate）、`libooenv`/`libooSpeeder`（叉叉助手/加速器）、`libxx*`（叉叉框架）为 hook 框架特征。`armbin`/`binarm` 与包名同表，配合 strstr 语义可覆盖 `libxxx_armbin.so` 一类翻译器/加固产物。

## 上报字段

0x23DA5C 是一条顺序拼装链，逐段写同一缓冲区，任一段失败即返回 -1：

```
0x23DB04 → 0x23DBB0 → 0x23DC34 → 0x23DDAC → 0x23DE84 →
0x23DF18(IsEmu) → 0x23DFAC(IsVAP) → 0x23E040(OPC) →
0x23E0C0 → 0x23E1B0 → 0x23E214
```

0x23DF18 形如 `v10 = sub_271730(sub_270364(...), v14, 64); sub_4A54DC(src,128, "IsEmu=%d|EmuName=%s|", v10 & 1, v14);`——`IsEmu` 是 0/1，`EmuName` 来自 0x271730 产出的品牌名（即 `*_tp` 或 `prop:x86`）。0x23DFAC 用 `IsVAP=%d|VAPName=%s|`，VAPName 取 0x2B54C8 写入的 `name[64]`（云手机品牌或 `UnKnownYun`）。

**OPC。** 0x23E040 用 `OPC=%08x|`，同族键名在 0x214C64 一并出现：`token`、`DST`、`OpcodePatched`、`ExpectOpcode`、`RealOpcode`、`IsCertValid`、`IsDevTrust`、`MayInVap`、`IsSupportDevTrustVerify`，格式 `%08X`/`%04x`/`%u`。据此推断：OPC 是**指令码校验（opcode check）的 32 位结果位图**，每位对应一类被内联 hook / inline patch 的指令现场；`ExpectOpcode`/`RealOpcode` 记录首条差异指令的期望值与实际值，`DST` 是目标寄存器/偏移，`OpcodePatched` 为被改指令计数。它与 `MayInVap` 并列，说明「代码段被改」同时作为虚拟多开/云手机的辅助判据（「推测」，依据为同函数键名共现）。

## 误报控制设计

四处设计值得注意：

1. **双层门控。** 每个检测入口先过完整性校验 `sub_22DA98(ctx, 命令名, 1, 1)`，再受云控字节开关约束（`ctx+0x3B4` 关模拟器扫描、`ctx+0x3B5` 关云手机扫描），运营可远程关停而不发版。
2. **版本排除。** KVM 检测用 `sub_2DB578(sub_2DAD4C()) > 32` 显式排除高版本系统（应为 API level，Android 13+ 起 `/sys/module/kvm` 普遍存在，「推测」），否则真机会被大面积误判为云手机。
3. **品牌互斥掩码。** RedFinger/ZYYun 要求必须命中 KVM、ShuangZiXinYun 要求命中 Rockchip、LeiDianYun 要求命中 `cloudphone` 属性；而 DuoDuoYun/XiaoDiYun 反过来要求 `bit0/3/4/5`（或 `bit0/1/4/5`）全不命中——即「特征越少越可能是该品牌」，用互斥条件压低误判。
4. **防重报与名单外置。** 0x2B9D98 命中后置 `*(_BYTE*)(v5+333)=1` 只报一次；黑名单优先读 `comm.dat` 外部配置，失败才用内置 64 条，便于热更新。

## 云控开关

0x1BCF84 是命令名 `strcmp` 分发链，命中后向全局状态对象（`sub_2DAD4C()` 返回值）写字节标志：

```
strcmp(cmd,"CloseEmulatorScan")   ==0 → STRB W8,[X0,#0x3B4] = 1   (0x1BDC70–0x1BDC9C)
strcmp(cmd,"CloseCloudPhoneScan") ==0 → STRB W8,[X0,#0x3B5] = 1   (0x1BDCA4–0x1BDCD0)
下一条命令                         ==0 → STRB W8,[X0,#0x3B6] = 1   (0x1BDCD8–)
```

同表还有 `CloseUserTagScan`(46321)、`IsEmulator2`(53929)、`ScanEmulator`(51955)、`ScanOpcode`(51983)、`StartSecScan`(31135)。各检测函数在入口用 `sub_22DA98(ctx, 命令名, 1, 1)` 单独门控：`cp_comm`(58417) 管 0x2B54C8 整组云手机扫描、`cp_kvm`(58427) 管 KVM 分支。

**规则引擎。** 0x4E3CAC 以 `{规则名, 检查函数, 类型号}` 三元组构造约 80 项规则表，规则名含明文 `module_size_in_range`（0x97DFD）与解密项 `is_simulator_cpu`(7895)、`is_x86_env`(7935)；类型号取值 `{0,1,2,3,4,5,7,11,14,15,17,18,19,20}`，用于结果分类。`is_simulator_cpu`/`is_x86_env` 具体绑定的检查函数因 OLLVM 跳转表平坦化未能与名称精确对齐（「推测」：应为 0x296084 与 0x270760 所在分支）。

## 检测特征清单表

| 类别 | 特征字符串 | 来源地址 |
|---|---|---|
| 云手机属性 | `ro.com.cph.cloud_app_engine` 等 21 条 | 0x2B6040 |
| 云手机属性 | `com.cph.cme.use_uinput`、`com.cph.disable_fb_permission` | 0x2B6040 |
| 云手机库 | `/system/lib64/libCPHMediaEngine.so` 等 12 条 | 0x2B5EA8 |
| 云手机字面量 | `cloudphone` | 0x2B6AC4 |
| 云手机机型 | `gemini`（17 条 ro.* 属性匹配） | 0x2B5B9C |
| 云手机品牌 | `RedFinger`/`DuoDuoYun`/`XiaoDiYun`/`LeiDianYun`/`VMOSYun`/`ShuangZiXinYun`/`ZYYun` | 0x2B9D98 |
| 云手机默认名 | `UnKnownYun` | 0x2B54C8 |
| 云手机上报 | `cp23:%d,%s,%s`、`cloud3_err4` | 0x2B9D98 |
| 属性系统 | `/dev/__properties__/` | 0x2B5D70 |
| 虚拟化 | `/sys/module/kvm`、`.../parameters/halt_poll_ns`、`cp_kvm` | 0x2B5A5C |
| 开发板 | `init.rockchip.rc`、`/sys/module/rockchip_rga`、`librockit.so` 等 11 条 | 0x2B6500 |
| 开发板 | `RK_ADEPT_DEVICE_TYPE`、`rk3588_docker` | 0x2B5B00 |
| 模拟器品牌 | `TencentAoYYB`/`Tencent`/`Win`/`LeiDian`/`Nox`/`NOX`/`XiaoYao`/`BlueStack`/`Google`/`Mac` | 0x280688 |
| 模拟器标签 | `nox_tp`、`bluestacks_tp`、`leidian_tp`、`tencent_yyb_tp`、`mac_tp` 等 9 条 | 0x280C3C |
| 模拟器管道 | `pipe:qemud:sensors` | 0x27B110 |
| 模拟器提示 | `It is found that you are running in an Android emulator...`、`Exit` | 0x29904C |
| x86 | `ro.enable.native.bridge.exec`、`ro.dalvik.vm.isa.arm`、`libhoudini.so` | 0x2975B8 |
| x86_64 | `ro.dalvik.vm.isa.arm64`、`x86_64`、`prop:%s` | 0x297EDC |
| x86 扫描 | `scan_x86`、`scan_x86_by_mem`、`x86_sys_scan`、`am_cnt` | 0x270760 |
| 多开 stub | `com.lody.virtual.client.stub.StubActivity`、`com.morgoo.droidplugin.stub.ActivityProxy` 等 21 条 | 0x28C914 |
| 多开反射 | `android/app/ActivityThread`、`currentActivityThread`、`mInstrumentation`、`getClassLoader`、`loadClass` | 0x28C378 / 0x28CB8C |
| 多开平台 | `com.bly.dkplat`、`info.red.virtual`、`com.vmos.app`、`com.vmos.pro`、`com.qihoo.magic` | 0x28C914 |
| 渠道沙箱 | `meta.core.client.stub.ShadowActivity `、`4399_clzs`、`meta_clzs` | 0x28CD40 |
| 作弊应用 | `bin.mt.plus`、`com.cyjh.gundam`、`gamehacker`、`org.sbtools.master`、`com.dimonvideo.luckypatcher` 等 64 条 | 0x230C78 |
| 代理/VPN | `com.github.shadowsocks`、`com.bige0.shadowsocksr`、`co.solovpn`、`com.fobwifi.transocks` | 0x230C78 |
| 加固后缀 | `armbin`、`binarm` | 0x230C78 |
| hook 框架 | `libsubstrate`、`libooenv`、`libooSpeeder`、`libxxdvm`、`libxxghost`、`libxxAndroidLoader` | 0x231998 |
| 名单文件 | `comm.dat` | 0x230BD0 / 0x231824 |
| 进程扫描 | `/proc`（`calloc(1,0x210)` + `opendir`） | 0x4DD77C / 0x4E2F30 |
| 上报字段 | `IsEmu=%d|EmuName=%s|`、`IsVAP=%d|VAPName=%s|`、`OPC=%08x|` | 0x23DF18 / 0x23DFAC / 0x23E040 |
| OPC 键名 | `OpcodePatched`、`ExpectOpcode`、`RealOpcode`、`DST`、`MayInVap` | 0x214C64 |
| 云控命令 | `CloseEmulatorScan`、`CloseCloudPhoneScan`、`IsEmulator2`、`ScanEmulator` | 0x1BCF84 |
| 云控开关名 | `cp_comm`、`cp_kvm` | 0x2B54C8 / 0x2B5A5C |
| 规则名 | `is_simulator_cpu`、`is_x86_env`、`module_size_in_range` | 0x4E3CAC |
| 属性读取 | `property_get` | 0x4CEE28 |
