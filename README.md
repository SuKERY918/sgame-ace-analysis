# 《王者荣耀》ACE 反作弊逆向分析

对《王者荣耀》12.1.1.1（`com.tencent.tmgp.sgame`，versionCode 1201010103）内置反作弊组件 ACE 的完整逆向分析：
静态结构、云控配置与规则引擎、上报协议、云端下发的原生检测模块，以及在一台 arm64 真机上的动态验证。

分析对象是 APK 内的 `libtersafe.so`（检测主体）与 `libtprt.so`（代码保护运行时），
样本本身未加壳，检测逻辑全部在 Native 层。

## 核心结论

1. **只采集、不判定。** 客户端没有"判定作弊"的代码路径：它把 root/模拟器/Hook/调试/设备指纹等检测结果编码成
   `id=<字段号>|k=v|...` 的文本项，Base64 + 固定密钥异或后经裸 TCP（端口 443，但**不是 TLS**）发给
   `*.cschannel.anticheatexpert.com`，判罚在服务端。
2. **双套字符串加密 + 全库控制流平坦化**，另外还有一层运行时保护：`libtprt.so` 提供 OBJ_VM
   （装载器 + 符号绑定 + 调用转发），负责执行云端下发的原生模块。
3. **41 个特征模块 / 9 个检查任务 / 101 个云控规则算子 / 88 个数字命令 + 22 个文本命令**，
   几乎每个检测面都对应一个可以单独关闭的云控开关。
4. **热更新模块 `libtersafeupdate2.so` 可整体接管。** APK 内没有这个文件，它由云端下发到 app 私有目录，
   通过 `GetTssExportFunc2` 返回函数表，接管加密、`ischeatpacket`、上报乃至 `JNI_OnLoad`。
5. **云端可下发新的原生检测代码。** `ano_tmp/*.zip` → `a64.dat`/`a64.sig` 经 RSA-2048 验签后由
   libtprt 装载执行（`ob_x`/`ob_cs2` 等，模块名如 `auto_clicker_proxy4`、`detect_live_app`、`enum_apk_r`）。
   容器与 S 盒固定，**只有完整性、没有机密性**。
6. **自校验是抽样且可配置的**：代码段校验只抽 1/20 槽、逐页 CRC 崩溃窗口很窄，证书判定可被配置短路。
7. **真机验证**：断网可存活 150 s+；联网时进大厅后 15–37 s 被终止；`frida-server` 文件留在
   `/data/local/tmp` 会被文件检测直接命中；本地"自杀"路径是一次故意的 `free()` 非法指针（可被运行时拦截，
   拦截后存活 55–57 s），但最终终止由服务端下令。

8. **伴生库 `libqimei` 才是设备标记的主链。** 字符串表用「每条记录 3 字节头 + 单字节变种 XOR」加密，9469 字节解出 398 条明文；内容覆盖 root/su、Xposed/LSPosed/Frida/Riru/Zygisk、模拟器与云手机、群控自动化（minitouch/scrcpy/按键精灵）、代理、无障碍、Widevine，以及 `/data/system/*` 的 inode/mtime 指纹与腾讯系 openid。QIMEI（q16/q36）以 ChaCha20 + RSA-2048 封包上报，服务端用 QIMEI + openid 建设备图谱——刷机与恢复出厂只清本地缓存，清不掉图谱。详见 `docs/qimei.md`。

9. **设备标记是三通道并行、单点交汇。** ACE（`libtersafe`）17 槽硬件画像、QIMEI（`libqimei`）12 维注册指纹、TDM（`libTDataMaster`）26 字段运营画像，三条链互不调用，只在 `Fake_Token_TDM_info` 处交汇：ACE 从 TDM 写入的文件里读 `xid/q16/q36/oaid`，拼成 `x:..;q:..;Q:..;o:..`，再包 `bt:<boot_id>;bd:<brand>`，随检测事件上报。q16/q36 由服务端按注册 JSON 计算并下发（本地只缓存 `A3`/`A153`），客户端没有生成路径；刷机只清本地缓存，清不掉服务端图谱。详见 `docs/devinfo_deep.md`。

10. **主字符串表已完全离线还原。** `libtersafe` 的 3,198 条加密记录落在 `.rodata` 的 `0xFBCB0`–`0x10C234`，格式为 `[key][len^key][cipher][check]`，逐字节递推 `k_{j+1}=(((k_j+j)&0xFF)^E)+C`，`(E,C)` 共 99–101 组（对应 `0x4E64D0..0x4ED3CC` 的封印装函数），尾部用 `(check^cs^key)==0xFF` 校验。据此解出全部路径、属性名、模块名、协议字段与格式串（3,246 个调用点、2,110 个 idx、876 个函数），并修正旧报告的 2,868 条为 3,198 条——`ft_oaid`(58,581)、`AndroidIdErr`(52,998) 正在旧表范围之外。详见 `docs/tersafe_strings.md`，全表见 `docs/strings.tsv`。

## 仓库结构

```
docs/
  main.md            # 主报告（13 章，约 1120 行）：架构、SDK 框架、云控、上报、检测项、弱点、动态验证
  partA_root.md      # Root / Magisk / KernelSU / Zygisk / 完整性 / 签名
  partB_emu.md       # 模拟器 / 云手机 / x86 / 虚拟多开 / 黑名单
  partC1_hook.md     # Frida / Xposed / Substrate / IDA / inline hook / ELF 篡改
  partC2_antidbg.md  # ptrace / TracerPid / GP3 / GP4 / GP6 / memtrap / mrpcs / mincore
  partD_devinfo.md   # 设备采集 / 伪造 token / keystore attestation / 反自动点击
  partE_integrity.md # various_opcode / opcode_scan / cert3 / cc2 / shell_checker / file
  partF_apps.md      # process / anti_virapp / black_app / collect_apk / anoscan 等
  partG_account.md   # info / tablet / user_tag / ksat / pe_rep / env_chk / info_publisher
  partH_misc.md      # live / cps_new / cs_vm / wb_daemon / ob_normal / win_data_sync / inf_sca / gp5
  partI_siblings.md  # 伴生库身份：libsaf / libTDataMaster / libqimei / libckguard / libencrypt
  qimei.md           # libqimei 设备标记机制：字符串表解密、398 条全表、280 个引用点、QIMEI 组装与上报
  devinfo_deep.md    # 设备标记三通道：ACE 17 槽、QIMEI 12 维/注册 JSON、TDM 26 字段、fake token 全链
  tersafe_strings.md # 主字符串表还原：记录格式、参数族、校验、全量重建与锚点验证
  strings.tsv        # 3198 条主表明文（offset/key/len/E/C/string）
  strings_usage.tsv  # 3246 个字符串引用点（func/call/idx/string）
  partJ_blob.md      # 下发 blob 的容器、段表、.img 原生码与 RSA-2048 验签
tools/               # 分析脚本（字符串解密、调用图、算子抽取、blob 解析等，按需修改路径后运行）
  so_elf.py          # ELF 读取、反汇编、.eh_frame_hdr 函数边界恢复
  qimei_scan.py      # 字符串表解密 + 取串点/调用点扫描
  java_grep.py       # 反编译产物按正则筛选
  ascii_strs.py      # ELF 内 ASCII 串提取
  bl_callers.py      # 扫描 .text 中调用指定地址的全部 BL
  tersafe_strings.py # 主表解密：记录切分、参数族提取与补全、(E,C) 消歧、全表导出
  tersafe_usage.py   # 主表引用点：BL 目标回溯 MOV W0,#idx，按函数归组导出
  hook_devinfo.js    # Frida 脚本：QIMEI 维度、TDM 设备信息、ACE fake token 与上报原文
```

## 方法

- **函数边界**：样本已 strip，用 `.eh_frame_hdr` 恢复 16284 个函数入口（IDA 报 17780 个，差额是无 unwind
  信息的小函数）。
- **字符串**：两套编码。主表 3,198 条记录、99–101 组 `(E,C)` 参数，记录按 `[key][len^key][cipher][check]` 连续切分、尾字节校验，已全量还原（见 `docs/tersafe_strings.md`）；
  内联串用固定的逐字节异或（密钥随解码器不同，已知 `0xAB/0xC6/0xE5/0xF3`），补出 945 条，合计约 4143 条。
- **代码**：多数检测函数是控制流平坦化状态机，IDA 反编译经常失败，只能逐块读汇编；`capstone` 扫描
  `.text` 找 `BL` 目标与 `MOV W0,#imm` 调用点，把字符串与函数对应起来。
- **动态**：Frida（含 patch 探测函数、跳过非法 free）、`logcat`/tombstone、`tcpdump` 抓包、
  以及重装 `libtersafe.so` 的静态 patch 对照实验。

## 复现要点

- 所有地址均为 `libtersafe.so`（MD5 `e06344e0b5f6b09d13820c625fa3a123`）的镜像内偏移（imagebase 0）。
- 报告中的"证据"一栏给出地址、字符串表偏移或关键指令，可直接在 IDA 中跳转核对。
- `tools/` 下的脚本按分析顺序命名，部分依赖 `capstone`/`pyelftools`，运行前需修改脚本内的本地路径常量。

## 说明

本项目为安全研究与教学目的，仅针对公开分发的 Android 客户端与其自带反作弊组件做静态与动态分析，
不包含可商用的绕过工具，也不针对具体账号或线上服务。
