# libtersafe.so（ACE 12.1.1.1）Hook / 注入框架检测机制

**总览**：ACE 把 Hook 检测拆成 `frida_scan`、`module2`、`elf_hook_scan`、`various_opcode` 四个注册模块（注册表 0x27FAE4），另有一套 0x257xxx–0x25Exxx 的"名单 + /proc/self/maps 子串匹配"扫描器。判据共五类：文件路径存在性（stat/access）、回环端口探活（27042/27043）、maps 行与模块名黑名单、函数序言/符号指针可读性与魔数（0x58000050）、线程 comm 名。命中统一走 `sub_1F2640(706, 标签)` 与 `sub_1F0148(串)` 两条事件通道，并由 `anti_ida`/`anti_frida` 等云控开关控制是否上送。全部子检测受 `attunlock3` 总开关门控。

## 一、frida_scan 模块（0x2A9040）：一条总控 + 六条判据

模块名串为 `"frida_scan"`（off 30863），在 0x280030/0x280038 处注册，虚表 0x5151C0，运行槽 `[+8]=0x2A9040`。

门控在 0x2A9040 开头：`sub_22DA98(cfg, "attunlock3"(off 48416), 1, 1)`，配合 `*(u8*)(cfg+80)` 模块使能位与 `*(u8*)(ctx+926)`，三者任一为真才继续；否则直接返回。命中后的统一出口是

```
if (*(u8*)(a1+89) || (命中串 && *(u8*)(a1+88)))
    sub_46CD24(chan, 命中串, ctx, 1);   // 走反作弊上报通道
```

六条判据与上报标签：

| 子函数 | 检测对象 | 命中动作 |
|---|---|---|
| 0x2A6AE0 | frida-server 文件路径 | `*(a1+89)=1` + `sub_1F2640(706,"frida_server")` |
| 0x2A80C0 | maps 中 frida 相关模块名 | `*(a1+88)=1` + `sub_1F2640(706,"frida_scan")` |
| 0x2A6FEC | 27042/27043 端口 | `sub_1F2640(706,"frida_scan")` |
| 0x2A880C | libart.so 中 ArtMethod 序言 | 上报 `"fri_art"`(off 27808) |
| 0x2A8B64 | /proc/self/task 线程名 | 上报 `"fri_thr"`(off 27866) |
| 0x2A8C6C | memfd JIT 映射 | 上报内联解密串 `"fri_me"`（6 字节） |

### 1.1 文件路径（0x2A6AE0）

先取 `"/data/local/tmp/12re.34frida.56server78"`（off 27374，夹入垃圾数字的反扫描变体），若存在则**直接返回 0**——这是故意设置的短路诱饵。随后把三条路径压栈成指针数组：

- `"/data/local/tmp/re.frida.server"`（off 27431）
- `"/system/bin/frida-server"`（off 27465）
- `"/data/local/tmp/frida-server"`（off 27492）

循环 `LDR X19,[X21,X20,LSL#3]` 逐条调用

```
sub_4CF408(path) = path && *path && (stat(path,0)==0 || access(path,0)==0)
```

命中即 `BL sub_1F0148`（事件码 0x100002342）上报该路径。注意 `sub_1F0148` 是**事件派发**而非常见的 unlink 删除，不产生主动反制。

### 1.2 端口探活（0x2A6FEC）

`sub_2A6E30` 取 `"27042"`（off 27290）、`"27043"`（off 27298）建端口链表，循环 `LDR W19,[X20,#0x10]` 取端口，`MOV W0,#0x68D8` → `sub_4E9188` 取 `"127.0.0.1"`（off 26840），调 `loc_2A6BAC(ip,port)` 做 connect；`loc_2A6BAC` 内部引用 `"REJECTED"`（off 27243），即以 Frida 协议握手响应字判定对端身份。另配合 `sub_4D18B8(port)`：枚举 `/proc/net/tcp`、`/proc/net/tcp6`（`sub_4D1298`/`sub_4D1548`），比较端口与状态字段（1=ESTABLISHED、10=LISTEN）。

### 1.3 maps 模块名（0x2A80C0）

`sub_4DD250(0)`/`sub_4DD3F0` 逐行取 `/proc/self/maps`。指向同一套名单构造器的字符串有：`libfrida-gadget.so`(27313)、`frida-agent-32.so`(27334)、`frida-agent-64.so`(27354)、`frida_agent_main`(27254)、`FRIDA_AGENT_1.0`(27696)、`frida-agent`(27714)。

判据顺序：

1. `sub_4A2228(line, "/data/local/tmp/")` → 前缀命中直报；
2. 名单逐项 `sub_4A47AC(line,name)`（strstr）命中则跳过；
3. `strstr(line,"frida")`（off 27282）或与自身可执行路径比较 → 命中。

命中行先用 `sub_489248` 算哈希去重（哈希表 `sub_1DB4B4`），再进 `loc_2A7470`/`0x2A7B5C` 二次判定，循环上限 100000 行。

### 1.4 libart 内联 Hook（0x2A880C）

`dlopen("libart.so")(off 27818)` + `dlsym("_ZN3art9ArtMethod12PrettyMethodEb")(off 27830)` 取函数地址，随后

```
sub_4DC8F8(addr, 20) && *(_DWORD*)addr == 0x58000050
```

`0x58000050` 即 ARM64 `LDR X16,#8`，是 Frida/Substrate 改写函数序言时最典型的第一条跳板指令。命中即 `fri_art`。前置门控为 `sub_2A83FC()` 与 `sub_4DC8F8(addr,20)`（后者按页可读性校验，防探测到非法地址）。

### 1.5 线程名（0x2A8B64 / 0x2A88B0）

云控开关 `sub_4EAEB0(27866)` 即 `"fri_thr"`；`opendir("/proc/self/task")`（off 27876）→ `readdir`（`sub_4B8A54`）→ 过滤 `d_type & 4`（DT_DIR，偏移 +18）、跳过 `.` 开头 → `sub_4A54DC(buf,128,"/proc/self/task/%s/comm"(off 27894), name)` → `loc_2A88B0` 读 comm 内容并比对四个特征名：`gum-js-loop`(27920)、`gmain`(27934)、`gdbus`(27942)、`pool-frida`(27950)。任一命中返回 1。

### 1.6 memfd JIT（0x2A8C6C）

内联 XOR 解密：`LDRB W14,[X10,#byte_D961F-0xD9618]` 与局部种子逐字节异或、`CMP X13,#6` 循环 6 次得 `"fri_me"`；另一处取 `"/memfd:jit-cache (deleted)"`（off 20276，站点 0x2A8E4C）。Frida 的 QuickJS JIT 缓存正是匿名 memfd，该串即其映射名（判据为 maps 行匹配，**推测**）。

## 二、Xposed / Substrate / LSPosed

**扫描器本体 0x25C090**：`sub_25C52C` 建黑名单 list → `sub_4DCC88` 打开 maps → `sub_4DCD28` 逐行 → `sub_4A47AC(line, 名单项)` → `sub_4DCCEC` 关闭。名单元素：

- app_process32_xposed(21) / app_process64_xposed(21) / libxposed_art.so(17) / XposedBridge.jar(17)（构造器 0x25C52C）
- `de.robv.android.xposed.installer`（0x25C7A4）
- `anti_xposed` / `gp3_xposed` / `gp3_edxposed`（0x25BE74）
- `EdHooker_` / `SandHookerNew_`（0x25C9D0，EdXposed 线程名）
- `taichi_magisk` / `libepic.so` / `libepic64.so`（0x25CE2C）

**通用 Hook 框架库名（0x259840）**：`libxhook.so`、`libsandhook.so`、`libsandhook-native.so`、`libhookzz.so`、`libwhale.so`；另有 `libsandhook.edxp.so`（0x25C438）。

**Substrate**：模块名/库名 `libsubstrate.so`(16)、`libsubstrate-dvm.so`(20)（0x25E210），标记串 `anti_substrate`（0x25D740）；C API 符号名表 `MSHookFunction`、`MSJavaHookClassLoad`、`MSJavaHookBridge`、`MSJavaHookMethod`、`MSCloseFunction`（0x25DAF4）——用于按符号名探测 hook 框架是否已注入。

**关键词表 0x231998**：以 24 字节节点（串 + 标志位）构造可疑名单，含 `"hook"`(19873)、`"libsubstrate"`(19934)、`"libhelpertool"`、`"libhhmspy"`、`"libooenv"`、`"libooSpeeder"`、`"libxxAndroidLoader"`、`"libxxdvm"`、`"libxxghost"`、`"dalvik"`，以及 `"/dev/"`、`"/system/"` 路径白名单项（标志位为 1 的节点单独处理）。

**周期上报 0x2DE854**：`sub_23A114(ctx)` 全局命中标志为真时，读 `"anti_ida"`(29288)、`"anti_frida"`(29299) 开关，分别调 0x25A1A8 / 0x257C20 发 `"ida:%d"`、`"frida:%d"`。名称表另有 `anti_blackmodule`(29269)、`anti_substrate`(29312)、`anti_xposed`(29329)、`anti_taichi`(29358)、`anti_profiler`(31079)，站点 0x259374–0x259464。

## 三、IDA / 调试器文件痕迹

**0x25B824**：先内联解密 23 字节路径（`unk_95D46`，密钥为 0xF2 起始的递增字节，明文 `/data/local/tmp/` + 干扰串），若存在则**短路返回 0**（诱饵）。否则：

```
v7[0] = "/data/local/tmp/android_server"   (27164)
v7[1] = "/data/local/tmp/android_server64" (27197)
```

逐条 `sub_4CF408` 判存在，命中且全局 `byte_55F2E0` 未置位时 `byte_55F2E0 = 1` 并 `sub_1F0148(path,0,0)`——**单次上报**，避免重复触发。这是 IDA 系 `android_server` 的落盘痕迹判据。

调试器语义判据（`android:debuggable`、`android/os/Debug`+`isDebuggerConnected`、`TracerPid`、`ptrace_stop`）与 0x25A210 的逐行解析细节见 [partC2_antidbg.md](partC2_antidbg.md)，本节不重复。

## 四、ELF / inline hook 扫描

### 4.1 module2（0x2AEEFC → 0x2AEF80）：maps 逐行完整性核对

注册名 `"module2"`（off 16503，0x2800E0/0x2800E8），构造器 0x2AEEA8，虚表 0x5153A8，入口 0x2AEEFC 分配 0x820 字节栈缓冲后进 0x2AEF80。

主循环 `getpid()` → `sub_4D4440(buf,255,pid)` 取自身上下文 → `sub_4DCC88()` 打开 maps → `sub_4DCD28` 逐行（上限 100000）→ `sub_4DCCEC` 关闭。逐行过滤与判定：

```
strstr(line, "[") == NULL && strstr(line, "/") != NULL    // 跳过 [stack] 等匿名段
sub_2AFD4C(ctx, line)                                      // zygisk / memfd 行判定
sub_2AFEB4(..., line, whitelist)  == 0                     // 白名单子串表，命中即跳过
sub_4B841C(line, &stat)  // stat(line)
*(u32*)(stat+24) != v37 && != v38                          // 该文件属主与基准不符
```

其中 `+24` 结合开关名 `filter_by_uid`(52170) 判断为 `st_uid`（**推测**，v37/v38 来自 `sub_2AF978`/`sub_2AF9F4` 取的本进程/系统 uid）；开关关时直接跳到上报分支。

命中后进

```
sub_2B012C(ctx, line, hashset, v45, v43, v41)
```

### 4.2 上报体 0x2B012C

`sub_2B1BBC(&unk_92482,29,v45)` 解出格式串 `"!%s, size:%d, crc:%08x, t:%s"`（站点 0x2B0174），`sub_2B1BBC(&unk_99095,9,v46)` 解出第二段。对模块名求 `sub_489248(name,len)` 哈希并 `sub_1DB4B4` 插入去重集；`sub_4B841C(name,...)` 取 `struct stat`，`timer = *((_QWORD*)&v50+1)` 取出时间值；`sub_2B130C(a1,name,&v40,a6)` 取基线 CRC/大小；`sub_4A1EC8(buf,64,&timer)` 格式化时间；最后 `sub_4A54DC(v37,64,v46,...)` 组串并 `loc_1ED10C(name, st_size, crc, ...)` 投递。即把「模块名 + 文件大小 + 计算 CRC + 时间戳」整体上送，由云端比对——**设备侧不做最终裁决**。

### 4.3 zygisk / memfd 行判定 0x2AFD4C

`+1048/+1040/+1044` 三个 DWORD 非 0 且 `+1032`（长度）> 0x1000 才继续；取 `"zygisk_module"`(20238) 过云控开关，`sub_4DCEEC(ptr,1)` 校验该内存可读，再取 `"zygisk_module_entry"`(20254) 得期望名，在 `[0, len-expect)` 内 `sub_4A4690` 逐字节滑窗比较（上限 0x3FFE），命中则以 `"zgkm.dat"`(20305) 模板组串 + `sub_23A198(ctx)` 置标志。同族字符串：`"zygisk"`(20229)、`"zygisk_anonymous"`(55447)、`/system/zygisk_magic`、`libzygisk_loader.so`、`libzygisk_injector.so`（0x2BCAE8 处，lib 与 lib64 各一对）、`"/data/data/com.topjohnwu.magisk"`（0x2BB764）。

### 4.4 函数序言 / 期望 opcode 抽样（0x2A9674）

`v12 = random() % 0x14`，从 20 个采样槽中选一，`sub_1B6CE4` 填 0x140 字节**期望 opcode 表**，取 `s[v12+12] ^ 0xACC9725E` 为期望值，与 `sub_2A9C18` 实测值比较；不等则组 `"%08x%08x%08x"` 记入 `sub_23A1AC(ctx,"various_opcode"(40127),...)`，并经 `sub_1EF680` 走 `OpcodePatched`/`ExpectOpcode`/`RealOpcode` 上报（串集中 0x214C64）。若满足 `v17!=v20 && 非0 && !sub_2DB8AC && (sub_23A114||sub_2DB888)`，再读 `"crash_various_opcode"`(40144) 开关，开则 `sub_46CD24(chan,"opcode_scan"(30819),tag,"opcode_crash"(29629),1)`。

### 4.5 PLT/GOT：自解析而非校验

0x2D9DB0 / 0x2DA1E0 引用 `".dynsym"`+`".rel.plt"` / `".rela.plt"`（站点 0x2D9DF4/0x2D9E08、0x2DA224/0x2DA238），二者由 0x2D998C 调用。0x2D9DB0 按符号名遍历重定位项：

```
if (strcmp(dynsym_name(idx), target) == 0) {
    old = *(QWORD*)(got + base);
    *(QWORD*)(got + base) = new_addr;   // 直接改写 GOT 槽
}
```

即「符号名 → GOT 槽 → 改写为目标地址」的**私有导入解析器**，用于绕过 PLT Hook 直接取得真实函数。配合 0x28EAF4 的私有函数指针表：以 `strcmp` 链比对 `"open"`(8201)/`"read"`(8208)/`"write"`(8215)… 后 `LDR X0,[open_ptr]`（`0x51C4C0`、`0x51C4C8`），全程不经过自身 PLT。

### 4.6 云控表达式规则名（0x4E3CAC）

0x4E3CAC 是规则名注册/解析表，把规则串映射为规则 opcode（站点 0x4E3D84–0x4E481C 逐个解密），共 86 项。与 Hook/注入直接相关的：

- `module_exists`(6864)：按模块名判定是否已加载；同族 `process_exists`(6825)、`root_process_exists`(6842)、`sock_exists`(8029)、`ts_exists`(6970)、`gc_exists`(6982)
- `file_crc_eq2`(6994)/`file_crc_not_eq2`(7009)、`inner_apk_file_crc_eq2`(7061)/`not_eq2`(7086)、`apk_crc_eq`(7197)：对任意文件（含 so/APK 内文件）下发比对 CRC
- `is_mem_readable`(7386)：内存可读性，`hidden_malware_exists`(7594)/`is_hidden_malware_exists`(7618)/`malware_exists`(7878)：隐藏模块存在性
- `del_file_if`(6743)、`dl_file_if`(6812)、`report_qos_if`(6757)/`report_str_qos_if`(6773)：命中后的删除/下载/上报动作

这些名字不是本地扫描器的名字，而是**云端表达式可直接调用的算子**，扫描结果（如 maps 行、CRC）与云端规则在此汇合；`module_exists` 的取模块列表路径与 4.1 的 maps 枚举一致（枚举实现见 `dl_iterate_phdr` 包装 0x50AE48←0x50A380，函数指针表 0x51BED8）。具体算子实现体**推测**落在 0x4E3CAC 之后的分发表中。

### 4.7 elf_hook_scan（0x28EA9C）

注册名 `"elf_hook_scan"`（off 31651，0x280148/0x280150），构造器仅写虚表 `*(a1)=&off_514EC8` 与 `+72=0`；虚表 0x514EC8 = `[0x1DB0B4, 0x28F5C0, 0x28EAF0, 0x28EAE8]`，其中 0x28EAF0 是单条 `RET` 的空桩、0x28EAE8 为 `STR WZR,[X0,#0x48];RET` 的置位器。**推测**：该模块在当前版本仅保留注册占位，真正的 ELF/inline 判定由 `module2`(4.1) 与 `various_opcode`(4.4) 承担。

## 五、上报通道与处置

两条事件通道形状一致（都是 0x6A0/0x670 字节消息 + 最多 64 字节字符串）：

- `sub_1F2640(code, tag)`：`MOV W8,#0x41` 置 cmd，`sub_4A4A20(msg+0x20C, tag, 0x40)`，`sub_1F4878` 派发。Frida 系命中固定用 code=706。
- `sub_1F0148(str,0,0)`：`v21[0]=0x100002342` 事件码，同样 `sub_4A4A20(...,64)`。

命中标志位：frida 走 `*(u8*)(ctx+89)`（frida_server）与 `*(u8*)(ctx+88)`（maps/端口）；通用扫描走 `sub_23A114(ctx)`（读）与 `sub_23A198(ctx)`（置位）；`module2` 用 `*(u8*)(a1+73)=1` 做**一次性执行锁**。设备侧不做 kill，处置是"打标 + 下次上报携带"。

## 六、云控开关

| 开关名 | offset | 作用点 |
|---|---|---|
| `attunlock3` | 48416 | 0x2A9040 frida_scan 总开关 |
| `fri_art` | 27808 | 0x2A880C ArtMethod 序言检查 |
| `fri_thr` | 27866 | 0x2A8B64 线程名遍历 |
| `chk_elf_header2` | 329 | 0x2AEF80 模块 size/CRC 核对 |
| `filter_by_uid` | 52170 | 0x2AEF80 按 uid 过滤 maps 行 |
| `zygisk_module` | 20238 | 0x2AFD4C zygisk 判定 |
| `anti_ida` | 29288 | 0x2DE854 是否上报 `ida:%d` |
| `anti_frida` | 29299 | 0x2DE854 是否上报 `frida:%d` |
| `crash_various_opcode` | 40144 | 0x2A9674 是否上送 opcode_crash |
| `force_antiprofiler` | — | 0x25EC24；对外命令 `CloseAntiProfiler`(46360) 见 0x1BCF84 命令表 |

模块级开关另有 0x27019C 的 `ScanOpcode`(51983)、`ScanCert`(52054) 等（注册点 0x2701D4–0x270284）。

## 七、特征清单表

| 框架/特征 | 特征串（off） | 来源地址 | 检测手段 |
|---|---|---|---|
| frida-server | `/data/local/tmp/frida-server`(27492) 等 4 条 | 0x2A6AE0 | stat/access 存在性 + 事件上报 |
| Frida 端口 | `27042`(27290)/`27043`(27298)、`127.0.0.1`(26840)、`REJECTED`(27243) | 0x2A6FEC / 0x2A6BAC | connect 握手 + /proc/net/tcp |
| Frida gadget/agent | `libfrida-gadget.so`(27313)、`frida-agent-32.so`(27334)、`frida-agent-64.so`(27354)、`frida_agent_main`(27254)、`FRIDA_AGENT_1.0`(27696) | 0x2A7380/0x2A7864/0x2A80C0 | maps 行 strstr |
| Frida 线程 | `gum-js-loop`(27920)、`gmain`(27934)、`gdbus`(27942)、`pool-frida`(27950) | 0x2A88B0←0x2A8B64 | /proc/self/task/*/comm |
| Frida JIT | `/memfd:jit-cache (deleted)`(20276)、`fri_me` | 0x2A8C6C | maps 匿名 memfd |
| Frida/Substrate 序言 | `0x58000050`（`LDR X16,#8`） | 0x2A880C | dlsym ArtMethod + 首指令魔数 |
| Xposed/EdXposed | `app_process64_xposed`(21)、`libxposed_art.so`(17)、`XposedBridge.jar`(17)、`EdHooker_`、`de.robv.android.xposed.installer` | 0x25C090/0x25C52C/0x25C7A4/0x25C9D0 | maps 行 strstr |
| Substrate | `libsubstrate.so`(16)、`libsubstrate-dvm.so`(20)、`MSHookFunction` 等 5 个 C API | 0x25D740/0x25E210/0x25DAF4 | maps + 符号名 |
| Hook 框架库 | `libxhook.so`、`libsandhook.so`、`libhookzz.so`、`libwhale.so`、`"hook"`(19873) | 0x259840 / 0x231998 | 名单 strstr |
| LSPosed/太极 | `taichi_magisk`、`libepic.so`、`libepic64.so` | 0x25CE2C | maps 行 strstr |
| IDA 调试服务 | `/data/local/tmp/android_server`(27164)、`android_server64`(27197) | 0x25B824 | stat + 单次事件上报 |
| Zygisk | `zygisk_module`(20238)、`zygisk_module_entry`(20254)、`zgkm.dat`(20305) | 0x2AFD4C | 内存滑窗 memcmp |
| magisk | `/data/data/com.topjohnwu.magisk`(29135/35242) | 0x2BB764 | 路径探测 |
| ELF 模块完整性 | `!%s, size:%d, crc:%08x, t:%s` | 0x2B012C | stat size + CRC 上报 |
| PLT/GOT | `.dynsym`/`.rel.plt`/`.rela.plt` | 0x2D9DB0/0x2DA1E0 | 符号名→GOT 槽改写 |
| opcode 采样 | `various_opcode`(40127)、`opcode_scan`(30819)、`opcode_crash`(29629) | 0x2A9674 / 0x28E364 | 期望 opcode 表异或比对 |
