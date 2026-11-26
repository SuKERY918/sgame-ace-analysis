# ACE 内联字符串表：875 条明文全量还原

libtersafe.so 有两套字符串加密。主表（索引式，3,198 条）见 [tersafe_strings.md](tersafe_strings.md)。本文处理第二套：**内联字符串**，即编译期直接内联在调用点、按地址引用、每条自带独立解密函数的密文串。

本轮把它从"只知道存在约 945 条"推进到**离线全量还原 875 条唯一明文**。

## 0. 结论摘要

- 内联串**不做索引**，而是以字面量地址被引用。总数 3,198 条的主表与它相互独立。
- 密文散布在 `.rodata` 的 `0x90EC0–0xFBCB0` 区段（主表之前的同一节内），与明文常量混排。
- 每条密文由一个**独立的小解码器**处理：函数头部把密钥作为常量写入栈槽，循环体逐字节异或并让密钥自增。
- 调用点固定形态：`adrp+add` 取密文地址 → `mov w1, #len` → `bl 解码器`。`len` 含结尾的编码字节，等于明文长度 + 1。
- 扫描结果：4,430 个 `.rodata` 字面量引用点，其中 2,888 个跟了 `bl`，最终解出 975 条、去重 875 条、全部可打印。
- 875 条中路径/库名 155 条、格式串 203 条（含 `%`）、JNI 签名 14 条、面向玩家的提示文案 8 条、其余为键名与短标识。

## 1. 编码形式

密文 `c[0..L-1]` 与明文 `p[0..L-1]`：

```
p[i] = c[i] ^ ((K + i) & 0xFF)
```

`K` 是每条密文不同的字节常量，内联在对应解码器函数体里。密文长度 `L` 由调用点的立即数给出，**包含明文结尾的 NUL**（NUL 也会被加密，故 `c[L-1] = (K + L - 1) & 0xFF`）。

例：`0x91186`，`K = 0xA8`，`len = 0xF`：

```
c0 c0 ce ce f3 c0 dd c8 d2 de ca 89 91 d1 b6   ->   hide_msgbox:%d\0
```

## 2. 解码器族

解码器都是同一模板生成的独立函数，差别只在密钥常量：

```
sub  sp, sp, #0x10
mov  w8, #0xA8          ; K
strb w8, [sp, #0xC]     ; 密钥存栈
str  wzr, [sp, #8]      ; i = 0
loop:
ldr  w8, [sp, #8]
cmp  w8, w1             ; w1 = len
b.hs end
sxtw x9, w8
add  x9, x0, x9
ldrb w9, [x9]           ; c[i]
ldrb w10, [sp, #0xC]
eor  w9, w9, w10        ; c[i] ^ K
and  w9, w9, #0xff
sxtb w10, w10
add  w10, w10, #1       ; K++
strb w10, [sp, #0xC]
sxtw x10, w8
add  x10, x2, x10
strb w9, [x10]          ; out[i] = 明文
add  w8, w8, #1
str  w8, [sp, #8]
b    loop
end:
```

签名 `void dec(const void *c, size_t len, char *out)`。`0x2D4834` 与 `0x2D4894` 是两个实例（`K` 都是 `0xA8`），说明同一密钥被多条串复用。

工具识别规则：函数前 10 条指令里出现 `mov wN, #imm` 紧跟 `strb wN, [sp, #imm]`，则 `imm` 为该解码器的 `K`。

## 3. 调用点形态

```
adrp x0, #0x91000
add  x0, x0, #0x186      ; 密文地址 0x91186
mov  x2, sp              ; 输出缓冲
mov  w1, #0xF            ; 长度（明文长度 + 1）
bl   #0x2D4834           ; 解码器
```

同一函数常常连续解出多条串（一次准备一组提示文案或一组字段名），例如 `0x25FF20` 连解 4 条，`0x284B70` 连解 5 条。

## 4. 统计

| 项 | 数量 |
|---|---|
| `.rodata` 字面量引用点（目标落在 0x90EC0–0xFBCB0） | 4,430 |
| 其后 14 条指令内出现 `bl` | 2,888 |
| `bl` 目标识别为解码器且取到长度 | 975 |
| 去重后的唯一密文地址 | 875 |
| 未跟 `bl`（数据引用/明文常量地址） | 1,542 |
| `bl` 目标不是解码器（memcpy/snprintf 等） | 1,913 |

`bl` 目标不是解码器的 1,913 条属于"引用同一 .rodata 但不是字符串解密"的情形，例如把明文常量直接传给 `snprintf`。

## 5. 分类与高价值样例

### 5.1 注入/Hook 框架（检测清单）

```
libfrida-gadget.so        frida-agent-64.so       libhookzz.so
libsandhook.so            libsandhook-native.so   libsubstrate.so
libsubstrate-dvm.so       libxhook.so             libepic.so
libepic64.so              libwhale.so             libfake-linker-21.so
libfake-linker-26.so      libfake-linker-30.so    libAndroidCydia.cy.so
/system/bin/linker64      de.robv.android.xposed.installer
```

### 5.2 Titan 系列（云游戏/虚拟设备 HAL 伪造）

```
camera.titan.jpeg.so      camera.titan.so         vulkan.titan.so
gps.titan.so              sensors.titan.so        vibrator.titan.so
fingerprint.titan.so      /egl/libEGL_titan.so    audio.primary.titan_legacy.so
/ueventd.titan.rc         /ueventd.titan.rc123
```

`titan` 前缀的一组 HAL 库名与两个 `ueventd.titan.rc`（其中一个带 `123` 后缀）是探针文件名：正常 Android 设备不会有这些库，它们只出现在特定云游戏/云手机实例里。`rc123` 这种"故意不存在的名字"用于区分"目录可读"与"文件存在"。

### 5.3 进程与内存探测

```
/proc/%d/task/%d/wchan    /proc/%d/task/%d/stat    /proc/%d/task/%d/comm
/proc/%d/task/%d/status   /proc/%u/status          /proc/%d/stat
/proc/self/environ        /proc/self/cwd           /./proc/self/cwd
/proc/self/maps           /./proc/self/maps        ./maps
 /proc/self/mounts        /proc/self/fd            /proc/self/fd/%s
```

`/./proc/self/maps` 与 `/proc/self/cwd/./...` 这类写法用于绕过基于路径字符串的 hook/过滤；`wchan` 用于判断线程是否阻塞在特定内核函数上（反调试、反注入）。

### 5.4 虚拟应用/分身

```
VMOS_ROOT_DIR   vap_axml   vap_2   !vap_2:%s, cert_md5:%s   !vap_2.5:%s
```

`vap` 前缀对应"虚拟应用包"检测，`cert_md5` 说明它比对分身内应用的签名。

### 5.5 面向玩家的提示文案（本地判定证据）

```
Your device has been rooted, which poses a security risk. Please resume the game after
returning to a non-Root environment.

You are using an unlocked device that is compromised or modified. Please restore to the
locked state or change the device to continue.

This game may be being debugged by the GPU Profiler tool. Please uninstall the tool to
continue the game.

AutoClicker found on your phone. To continue, drag the scroll bar to the number %d.

It is found that you are running in an Android emulator. Please resume the game after
returning to physical devices.

Malware found on your phone. Please uninstall it before entering the game.
```

这 6 类文案直接以英文句子形式内联在客户端，且都写着"继续游戏前先……"，说明 root、解锁设备、GPU Profiler、自动点击器、模拟器、恶意软件这六项**在客户端本地就会判定并阻断**，不只是上报。这与"客户端只采集不判定"的旧结论冲突，需要按项修正：**上报判罚仍由服务端做主，但上述六项存在本地即时拦截路径**。

自动点击器那条带 `%d`，配合 `drag the scroll bar to the number %d` 说明它要求玩家拖动滑块到指定数字——这是一种交互式人机验证，不是单纯封禁。

### 5.6 字段与协议键

```
role_id:%s;inc_id:%d       game_ver:%s sdk_ver:%s       Platform:%s;Android %s,level %d,Language:%s
AndroidID                  token                        wait_token_resp
game_status                get_report_data              ace_pre_init
hide_msgbox:%d             msgbox:%d|%s|%s|%s|%s|%s|%d|%d
```

## 6. 与主表的关系

| | 主表 | 内联串 |
|---|---|---|
| 定位方式 | 索引 `idx`（`mov w0, #idx; bl 0x4Exxxx`） | 字面量地址（`adrp+add`） |
| 记录结构 | `[key][len^key][cipher][check]`，参数化 `(E,C)` | `[cipher L]`，密钥 `K` 内联在解码器里 |
| 递推 | `k_{j+1}=(((k_j+j)&0xFF)^E)+C` | `k_{j+1}=(k_j+1)&0xFF` |
| 条数 | 3,198 | 875（唯一地址） |
| 用途 | 云控键名、命令名、路径、日志格式、模块名 | 检测项清单、提示文案、协议键、探针路径 |

两套编码都只是"字符串隐藏"，不含机密性：拿到算法与常量即可离线全解。

## 7. 遗漏与未覆盖

- 1,542 个引用点没有跟 `bl`：这些是纯数据引用（把 `.rodata` 里的明文常量直接当参数），不属于加密串。
- 1,913 个引用点的 `bl` 目标是 `snprintf`/`memcpy` 一类函数：同样是明文常量。
- 875 条里可能混入少量非字符串常量（例如以可打印字节开头的二进制表），概率低但未逐条人工核对。
- 只覆盖了 `0x90EC0–0xFBCB0`。`0xFBCB0` 之后是主表区间，个别内联串（如模拟器提示 `0xD917C`）落在主表区段内，已被本轮扫描覆盖。

## 8. 复现

```bash
python tools/inline_strings.py <libtersafe.so> 0x1B6C20 0x50DFC8 0x90EC0 0xFBCB0 out.tsv
```

输出列：`密文地址 密钥 长度 明文`。全量结果见 [inline_strings.tsv](inline_strings.tsv)。
