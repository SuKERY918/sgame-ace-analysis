# J. 云端下发 blob 静态格式逆向（a64 / a32 / comm / mrpcs / sig）

对 `ano_tmp` 中被 `libtersafe.so` 落盘的二进制 blob 做纯静态逆向。结论均由 `tools/blob.py` 复现（J.10）；原始文件只读。

**一句话结论**：`a32/a64.dat` 是“日期魔数 + 段表”容器，每段是一个 `<模块名>.img` **原生代码模块**（非字节码、非压缩包），含导入表、代码区与尾部元数据，由 **RSA-2048+MD5** 保护（6/6 通过）；`comm.dat` 是 `tlf` 容器，承载模拟器/外设/黑产包名与路径清单。**云端能下发检测逻辑本身，而不只是开关和配置。**

## J.1 结论速览

| # | 结论 | 强度 |
|---|---|---|
| 1 | 容器 `magic 0x20220118 \| nsec \| 段 \| magic`，四文件精确闭合到 EOF−4 | 确定 |
| 2 | 段名 = 36 字节密钥 XOR；载荷 = S 盒 `pt=T[ct^0x23]`（两套变换不可混用） | 确定 |
| 3 | 段名 `acp`/`cse`/`detect_live_app`/`enum_apk_r`/`obj_uid_check`/`qxk`/`auto_clicker_proxy4`/`close_tprt_hb_debug`/`win_vm_wb` | 确定 |
| 4 | 每段 = `.img` 模块：头魔数 `0x20220623`、四类表、原生代码区、尾部元数据 | 确定 |
| 5 | 代码区是 ARM64/ARM32 原生码（导入 libc++ 符号），“字节码”假设不成立 | 强 |
| 6 | 签名 256 B = **RSA-2048**（非 1024），明文 `00‖MD5‖00×240` | 确定 |
| 7 | `ob_cs2` 主包（5 模块，最大 46 KB）vs `ob_x` 轻量包（4 模块，1/7 体积） | 强 |
| 8 | `comm.dat`：`u32 3 + "tlf\0"` + 内存态解压记录流，36-XOR 可捞 971 路径/329 包名 | 强 |

## J.2 容器格式

```
0x00  u32BE magic 0x20220118     # "20 22 01 18" → 日期 2022-01-18
0x04  u32BE nsec
      ×nsec: u32BE namelen; u8[namelen] name(36key XOR); u32BE paylen; u8[paylen] payload(S盒)
尾    u32BE magic 0x20220118
```

只有 8 字节头。常见误读：`0x08` 的 `00000007` 不是独立计数，而是段 0 的 `namelen`。

```
# ob_x_a64.dat 前 32 字节
20 22 01 18 00 00 00 04 00 00 00 07 51 52 42 1d 5d 58 51 00 00 1b 78 04 00 00 00 19 51 44 46 5c
└magic────┘ └nsec=4─┘ └name=7─┘ └─acp.img(密)─┘ └paylen=0x1b78=7032┘ └namelen=25──┘
# ob_cs2_a64.dat：20 22 01 18 00 00 00 05 00 00 00 07 53 42 57 1d 5d 58 51 00 00 1d 5c 04 …
```

| 变换 | 实现 | 公式 | 范围 |
|---|---|---|---|
| 36 字节循环 XOR | `sub_237DC4`→`sub_4E9A88(30548)` 取钥 | `pt[i]=ct[i]^K[i%36]`，`K="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"` | 段名、`.img` 导入名、`comm.dat` 串 |
| 256 字节 S 盒 | 主循环 case 24：`a1[v17++]=v7[v37^v18]`，`v7=&unk_9A240`，`v18=0x23` | `pt=T[ct^0x23]`，`T=libtersafe+0x9A240` | 段 payload、`.img` 全体 |

旁证：S 盒前 8 字节 `ab e4 7f a8 46 24 58 9d` 在 `libtersafe.so` 出现 2 次（`0x9A240`、`0xD963C`）、`libtprt.so` 1 次（`0x173C36`=`byte_173C36`），即两库共用同表。`T` 为双射且 `T[0xA0]=0x00`，故最高频字节 `0x83`（34–42%）解密即 `0x00`，其 mod 2/4/8/16 均匀分布只是加密残留、非对齐特征。

### J.2.1 关于「magic 0x18012220 / 0x1d574253 / +16、+20」的更正

- 头 4 字节 `20 22 01 18`：**小端**读 0x18012220、**大端**读 0x20220118。`sub_4A0198` 为大端读取且比较常量 539099416=0x20220118，故以 BE 为准；两种写法指同一字节序列。
- `0x1d574253`（字节 `53 42 57 1d`）**不是版本字段**，而是段 0 名字的前 4 字节：`cse.img` 经 36-XOR 得 `53 42 57 1d 5d 58 51`；ob_x 同位置 `51 52 42 1d 5d 58 51`（`acp.img`）。
- 故 0x0C 起无独立版本号，「4/5」其实是 **0x04 的 nsec 段数**（ob_x=4、ob_cs2=5）；「+16/+20」落在段 0 名字尾部与 `paylen` 上，`0x13` 才是 paylen（7032/7516），0x17 起为 payload。
- `0x83` **不是 4 字节对齐填充、也不是 VM 指令槽/立即数编码**：它是 S 盒对 0x00 的像（`T[0xA0]=0x00`），mod 2/3/4/8/16 上分布均匀，按任意字宽切槽都不会出现「每槽高字节恒定」。

## J.3 段表实测

| 文件 | 大小 | nsec | 段名 / 偏移 / 长度 |
|---|---|---|---|
| `ob_x_a64.dat` | 16970 | 4 | `acp.img` 0x17/7032；`auto_clicker_proxy4.img` 0x1BAE/2520；`close_tprt_hb_debug.img` 0x25A5/1872；`win_vm_wb.img` 0x2D0A/5436 |
| `ob_x_a32.dat` | 18259 | 4 | 同名，0x17 起，7304/2807/2067/5971 |
| `ob_cs2_a64.dat` | 117291 | 5 | `cse.img` 0x17/7516；`detect_live_app.img` 0x1D8E/31445；`enum_apk_r.img` 0x9879/1619；`obj_uid_check.img` 0x9EE5/46591；`qxk.img` 0x154F3/30004 |
| `ob_cs2_a32.dat` | 118582 | 5 | 同名，0x17 起，7659/31570/1648/47607/29982 |

尾魔数 0x4246 / 0x474F / 0x1CA27 / 0x1CF32 均等于 `filesize−4`。段名语义（推测）：`detect_live_app`＝直播 App 检测、`enum_apk_r`＝APK 枚举、`obj_uid_check`＝UID 校验、`auto_clicker_proxy4`＝自动点击器/代理、`close_tprt_hb_debug`＝关调试通道——**段名即云端下发的模块名**。

## J.4 `.img` 载荷格式

`libtprt.so` 的 `sub_1528B0(obj,payload,secname,name,out)` 是解析器（要求名含 `.img`）；偏移为段内、解密后，小端：

| 偏移 | 内容 | 实测 |
|---|---|---|
| +0x00 | 魔数 `0x20220623`（字节 `23 06 22 20` → 2022-06-23） | 全部命中，否则返回 −1 |
| +0x04/+0x08/+0x0C | 恒 `0`/`1`/`100` | 4/4 文件一致（推测版本/类型） |
| +0x10 | 0 | 实测全 0 |
| +0x14 | `countA` → `countA×(u32,u32)` 打包 u64 入 vector | 2–181 |
| +0x18 | `countB` → `countB×(u32 id, u32 len+name)`，`sub_151FF8` 查处理器，命中才入表 | 19–336 |
| +0x1C/+0x20 | `countC`/`countD` 表（`countC×([u32 len+name],u32,u32)`、`countD×(u32,u32)`） | **全 0** |
| 表后 | `u32 code_len` + `code[]` | 804–26456 |
| 之后 | `0`、`0x20220623`（复验）、`0x20220426`、`0xC1`、`0x94`、u32、`u16[]` | `0xC1/0x94` 恒定 |

```
cse.img 解密后头部：23 06 22 20 | 00 00 00 00 01 00 00 00 | 64 00 00 00 00 00 00 00 12 00 00 00 5a 00 00 00 00 00 00 00
                  └0x20220623┘ └──0─┘ └──1─┘ └─100┘          └0┘ └cA=18┘ └cB=90┘ └cC=0┘
```

`countA`（18 项）：`(16,320)(184,744)(212,896)(220,1160)(292,3736)…(3580,896)`，两侧都在代码区（3940 B）内，推测 `(块起始, 结束/属性)`；`countB` 的 id 单调递增（32,36,56,84,…,3560）且在代码区内，即**代码内偏移 → 外部符号**的导入/重定位表。`.img` 导入名除 `__ff_N` 外全是标准符号，**无检测语义串**（语义在代码里）；`cse.img` 尾部明文残留 `5a 50 51 58 4c 4c 4c 5f 59 57` 经 36-XOR 为 `jackxyz`+`ohe`（推测开发者标记），段内另有日期魔数 `0x20221027`/`0x20230609`（小端），说明按日期流水线产出、可灰度。

导入符号（`ob_cs2_a64.dat` 去重 84 项）：`__ff_12`×155、`__ff_64`×132、`__ff_121`×127、`__ff_30`×64、`memset`×33、`_ZdaPv`×9、`_Znam`×7、`_Znwm`×5、`_ZdlPv`×3，余为 `__ff_N`（N∈0–294）。C++ mangled 分配器符号是决定性证据：这是 C++ 编译的**原生模块**，与“虚拟机字节码”互斥。

## J.5 代码区统计与“字节码”假设检验

| 模块 | 代码字节 | 32 位字 | capstone 顺序成功 | top-byte 前三 |
|---|---|---|---|---|
| `cse.img` | 3940 | 985 | 0 | `F9`×41, `00`×29, `99`×20 |
| `detect_live_app.img` | 18172 | 4543 | 0 | `00`×1191, `AA`×148, `FF`×80 |
| `enum_apk_r.img` | 804 | 201 | 1 | `00`×12, `B1`×5, `95`×5 |
| `obj_uid_check.img` | 26456 | 6614 | 1 | `00`×1250, `AA`×161, `FF`×107 |
| `qxk.img` | 17580 | 4395 | 2 | `00`×1265, `AA`×83, `91`×57 |

```
# cse.img 代码区前 8 字
99be4ffc 99417bfd db0043fd e71d83ff 8c123456 51000080 14000044 528003e0
```

1. **非定长字节码**：首字节直方图无平台期、无操作码聚集，mod 2/3/4/8/16 均匀。
2. **是 ARM64 原生码但逐字混淆**：`0x99be4ffc ^ 0x30000000 = 0xa9be4ffc` 即序言 `stp x28,x19,[sp,#-0x20]!`；`0x99417bfd` 与 `stp x29,x30,[sp,#-0x20]!`（`0xa9bf7bfd`）仅 top 16 位不同——top 字节级扰动。
3. 混有**完全合法**指令：`0x14000044`=`b`、`0x528003e0`=`mov w0,#0x1f`、`0x9400002d`=`bl`、`0xd503201f`=`nop`、`0xd65f03c0`=`ret`（各模块 2–6 处）。
4. 每模块第 5 字恒为 `??123456`（`8c123456`/`d4123456`/`74123456`/`38123456`），紧接 `??000080`——推测入口桩/待重定位占位符，按 `countB` 回填。

代码区之后的尾部（cse @0x1563）：`00000000 | 23062220 | 26042220 | C1 | 94 | B2070000 | u16 表`，`0xC1`/`0x94` 五模块相同（推测版本/特性位），第三个 u32 随模块变（1970/9086/402/13228/8790）。**结论**：`.img` 不承载解释器字节码，而是按架构下发的原生代码模块（a32/a64 同名段字节相同率仅 10.9%–37.9%，即“同源码两份编译产物”）；`libtprt` 的 `.tptext`、`g_tprt_pfn_array`、`__ENABLE_OBJ_VM__`、`sub_15321C(obj,0x10000)+0xFFC0`（64 KB 空间）承担**装载/符号绑定/调用转发**，非指令解释。

## J.6 `comm.dat` 与 `mrpcs*.data`

### J.6.1 `comm.dat`（69731 B）

头 `00 00 00 03 74 6c 66 00` = u32BE 3（版本）+ 魔数 `tlf\0`。`sub_23088C`（配置 id 713）先经 `sub_22E350(&reader,7,blob,1)` 做**内存态解压**（内部 `sub_4A00E4`+`sub_4A00F0` 整体替换 reader 缓冲区），再读 `u32BE` 条目数（≤255），循环 `sub_4A0360` 读 `[len][36-XOR 串]` + `u32 id` 交 `sub_230B54` 追加 96 字节节点。

磁盘形态经压缩/编码，记录流只在内存存在：zlib(`15/-15/31`)、lzma、bz2 在 0–39 偏移全失败，熵 6.538。36 相位全扫得 971 路径、329 包名、40 个 `*.so`。

| 类别 | 样本 |
|---|---|
| 模拟器 | `/system/lib/arm/libhoudini.so`、`/system/vendor/etc/lib64/libhoudini.so`、`/system/lib64/libhyzm.so`、`/system/etc/mumu-configs/shared_libs/libhp9_x86_64.so`、`com.mumu.launcher`、`/system/lib/libc_malloc_debug_qemu.so`、`/D/+7izWXYN/fstab.cancro_x86_64`；`audio.primary.tenc.so`、`camera.msm8998.jpeg.so` |
| 虚拟触控/手柄 | `com.xiaoji.virtualtouchutil`、`com.chaozhuo.gameassistant/lib/libmocute.so`、`com.handjoy.goplay/lib/liblogx.so`、`com.game.motionelf/lib/libjnihelper.so`、`com.qx.joymap/lib/libbridge.so` |
| 越狱/注入框架 | `com.saurik.substrate`、`com.topjohnwu.magisk`、`com.bocharov.xposed.fsbi`、`com.sollyu.xposed.hook.model`、`bin.mt.plus`、`catch_.me_.if_.you_.can_`（Frida 测试包名）、`blbvlsd.anhu.ozlv` |

对应 `main.md` 的消费者 `0x230BD0`（包名表，失败回退 64 条内置）与 `0x231824`（21 条 so/框架串）。抽取注意：零字节⊕密钥会得到密钥字符，污染尾部（如 `audio.primary.tenc.so0122456`）。

### J.6.2 `mrpcs*.data`

| 文件 | 大小 | 外层 | 条目名 | 内层解压后 | 熵 |
|---|---|---|---|---|---|
| `mrpcs.data` | 31582 | ZIP/deflate | `unzipmrpcs.data` | 98114 | 5.670 |
| `mrpcs_MVM.data` | 23810 | ZIP/deflate | 同上 | 116399 | 4.864 |
| `mrpcs_com.data` | 266 | ZIP/deflate | 同上 | 168 | 2.867 |

内层头无已知魔数（`1c 96 42 0c…`/`c9 a4 e2 21…`），zlib/lzma/bz2 全失败，36-XOR 与 S 盒代入无可读头。`mrpcs` 是**第三条独立通道**（与 `tlf`、`0x20220118` 格式互不相同），静态未见检测语义，推测日志/策略缓存或二次加密（低置信）。

## J.7 签名块：RSA-2048 完整验证链

```c
if (a4 < 0x100) return false;                     // 签名必须 ≥256 B；memcpy(dest,sig,0x100) 只取前 256 B
md5(data,len) -> v13;
(rsa(&unk_547A68,dest)==1 || rsa(&unk_547860,dest)==1) && !memcmp(&v11[1],v13,16)
```

`sub_489F10` 为 64×32 位 limb 的 Montgomery 模幂：`key[0]` 必须=n/4 且 ∈{64,32}（2048/1024 位），指数固定 `0x10001`。

| 密钥结构（520 B，vaddr `0x547860`/`0x547A68` → 文件 `0x53F860`/`0x53FA68`） | |
|---|---|
| +0x000 | `nwords=64`（LE），+0x004 未知（`ade1efc9`/`61801af0`，推测 key id） |
| +0x008 | **模数 n，小端**，256 B |
| +0x108 | `2^4096 mod n`，小端（Montgomery 预计算，两把均验证相等） |

**“256 B 签名 vs RSA-1024=128 B”矛盾解除**：模长就是 256 B（2048 位），1:1 对应，不存在拼接；代码里的 32-limb 分支只是兼容 1024 位旧钥。

```python
n = int.from_bytes(so[0x53FA68+8:0x53FA68+8+256],'little')
m = pow(int.from_bytes(sig,'big'),65537,n).to_bytes(256,'big'); assert m[0]==0 and m[1:17]==md5(data)
```

明文 = `00 ‖ MD5 ‖ 00×240`，验签比较 `m[1:17]`。**非 PKCS#1 v1.5**：填充只在 `s^e mod n` 之后出现且本方案用零填充，故 `.sig` 中看不到 `00 01 FF` 属正常。

| 文件 | 大小 | MD5 | K1 | K2 |
|---|---|---|---|---|
| `ob_x_a64.dat` | 16970 | `08bc64d9ef58f2d3fc95d48e4e4a977b` | ✗ | ✓ |
| `ob_x_a32.dat` | 18259 | `d7e6eaddf3dd21d09c389b6336bf1026` | ✗ | ✓ |
| `ob_cs2_a64.dat` | 117291 | `8ae2c3d28e623a1a78784bbba40b4666` | ✗ | ✓ |
| `ob_cs2_a32.dat` | 118582 | `915e28f7f7e1d736c2083be7273092a7` | ✗ | ✓ |
| `comm_comm.dat`（`sig4`=`sig5`） | 69731 | `1ac0ae51442faaa49e12eae0191940f0` | ✗ | ✓ |

`comm_sig4` 与 `comm_sig5` **逐字节相同**：两槽位复用同一签名，而非两钥各签一份。K1 未命中任何样本，推测用于 `.so`/其它配置或作轮换备用钥。

## J.8 `ob_x` 与 `ob_cs2` 差异

| 维度 | `ob_x.zip`(18408) | `ob_cs2.zip`(96183) |
|---|---|---|
| a64/a32 大小 | 16970 / 18259 | 117291 / 118582 |
| 段数 | 4 | 5 |
| 模块 | `acp`、`auto_clicker_proxy4`、`close_tprt_hb_debug`、`win_vm_wb` | `cse`、`detect_live_app`、`enum_apk_r`、`obj_uid_check`、`qxk` |


两者**模块集合完全不同**（非同一模块新旧版），可独立下发、独立验签；`ob_cs2` 为主包，`ob_x` 为轻量专项包（约 1/7 体积）。a32/a64 成对下发，由 `0x1D7064→0x1D6F1C` 按位数生成 `a64.dat`/`a64_%d.dat`（最多 10 轮）后择一装载。

## J.9 结论：这些 blob 能承载什么

1. **能下发新检测逻辑，且是原生代码**：每段 = 头 + 函数/导入表 + 该架构原生代码 + 尾部元数据，a32/a64 双份。字符串/配置无法解释 `_Znwm`/`memset` 导入与合法 ARM64 指令，故**新增检测项可随包下发而无需更新 `libtersafe.so`**，与 `libtprt` 的 OBJ_VM 装载器闭环；符号由 `sub_151FF8` 绑定，未知符号模块整体拒装。
2. **只有完整性、没有机密性**：RSA-2048+MD5 只防篡改/替换，blob 不加密（容器与 `.img` 均固定变换），逻辑可静态提取——既是分析突破口也是固有弱点（可离线还原再 patch）。
3. **静态可见语义**全在 `comm.dat`（模拟器、触控/手柄、Substrate/Magisk/Xposed/MT/Frida 包名）；`.img` 内无字符串级语义。
4. **待解**：代码区逐字混淆（序言 top 字节扰动 + `??123456` 占位符）需复刻装载期还原才能得可反编译函数体；`comm.dat` 解压算法与 `mrpcs` 内层格式未定（推测私有 LZ/二次加密）。

## J.10 复现命令

```powershell
$py="D:\dev-tools\python-3.14.10\python.exe"
& $py tools\blob.py info    # 段表 + .img 头 + 表计数
& $py tools\blob.py img  dyn\unpack\ob_x_a64.dat acp
& $py tools\blob.py names dyn\unpack\ob_cs2_a64.dat
& $py tools\blob.py comm    # 路径/包名/so 清单
& $py tools\blob.py mrpcs ; & $py tools\blob.py verify   # 验签 6/6 通过
```
