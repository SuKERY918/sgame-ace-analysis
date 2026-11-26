# ACE provider 框架与 Fake Token 数据链

本文补 `main.md` §4.2/§6.2/§7.5 未展开的一层：**libtersafe 内部存在一个 provider 注册表与能力查询框架，TDM/QIMEI 等外部 SDK 的数据正是经它进入 ACE 的上报字段**。所有地址为 libtersafe.so（MD5 `e06344e0b5f6b09d13820c625fa3a123`）镜像内偏移，imagebase 0。

## 1. 结论先行

1. ACE 与 TDM **不是** dlopen/DT_NEEDED 关系（该结论已由 §3.1、§3.4、partI 证实），二者通过**运行期由 Java 层注入的 GCloudCore 对象**交换数据。libtersafe 只在 `0x563710` 保存一个 32 字节的"双向注册槽"，provider 树本体在 GCloud 侧。
2. 注册槽 32 字节：`+0` vtable `0x518CF0`、`+8` vtable `0x518D50`、`+0x10`/`+0x18` 两个指针初值 0。其中 `+0x18` 由 `0x2D1738` 经 `0x4C3804`（`str x1,[x0,#0x18]`）写入，值就是 JNI 取回的 **GCloudCore**；同一函数还把 `&reg+8` 反手交给 GCloudCore 保存，形成双向引用。
3. 注册 provider 有硬性版本门槛：ACE 自身 provider 名 `TSS`（`0x97195`，版本 `7.7.50.28931`），外部 TDM provider 名 `TDM`（`0x935B9`，期望版本 `1.6.0.760`）。版本串按 `.` 分段解析为整数比较（`0x4C27E4`）。
4. fake token 的四元组 `x/q/Q/o` 是**五层开关串联**的结果，任一关闭即整体退化为空串（只剩 `bt`/`bd`）。默认姿态下大概率只有 `bt`/`bd`。
5. 四元组的键名是 ACE 侧的混淆名：`xid`(51396)、`QiMaM`(51402)、`QIMEI36`(51410)、`OsEz`(51420)。其中 **`OsEz` 就是 OAID**，这与 TDM/QIMEI 侧的标准名（OAID/QIMEI/q36）构成一层名字映射。

## 2. 分层结构

```
配置/参数层  0x22D820 provider 单例 (176B, @0x55F140, vtable 0x513F88)
             └─ 0x22DA98(provider, name, 1, 1) -> bool      ← 云控键查询
                0x22CCA7C(name, buf, len) -> string         ← 命名参数取值

桥接层      0x4C25D0 -> wrapper (16B @0x568DF0, {impl*, ready})
             └─ 0x4C2998(wrapper) = wrapper->impl
                0x4C26A8 决定 impl 是否创建（TDM 可用性）

外部 provider 层
            0x563710 registry (32B, vector<provider*>)
             ├─ "TSS" 内置 adapter（vtable 0x518CF0，版本 7.7.50.28931）
             └─ "TDM" 外部 provider（由 TDM SDK 注入，期望 ≥1.6.0.760）

消费者     0x2CC6C4 取 o 值   0x2CCD20 拼四元组
            0x2CCE84 取 boot_id   0x2CCF54 拼 bt/bd
            0x2C9208 -> 0x1F3644 事件对象
```

## 3. 各层细节

### 3.1 配置/参数层：0x22D820

`0x22D820` 是一个 176 字节单例的 getter，平坦化实现（状态表 `0x52A460`，8 项全部指向 `0x22D8xx~0x22DAxx` 自身，说明是状态机分派表而非注册表）。

```c
// 0x22D820 关键序列
ldr  x19, [x20, #0x140]      // x20 = 0x55F000, 单例指针 @0x55F140
eor  w8, w9, w8              // 两个立即数异或得索引：存在=0 / 不存在=2
csel w8, w8, wzr, eq
ldr  x8, [x21, w8, uxtw #3]  // x21 = 0x52A460
br   x8
```

创建分支 `0x22D86C` 先 `0x50E3B0(&0x55F148, 0x22D910)`（pthread_once），`0x22D8B0` 处分配：

| 偏移 | 内容 |
|---|---|
| +0x00 | vtable `0x513F88` |
| +0x08 | 0 |
| +0x10 | 0 |
| +0x18 | `malloc(0x100)` 缓冲首址 |
| +0x20 | 同上 |
| +0x28 | 缓冲末址 = `buf + 0x100` |
| +0x30..+0x60 | 0 |
| +0x70 | `uint16` 0 |
| +0x78 | `0x4CDA6C` 初始化的容器 |

`0x513F88` vtable：`0x22D980`(析构，释放 +0x78/+0x60/+0x50/+0x40/+0x30) / `0x22DA48` / `0x22FAFC` / `0x227DB8` / 0 / 0 / `0x238874` / `0x238910`。

**查询语义**（`0x22DA98`，232B，300+ 调用点）：

```c
bool get(provider, const char *name, int a3, int a4) {
    bool b = false;                       // strb wzr,[sp,#4]
    int hit = sub_22DB80(provider, name, &b);   // 0 = 命中
    if (hit == 0 && a4 != 0) return b;    // 命中且 a4 允许强制
    return sub_238000(...) & 1;           // 否则取默认
}
// 出口：and w0, w19, #1; ret  —— 返回值恒为 0/1
```

其余变体在同一张表 `0x52A4A0`：`[0]=0x22DB00`(返回 bool)、`[1]=0x22DB60`(取默认)、`[3]=0x22DB10`(调 `0x22DC14`+`0x22DC84`，`cmn w0,#1` 判 -1 未配置)、`[6]=0x22DC14`、`[7]=0x22DC78`(string 变体)。

因此 `0x22DA98(provider, "tdm_dev_info", 1, 1)` **是查开关，不是取数据**。这一点此前在多篇文档里被误读为"取 TDM 设备信息"。

### 3.2 桥接层：0x4C25D0 / 0x4C26A8 / 0x4C2998

`0x4C25D0` 是 wrapper 单例 getter：

```c
ldr x19, [x20, #0xdf0]        // x20 = 0x568000, wrapper @0x568DF0
pthread_once(0x568DF8, 0x4C264C)
obj = malloc(0x10);           // {impl*, uint8 ready}
obj->impl = 0;
obj->ready = sub_4C26A8(obj); // 返回值直接当 ready
```

`0x4C26A8` 是**TDM 可用性判定**，顺序如下：

1. `0x2DAD4C()` 取 ctx，`0x239BC8(ctx)` —— bit0 置位则失败。
2. `0x22DA98(provider, "tdm_dev_info", 1, 1)` —— 云控开关必须开。
3. `0x2D15F0()` → `0x2D1738()` —— 后者解出内联串 `gcloud_regist`（`0x978E8`，14B，密钥 0x86 递增）并查同名开关；非 0 则失败。
4. 取注册槽 `0x563710`（懒创建同 3.4），读出 `[reg+0x18]` —— 即 GCloudCore；为空直接失败。
5. `GCloudCore->vtable[+0x20]("TDM")` 按名拿 TDM provider；为空失败。
6. `子->vtable[+0x18]()` 取版本串；为空或首字节 0 失败。
7. 与常量 `"1.6.0.760"`（`0x94AA5`）比较，规则见 `0x4C27E4`。
8. 通过则 `子->vtable[+0x40]("REPORT")`（`0x91EE9`）。

`0x4C27E4` 是版本解析器：逐字符扫 `.`，用 `0x50E1A0`/`0x50ED20`/`0x50E100` 切段并 `atoi`，`w20`/`w21` 初值 -1 表示"段缺失"，段号计数器 `w25` 区分 major/minor。

`0x4C2998` 只有两条指令：`ldr x0, [x0]; ret` —— 取 `wrapper->impl`。`0x2CCA7C` 随后 `ldr x8,[impl]; ldr x8,[x8,#0x60]; blr x8` 调 provider 的字符串接口。

**impl 为空时整条链短路**：`0x2CCA7C` 在 `cmp x0,#0` 后 `csel` 直接跳到返回，`dst` 保持 memset 后的空串。

### 3.3 字符串取值：0x2CCA7C

```c
char *get_str(/*x0 未用*/, const char *name, char *dst, size_t len) {
    void *w = sub_4C25D0();          // wrapper
    void *impl = sub_4C2998(w);
    if (!impl) return dst;           // 空串
    char buf[0x100]; memset(buf, 0, 0x100);
    struct { char *p; } arg = { buf };
    impl->vtable[+0x60](impl, name, &arg, 0x100);
    sub_4A4998(dst, buf, len);       // 有界拷贝
    return dst;
}
```

注意栈上是 256 字节固定缓冲，调用方给的 `len` 只用于最后拷贝（`0x60`/`0x40`）。provider 接口按名字返回，不做类型校验——**这是整条链最薄的一环**：任何能写 `impl` 指针或伪造 vtable 的代码都能让 ACE 采信任意 x/q/Q/o 值。

### 3.4 双向注册槽：0x563710

`0x563710` 是全局槽，懒创建逻辑在至少 7 处重复出现（`0x2D1794`/`0x4C1844`/`0x4C23FC`/`0x4C24D4`/`0x4C2710`/`0x4C300C`/`0x4C30D0`，均为 `ldr`+`cbnz`+`malloc(0x20)`+`str`）。它的语义不是"provider 容器"，而是一个**双向引用槽**：`+0x18` 存 GCloudCore，`+8` 反过来交给 GCloudCore 保存。

```c
reg = malloc(0x20);
*(uint64*)(reg + 0x10) = 0;
*(uint64*)(reg + 0x18) = 0;
*(uint64*)(reg + 0x00) = 0x518CF0;   // vtable A
*(uint64*)(reg + 0x08) = 0x518D50;   // vtable B
```

两套 vtable 内容（均为桩 + 少量实现）：

| vtable A `0x518CF0` | 目标 | 语义 |
|---|---|---|
| +0x00 | `0x4C381C` | `ret` |
| +0x08 | `0x4C3820` | 跳 `0x508230`（free 包装） |
| +0x10 | `0x4C3824` | 返回 `"TSS"`（`0x97195`） |
| +0x18 | `0x4C37FC` | 跳 `0x4C36A0`，返回版本对象 |
| +0x20~+0x38 | `0x4C3830..0x4C383C` | 全 `ret` |
| +0x40 | `0x4C37C4` | — |
| +0x48 | `0x4C3804` | `str x1,[x0,#0x18]` 裸 setter |

| vtable B `0x518D50` | 目标 |
|---|---|
| +0x00 | `0x4C3840` `ret` |
| +0x08 | `0x4C3844` `sub x0,x0,#8; b 0x508230`（析构） |
| +0x10 | `0x4C384C` |
| +0x18 | `0x4C3800` 跳 `0x4C36A0` |
| +0x20 | `0x4C3858` |

`0x4C36A0` 是版本号构造：`0x4A4940("7.7.50.28931")` 建串，`0x50E4E0` 以 `"."`（`0x92C5F`）切分，重复 `0x4A491C` 追加。单例缓存 `0x568E48`。

### 3.4.1 GCloudCore 绑定：0x2D1738（关键闭环）

`0x2D1738` 是**唯一往 `reg+0x18` 写值的地方**，伪代码（IDA）：

```c
__int64 sub_2D1738(__int64 a1) {          // a1 = sub_2D15F0() 的 16B 对象
  sub_2D19C0(0x978E8, 14, &name);         // 解出 "gcloud_regist"
  provider = sub_22D820();
  if (!(sub_22DA98(provider, name, 1, 1) & 1)) return -1;
  if (*(uint8*)(a1 + 8)) return 0;        // 已注册过，幂等
  reg = qword_563710 ? : calloc_reg();    // 懒创建 32B
  gcore = sub_2D1864(a1);                 // JNI: GetNativePluginManager() -> GCloudCore
  if (!gcore) return -1;
  (*(gcore->vtable[0]))(gcore, reg + 8);  // ① 把 &reg+8 交给 GCloudCore
  reg->vtable[+0x48](reg, gcore);         // ② reg+0x18 = gcore（0x4C3804: str x1,[x0,#0x18]）
  *(uint8*)(a1 + 8) = 1;
  return 0;
}
```

`0x2D1864` 做 JNI 调用：解内联串 `GetNativePluginManager`（`0x978F7`，23B）与签名 `()J`（`0x980D9`，4B），经 `0x2D0D30` 取 JavaVM/env、`0x2CFFE8`/`0x2D0164` 取方法、`0x2CFDA8` 构造调用、`0x2CEC44` 发起 `CallObjectMethod`，失败走 `0x2CE528`/`0x2CE538` 清异常。

于是 `reg+0x18` = **Java 层 GCloud 插件管理器返回的 GCloudCore 对象**。它提供 `vtable[+0x20]` 按名查子 provider、`vtable[+0x40]` 取子接口、`vtable[+0x18]` 取版本。

`0x4C2FE0` 末尾是另一条写入路径（`&reg+8`）：

```c
x0 = reg; add x0, x0, #8;      // &reg+8
add x1, sp, #8;                // &provider
bl  0x4C3260;                  // 插入
```

`0x4C3054` 是 TSS 自注册入口（`tdm_report` 开关缓存于 `0x568E3D`/`0x568E3C`），伪代码：

```c
if (!tdm_report) return 0;
v11 = (a4 & 1) ? 1 : 3;
gcore = qword_563710[3];                       // +0x18
core  = gcore->vtable[+0x20]("GCloudCore"(49902));   // 注意：再次按名取
rep   = core->vtable[+0x40]("COREREPORT");            // 0x94EDB
h     = rep->vtable[+0x20](v11, 2004, a1);            // a1 = 外部对象
rep->vtable[+0x18](110100, "TSS",   str("TSS"));
rep->vtable[+0x18](110101, version, str(version));
rep->vtable[+0x18](110102, a2,      str(a2));
rep->vtable[+0x20](100100, a3);
rep->vtable[+0x20](40004, 5);
return h;
```

即 ACE 把自身标识（`110100`）、版本（`110101`）、通道参数（`110102`）挂进 GCloud 的 `COREREPORT` 命名空间。`dword_568E40` 是失败重试计数，超过 3 次置 `byte_568E3C = 0` 永久关闭。

### 3.4.2 GCloud 层级

`0x4C17D4`（`gcloud_connector` 初始化）显示 provider 树形状：

```
GCloudCore (reg+0x18)
 ├─ "TDM"        → 版本 ≥1.6.0.760 → "REPORT" 子接口 → wrapper->impl
 ├─ "GCloud"     → "CONNECTOR" 子接口（要求 vtable[+0x20]() 返回 ≥1）
 └─ "COREREPORT" → ACE 自注册项 110100/110101/110102/100100/40004
```

`0x4C17D4` 里 `*(a1+24) = connector`，随后 `sub_20D8B4()->vtable[+0x10](name, 100, a1+8)` 注册 100ms 超时的观察者，最后 `sub_4E5F10(ctx, 17)` 与 `sub_4E5710(ctx, "init ct")` 记日志。

### 3.4.3 ACE 注册到 GCloud 的全部条目

五个函数结构完全一致（`sub_4C2F44` → 取两个名字 → `sub_4C3054(名字1, 名字2, 参数, 0)` → `vtable[+0x28]` → 插入 `&reg+8`），区别只在名字与节流计数器：

| 注册函数 | 插件名（idx） | 事件名（idx） | 节流 |
|---|---|---|---|
| `0x4C2FB4` | `TSSInit` (33811) | `tss_sdk_init_start` (33875) | — |
| `0x4C32D8` | `TSSInit` (33811) | `tss_sdk_init_finish` (33896) | — |
| `0x4C3378` | `TSSConnectionCount` (33839) | `tss_connect_count` (33971) | — |
| `0x4C3438` | `TSSHeartBeat` (33860) | `tss_heart_beat` (33991) | `dword_568E04`/`dword_568E00`，各 ≤3 次 |
| `0x4C3510` | — | `TssSDKInit`(33682) / `TSSDKSetUserInfo`(33695) / `TssSDKOnPause`(33715) / `TssSDKOnResume`(33731) / `TssSDKGetReportData`(33748) / `TssSDKDelReportData`(33770) / `TssSDKOnRecvData`(33792) | `dword_568E0C`/`E08`/`E10`，各 ≤3 次 |

**这是 §6.3 "API 遥测"的真实实现**：不走 ACE 自己的裸 TCP，而是经 GCloud 的 `COREREPORT` 上报。也就是说同一个 APK 里有两条独立上报路径：

- **检测命中 / 取证字段** → `0x4CBEF0` 容器 → 36B XOR + Base64 → 裸 TCP 443 → `*.cschannel.anticheatexpert.com`
- **API 调用遥测 / 心跳 / 连接计数 / init 里程碑** → GCloud `COREREPORT` → 腾讯 GCloud 通道

两条路径的开关也是分开的（前者受 `report_bk`/`sc_dlp` 等，后者受 `tdm_report`/`gcloud_regist`）。



### 3.5 Fake Token 全链

```
0x2CC6C4(dst, len, a2, a3)                  取 o 值
  ├─ 0x22DA98(provider, "ft_oaid", 1, 1)    开关：是否优先用 TDM 的 OAID
  ├─ 0x2CCA7C("OsEz", buf, 0x40)            取 OsEz
  ├─ strcmp(buf, "Unknown")                 0x34159，命中则视为无效
  ├─ 非空且非 Unknown → 输出 "%s"(50177)
  └─ 否则 0x22DA98(provider,"fake_token_androidid",1,1)
          └─ 0x2496E4(0,0) 取 AndroidID → 输出 "%s"

0x2CCD20(_, dst, len, a3)                   拼四元组
  ├─ 0x22DA98(provider, "Fake_Token_TDM_info", 1, 1)   总闸
  ├─ 0x2CCA7C("xid",     b1, 0x60)   51396
  ├─ 0x2CCA7C("QiMaM",   b2, 0x40)   51402
  ├─ 0x2CCA7C("QIMEI36", b3, 0x40)   51410
  ├─ 0x2CCA7C("OsEz",    b4, 0x40)   51420
  ├─ 四个首字节全 0 → 直接返回
  └─ snprintf(dst, len, "x:%s;q:%s;Q:%s;o:%s"(50303), b1,b2,b3,b4)

0x2CCE84(dst, len)                          读 /proc/sys/kernel/random/boot_id(51301)

0x2CCF54(dst, len, a3)                      最终封装
  ├─ buf1[0x140] ← 0x2CCD20(...)            四元组串
  ├─ buf2[0x40]  ← 0x2CCE84(...)            boot_id
  ├─ 0x2DAD4C() ctx; 0x2DB440(ctx, sp, sp)  取 brand
  └─ snprintf(dst,len,"%s;bt:%s;bd:%s;"(50325), 四元组, boot_id, brand)
```

输出样例（全部生效时）：`x:<xid>;q:<QiMaM>;Q:<q36>;o:<OAID>;bt:<boot_id>;bd:<brand>;`

### 3.6 开关串联

| 开关 | 地址/idx | 作用 | 默认 |
|---|---|---|---|
| `tdm_report` | `0x91AAA` | 是否创建/插入 TDM provider（`0x4C3054`） | 关 |
| `tdm_dev_info` | `0x97551` | 是否启用 TDM 设备信息桥（`0x4C26A8`） | 关 |
| `Fake_Token_TDM_info` | idx 51374 | 是否拼装 x/q/Q/o 四元组 | 关 |
| `ft_oaid` | idx 58581 | fake token 主值是否用 OAID（OsEz） | 关 |
| `fake_token_androidid` | idx 50001 | 主值回落 AndroidID | 关 |

任一为假即断链。这也解释了 §12.4 大厅实测只看到 `id=1`/`id=9` 两类上报——四元组根本没参与构造。

## 4. 静态可证结论与边界

1. **注册表与 provider 指针是普通堆对象**，没有 mprotect/校验和/加密保护。`impl` 指针位于 `0x568DF0` 对象的首 8 字节，`wrapper->ready` 在 +8。
2. **框架不校验调用者**：`0x2CCA7C` 只判 `impl != 0`，随后无条件 `blr [vtable+0x60]`。伪造 vtable 即可让 ACE 上报任意设备标识——这是比 §8.2 第 14 条（热更新模块可替换）更细粒度的注入面。
3. **TDM 数据的存在性取决于 Java 层**：`reg+0x18` 的唯一写入者是 `0x2D1738`，它必须 JNI 调通 `GetNativePluginManager`（前置 `gcloud_regist` 开关）。静态链是完整的，但运行期要等游戏把 GCloud 插件管理器建起来——这解释了 §12.4 大厅阶段四元组恒空。
4. **provider 接口无类型/归属校验**：`vtable[+0x20]` 按名返回、调用方只判非空；`vtable[+0x60]` 直接往 256B 缓冲写。伪造 `reg+0x18` 或 `wrapper->impl` 即可接管 x/q/Q/o 全部四个字段，且不需要任何签名或校验。
5. 未解决：`0x4C23E0` 的 `vtable[+0x10](name, 100)` 带 100ms 超时，语义疑为观察者注册；`0x4C2FB4`/`0x4C32D8`/`0x4C3378`/`0x4C3438`/`0x4C3510` 这组同样读写注册槽的函数对应 monitor/统计类接口（`0x4C3510` 是 §6.3 的 API 遥测），尚未逐个还原。

## 5. 复现命令

```
python tools/elfx.py dis <libtersafe.so> 0x22DA98 60
python tools/elfx.py dis <libtersafe.so> 0x2CCA7C 60
python tools/elfx.py dis <libtersafe.so> 0x2CCD20 90
python tools/elfx.py dis <libtersafe.so> 0x4C26A8 70
python tools/elfx.py dis <libtersafe.so> 0x4C27E4 60
python tools/elfx.py dis <libtersafe.so> 0x4C2FE0 32
python tools/elfx.py tab <libtersafe.so> 0x513F88 16
python tools/elfx.py tab <libtersafe.so> 0x518CF0 20
python tools/elfx.py xref <libtersafe.so> 0x563710
```

内联串解密（`0x2D1960`/`0x2D19C0`，初始 key 0x86，逐字节 +1）：

```python
def dec(data):
    k, out = 0x86, bytearray()
    for c in data:
        out.append((c ^ k) & 0xFF)
        k = (k + 1) & 0xFF
    return bytes(out)
```

`0x978E8`(14B) → `gcloud_regist`；`0x978F7`(23B) → `GetNativePluginManager`；`0x980D9`(4B) → `()J`。
