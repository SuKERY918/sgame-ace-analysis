# ObfQos 事件、COREREPORT 遥测与 OZ k 编码（静态补遗）

本文补 `docs/devinfo_deep.md`、`docs/devinfo_layers.md`、`docs/qimei.md` 未展开的三处运行时面：ACE 侧 `0x1F3644` 事件对象的字段语义、TSS 到 GCloud `COREREPORT` 的遥测通道、`libqimei` 的 `k<i>:<value>;` 指编码（OZ）；并结案 `iAppMachUUID` / `iAppMachOUUID` 两条串。全部结论来自静态分析（IDA Hex-Rays + 字节级扫描），不做动态验证。

分析对象：王者荣耀 12.1.1.1（`com.tencent.tmgp.sgame`，versionCode 1201010103）。

| 库 | 大小 | MD5 |
| --- | --- | --- |
| libtersafe.so | 5,598,144 | `e06344e0b5f6b09d13820c625fa3a123` |
| libqimei.so | 539,416 | `62bb50c92d64eb5160ecce4cdfed63e5` |

地址均为镜像内偏移（imagebase 0）。

---

## 1. `0x1F3644` 事件对象：一个叫 ObfQos 的运行环境事件

`devinfo_deep.md` §8 把"`0x1F3644` 事件对象字段语义"列为未解。本轮把 `0x2C8AC0 → 0x2C8CBC → 0x2C916C → 0x1F3644` 整链拉通后，它是一个独立事件，与 17 槽上报并列。

### 1.1 调用链与入参

```
sub_2C89D4  (入口门: ctx+953==0 或 has("force_fake_token", 46601))
  -> sub_2C8AC0
       -> sub_2C8C28(ctx, buf64, buf64)          取 64B 串（sub_2C9254 / 回落 sub_2C931C）
       -> sub_2C8CBC(ctx, buf64, buf64)          17 槽采集 + 40 字符摘要
       -> sub_4A4770() == 40                     长度校验
       -> sub_2C8F28(ctx, digest, slot17_crc)    缓存落盘（"ce:%s;%s" 50044）
       -> sub_2C90D0(ctx, digest)                MediaStore 写入（云控 media_store 53437）
       -> sub_2C916C(ctx, digest, slot17_crc, 1)
            -> sub_2DB578 / sub_2CC910 / sub_2CCB80 / sub_2CCC5C / sub_2CC358(mode=1) / sub_2CCF54
            -> sub_1F3644(flag, sdk_int, v9, v10, v11, digest, appinfo, fake_token, slot17_crc)
```

`sub_2C916C` 的六个取值函数：

| 函数 | 语义 | 证据 |
| --- | --- | --- |
| `sub_2DB578` | SDK_INT | `0x2C916C` 首参 |
| `sub_2CC910` | **设备最早使用痕迹时间**：对 `/data/data`(8575)、`/sdcard/Android`(51268)、`/sdcard/DCIM`(51286) 取最早 mtime，且要求 ≥ `1262304001`（2010-01-01） | 三个路径串 + 常量 `0x4B3E6C01` |
| `sub_2CCB80` | 内存 kB：`/proc/meminfo`(51335) + `MemTotal`(51351) + `sscanf(": %llu")`(50363/50367) | 直接引用 |
| `sub_2CCC5C` | CPU 核数：统计 `/proc/cpuinfo`(38230) 中含 `processor`(51362) 的行数 | 直接引用 |
| `sub_2CC358(mode=1)` | 已安装应用计数（与 16 号槽同函数、不同 mode） | `0x2C916C` 调用点 |
| `sub_2CCF54` | fake token 串（`"td:%s;bt:%s;bd:%s"` 50343 等） | 直接引用 |

### 1.2 0x658 字节对象的布局

`sub_1F3644` 先 `memset(v32, 0, 0x658)`、`v32[116] = 2`，然后：

| 偏移 | 字段 |
| --- | --- |
| `+0x00` | `0x800002350`（事件类型） |
| `+0x04` | `7` |
| `+0x08` | `a1 & 1`（force_fake_token 命中标志） |
| `+0x0C` | SDK_INT |
| `+0x10` | 最早使用痕迹时间 |
| `+0x14` | MemTotal（kB） |
| `+0x18` | CPU 核数 |
| `+0x28` | 64 B 串：40 字符摘要（8 hex CRC32 + 32 hex 128 位哈希） |
| `+0x68` | 64 B 串：AppInfo 串（`sub_2CC358` 输出） |
| `+0x28C` | 1024 B：`snprintf("ce:%s;%s", fake_token, "<槽17 CRC hex>")` |

两段 64 B 串由 `sub_4A4A20(&dst, src, 64)` 拷入；`0x28C` 处由 `sub_4A54DC`（`vsnprintf` 覆盖写包装）格式化。

### 1.3 投递端：`cs3` 选择双通道

```
sub_1F8248 -> qword_55EB10 / qword_55EB00   单例
sub_1F8284 -> sub_1F848C(inline 0x917EF, 4)  逐字节 XOR，密钥从 0xB1 递增  => "cs3"
           -> 云控 has("cs3") ? vtable off_5138A0 : vtable off_5136A0
           -> sub_508180(8) 分配对象，回写 qword_55EB10 / unk_55EB08
```

两套 vtable（`.rela` RELATIVE 重定位 addend）：

| 槽 | A 版 `0x5136A0` | B 版 `0x5138A0` |
| --- | --- | --- |
| `+0x00` | `0x1FFA44` | `0x1FFA44` |
| `+0xD8` | `0x1FF670` | `0x2083B0` |
| `+0xE0` | `0x1FF6B0` | `0x208428` |
| `+0x110` | `0x200A64` | `0x20AF10` |
| `+0x118` | `0x200A98` | `0x20B108` |
| `+0x120` | `0x200E34` | `0x20B8F4` |
| `+0x128` | `0x2010B8` | `0x20B98C` |
| `+0x130` | — | `0x20BB40` |
| `+0x138` | — | `0x20BCDC` |

- `+0xD8`：`sub_4CADD0 → sub_4CB35C(this, arg)` 判重/节流，遍历两张表比较 `(dword/1000, dword%1000)` 与 `(arg+4 != 0 && *(u64*)(arg+8) == 余数)`，命中返回 0。A 版未命中转 `sub_225B48`，B 版尾调 `sub_20905C`。
- `+0xE0`：A 版 `0x1FF6B0` 为 14 分支 CFF（case12 → `sub_4B8F38` + `sub_1F8214`）；B 版 `0x208428` 为 13 分支 CFF（case6 → `sub_209798` → `sub_2008E8` → `sub_200FEC`，用 `LDR W8,[X19,#4]` 与 `ORR W1,W8,#0x1120000` 组包）。

结论：该事件是"设备画像 + 运行环境"遥测（硬件规模、使用痕迹、应用数、fake token），走独立于 17 槽字段的投递对象；`cs3` 决定走直连还是备份通道。它不构成本地判罚项。

---

## 2. TSS → GCloud `COREREPORT` 遥测

`partD_devinfo.md` 只记了"7 个 API 各注册 monitor 事件"，没有展开落点。实际落点是 GCloud 的 `COREREPORT` 记录，不含任何设备标识。

### 2.1 `0x4C3054` 的写入链

```
gcore = qword_563710 + 0x18
sect  = gcore->vtable[+0x20]("GCloudCore", 49902)
rec   = sect->vtable[+0x40]("COREREPORT", 0x94EDB)
rec->vtable[+0x20](v11, 2004, name)          v11 = (a4 & 1) ? 1 : 3
rec->vtable[+0x18](110100, "TSS", len)
rec->vtable[+0x18](110101, sub_4C36A0() = "7.7.50.28931", len)
rec->vtable[+0x18](110102, value, len)
rec->vtable[+0x20](100100, a3)
rec->vtable[+0x20](40004, 5)
```

门控是云控 `tdm_report`（`0x91AAA`，缓存 `byte_568E3D` / `byte_568E3C`）；失败计数 `dword_568E40` 超过 3 次后永久关闭（写 `byte_568E3C = 0`）。

### 2.2 `0x4C3510` 的 7 个 API 名

| idx | 串偏移 | 名称 | 去重/上限 |
| --- | --- | --- | --- |
| 0 | 33682 | TssSDKInit | `dword_568E14[0]` 置 1 |
| 1 | 33695 | TSSDKSetUserInfo | `[1]` |
| 2 | 33715 | TssSDKOnPause | `[2]` |
| 3 | 33731 | TssSDKOnResume | `[3]` |
| 4 | 33748 | TssSDKGetReportData | `dword_568E08`，> 2 停 |
| 5 | 33770 | TssSDKDelReportData | `dword_568E0C` |
| 6 | 33792 | TssSDKOnRecvData | `dword_568E10` |

末尾统一 `sub_4C3054("monitor", name, api_id, 1)`。

结论：这条通道只上报 ACE 身份（`TSS`）、版本（`7.7.50.28931`）、通道参数与两个整数（`a3`、`5`），**没有设备数据**，与裸 TCP 上报是两条独立路径。

---

## 3. `libqimei` 的 OZ：`k<i>:<value>;` 指编码

`devinfo_deep.md` §8 与 `qimei.md` 附录 C 把 `0x45DF8` 的 `k%d:%s;` 编码器列为未解。本轮把编码端、槽模型、索引表与取值来源都定位了；未完成的是"k 号 ↔ 具体路径/字段"的逐项对照。

### 3.1 取串器 `sub_1EFB8(a1, a2)`

- `a2` 是串表字节偏移（判 `a2 <= 9469`，表基址 `qword_84340`），`a1` 是**诱饵参数**，函数体不读。
- 首次调用时把 `unk_6CFA4` 的表**复制到堆**（`qword_84340`）并**原地解密**表项，返回明文指针；失败分支返回空串 `""`。
- 证据：`0x1F44C` 处 `X28 = v8 + 3`（表项密文起点），`0x1F41C` 处 `X28 = ""`（`asc_6CC5B`）；`0x1F3A4` 处 `ADRL X9, unk_6CFA4` 后 `ADD X8, X9, a2`。

### 3.2 编码器 `sub_45DF8(buf, idxlist, n)`

```
dest = sub_412E0(0, n << 7)                  // n * 128 B
for (i = 0; i < n; i++) {
    slot = buf + idxlist[i] * 0x80;          // 0x46090
    sub_45A8C(slot);                         // 0x46098 清洗
    snprintf(s, 0x80, "k%d:%s;", idx, slot); // 0x45FB8
    strncat(dest, s, 0x80);                  // 0x45FC8
}
```

- `sub_45A8C` 是值清洗器：内部判 `38`（`'&'`），把会破坏 `k=v;` 结构的字符替换掉。
- 槽缓冲固定 **122 槽 × 128 B = 0x3D00**：`sub_24364` 的 `malloc(0x3D00)`，最后一个槽由 `sub_24004` 写到 `a2 + 15488`（= `121*128`）。
- 两套索引表：
  - **74 项**：`unk_6F59A`，`sub_24364` 用 `memcpy(&dest, &unk_6F59A, 0x4A)` 取；
  - **9 项**：内联 `dest = 0x0908040307060500`、`v18 = 10`，即 `{0,5,6,7,3,4,8,9,10}`。
- `k10` 例外：走 `"k10:%d"`（串 0x140E），其余走 `"k%d:%s;"`（0x1403）。
- 结果单例缓存：`sub_2471C` 加 `pthread_mutex_lock(&stru_84358)`，`qword_84380` 非空直接返回。

74 项索引（十进制）：

```
0,1,112,115,113,114,116,117,121,2..19,108,109,110,111,20,21,22,23,24,25,26,27,28,29,30,31,32,
34,36,37,40,42,44,46,50,53,54,58,62,64,65,66,70,72,74,76,78,82,84,86,90,94,97,98,101,104,120
```

### 3.3 槽值的来源：路径的文件系统元数据

`sub_24004(a1, out)` 先用 `sub_1EFB8` 取 31 条路径，再交给 `sub_23968(a1, entries, 31, out)`：

```
/storage/emulated, /storage/emulated/0, /data/data, /data/user, /mnt,
/storage/emulated/0/Android/data, /storage/emulated/0/Android,
/storage/emulated/0/tencent, /data/system/job, /data/dalvik-cache,
/data/system/locksettings.db, /data/system/inputmethod, /cache, /data/app-lib,
/data/system/recoverablekeystore.db, /data/system/graphicsstats,
/data/system/sensor_service, /data/system/last-header.txt, /data/system/sync,
/data/system/netstats, /data/media, /data/system/procstats,
/data/system/notification_log.db, /data/resource-cache, /data/lost+found,
/data/ss, /data/system/uiderrors.txt, /mnt/sdcard, /system/etc,
/proc/sys/kernel/random/boot_id, /etc
```

`sub_23968` 用 `"%s && %s %s"`（`aSSS` 0x6F58E）拼 shell 命令，经 `sub_44AC4`（`malloc(40*n)` 的结果数组读取，`sub_453B0` 收尾）执行；槽 121 另由 `sub_43E54`（`open` + `read`，并反射 `java/io/FileInputStream`）填入。

因此 `k<i>` 的值是**这些路径的 shell 级文件/目录元数据（时间戳一类）**，与 ACE 15 号槽（FileFirstTime）思想同源。`sub_24364` 的 `a2 <= 22` 决定用 74 项表还是 9 项表，即"完整版 / 轻量版"两种 OZ。

### 3.4 未完成

`sub_23968` 是 248 行 CFF，31 条路径与 74 个 k 号的逐项对应尚未展开；槽 121 的语义也未定。

---

## 4. `iAppMachUUID` / `iAppMachOUUID`：本版不可达的死表项

`devinfo_layers.md` 曾把这两个名字列为"未解（16 字节输入源）"。本轮可以结案。

| 偏移 | 明文 |
| --- | --- |
| 10427 | `iAppMachOUUID:%.2X%.2X%.2X%.2X%.2X-%.2X%.2X-%.2X%.2X-%.2X%.2X-%.2X%.2X%.2X%.2X%.2X` |
| 10512 | `iAppMachUUID:%.2X%.2X%.2X%.2X%.2X-%.2X%.2X-%.2X%.2X-%.2X%.2X-%.2X%.2X%.2X%.2X%.2X` |
| 10596 | `iTssSDKUUID:%s` |
| 8422 | `machine_name` |

证据：

1. 三个名字只存在于 **libtersafe 的加密串表**（`docs/strings.tsv` 之外的这段由 `tools/tersafe_strings.py` 解出）；全 APK 明文扫描（6 个 dex + 全部 arm64/armeabi-v7a `.so`）对 `iAppMachUUID` / `iAppMachOUUID` **0 命中**。
2. libtersafe `.text` 全段立即数扫描：`0x28BB`(10427)、`0x2910`(10512)、`0x2964`(10596) **零引用**。
3. 对照组：同表 `0xC37C`(50044 = `"ce:%s;%s"`) 命中 `sub_2C8F28` 的两处（`0x2C905C`、`0x2C9B50`），说明"串表偏移即立即数"的用法判定成立。
4. 按表基址 `0xFBCB0` 折算出的对应位置（`0xFE56B` / `0xFE5C0` / `0x108181`）也无数据 xref。

结论：这三个格式串在这版 arm64 libtersafe 中是死表项（推测是腾讯共用串表里其它产品线留下的），当前版本不存在 16 字节输入源可追，`devinfo_layers.md` §12 的对应条目可以关闭。armeabi-v7a 变体未单独核对。

---

## 5. q16 / q36：现状判断

- `A3` / `A153` 两个响应键只在 `classes2.dex`、`classes3.dex` 出现（各 1 次），任何 `.so` 都没有。
- libqimei 的导入表没有 MD5 / SHA / EVP 一类原语（只有 zlib、socket、getprop、dl\*），没有本地算 32 hex 的现成手段。
- `files/com.tencent.qimei.sdk.QimeiSDK`（base64 16 B）与 `QV1*.xml` 的 `tt` 都是写入侧缓存。

尚未完成：`uin.U` / `ai.b.a()` 中 `A3` / `A153` 到 `f15474b` / `f15475c` 的赋值链需要在 dex 层用 jadx/baksmali 跟完，本工作区只有 APK 原件，没有反编译产物。

---

## 6. 对既有文档的两处校正

1. `docs/partD_devinfo.md:27` 写"整串再经 `0x49F018`/`0x49F170` 追加进 protobuf 式流"，实际是 `sub_2C8CBC` 用 40 字符摘要**覆盖**栈上原文（`sub_49F018` 清零 36 B 上下文、`sub_49F170` 更新、`loc_488754` 出 32 hex，末尾 `"%08X%s"` 拼 8 hex CRC32），原文不外发。
2. `docs/partG_account.md:28` 把 `0x2C8CBC` 归入 FakeToken(A)，实际它是 17 槽总拼装 + 摘要，`force_fake_token` 只是 `0x2C89D4` 的入口门。

`devinfo_deep.md` §8 未解清单中第 6 项（`0x1F3644` 事件对象字段语义）由本文 §1 关闭；`iAppMachUUID` 条目由 §4 关闭。

---

## 7. 复现

```powershell
# 主表解密（libtersafe）
python tools/tersafe_strings.py libtersafe.so 0xFBCB0 66948 0x4E64D0 0x4ED3CC 4000 strings.tsv

# libqimei 串表
python tools/qimei_scan.py libqimei.so

# APK 全量明文扫描（含 dex 与双 ABI 的 so）
python - <<'PY'
import zipfile
pats=[b'iAppMachUUID',b'iAppMachOUUID',b'iAppTssSDKUUID']
z=zipfile.ZipFile('sgame.apk')
for p in pats:
    print(p, sum(1 for i in z.infolist()
        if i.file_size<80_000_000 and (i.filename.endswith('.dex') or i.filename.endswith('.so'))
        and p in z.read(i.filename)))
PY
```

IDA 侧核对点：`sub_1F3644`(0x1F3644)、`sub_2C916C`(0x2C916C)、`sub_24004`(0x24004)、`sub_24364`(0x24364)、`sub_45DF8`(0x45DF8)、`sub_1EFB8`(0x1EFB8)、`sub_4C3054`(0x4C3054)。
