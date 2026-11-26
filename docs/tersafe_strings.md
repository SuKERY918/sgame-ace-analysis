# libtersafe 主字符串表：结构、参数族与全量重建

本文记录 `libtersafe.so`（ACE 主库，5,598,144 B，MD5 `E06344E0B5F6B09D13820C625FA3A123`）主字符串表的完整还原过程与结果。表中存放 ACE 的路径、属性名、模块名、协议字段与格式串；此前只能静态读到其中的明文部分，本次做到了**离线全量解密**。

## 1. 定位

| 项 | 值 |
| --- | --- |
| 表基址 | `0xFBCB0`（`.rodata`，由 `sub_4E4A68` 的 `adrp x0,#0xFB000; add x0,x0,#0xCB0` 得到） |
| 表上限 | `0x10C234`（`.rodata` 结束，紧随 `.eh_frame_hdr`） |
| 有效长度 | 66,948 B，其中密文记录止于约 60,947 |
| 明文缓存 | `sub_4E4A7C` 返回 `0x568FC4`（`.bss` 区，运行时写入，记录级缓存：首字节置 1 表示已解） |
| 记录数 | 3,198 条（旧报告记 2,868，见 §6） |

`.rodata` 段为 `0x90EC0 + 0x7B374`；表尾之后（`0xFBCB0+0x4F84` 起）是 C++ typeinfo 等明文数据，不属于表。

## 2. 记录格式

每条记录：

```
[key:u8][len_xor_key:u8][cipher:len][check:u8]
```

- `key = A[off]`
- `len = A[off+1] ^ key`（`len` 上限实测 118，超过 180 视为越界）
- 密文自 `A[off+2]` 起 `len` 字节
- `check = A[off+2+len]`

解密：

```
k_0 = key
for j in 0..len-1:
    plain[j] = cipher[j] ^ k_j
    k_{j+1} = (((k_j + j) & 0xFF) ^ E) + C   (mod 256)
```

`(E, C)` 是每条记录所属封印装函数的私有参数，全库共 99–101 组。

## 3. 参数族

解密封装函数位于 `0x4E64D0..0x4ED3CC`（旧报告记 100 个），每个函数形如：

```asm
mov w20, w0          ; idx
bl  0x4e4a68         ; A = 表基址
bl  0x4e4a7c         ; B = 明文缓存
mov w15, #E          ; 参数 E
add w1, w1, #C       ; 参数 C
```

因此 `(E, C)` 可直接从指令流静态提取：扫描 `mov w15, #imm` 后接 `add w1, w1, #imm`。实测提取到 75 组，其余由"失败记录的高频候选"补全（阈值：同一 `(E,C)` 在 ≥8 条校验失败的记录上出现），最终 99–101 组，与封装函数数量吻合。

参数分布有规律：同一族内 `E + C` 恒为 7 的倍数（14/21/28/…/105），`E` 覆盖 0–99。这也解释了为什么很多单字节记录对全部参数都解出同一结果（`len=1` 时递推不参与）。

## 4. 校验与消歧

封装函数尾部对明文做校验：

```asm
cs = 0xFF
for b in plain: cs ^= b
if (check ^ cs ^ key) != 0xFF:  标记失败
```

该式只提供 8 位区分度，因此：

- 长串（≥8 字节）几乎唯一确定；
- 短串（1–4 字节）会出现多个参数同时通过的情况，此时用语义打分（可打印字符、大小写、路径/格式符权重）取最优；
- 3,198 条中 1,298 条对候选集合给出**唯一明文**，其余按打分落定，无解 7 条、不可打印 0 条。

已知锚点全部命中，可认为重建正确：

| off | 明文 | 出处 |
| --- | --- | --- |
| 49995 | `ERR` | `partD` 的 3 号槽 ErrKey；`sub_4ECF50(0xC34B)` |
| 50001 | `fake_token_androidid` | 17 槽回落来源 |
| 50303 | `x:%s;q:%s;Q:%s;o:%s` | fake token 主体格式 |
| 50325 | `%s;bt:%s;bd:%s;` | fake token 外层包装 |
| 50343 | `td:%s;bt:%s;bd:%s` | 无前缀变体 |
| 51374 | `Fake_Token_TDM_info` | provider 键 |
| 51396 / 51402 / 51410 / 51420 | `xid` / `QiMaM` / `QIMEI36` / `OsEz` | TDM_info 的四个子键（`QiMaM`=QIMEI、`OsEz`=OAID，键名被改名混淆） |
| 52998 | `AndroidIdErr` | `sub_2C9D78` 的 17 槽 |
| 58581 | `ft_oaid` | 17 槽首选来源 |
| 51301 | `/proc/sys/kernel/random/boot_id` | `sub_2CCE84` |
| 57640 | `ro.com.cph.mac_address` | `sub_2B6040`（oppo 系 MAC 属性） |

## 5. 引用点

`tools/tersafe_usage.py` 线性扫 `.text`，在 `bl` 目标落入 `0x4E64D0..0x4ED3CC` 时回溯最近的 `mov w0, #idx`，并用 `.eh_frame_hdr` 恢复的函数起点归组。结果：

- 调用点 3,246 处
- 不同 idx 2,110 个（占 3,198 条的 66%）
- 覆盖 876 个函数

产出 `docs/strings_usage.tsv`（`func / call / idx / string`）与 `docs/strings.tsv`（`offset / key / len / E / C / string`）。

高密度引用函数（前几名）：`sub_4E3CAC` 101 次、`sub_230C78` 64 次、`sub_1BCF84` 47 次、`sub_269EFC` 40 次、`sub_2CB31C` 39 次（Camera 采集）、`sub_27FAE4` 37 次（模块注册表）、`sub_28EAF4` 32 次、`sub_4C63CC` 32 次。

## 6. 与旧报告的差异

| 项 | 旧报告 | 本次实测 |
| --- | --- | --- |
| 记录数 | 2,868 | 3,198 |
| 密文表尾 | 约 60,586 | 60,947（最后一条非空记录） |
| 参数组数 | 98 | 99–101（提取 75 + 频次补全 24–26） |
| 表基址 | 0xFBCB0（正确） | 0xFBCB0 |

旧报告 2,868 应是把尾部若干条（含 `ft_oaid`、`AndroidIdErr`）漏掉后的计数；本表按 3,198 条重建，`ft_oaid`（58,581）在旧表范围外，这正是此前 `0x2CC6C4` 首行显示空串的原因。

## 7. 复现

```powershell
cd sgame-ace-analysis\tools
python tersafe_strings.py ..\..\work\libs\libtersafe.so 0xFBCB0 66948 0x4E64D0 0x4ED3CC 4000 ..\..\work\out\tersafe_strings.tsv
python tersafe_usage.py  ..\..\work\libs\libtersafe.so 0x1b6c20 0x50dfc8 0x4E64D0 0x4ED3CC ..\..\work\out\tersafe_strings.tsv ..\..\work\out\tersafe_usage.tsv
```

第 4/5 参是参数扫描区间，第 6 参是记录上限（给 4000 即可覆盖全表）。

## 8. 尚未覆盖

- **内联串 945 条**：不在这张表里，由 262 个内联解码器就地解密，算法为 `p[i]=c[i]^((k+i)&0xFF)`，`k` 固定（已见 0x8A/0x91/0xC6/0xE8/0xAB/0xE5）。`ft_oaid` 之外的 OAID 相关常量、部分云控键在这一套里。
- **7 条无解记录**：参数不在 0–127 / C 0–7 的搜索空间内，属于未提取到的封装函数。
- **3 条空串调用点**：`idx` 落在记录中间（内联串编码），已被 usage 表排除。
