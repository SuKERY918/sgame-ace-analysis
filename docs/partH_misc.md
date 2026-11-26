# PartH：云游戏 / 串流 / 守护 / 混淆通道

对象 `libtersafe.so`（arm64，base 0，strip）。范围：注册表 `sub_27FAE4`（全库 40 模块）中本组 10 个。地址为文件虚址；`off=` 为字符串解密器 id（同 `out/strings.tsv`）。

## 0. 公共注册机制与总览

`BL getter → MOV W0,#strId → BL sub_4EXXXX → sub_222284(reg,ctx,name,f3,f4)`；后者建 `{ctx@0;name[32];u8 f3;u8 f4}` 交 `sub_2222F4(reg+8)`。`f3` 均为运行期设备态谓词：`sub_239A6C()`=`dev->[0x80]==0x7D5`（`00239a6c`）、`sub_2399A8()` 同判据分支化（`002399a8`）、`sub_239BC8()`=`sub_1D1EDC()!=0`（`00239bc8`）；`f4` 全 0。部分名字二次隐藏：`.rodata` 密文 + 滚动 XOR（`sub_282948` 首键 0xF3 逐字节+1，`0x94079` len7 → `ace_wb`）。

| 模块 | 注册点 | ctx / 对象 | 虚表 | 运行槽 | 主入口 |
|---|---|---|---|---|---|
| live | 0x2801C8 | 单例 `0x55F5D0`，288B | 0x5152E8(+0x48→0x515318) | — | 0x2AD898 |
| cps_new | 0x2801F8 | calloc(0x150) | 0x515540 | — | 0x2B5194 |
| cps_new3 | 0x280238 | calloc(0x150) | 0x515590 | — | 0x2B5194 |
| cs_vm | 0x280090 | 单例 `0x55F5E0`，72B | 0x515348 | — | 0x2ADD70 |
| wb_daemon | 0x27FF3C | `obj+0x70`，264B | 0x514C58 | 0x514C88(=+0x30) | 0x280A48 |
| wb_new_sync | 0x27FDEC | calloc(0x48) | 0x5150E8 | — | 0x29E828 |
| ob_normal | 0x27FC5C | 单例 `0x55EA28`，72B | 0x512FF0 | — | 0x1D90BC |
| win_data_sync | 0x27FB28 | `obj+0x78`，384B | 0x514048 | 0x514080/0x5140B0 | 0x251760 |
| inf_sca | 0x27FEF4 | calloc(0x50)+`sub_29A600` | 0x514FF8 | — | 0x29A654 |
| gp5 | 0x27FF8C | 单例 `0x55F320`，80B | 0x514468 | — | 0x260C68 |

`inf_sca`/`win_data_sync` 名字由 `sub_280340` 从 `.text` 内嵌立即数字节拼出（`0x27FB14` unk_98C39 len8；`0x27FB28` unk_92831 len0xE），静态扫 `.rodata` 不可见。

## 1. live（直播/投屏，288B 单例）

getter `sub_2AC258` 以 `__cxa_guard`(`0x50E3B0`+`adr 0x2AC2B0`) 构造 `0x55F5D0`；`0x2AC2E8` 写 vtable `0x5152E8`、`+0x48`=二级表 `0x515318`、`+0x58` u16=0。**实测 288B 且不调用 `sub_2B5138`，与线索（336B）不符。** 主虚函数 `+0x10=0x2AD898`：`sub_2ADA10` 解内联串 `0x965B8` len5→`"lsvd"`（`002ad8c0`），读 `dev->[0x3b8]` 选直读/查云控；开关 `sub_22DA98(cfg,"lsvd",0,1)`（`002ad918`）。判据 `0x2AC388` 21 条包名：`com.ss.android.ugc.aweme(.lite/.live/trill)`、`tv.danmaku.bili`、`com.bilibili.bilibililive`、`com.bilibili.studio`、`air.tv.douyu.android`、`com.duowan.live/.kiwi/.mobile`、`com.yy.huyaassist4game`、`com.kwai.livepartner`、`com.kuaishou.nebula`、`sg.bigo.live`、`tv.twitch.android.app`、`com.tencent.weishi`、`com.prism.live`、`com.streamlabs`；仅存在性检测（推断）。上报 `0x2ACA20` 反射 `android/view/Display` 的 `getDisplays`/`getUniqueId`/`getSystemService`，配 `0x2AD3D0` 的 `"priv_scn,unknown"`、`"uniqueId"`。降级：`lsvd` 关且 `dev->[0x3b8]==0` 直接返回。

## 2. cps_new（云手机扫描第二套，336B）

`0x2801E4` calloc(0x150)+`sub_2B5138`：写 `0x513108`、`sub_1DAFC0(+8,0)`、`sub_1DB038(+0x28,0)`，再 vtable `0x515540`、`+0x48` u16=0、`memset(+0x4a,0,0x100)`（名字缓冲 `0x4a..0x14a`）。主函数 `0x2B5194`：读 `dev->[0x3b6]`，`sub_22D820()` 取云控，`sub_22DA98(cfg,"force_cp2_scan",0,1)`（`0xCC02`=52226）；真→`sub_2B5270()`，假→`sub_23976C(dev,buf,0x40)` 后再判 `sub_2B5338`。其余槽 `+0x20=0x2B6C30`(`cpfc.zip`,52263)、`+0x28=0x2B53BC`、`+0x30=0x2B6D38`(`abcd1234`/`ce_pho_fpa.zip`52624/`magic:%d`58436)、`+0x38=0x2B9748`(`9009_new_error_alert`,52284)。

聚合入口 `0x2B54C8`（两套共用）：`if(!x1)return`；云控 **`cp_comm`**（`0xE431`=58417，默认 1，`002b5504`）→ 6 位 bitmap：

| bit | 函数 | 判据串 |
|---|---|---|
| 01 | 0x2B5A5C | `/sys/module/kvm`(55786)、`.../halt_poll_ns`(55804)、开关 `cp_kvm`(58427) |
| 02 | 0x2B5B00 | `RK_ADEPT_DEVICE_TYPE`(56379)=`rk3588_docker`(56402) |
| 04 | 0x2B5B9C | 17 条 `ro.build.*`/`ro.product.*`/`ro.*build.fingerprint`(55966–56346) 命中 `gemini` |
| 08 | 0x2B5D70 | `/dev/__properties__/`(55846) |
| 10 | 0x2B5EA8 或 0x2B6040 | 12 个 `libCPH*.so`(56926–57330)；22 条 `com.cph.*`/`ro.com.cph.*`(57370–57876) |
| 20 | 0x2B6258 | 无字符串（纯逻辑，推断容器/挂载态） |

非 0 时写 `{u8 valid=1; u32 bitmap@+4; char name[64]@+8}`，名字默认 **`UnKnownYun`**（`0xDA3D`=55869，`002b55b4` strncpy 0x40）。旁证：`0x2B68C4` `CloudAppEngine`/`CloudGaming`；`0x2B69F0` `init.svc.cloudAppEngine`/`storage.cloud.mode`；`0x2B6500` Rockchip 模块+`librockit.so`；`0x2B6684` `ro.rk.*`；`0x2B6AC4` `wifi_name`/`*.model`/`cloudphone`；`0x2B62BC` `ro.build.characteristics=tablet`；`0x2B6320` `/proc/self/environ`；`0x2B9590` `/proc/self/ns/mnt`（容器判定，推断）。缓存 `0x2B5850`/`0x2B597C` 读写 **`cpcah.dat`**（JSON：`sub_49F018/49F090/49F414`）。落盘 `0x2B6F64`/`0x2B7074`/`0x2B7180`：`tss_fap_info.dat`、`tss_dev_info.dat`、`tss_flag_info.dat`；`0x2B7074` 内容 **`root:%d;x86:%d;emu:%d;name:%s`**（id `0xCDDB`），值取 `sub_23A114()`/`sub_2DB8AC(dev)`/`sub_23A0B0(dev,buf,0x40)`。云特性引擎 `0x2B7318` 读 **`cloud_feature.xml`**(52321)+**`sig.dat`**(52274)（签名校验，推断）；`0x2B769C` 入口（5 参非空，JSON 句柄+`sub_2B7850` 解析），规则键 `0x2B7C1C` `type`/`match_all`/`match_any`/`match_part`/`percent`/`element`/`key`/`value`，结果 `%d,%d,%d;`(0x2B7EB8)；指纹 `0x2B86C4` `Brand/CPUName/CpuModel/CpuAbi/SysVer/Model/Screen`、统计 `0x2B8B44` `DevCnt/UserAppCnt/SysAppCnt`、屏幕 `0x2B8D1C` 反射 `DisplayMetrics` 出 `%d:%d:%x`、`0x2B937C` 读 `Build.HARDWARE`。

## 3. cps_new3（第三套）

`0x280214`：calloc(0x150)+`sub_2B5138` 后 `vtable=*(0x51C580)+0x10=0x515590`，仅 `+0x20..+0x38` 不同：`+0x20=0x2B98AC`(**`cpfc3.zip`**,54823)；`+0x28=0x2B999C`（`if(!x1)return -1`，否则 `sub_2B55D4(this,x1+8,0x40)` 刷新名字、`out->valid=ret&1`，`002b99f8`）；`+0x30=0x2B9A08`（实体仅 `ret`，能力被裁）；`+0x38=0x2B9A98`（一次性上报：`sub_239A6C()` 且 `sub_238000(1)` 为真；`out->valid==0` 或 `this+0x14a!=0` 跳过，否则置 `+0x14a=1`，`sub_46F418()` 取日志器，事件 **`cloud3_err1`**(`0xE3CB`=58315)，载荷 `out+8` 厂商名，`sub_474EF4` 上报，`002b9afc`）。错误码族 `0x2B9B6C` `cloud3_err2`+**`cp2:%d,%d,%s`**、`0x2B9CE8` `cloud3_err3`+**`cp3:%d,%d,%s`**、`0x2B9D98` `cloud3_err4`+**`cp23:%d,%s,%s`** 与 7 厂商名 `RedFinger`(55881)/`DuoDuoYun`(55894)/`XiaoDiYun`(55906)/`LeiDianYun`(55918)/`VMOSYun`(55931)/`ShuangZiXinYun`(55941)/`ZYYun`(55958)，入参 `(this,&result,buf)` 读 `result[0]`/`result[4]`/`this+0x14d` 按位映射（推断）。尾部 `0x2BA5FC` `libtprt.so`/`unwind_xx_info_query`；`0x2BA7F4` `/sdcard/sdk`+`enable.log`；`0x2BA960` `acecrh.dat`+`a:%x;t:%x;m:%x;s:%x`；`0x2BAEE0` `unlock_root`。

## 4. cs_vm（云端沙箱数据通道，72B 单例）

单例 `0x55F5E0`，init 在 `0x2ADD18` 分支；vtable `0x515348`（`+0x10=0x2ADD70`、`+0x18=0x2ADD6C`、`+0x30=0x2AE0B8` 实体 `ret`）。`0x2ADD70`：`dec(0x2C9)`=**`comm.dat`**(713)→`sub_23070C(path,&h)`，成功则 `sub_2ADE04(h)`；再 `dec(0x2F9)`=**`tss_cs2.dat`**(761) 同样处理；收尾沿链表 `sub_1DB2FC` 释放（`002adde0`）。`0x2ADE04` 为记录消费器（无字符串，推断解析挂链）。`0x2AE0C4` 有 `cert_crash`/`white_mode`/`official_cert_md5` → 官方证书 md5 白名单门禁（推断）。降级：两文件任一缺失 `sub_23070C` 非 0 即跳过（`002add9c`/`002addc4` 的 `cbnz w0`）。

## 5. wb_daemon（ACE Keeper 守护，264B）

getter `0x280404`→单例 `0x55F450`；ctor `0x280530`：`0x94079` len7 经 `sub_282948` 解出 **`ace_wb`**，`sub_4CD5C8(obj,&name)`；vtable `0x514C58`，`+0x70` 存 `0x514C58+0x30=0x514C88`（**运行槽**，注册表取 `obj+0x70`）；`sub_1DAFC0(+0x78,0)`、`sub_1DB038(+0x98,0)`、`+0xb8`=0、`0xbc..0x104` 清零。槽 `+0x00 0x2805C0`、`+0x08 0x2805CC`、`+0x10 0x280A48`、`+0x18 0x280618`(`emu_tp`)、`+0x30 0x2805C4`(运行槽)、`+0x38 0x2805F0`、`+0x40 0x280A40`、`+0x48 0x1DAF64`。模拟器判据 `0x280688` 十条 `TencentAoYYB/Win/LeiDian/Tencent/Nox/NOX/XiaoYao/BlueStack/Google/Mac`，`0x280C3C` 九标签 `tencent_yyb_tp/tencent_tp/win_tp/leidian_tp/nox_tp/xiaoyao_tp/bluestacks_tp/google_tp/mac_tp`。上报 `0x280BD0`：格式 **`is_frond:%d,emu:%d,MBS_show:%d,heart_cnt:%d`**（id `0xA90E`），参数 `sub_4C7488()&1`、`byte[+0xb8]`、`dword[+0xc0]`、`dword[+0xbc]`，`sub_4A54DC` 格式化后 `sub_1EE218(109,buf)`（事件 109）。心跳 `0x281200` **`func=WB_HeartBeat|index=%d|md5=%s|uid=%d`**+`%ld_%ld_%ld`+`check_sum`；`0x2810A4` **`WB_SyncOpenIDEx`** 格式 `%s|emu=%d|report=%d|locale=%d`，前置 `sub_2820D4()`。报告串 `0x28131C` 自称 **`WB_GetReportStr`**，逐段 `"win:%s;"`(00281538)+`channel`；公共格式器 `0x2823C4` **`func=%s|game_id=%d|open_id=%s|pkg_name=%s|uid=%d`**；`0x28220C` **`func=WB_SyncGs2Host|game_id=%d|cdn_host=%s|cs_host=%s|cs_ip=`**；`0x282BCC` `.so`（dlopen，推断）。云控 `0x28204C` 读 **`daemon_report`**：`dev=sub_2DAD4C()`，`sub_239BC8()` 真→默认 0，假→默认 `sub_2399A8(dev)&1`（`00282090`–`002820ac`），再 `sub_22DA98(cfg,"daemon_report",def,1)`。Keeper：`0x281D50` 用云控键 **`wsa_name_cn`**(60475) 取服务名（`sub_22DFD0` 双输出），缺省 **`ACE Keeper`**(43968,`00281e0c`)；`0x281E44` 持 `windows`+`wsa_dialog_init_cn`(60489)/`wsa_dialog_succ_cn`(60510)/`wsa_dialog_reconn_cn`(60531)+域名 **`acekeeper.anticheatexpert.com`**(60554,`00281fa0`)→ 连接/弹窗/重连守护环（推断）；`0x24ED60` 另有 `wsa_popen_ip`/`wsa_netlink_ip`/`wsa_udp_ip` 三通道。窗口 `0x281600` 用 `sub_282760` 连解 4 条内联串（len 9/10/10/12，`0x920C39`/`0x98913`/`0x94C45`/`0x94550`），旁证 `screenshot`。

## 6. wb_new_sync（WB 账号/白名单同步 + 异常箱，72B）

`0x27FDB4` calloc(0x48)：`0x513108`→`sub_1DAFC0(+8,0)`→`sub_1DB038(+0x28,0)`，终表 `0x5150E8`。槽 `+0x00 0x1DB0B4`、`+0x08 0x29EB88`、`+0x10 0x29E828`、`+0x18 0x29EB84`、`+0x30 0x29EF50`、`+0x38 0x29F014`、`+0x40 0x29F95C`(`msg_box`)、`+0x48 0x2A3844`。主函数 `0x29E828`：`dev=sub_2DAD4C()`，`dev->[0x3a8]` 作 locale；`sub_4E80B8(0x3A4D)` 解出 **`func=WB_SyncOpenID|open_id=%s|game_id=%d|locale=%d`**(14925)，`sub_24E4BC(buf,0,fmt,x20,w21,w22)` 组装（`0029e954`）；同函数另有 `WB_GetTPShellVersion`、`tp_ver:NULL`/`tp_ver:%s`、`WB_GetReportStr`、`win:%s;`（`0029ea54`）→ 上报体=open_id+game_id+locale+TPShell 版本+窗口串。异常箱/反注入 `0x29F060` `ano_box`/`msg_box`；`0x29FC20` `super_white`/`people`/`party`；`0x2A09E0` `anocrash_all`；`0x2A0B80`/`0x2A10A0` `ano_box_%08x`+**`tss_ano.dat`**；`0x2A11A4` `ano2_box_%08x`；`0x2A1440` `tencent/android/google/huawei/xiaomi/miui/qq/qualcomm`；`0x2A34DC` **`classes.dex`**+**`zygisk`**；`0x2A3650` 反射类 `SecretKeySpec`/`BaseDexClassLoader`/`PackageInstaller`/`ProgressDialog`/`AppComponentFactory`/`Cursor`（推断）。

## 7. ob_normal（混淆数据包，72B 单例）

getter `0x1D9050`→单例 `0x55EA28`；vtable `0x512FF0`（`+0x10=0x1D90BC`、`+0x30=0x1D92F4`、`+0x38=0x1D92F8`）。`0x1D90BC`：先 `sub_1D9198`（内含 **`ace_ov`**）与 `sub_1D926C`；逐解三包名 **`ob_normal.zip`**(44292,`0xAD04`)/**`ob_normal_ver.zip`**(44308,`0xAD14`)/**`ob_normal_64.zip`**(44347,`0xAD3B`)，`0x1D9110`–`0x1D912C` 以 8 字节步长循环 3 次 `sub_1D7064(obj,&list,str,0)`；然后 `sub_1D8090(list,0)` 提交、`sub_1D8168`×2 清理、`sub_475CC8` 释放。旁证 `0x1D9C34` **`ace_x_task`**、`0x1D9F38` **`builtin.zip`**。无云控开关串，无命中即空转；未见 md5/签名校验（推断）。

## 8. win_data_sync（窗口特征同步，384B）

getter `0x250F64`→单例 `0x55F290`；ctor `0x251098`：内联名 `0x91042` len8 经 `sub_252918` 解出后 `sub_4CD5C8(obj,&name)`；vtable `0x514048`；`+0x70=0x514048+0x38`、`+0x78=0x514048+0x68`（**两个运行槽**）；`sub_1DAFC0(+0x80,0)`、`sub_1DB038(+0xa0,0)`；`sub_238824(+0xc0,-1)`/`(+0xf8,-1)`/`(+0x130,-1)`；`+0x168`=0、`+0x170`=0、`+0x178` u16=0、`+0x17c`=0。槽 `+0x00 0x25114C`、`+0x08 0x2511A8`、`+0x10 0x251760`、`+0x18 0x251488`、`+0x20 0x251400`、`+0x38 0x251168`、`+0x40 0x2511E4`、`+0x48 0x251758`、`+0x50 0x227DB8`、`+0x68 0x251188`。特性接收 `+0x18=0x251488`：拼 `ob_`(45341)+`_w.zip`(58805) 下载名；侧证 `0x251264` **`win_fea_sync`**。三段式 `0x251520`：入口 `if(!x1||!x2||!*x2)return; if(!sub_252350(this))return;`（`enable_gs3` 未开即跳过）；日志 **`func=feature_rcv_start|name=%s|crc=%d|size=%d`**、`feature_ptr`、`func=feature_rcv_append|feature_ptr=%s|buf=%s`、**`func=feature_rcv_end|feature_ptr=%s|append_suc=%d`** → 云下发窗口特性包按 crc+size 校验、分片 append、按结果落盘。联动 `0x25190C` **`func=set_user_info|entry_id=%d|open_id=%s`**、`0x252350` `func=enable_gs3`、`0x2524CC` **`func=init_sdk|game_id=%u`**、`0x252AB0` `mt2_evt`、`0x251400` `gs3_init`。失败路径均 `retval=0` 早退。

## 9. inf_sca（信息扫描，80B）

`0x27FEF4` ctx=calloc(0x50)+`sub_29A600`；vtable `0x514FF8`（`+0x10=0x29A654`、`+0x30=0x1DB0B4`、`+0x38=0x29B37C`、`+0x40=0x29B194`）；`+0x48` 为 once 标志。`0x29A654`：`byte[+0x48]==0` 则置 1 并尾调 `0x29A6A0` 全扫，否则 return（全进程仅一次）。Binder 直取包信息：`0x29A758` `package`+`android.content.pm.IPackageManager`；`0x29A8F4` 手拼 Parcel `()I`/`PackageInfo`/`CREATOR`/`createFromParcel`/`readInt`/`(Landroid/os/Parcel;)...`，日志 **`binder path:%s,cert:%s`**；`0x29AC70` `signatures`/`[Landroid/content/pm/Signature;`/`toByteArray`/`()[B`；`0x29ADE0` `applicationInfo`/`sourceDir`。逐项格式 `+0x40=0x29B194`：内联 `0x9308A` len0x16 经 `sub_29B380` 解出 **`|%s:0x%08x, from_c:%d`**(602250)，`sub_5081F0(0x208)` 取缓冲后 `sub_2324E8` 追加。标签/云控 `0x29B5A0` **`user_tag:%s%d`**+`user_tag`+**`force_usertag_scan`**；`0x29B7B4` 打分行 **`name`/`cs`/`score`**；`0x29BC98` 落 `%s/ano_tmp/%s`+**`ano_uts_c2.dat`**。结果落盘待上报。

## 10. gp5（GP3/GP5 进程保护，80B）

getter `0x260BC0`→单例 `0x55F320`；vtable `0x514468`（`+0x10=0x260C68`、`+0x18=0x260D84`、`+0x30=0x4CD650`、`+0x38=0x262B34`、`+0x40=0x261E8C`）；`+0x48`=0。判据/字段 `0x260D88` **`cn.mm.gk`**+**`anti_inot_failed`**；`0x260F20` 键 `type`/`id`/`scancode`/`;`；`0x261320` **`gp5_%u`**+**`gp5_crash`**。GP3 复用 `0x2616DC`/`0x261760` `gp3`、`0x2619DC` `StartGP3`、`0x261A34` `ano_tmp`+**`g3s.dat`**+`/data/data/%s/files/%s/%s`、`0x261B04` `=`/`GP3_Getpid`/`pid=%d`、`0x261DB8` `func=GP3_Getpid`、`0x262344` **`gp3_traced`**+**`gp3_2022`**。`0x262020` 实测：`snprintf` 拼 **`/proc/%d/task`** → `sub_50E6E0` opendir → 遍历 `sub_50E670`，跳过 `d_name[0]=='.'`（`00262090` `cmp w8,#0x2e`），读 `d_name+0x13` 处线程名比对。降级：`+0x30` 为基类通用实现，`+0x48`=0 时不启动扫描；崩溃/traced 分事件名互不阻塞。

## 小结

**证据强度**：注册点/ctx 布局/虚表槽均由 `.rela.dyn` 重定位+逐槽反汇编坐实（强）；cps 家族 6 位 bitmap 与判据串落到指令级 site（强）；上报格式串（`is_frond:...`、`cp2/cp3/cp23`、`feature_rcv_*`、`WB_SyncOpenID`、`|%s:0x%08x, from_c:%d`）由「id→解密→格式化」三段对齐（强）；`0x2ADE04`、`0x2B7C1C`、`0x280618` 仅到入口+字符串层（中，已标推断）。`live` 以实测 288B 单例为准。

**设计缺陷**：①门控过度集中：云手机仅由 `cp_comm`(`0x2B54C8`)+`force_cp2_scan`(`0x2B5194`) 控制，`cp_comm` 默认 1（`002b5504` 的 `w2=1,w3=1`），云端不可达仍全量扫描，关一位则全部探测与 `cloud3_err*` 上报同时静默。②一次性标志散落对象尾部（`this+0x14a`、`this+0x14d`、`inf_sca+0x48`）无锁无版本，重扫只能重建对象；`cps_new3 +0x30` 直接是 `ret`，第三套与第二套非全集关系且版本差异不入协议。③字符串三套策略并存（内联拼名 `sub_280340`、滚动 XOR `sub_282948`、集中表 `sub_4EXXXX`），分批拼装痕迹明显，集中表泄露即半数模块裸奔。④`is_frond`（疑 `is_front` 笔误）与 `MBS_show`/`heart_cnt` 复用 `+0xb8/0xbc/0xc0`，与 `win_data_sync` 的 `+0xc0/+0xf8/+0x130` 句柄段重叠，越界即污染他人上报真值。⑤探测面与降级不对称：KVM/`rk3588_docker`/`gemini`/`CPH` 均存在性检测、无启动态或完整性复核；`cs_vm` 仅凭 `comm.dat`/`tss_cs2.dat` 是否存在决定工作，文件被清即模块消失，比被改更易漏报。⑥守护链路把域名与文案硬编码在同一函数（`0x281E44`：`acekeeper.anticheatexpert.com`+三条 `wsa_dialog_*_cn`），域名不可云控切换，单点失效即整条 keeper 链断。
