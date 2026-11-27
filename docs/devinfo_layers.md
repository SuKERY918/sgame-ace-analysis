# 设备标记机制分层分析（12.1.1.1）

本文是 `devinfo_deep.md` 的续篇与校正：把「设备标记」拆成六层，逐层给出采集面、落地位置、上报形态与稳定性，并修正旧文档中三处与二进制不符的结论。

地址均为 `libtersafe.so`（MD5 `e06344e0b5f6b09d13820c625fa3a123`）、`libqimei.so`（MD5 `62bb50c92d64eb5160ecce4cdfed63e5`）的镜像内偏移。工具见 `tools/dex_devkeys.py`、`tersafe_devkeys.py`、`qimei_table_audit.py`、`qimei_table_decode.py`、`qimei_string_xref.py`。

---

## 0. 结论

1. **设备标记不是"读一个硬件号"**，而是「系统标识 → MSDK 汇聚 → QIMEI 服务端主键 → ACE 交叉校验」的四段收敛，中间夹着 TDM、TGPA 两条旁路。
2. **IMEI、序列号、Widevine 设备 ID 在本包都没有被读取**：前两者缺 `READ_PHONE_STATE`（且 targetSdk 30 的 Android 10+ 限制），后者是字典残留、符号解析路径不存在。
3. **QIMEI 的 q16/q36 由服务端签发**（`https://snowflake.qq.com/ola/v2` 的 `A3`/`A153`），客户端只做采集、缓存、上报；本地没有可复现的生成算法。
4. **Java 侧把标识送进 QIMEI 的唯一入口是 MSDK** 的 `sensitive_json_info`；同一条 JSON 同时写 Beacon 与 QimeiStrategy，共 8 个键。
5. **QIMEI 还有一条远程 JS 指纹通道**：云端 `fp.js`/`my.html` 在 WebView 里执行，结果加密后经 `javascript:window.qimeiCallback('<hex>')` 回传。
6. **TDM 不读硬件**：`GetDeviceID` 返回 `"Unknown"`、`GetMacAddress` 返回 `"TDM_NULL"`、`TDataSign = MD5(android_id)`（大写、未补零）。
7. **ACE 的 `Fake_Token_TDM_info` 有四个子键**：`xid`、`QiMaM`(q16)、`QIMEI36`(q36)、`OsEz`(oaid)，拼成 `x:%s;q:%s;Q:%s;o:%s` 再包 `bt:<boot_id>;bd:<brand>`。
8. **XID 来自 TGPA**：`SharedPreferences("tgpa").getString("XID","")`，长度必须 64 的 hex。
9. **ACE 的 IMEI 相关串全是日志格式**，`imei_ex` 是留给 Java 的注入槽，而本包 Java 侧无调用者。
10. 稳定性由服务端保证：本地可改的是 android_id/OAID/Build/`/proc`，改不了的是 q16/q36 与 TEE 侧的 Widevine ID（而后者未被使用）。

---

## 1. 分层总览

```
系统层    android_id  OAID(厂商/MSA)  boot_id  Build.*  /proc  /sys
          IMEI / Serial / Widevine ID ── 无权限或未实现，读不到
                │                    │
汇聚层    MSDK sensitive_json_info    TGPA/MGPA(XID,OAID)
                │                    │
主键层    QIMEI q16/q36（服务端）     tgpa.xml(XID 64hex)
                │                    │
旁路      TDM(tdm_cache.%d.dat)  ─────┘
                │
校验层    libtersafe：17 槽 + Fake_Token_TDM_info + imei_ex + boot_id
```

---

## 2. 系统层：拿得到与拿不到

| 标识 | 可获得性 | 依据 |
|---|---|---|
| `android_id` | 可读 | `Settings.Secure.getString(cr,"android_id")`，QIMEI/TDM/MSDK 三处均有 |
| OAID | 可读（厂商 provider） | OPPO `com.heytap.openid.*`、荣耀 `com.hihonor.cloudservice.oaid.IOAIDService`、魅族 `content://com.meizu.flyme.openidsdk/`、努比亚 `content://cn.nubia.identity/identity`、vivo `content://com.vivo.vms.IdProvider/IdentifierId/OAID`、`com.android.id.impl.IdProviderImpl` |
| `boot_id` | 可读 | `/proc/sys/kernel/random/boot_id`（QIMEI 与 ACE 都读） |
| Build/内核/inode | 可读 | QIMEI 注册 JSON、ACE 17 槽 |
| IMEI | **读不到** | 清单 68 条权限无 `READ_PHONE_STATE`；`TelephonyManager.getDeviceId()` 调用点全部 catch `SecurityException` |
| 序列号 | **读不到** | Android 10+ 无 `READ_PRIVILEGED_PHONE_STATE` 即不可读，代码里也没有调用 |
| Widevine 设备 ID | **未使用** | 见 §4.2 |

---

## 3. 汇聚层

### 3.1 MSDK：唯一闸门

`classes2.dex`：

- `Lcom/itop/gcloud/msdk/api/sensitive/MSDKSensitiveHelper;-><clinit>`：`PARAMS_LIST = {"AndroidID","Imei","Apn"}`。
- 数据来自 `MSDKWare`：`sensitive_json_info`、`sensitive_could_collect`（与字面量 `"true"` 比较）、`sensitive_collect_cache`。
- `Lcom/itop/gcloud/msdk/report/BeaconReport;-><init>` 固定顺序：

```
MSDKSensitive.registerSensitiveObserver(this)
IT.getConfig("BEACON_APP_KEY_ANDROID","")
QimeiSDK.getInstance(appKey).getStrategy().setUserAgreePrivacy(false)
setCouldCollectSensitiveInfo(getCouldCollectSensitiveInfo())
setSensitiveInfo(getSensitiveInfo())
```

- `setSensitiveInfo(String json)` 逐键 `has()` 后**双写**：

| JSON 键 | Beacon | QIMEI |
|---|---|---|
| `UserAgreePrivacy` | — | `setUserAgreePrivacy(z)`，z = 可采集 && 开关 |
| `AndroidID` | `setAndroidID` | `setAndroidId` |
| `WiFiMacAddress` | `setMac` | `setMAC` |
| `Imei` | `setImei` | `setIMEI` |
| `Model` | `setModel` | `setBuildModel` |
| `Oaid` / `Imsi` / `Cid` | 同名 setter | 同名 setter |

- 写侧来自 JS 桥：`Lcom/itop/gcloud/msdk/pixui/core/sensitive/MSDKSensitive` → `JSMessageDefine$SensitiveMethod` → `MSDKPIXMessageUtils.sendMsgToJs("","msdkpix-sensitive",map)`；`global-metadata.dat` 的 `0xb59b93` 附近有 C# 适配器 `SetSensitiveInfo`/`setSensitiveInfoAdapter`。

结论：本包**不存在第二条**把 IMEI/MAC/OAID 写进 QIMEI 的 Java 路径；实际有没有值，取决于注入的 JSON。

### 3.2 TGPA / MGPA

- `Lcom/itop/gcloud/msdk/tools/MSDKDeviceInfo;->getXid()`：内存 `deviceInfoMap["xid"]` → `getSharedPreferences("tgpa",0).getString("XID","")`，**仅 length()==64 接受**，日志 `Get xid success:` / `Start getting xid`。
- `Lcom/ihoc/mgpa/deviceid/DeviceIDHelper`（`1.0.3`）：`getOAID(Context,IDeviceIDGetter[,VendorType])`、`getOAIDOnce`、`registerTool`；`IDType={UNKOWN,UDID,OAID,VAID,AAID}`，`VendorType` 11 项（HUAWEI/HONOR/XIAOMI/BLACKSHARK/VIVO/OPPO/ONEPLUS 及小写变体）。
- 任务面：`Lcom/ihoc/mgpa/gradish/u2;->run` 的 `Task_OAID`/`Task_XID`，`gradish/t3;->c` 的 `XIDV8`。

---

## 4. 主键层：QIMEI

### 4.1 双栈

| 栈 | Java | native | 备注 |
|---|---|---|---|
| 主 QIMEI | `Lcom/tencent/qimei/sdk/QimeiSDK;`（SDK `2.1.2.126`） | `libqimei.so`（`JNI_OnLoad`@`0xa108`，注册类 `com/tencent/qimei/uin/U`） | MSDK/Beacon 主用 |
| TDM QIMEI | `com.tdatamaster.qimei.TDMQimei`（反射） | `libtdmbeaconid.so`（`Lcom/tencent/tdm/qimei/beaconid/U` → `loadLibrary("tdmbeaconid")`） | TDM 自用 |

两者不互相调用：`com.tencent.qimei.sdk.IQimeiSDK.getQimei` 的调用者只有 Beacon/MSDK 侧（`QimeiWrapper`、`QmspModule`）。

### 4.2 采集面与死区

字典位置：`libqimei.so` 偏移 `0x6CFA4`，长度 `0x24FD`（9469），398 条，格式 `u16 len + u8 key + cipher`，明文 `= cipher ^ ((key + i*0x53) & 0xff)`。

`tools/qimei_table_audit.py` 的结果：

```
表记录数: 398  取串点: 279  唯一偏移: 235  覆盖记录: 235
未被引用记录: 163
死区块：
  0x0000-0x01da  30     0x022c-0x02e6  7    0x0339-0x07b5  51
  0x0b16-0x0b67   4     0x0c20-0x0cb0 10    0x0d41-0x0f34  26
  0x0f94-0x1262  28     0x12a7-0x12a7  1    0x17d2-0x1812   5
```

其中 `0x0F94–0x1262` 这一块值得单独看：

```
0x0f94 minitouchagent        0x0fa6 minicapagent       0x0fb6 scrcpy
0x0fc0 /data/local/tmp/minitouch                    0x0fdd /data/local/tmp/minicap
0x101a /sdcard/eagleeye      0x102e scrcpy-server.jar  0x1053 yyds.py
0x106e io.appium.settings    0x1099 scrcpyTouch.apk    0x10c1 aibot.client
0x113f deviceUniqueId        0x1151 libmediandk.so      0x1163 AMediaDrm_createByUUID
0x117d AMediaDrm_getPropertyByteArray                0x119f AMediaDrm_release
0x11b4/0x11d6/0x11f8 /sys/block/mmcblk0/device/{type,name,cid}
0x1219 ro.serialno           0x1228 freeifaddrs        0x1237 getifaddrs
0x1245 /sys/class/net/%s/address                     0x1262 /sys/devices/virtual/net/%s/address
```

**必须区分两件事**：

- 就「字符串没有被直接取用」而言，这些记录确实没有 `mov w1,#imm` 形式的取串点；但该统计不覆盖「寄存器/循环间接取串」，所以**不能仅凭它断言整块代码是死的**（同一块里的 minitouch/scrcpy 路径在旧版文档中被动态验证为有效，说明存在其它取串方式或历史版本差异）。
- 就 **Widevine 不可能被调用** 而言，有独立且更强的证据：`libqimei.so` 的 `DT_NEEDED` 只有 `libandroid/liblog/libz/libm/libdl/libc`，**没有 `libmediandk.so`**；而全库 `dlopen` 桩 `0x91A0` 只有 1 个调用点 `0x41F24`、`dlsym` 桩 `0x9020` 只有 1 个调用点 `0x41F78`，只解析 `__system_property_read`(`0x1440`) 与 `__system_property_find`(`0x57`)。没有 `dlopen("libmediandk.so")`，就取不到 `AMediaDrm_*` 函数指针，字典里那 5 条串在本包里就是**不可达的遗留项**。

### 4.3 注册与下发

- `Lcom/tencent/qimei/x/b;->p(I,String)`：POST `application/json` → `https://snowflake.qq.com/ola/v2`（测试 `https://test.snowflake.qq.com/ola/v2`），参数 `0`、`452`；`Lcom/tencent/qimei/x/a` 解析 `{error,body,msg}`，头字段 `ic`/`em`。
- 响应 `A3` → q16、`A153` → q36（旧文档已记录，本次复核一致）。
- 落盘：`files/com.tencent.qimei.sdk.QimeiSDK` = `base64(16 B)`，32 位 hex 是这 16 字节的十六进制展开。

### 4.4 本地存储

| 载体 | 名称/键 | 证据 |
|---|---|---|
| SharedPreferences | `QV1` + 两字段拼接 | `Lcom/tencent/qimei/aa/f;->a()` |
| SharedPreferences | `beacon`（标记 `V1`，密钥 `BEACONDEFAULTAES`，`ISO8859-1`） | `Lcom/tencent/qimei/aa/e;->a(Context,String)` |
| SP 键 | `q16`/`q36`/`qimei`/`qimei36` | classes3 串表 |
| SP 键 | `hm_md_tm`/`js_md_tm`/`lc_fe_tm`/`lc_fe_st_hm` | `Lcom/tencent/qimei/aw/a` |
| 目录 | `files/jsfile/` | `aw/a;-><init>` |

### 4.5 WebView 远程 JS 指纹

1. `Lcom/tencent/qimei/aw/a;-><init>(Context,String,...)`：缓存目录 `getFilesDir().getAbsolutePath() + "/jsfile/"`。
2. `aw/a;->a(Z)` 读 SP `hm_md_tm`，构造 `Lcom/tencent/qimei/w/a("https://tun-cos-1258344701.file.myqcloud.com/my.html", ...)`，由 `Lcom/tencent/qimei/t/a;->a(Runnable)` 调度；`aw/a$a;->a` 另有 `.../fp.js`。
3. 回传：`Lcom/tencent/qimei/ac/d;->b(String)` 用字面量 `"35b4cfe6f7eae7acbd7bace522d0db54".getBytes()` 调 `U.a([B,[B)[B` 加密再转 hex；`ac/d;->a(String)` 拼 `javascript:window.qimeiCallback('<hex>')`，目标是 `android.webkit.WebView` 或 `com.tencent.smtt.sdk.WebView` 时 `loadUrl`。
4. `aw/a;->b(Z)` 读 `js_md_tm` 摘要，`aw/a;->a(...)` 写 `lc_fe_tm`。

含义：q16 的输入包含**云端下发的 JS 在 WebView 里采到的浏览器指纹**，维度随 `fp.js` 热更新，静态无法穷举。

### 4.6 native 能力

`libqimei.so` 导入含 `socket/bind/connect/getaddrinfo/inet_ntoa/listen/recv/send` 与 `dlopen/dlsym/dlclose`、`__system_property_get`。即原生层可自建 TCP，不依赖 Java HTTP；与 `partI_siblings.md` 的「有 socket 但无硬编码 host」一致，此处补充完整导入面。

### 4.7 反 Hook 名单

字典 `0x0b67` = `1,Telephony,getDeviceId;2,Telephony,getSubscriberId;3,SystemProperties,get;4,WifiInfo,getMacAddress;5,Settings$Secure,getString;6,WifiInfo,getSSID;7,WifiInfo,getBSSID;`。这是**被检查是否被 hook 的 API 清单**（入口字节比对），不是采集清单——出现 `getDeviceId` 恰恰说明它预期别人会调。

---

## 5. TDM

`Lcom/tdatamaster/tdm/device/DeviceInfoCollect`（classes2）：

| 方法 | 实现 |
|---|---|
| `GetAndroidID` | `Settings.Secure.getString(cr,"android_id")`，失败日志 `GetAndroidID Fail, ` |
| `GetDeviceID` | 直接 `new DeviceInfo("Unknown", 3)` |
| `GetMacAddress` | 直接返回 `"TDM_NULL"` |
| `GetTDataSign` | `MD5(android_id)`，逐字节 `Integer.toHexString(b&0xff)` 拼接后 `toUpperCase(Locale.ENGLISH)`；异常 → `"Unknown"` |
| `GetQIMEI`/`GetQIMEI36` | 反射 `com.tdatamaster.qimei.TDMQimei`，配置键 `TEST_MODE`/`APP_ID`/`APP_VERSION`(`1.24.001.1967`)/`QIMEI_ENABLE` |
| 其余 | Brand/Model/AppVersion/BundleId/CPUCores/CPUMaxFreqKHz/CPUName/SysVersion/ScreenW/H/TotalMemory/TotalSpace/UserAgent |

注意 `GetTDataSign` 的 hex 转换**不补零**，长度可能小于 32。

缓存文件：`libTDataMaster.so` 明文 `tdm_cache.%d.dat`（文件偏移 `0x2E8524`），旁边是构建路径 `/Users/bkdevops/DevopsAgent/agent/workspace/p-9df4cdec05f242e39586807895cf0514/src/Project/TDM/Source/TDataMaster.cpp`。

TDM 的 q16/q36 生命周期键族（classes3）：`KEY_DATA_ENABLE_Q16/Q36`、`KEY_PARAMS_Q16/Q36`、`REPORT_DATA_Q16/Q36`、`REPORT_CLONE_CACHE_Q16/Q36`、`REPORT_CLONE_CACHE_NEW_Q16/NEW_Q36`、`REPORT_COLLECT_RATE_Q16/Q36`、`REPORT_QM_CHANGE_OLD_Q16/Q36`——换发、克隆缓存、采集率都在服务端决策。

`libtdmbeaconid.so`（98,712 B，MD5 `de35d1d4356949288e2d7bacfd5ed7b0`）明文只有一个标识键 `android_id`（`0x15606`）与 JNI 类路径；**没有** `qimei`/`imei` 独立明文（旧版此处曾把类路径子串误判为明文键）。

---

## 6. 校验层：ACE

### 6.1 17 槽

见 `partD_devinfo.md`（1 Brand / 2 Model / 3 SDK_INT / 4 Battery / 5 GPU / 6 MaxVolume / 7 缺 / 8 Camera / 9 Sensor / 10 Kernel / 11 Fingerprint / 12 BaseBand / 13 LibcInode / 14 FileSystem / 15 FileFirstTime / 16 AppInfo / 17 AndroidId 或 OAID）。调度函数 `0x2C9D78` 为 CFF 平坦化（跳表 `0x538860`），拼装 `0x2C8CBC`，槽 17 先 `sub_489248`（CRC32）再 `%x`。

### 6.2 槽 17 取值顺序（`0x2CC6C4`）

```
root = 0x22D820()
if has("ft_oaid"):                       # idx 58581
    v = extract("OsEz")                  # idx 51420，OAID
    if v == "Unknown"(34159) or empty:   # strcmp 0x4A46C0
        → android_id 分支
else: has("fake_token_androidid")        # idx 50001 → android_id
```

### 6.3 Fake_Token_TDM_info（`0x2CCD20`）

```
name = "Fake_Token_TDM_info"   # idx 51374
obj  = get_or_create(name)     # 0x22DA98(root, name, 1, 1)
x    = extract(obj,"xid")      # idx 51396
q    = extract(obj,"QiMaM")    # idx 51402
Q    = extract(obj,"QIMEI36")  # idx 51410
o    = extract(obj,"OsEz")     # idx 51420
snprintf(buf, "x:%s;q:%s;Q:%s;o:%s", x,q,Q,o)   # idx 50303
```

`QiMaM`=q16、`OsEz`=OAID 是混淆别名。三个名字（`Fake_Token_TDM_info`/`QiMaM`/`OsEz`）在 12 个 so 与 6 个 dex 的**明文中都不存在**，只存在于 libtersafe 的加密串表；因此写入方不是 Java 明文常量，也不是 `libTDataMaster` 的明文常量。旧文档「来源是 TDM 写入的文件」缺少证据——`libTDataMaster` 只有 `tdm_cache.%d.dat`，没有这三个键；实际写入点未定位（CFF + 间接调用）。

### 6.4 IMEI 相关串

| idx | 串 | 引用 | 语义 |
|---|---|---|---|
| 6114 | `imei:` | 无 | 日志标签 |
| 6122 | `ImeiEx:%s` | 无 | 日志格式 |
| 6134 | `SImei:%s` | `0x2DEB80`→`0x2DEBC8` | 日志格式（`snprintf` 后接 `0x1F0148` 日志函数） |
| 6424 | `imei_eq` | 无 | 比较键 |
| 8400 | `imei_ex` | `0x2C3118`→`0x2C35DC` | `key:value` 注入槽 |

Java 侧对应注入 API 是 `Lcom/tencent/tp/m;->d(String)` = `a("*#06#:" + imei)`，**全 dex 调用者为 0**；`*#06#` 在 native 侧 0 命中。即 ACE 预留了 IMEI 上报能力，本包没有喂值。

### 6.5 其它设备标识词表

| idx | 串 | 引用 |
|---|---|---|
| 10427 | `iAppMachOUUID:%.2X...`（16 B，5-2-2-2-6） | 无 |
| 10512 | `iAppMachUUID:%.2X...` | 无 |
| 31922 / 39446 / 39459 / 39411 / 52998 | `AndroidId` / `ANDROID_ID` / `AndroidId:%s` / `AndroidID_Enabled` / `AndroidIdErr` | 39446 → `0x2496E4`；其余无 |
| 32034 / 43272 / 43779 / 43866 | `MacAddress` / `Mac` / `mac_tp` / `mac` | 43272 → `0x280688`；43779 → `0x280C3C`；43866 → `0x24EBD4` |
| 57396 / 57640 | `com.cph.bluetooth_mac` / `ro.com.cph.mac_address` | 无 |
| 24877 | `/libmsaoaidsec.so` | `0x264038`（APK 内不含该 so） |
| 34468 | `tdm_cache.dat` | `0x4E4B2C` |
| 32413 | `root=%d\|x86=%d\|apk_cnt=%d\|adb=%d\|machine=%s\|sys_ver=%s\|root_record=%d` | `0x4CBB2C` |

---

## 7. Beacon 与其它 SDK

- Beacon（191 类）：`QmspModule` 日志 `[qmsp] init qmsp qimei qimei16: %s, qimei36: %s`；`BeaconConfig.toString` 含 `, imei='`/`, imei2='`/`, oaid='`/`, androidID='`；`RequestType` 有 `QIMEI`；`QimeiWrapper`/`onQimeiDispatch` 负责取主键。字段是**槽位**，本包的值由 §3.1 决定。
- Turing FD：108 类全混淆，只做环境指纹（`/proc/self/{maps,mountinfo,status}`、`/proc/%d/cmdline`、`framework-res.apk`、`BATTERY_CHANGED`）；`libturinggame.so` 明文无标识键。
- oaid2：`IVendorCallback`/`VM`/`VendorChecker`(+12 内部类)/`VendorManager`，厂商分发用的 OAID 客户端；`VM` 无 Java 调用者。
- GCloudCore：`Lcom/gcore/abase/GCloudCoreSystem;->GetUdid(Context)Ljava/lang/String;` 读 `android_id`，是另一条 UDID 通道（与 provider 框架相关）。
- GameMatrix：`Lcom/tencent/gamematrixsdk/msg/DeviceInfo;->parseFromJson` 含 `imei`，云游戏消息结构，不构成采集。

---

## 8. 跨通道 join

```
android_id ─┬─→ TDataSign = MD5(android_id)
            ├─→ QIMEI 注册 JSON
            ├─→ ACE 槽 17（无 OAID 时，CRC32 后）
            ├─→ GCloudCore GetUdid
            └─→ Unity deviceUniqueIdentifier → deviceUniqueIdentifierHashCode

oaid ───────┬─→ QIMEI 维度 setOAID
            ├─→ Beacon/ReportKey.oaid
            └─→ ACE 槽 17（ft_oaid → OsEz）

q16/q36 ────┬─→ Beacon 每条事件
            ├─→ TDM（GetQIMEI/GetQIMEI36）
            └─→ ACE Fake_Token（QiMaM/QIMEI36）

xid ────────┬─→ MSDK getXid
            └─→ ACE Fake_Token（xid）
```

ACE 包内唯一的 join 点是 `Fake_Token_TDM_info`：把 TGPA 的 xid、QIMEI 的 q16/q36、系统的 OAID 压成一个字符串，再加 `bt:<boot_id>;bd:<brand>`。四路里任一路与其它路矛盾，就是服务端可判的风控信号。

---

## 9. 稳定性

| 标识 | 重装 | 清数据 | 恢复出厂 | 刷机 | 改机 |
|---|---|---|---|---|---|
| android_id | 不变 | 不变 | 变 | 变 | 可改 |
| OAID | 不变 | 不变 | 变 | 变 | 可改（厂商校验签名） |
| TDataSign | 不变 | 不变 | 变 | 变 | 跟随 android_id |
| q16/q36 | 不变（缓存） | 丢缓存重新注册 | 可能不变 | 可能换发 | 无法本地伪造 |
| XID | 视 TGPA | 可能丢 | 变 | 变 | 可改 xml |
| ACE 槽 1–16 | 不变 | 不变 | 部分变 | 变 | 多数可改 |
| Widevine ID | — | — | — | — | 未使用 |

---

## 10. 对既有文档的校正

| 旧结论 | 校正 |
|---|---|
| `qimei.md:175`：QIMEI 用 `AMediaDrm_createByUUID`+`getPropertyByteArray` 取 Widevine 设备唯一 ID | 本包不成立：无 `libmediandk` NEEDED，`dlopen` 仅解析两个 `__system_property_*`，5 条串不可达 |
| `devinfo_deep.md:19`：`Fake_Token_TDM_info` 来源是 TDM 写入 | 存疑：该名与 `QiMaM`/`OsEz` 在 12 so + 6 dex 明文 0 命中，`libTDataMaster` 只有 `tdm_cache.%d.dat` |
| `partI_siblings.md`：TDM 采集 OAID/QIMEI/IMEI/序列号/位置 | 需限定：字段存在，但 `GetDeviceID`=`"Unknown"`、`GetMacAddress`=`"TDM_NULL"`，是占位而非读取 |
| `devinfo_deep.md:66`：IMEI 由 Java 以 `imei_ex` 传入 | 方向正确，本包无调用者（`m.d` 调用数 0） |
| README 结论 8 把 Widevine 列为 libqimei 的检测项 | 降级为"字典遗留条目" |

新增（旧文档未覆盖）：

1. QIMEI 的 WebView 远程 JS 指纹链与 `qimeiCallback` 回传。
2. MSDK `sensitive_json_info` 闸门与"双写 Beacon + QIMEI"的 8 键映射，以及 `<init>` 先 `setUserAgreePrivacy(false)`。
3. `Fake_Token_TDM_info` 的四个子键与别名 `QiMaM`/`OsEz`。
4. TDM `tdm_cache.%d.dat` 与构建路径。
5. `iAppMachUUID`/`iAppMachOUUID` 的 16 字节 UUID 格式化。
6. Unity 侧 `deviceUniqueIdentifierHashCode` 埋点与 GCloudCore `GetUdid`。

---

## 11. 复现

```bash
# QIMEI 字典与取串点覆盖（死区）
python tools/qimei_table_decode.py libqimei.so 0x6CFA4 0x24FD qimei_strings.txt
python tools/qimei_table_audit.py  libqimei.so 0x6CFA4 0x24FD 0x1EFB8

# dex 侧标识键归属
python tools/dex_devkeys.py <dex目录>

# ACE 设备键与引用点连接
python tools/tersafe_devkeys.py docs/strings.tsv docs/strings_usage.tsv
```

`libtersafe` 侧关键反汇编：

```
0x2CCD20  Fake_Token 组装（xid/QiMaM/QIMEI36/OsEz → x:..;q:..;Q:..;o:..）
0x2CC6C4  槽 17（ft_oaid → OsEz → fake_token_androidid）
0x2DEB80  SImei:%s 日志行
0x4E4B2C  tdm_cache.dat 路径构造
0x264038  /libmsaoaidsec.so
```

---

## 12. 未解

1. `Fake_Token_TDM_info` 的写入点（CFF + 间接调用）。
2. `iAppMachUUID`/`iAppMachOUUID` 的 16 字节输入源。
3. QIMEI 是否存在第二张表/第二套取串器（`devinfo_deep.md` 提到的 `0x2B9D4` 尚未与 `0x1EFB8` 打通）。
4. 云端 `fp.js` 的指纹维度（需动态抓取）。
5. 本文所有"运行时行为"均为静态推断，未做真机验证。
