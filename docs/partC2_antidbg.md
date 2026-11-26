# libtersafe.so（ACE 12.1.1.1）反调试与内存保护 / 内存扫描机制

**总览**：ACE 不用 TRACEME 自陷，反调试分三层：① 进程内被动检测——TracerPid、stat 第 4 字段 T/t、wchan=ptrace_stop 三路互证；② 进程外主动探测——GP3/GP6 代理反向 ATTACH，用 NT_ARM_HW_BREAK/WATCH 统计硬件断点、PTRACE_SYSCALL 代理 syscall（魔数 0xBEEF00AD）；③ 页级 memtrap 与 maps/pagemap 自检。命中均经 GP3/GP4 上报，并受云控 Close* 开关约束。

## 一、ptrace 调用点全表与分工

`ptrace` 导入桩为 `0x50e6f0`（GOT 0x578a58），全库共 17 个 BL 调用点（另有 `j_.ptrace` 尾跳板），分属 11 个函数，**没有任何 `PTRACE_PEEKDATA/POKEDATA`（request 2/5）**——即 ACE 不用 ptrace 直接读写内存，改用 GP6 服务进程的 `GP6_Read`/`GP6_ReadMemory` 命令与 `/proc/<pid>/mem`。

| 调用点 | 函数 | request | 用途 |
|---|---|---|---|
| 0x262404 | sub_2623D4 | 0x10 ATTACH | 附着外部目标 pid |
| 0x262514 | sub_2623D4 | 0x4200 SETOPTIONS=14 | TRACEFORK\|TRACEVFORK\|TRACECLONE |
| 0x2625c8 | sub_2623D4 | 7 CONT | 恢复运行，透传 stop signal |
| 0x2628f0 | sub_2626C0 | 7 CONT | 事件循环内继续 |
| 0x26296c | sub_262920 | 0x11 DETACH | 解绑并清槽位 |
| 0x262b20 | sub_262AF0 | 0x11 DETACH | kill(pid,19)→waitpid→DETACH→kill(pid,18) |
| 0x269314 | sub_2692E0 | 0x4204 GETREGSET(NT=1,len=272) | 读寄存器判魔数 0xBEEF00AD |
| 0x2693c8 | sub_26937C | 0x4205 SETREGSET(NT=1) | 回写被改的寄存器 |
| 0x269424 | sub_2693EC | 0x4205 SETREGSET(0x404 NT_ARM_SYSTEM_CALL) | 改写 syscall 号 |
| 0x2698d4 | 0x269658 状态机 | 0x18 SYSCALL | 逐 syscall 停（≤0x10000 次） |
| 0x269a34 | 同上 | 0x11 DETACH | 代理结束清理 |
| 0x269a88/0x269aec/0x269b1c | sub_269A64 | 0x10 / 0x18 / 0x11 | ATTACH→waitpid(__WALL)→SYSCALL，失败即 DETACH |
| 0x26b2a0/0x26b358 | sub_26B25C | 0x10 / 0x11 | 附着指定 pid 查硬件断点后解绑 |
| 0x26b614 | sub_26B590 | 0x4204 GETREGSET(0x402/0x403) | 读硬件断点/观察点寄存器组 |
| 0x4b6b5c | j_.ptrace | — | 导入跳板，非独立检测逻辑 |

### 1.1 迷你调试器：外部进程跟踪器（0x262xxx）

`sub_2623D4(ctx,pid)` 执行 `PTRACE_ATTACH`（0x262404）→ `waitpid(pid,&st,__WALL=0x40000000)`（loc_261610）→ 返回值必须等于 pid 且 `(st&0x7F)!=0`（WIFSTOPPED）才继续 → `SETOPTIONS=14`（0x262514）→ 在 **ctx+0x70 起的 512 项 int 数组**中找空槽写入 pid → `PTRACE_CONT(7,pid,0,sig)`（0x2625c8，sig = `(st&0xFF)==0x7F ? 0 : (st>>8)&0xFF`）。

`sub_2625E8` 是事件循环：`waitpid(-1,&st,__WALL|WUNTRACED=0x40000002)`（0x262664），按 st 走 `off_52F440` 跳转表。`sub_2626C0` 判定停止信号，位掩码 **0x129D0**（SIGILL4/SIGABRT6/SIGBUS7/SIGFPE8/SIGSEGV11/SIGPIPE13/SIGSTKFLT16）→ 调 `sub_262920` 用 `PTRACE_DETACH(0x11)` 解绑并清槽；其余 `CONT(7)` 放行；`SIGSTOP(19)` 走单独分支。`sub_262AF0` 用 `kill(pid,19)`/`kill(pid,18)` 包裹 waitpid+DETACH，保证解绑不破坏目标状态。`sub_262A1C` 是同一状态机的 OLLVM 平坦化入口（`LDR W19,[X21,#0x70]` 读 pid 表，经 `off_52F510` 跳转），推测为"按表批量查找/停止被跟踪线程"。

### 1.2 GP6 syscall 代理（0x269658 状态机）

对象布局：`+0x70`=pid、`+0x74`=错误码、`+0x78`=running。跳转表 `jpt_2696BC`（off 0x52fff0）关键分支：

- case 2 @0x2696CC：写入 pid 后调 `sub_269A64`（ATTACH + waitpid(__WALL) + `SYSCALL(0x18)`）。
- case 8 @0x26979C：`waitpid(pid,&stat,__WALL)`；case 6 @0x2697DC：`TST stat,#0x7F` 判 WIFSTOPPED。
- case 18 @0x269804：取信号后 `sub_2692E0`，再 `CMP W0,#0xBEEF`（0x269820 `MOV W10,#0xBEEF`）。
- case 1 @0x269880：`sub_2693EC` 用 `NT_ARM_SYSTEM_CALL` 改 syscall 号后返回 3。
- case 16 @0x2698C4：`PTRACE_SYSCALL(0x18)`；case 15 @0x26990C：计数器与 `0x10000` 比较——**单次代理最多 65536 次 syscall 停顿**。
- case 11 @0x269A28：`DETACH(0x11)` 并清 running。

`sub_2692E0` 读 `NT_PRSTATUS`（len 272）后判 `v8==0xAD && (v7&0xFFFF0000)==0xBEEF0000`，即 **0xBEEF00AD**，命中即 `sub_26937C` 回写寄存器；`sub_2693EC` 再把 syscall 号写回（`NT_ARM_SYSTEM_CALL`，len 4）。判据（推测）：**x8/syscall 号被 ACE 用魔数打标 = 该 syscall 由代理代执行或需跳过**，处置是改号后单步放行，而不是杀进程。

## 二、TracerPid 与三种替代判据

- **主判据** `sub_263D58(pid)`：解密取 "TracerPid"（site 0x263d6c）与 `/proc/%u/status`（site 0x263de8），`snprintf(s,255,...)` 后逐行 `fgets(1024)`、`strstr` 命中键即回调 `sub_263F4C`：跳到 `\t` 后按 `v7=v3+10*v5; v5=v7-48` 解析十进制写入 out；最多扫 15 行。返回值 >0 即"被跟踪"。
- **缓存**：GP3 初始化 `sub_26439C` 里 `dword_55F344 = sub_263D58(getpid())`，把自身 TracerPid 缓存为全局量，供后续比对（避免重复读 /proc）。
- **替代一** `sub_25A5EC(obj,pid,tid)`：`/proc/%d/stat`（0x25a618）或 `/proc/%d/task/%d/stat`（0x25a62c），读到 `')'` 后取 `v24[2]`，判 `((v24[2]-84)&0xDF)==0` → 状态字符 ∈ {`'T'`(84),`'t'`(116)}，即"已停止/被跟踪"。
- **替代二** `sub_25AB10(obj,pid,tid)`：`/proc/%d/wchan`、`/proc/%d/task/%d/wchan`，用 `memmem(buf,"ptrace_stop",11)` 命中即真——**逐线程**检查是否停在 `ptrace_stop`，可发现只跟踪单线程的调试器。
- 另有 0x25A210 处内联同族实现（"/proc/%u/status" + "TracerPid"，site 0x25a248/0x25a270）与 0x290E0C（读 /proc/self/status）。

## 三、GP3 硬件断点检测（0x261B04 / 0x262020 / 0x26B25C / 0x26B590）

命令协议为 `cmd=GP3_Getpid` 形式（`sub_261B04` 用分隔符切分再 `strcmp("GP3_Getpid")`，命中回 `"pid=%d"`，site 0x261cac）。三个核心动作：

1. **枚举线程** `sub_262020(pid,out[],max)`：`/proc/%d/task`（off 24787）→ `opendir` + `readdir`，`if (d_name[0]!=46)` 跳过 `.`/`..`，`atoi(d_name)` 收 tid，返回个数。
2. **附着并查询** `sub_26B25C`：`atoi(nptr)` 从**命令字符串**取 pid → `PTRACE_ATTACH(0x10)`（0x26b2a0）；失败回 `"err=-1"`（site 0x26b2ac）；成功 `waitpid(__WALL)` → 两次 `sub_26B590`（flag=1 查 watchpoint、flag=0 查 breakpoint）→ `DETACH(0x11)`（0x26b358）。
3. **解析 debug regs** `sub_26B590`：`v7 = (flag&1) ? 1027 : 1026`，即 **0x403=NT_ARM_HW_WATCH / 0x402=NT_ARM_HW_BREAK**；`GETREGSET(0x4204,pid,v7,&iov{buf,len=264})`（0x26b614）。`buf[0]`=dbg_info；若 dbg_info ∈ [1,16] 视为异常返回 -1（`__CFADD__(lo-17,16)`）；否则 `used = buf[1]!=0` 再遍历 `i=1..n-1` 统计 `buf[2i+1]!=0`，返回已用槽数；`all = dbg_info`。

**上报**：`sub_4E8418(26028)` 组织 `"err=%d|all_wp=%d|all_bp=%d|used_wp=%d|used_bp=%d"`（site 0x26b360）→ `sub_262D88` → 封装为**消息类型 2001（0x7D1）**：`sub_262E18` 写 `[len:4][payload][time&0xFF]`，`malloc(0x1000)` + `sub_49EC04` 序列化 + `sub_24E314(...,0x1000,...)` 投递。判据即"**all>0 或 used>0 ⇒ 存在调试器/硬件断点**"，处置是上报风控而非本地杀进程（推测，未见与 kill 联动）。

## 四、prctl：VMA 命名与 memtrap

`prctl` 导入桩 0x50e5d0，全库 11 个 BL 调用点（另有 `j_.prctl` 跳板 0x4B6BB0）。关键常量：

- `PR_SET_VMA = 0x53564D41`（`MOV W0,#0x4D41` + `MOVK W0,#0x5356` @0x253cac/0x253cb8），`PR_SET_VMA_ANON_NAME = 0`，共 **7 处**：0x253CB8（memtrap_name）、0x31BD28、0x367EFC/0x367F30（sub_367960）、0x440008（sub_43FE98）、0x463584（sub_463490，紧邻 mincore 0x463BA4）、0x469378（sub_468F7C）。
- `PR_SET_DUMPABLE = 4`：0x261844（GP3 初始化，紧邻 "gp3_fork" site 0x26182c）、0x26bf98（0x26BE84 区域，附近 "ano_tmp"/"g6s.dat"/`/data/data/%s/files/%s/%s`）。
- **未发现 `PR_SET_PTRACER(0x59616D61)`**：`#0x6D61` 仅出现在 0x4FE790/0x4FEA30 的 C++ 字符串拼接（`"> typename "`），`#0x5961` 零命中。→ ACE 用 `PR_SET_DUMPABLE=1` 放开自身可被 dump/ptrace，让 GP6 子进程能附着主进程，而不是白名单声明。

**memtrap（无 SIGSEGV，纯页状态巡检）**：

- `sub_2537A8` 遍历待保护区段（`sub_4DCC88/4DCD20/4DCD28/4DCCEC` 迭代），对每页调 `(*(a1+168))(addr, pagesize, 3, 34, -1, 0)` = `mmap(addr, pagesize, PROT_READ|WRITE=3, MAP_PRIVATE|MAP_ANONYMOUS=0x22, -1, 0)`；地址非页对齐则重试（每页 ≤32 次）；第 4 页时调 `sub_253C24` → `prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, addr, len, "memtrap_name")`（site 0x253c4c）；随后 `(*(a1+192))(addr, pagesize, 4)` = `mprotect(...,PROT_EXEC)`；最后用页状态回调 `(*(a1+160))(addr,pagesize,&out)` 返回 0 且 `out==1` 的页记为"干净页"加入 `obj+136..obj+144` 数组。
- `sub_253E50` 周期性巡检该数组：对每项再调同一回调，若 `(entry_flags|ret)==0 && out==1` → 计数 `*(obj+28)++`，**计数 ≤4（即最多 5 次）**时调 `loc_267080(gp4ctx,0,0,"mem_trap",0,0,0,0)` 上报。
- 结论：memtrap 是"**给自己的匿名页改名 + 改 PROT_EXEC + 轮询页状态**"，靠页被外部读取/改写后状态翻转来发现内存扫描器或 dump 工具，命中上报 `mem_trap`；链路中无 `sigaction/SIGSEGV`（sigaction 有导入但不在该调用链）。

## 五、内存扫描：maps / pagemap / mincore / memmem

- **maps 解析** `sub_266E54(obj,pid)`：`sub_4A2610` 取文件对象 → `sub_4A2960(file, 8160, 0, 0)` 一次读 **8160 字节** maps → 行布局 `+0`=起始地址、`+4`=权限掩码、`+12`=长度、`+16`=路径；过滤 `(perm & 0x29)!=0 && (perm & 0x40000000)==0`（可读或可执行、且非"不可见"标记）。命中行的处理：路径 `strcmp("mem")`（`sub_4E94E8(12443)`）或 `*(BYTE*)(obj+71)!=0 && strstr(path,"pagemap")`（`sub_4EA144(16954)`）→ 查 `obj+32` 红黑树取已有记录，**限频 3 秒**（`time(0)-*(QWORD*)(obj+48)>=3`）后调 `loc_267080(obj,_,rec,path,(perm&8)!=0,0,1,0)`；路径等于 `"pagemap"` 时按位分派：`perm&1` → `sub_253CD0`，`perm&0x20` → `sub_253E50`（memtrap 巡检）。→ **扫描目标是自身 maps 中路径含 `mem`/`pagemap` 的映射**，用于发现 `/proc/<pid>/mem`、pagemap 类"无 root 读写"通道被打开。
- `loc_267080` 为 GP4 上报器，使用字符串 `"pagemap"`(0x266ef8)、`"mem_trap_no_root"`(0x267250)、`"kwrite"`(0x267298)、`"gp4_2"`(0x20ec60)、`"gp4_cs"`(0x266b14)、`"mem_trap"`(0x253ec0)。
- **mincore** `sub_2F1950`：`if (byte_53B9F8) result=sub_345360(a1,a2,a3); else result=mincore(a1,a2,a3);`。`sub_345360` 是内联 `svc` 的 `linux_eabi_syscall(__NR_mincore,...)`（返回值 >0xFFFFFFFFFFFFF000 时取负并走 errno 封装 `sub_2F18A8`）——**检测到 libc 被 inline hook 时可切直 syscall**（反 hook 设计）。
- 另两个 mincore 调用点 `0x463BA4`（与 VMA 命名 0x463584 同处 sub_463490 一带）与 `0x4B8930`（紧邻 `madvise` 尾跳板 0x4B891C 的通用内存封装簇 0x4B85D0–0x4B88B0）属通用页状态封装，本次未展开（推测）。
- **memmem 引擎** `sub_37048C`：懒初始化单例（qword_564878，120 字节 = 15 个函数指针）：`open/malloc/snprintf/read/lseek/memset/memcpy/memmem/strstr/strlen/free/sscanf/atoi/sleep/_android_log_print`；调用者 0x383C30/0x383EC4——特征串搜索走这套自带"libc 子集"表，便于整体替换规避 hook。

## 六、GP6 进程隔离代理

- **启动** `sub_268EE4`：反射 `android/content/Intent`(0x247f98) → `setAction("ioctl")`(0x269184) → `setPackage("%s.%s")`(0x268f60 + "GP6Service" 0x268f6c) → `putExtra(String,String)`(0x2691ec，签名 0x2691f8) → `startService`(0x269240) / `stopService`(0x269298)。包名常量 **`com.ace.gshell.GP6Service`**（site 0x2619fc，fn 0x2619DC，与 "StartGP3"/"StartGP6" 同族）。
- **命令面** `sub_269EFC` 分发 16 条：`GP6_Stop`(0x26a0f4)、`GP6_Gettid`(0x26a088)、`GP6_Open`(0x26a174)、`GP6_Close`(0x26a220)、`GP6_Read`(0x26a28c)、`GP6_Lseek`(0x26a31c)、`GP6_Readlink`(0x26a3c8)、`GP6_Access`(0x26a438)、`GP6_Stat`(0x26a4a8)、`GP6_GetRegister`(0x26a510)、`GP6_ReadMemory`(0x26a584)、`GP6_SetEscapeMode`(0x26a67c)、`GP6_Dladdr`(0x26a610)、`GP6_GetHWBPStat`(0x26a6f0)、`GP6_VMFunc0`(0x26a760)、`GP6_VMFunc1`(0x26a7bc)。参数解析 `sub_26956C`：字典取值后 `sscanf` 解 1 个 `unsigned int`，命令形如 `GP6_Gettid=<数值>`。
- **通道**：`sub_268C14` 单例（`pthread_once` dword_55F360 → `sub_268CF4`）分配 0x80 字节对象、名称 **`ace_gp6`**(25185)、vtable off_514598、`+0x70 = -1`（服务端）；`sub_269B64` 单例（dword_55F370）分配 0x78、名称 **`ace_gp6_c`**(25195)、vtable off_5145C0、`+0x70 = 1`（客户端）。两侧同名域 + 极坐标式 ±1 标志，配合 `socket/send/recv` 导入，推测为**本地 socket/共享内存的请求-应答通道**（未在字符串中发现 `sun_path` 字样，故标推测）。
- `sub_26B71C` 用 `"RunningOnGP6Child"`(0x26b788) 与 `"vm_gp6.img"`(0x26b830) 判定当前进程是否 GP6 子进程并给出内存镜像文件名；`0x26BE84` 区域以 `"ano_tmp"`/`"g6s.dat"`/`/data/data/%s/files/%s/%s` 定位 GP6 的落盘状态文件并 `prctl(4,1)`。
- 用途归纳：**主进程只做判定，重活（attach、读内存、读寄存器、查硬件断点、dladdr）全部转交给独立包名的 GP6 服务进程**——这样 ptrace 关系里被跟踪者是游戏、跟踪者是另一个"干净"进程，规避"自我 ptrace"检测与 seccomp 限制（推测）。

## 七、mrpcs：模块下发 / 指令桥

`0x1BD084` 是 >80 分支的 OLLVM 命令分发器（`MOV W0,#<串索引>` → `BL sub_4Exxxx` 解密 → `strcmp(命令串)` → `CBZ` 跳处理块，IDA 未识别为函数）。mrpcs 三条命令：

| 命令 | 索引/MOV | 解密调用 | 处理块 |
|---|---|---|---|
| `OpenMrpcsBridge` | 43981 (0xABCD) @0x1bd19c | sub_4EBF90 | loc_1BD864 |
| `MrpcsBridgeCmd` | 43999 (0xABDF) @0x1bd1b4 | sub_4ED3CC | loc_1BD8F8 |
| `CloseMrpcsBridge` | 44016 (0xABF0) @0x1bd1cc | sub_4E76A0 | 未命中继续 |

`0x219D84` 函数内的字符串给出 mrpcs 的真实语义：`"mrpcs"`(0x219fa8)、`"mrpcs.data"`(0x219a28)、`"mrpcs_abort.dat"`、`"notify mrpcs, hash:0x%08x"`、`"dl custom, name:%s, len:%d, crc:%08x, channel:%d"`(0x219f70)、`"comm.dat"`、`"comm.zip"`、`"sig5"`、`"ob_ace_gs"`。→ **mrpcs 是"模块/插件下发 + 校验 + 通知"桥**：外部（PC 助手/模拟器侧）经该桥下发带 CRC 与 sig5 签名的自定义模块（comm.dat/comm.zip 打包），SDK 侧校验后 notify hash，并提供 abort 文件中断。它不是内存读取桥（读内存由 GP6 的 `GP6_ReadMemory` 承担），标"推测"的部分仅是传输载体的具体形态。

## 八、自保护：fork 看门狗、kill 与 inotify

- **gp3_fork**：`sub_261808` 区域（字符串 `"gp3_fork"` site 0x26182c）内 `prctl(4,1)` @0x261844，紧接着 fork/子进程建立逻辑（推测：子进程继承"可被 dump"属性并作为看门狗/代理存活）。
- **kill**：`kill@@LIBC`=0x578840，**无直接 BL**，只以函数指针形式出现于 `0x25b138`（fn `sub_25AF5C`，0x3b0 字节）与 `0x28efe8`（fn `sub_28EAF4`，0xacc 字节），另有 `.kill` 桩 0x50e140。→ 杀进程/杀调试器动作由这两处经指针表发起（推测为看门狗超时处置）。
- **inotify 监控器** `sub_3F5070(path, mask)`：`if (path==NULL) return -1;` → `fd = inotify_init()`（0x3f50b0）→ `fcntl(fd, 4=F_SETFL, 0x800=O_NONBLOCK)`（0x3f50e4）→ `inotify_add_watch(fd, path, mask)`（0x3f5108 起）——**对指定路径布非阻塞 inotify 监控**，用于发现自身 so/数据文件被替换或删除。`inotify_init`=0x578d50、`inotify_add_watch`=0x578d48 仅有 PLT/GOT 引用（0x51d318）；另有 `0x266714` 读取 `/proc/sys/fs/inotify/{max_user_watches,max_queued_events,max_user_instances}`（sites 0x26674c/0x266784/0x2667bc），先探测系统限额再决定布控规模。0x4B6B5C/0x4B6BB0/0x4B6BB4/0x4B6BB8 分别是 `j_.ptrace`/`j_.prctl`/`inotify_init`/`inotify_add_watch` 的导入跳板，非独立逻辑；0x4B67CC 是 `BLR [off_568D28]` 通用间接调用 thunk（0x4B6828 只是其 RET）。
- **.text 自校验**：未在本次抽样中定位到对 `.text` 区间做 CRC 的单一函数（OLLVM 平坦化 + 分散校验），标"推测"：校验散落在各模块初始化（如 `sub_26439C` 先把 9 字节配置 `sub_262BB8(&unk_97845,9,...)` 拷入上下文并置两个开关位 `*(WORD*)(v0+2164)=257`）。

## 九、云控开关（CloseAntiProfiler 等）

同一分发器里 `Close*` 命令各自对应**上下文字节开关**，先做一次能力检查再落开关：

- `CloseAntiProfiler`：索引 46360 (0xB518)，`MOV W0,#0xB518` @0x1bdb80 → `sub_4EA800` → 命中 `loc_1BDCA4`：`sub_4E5284` 取配置对象 → `sub_4E5F10(obj,0x44)` 检查（失败记 `"!cap"`，0x91b2e）→ `sub_2DAD4C()` 取全局 SDK 上下文 → **`STRB W8,[X0,#0x3B5]`（=1）**，即 `ctx+0x3B5 = 1` 关闭 anti-profiler 模块。
- `CloseCloudPhoneScan`（0xB52C @0x1bdb98）→ `loc_1BDCD8`，同理写 **`ctx+0x3B6 = 1`**（日志标记 `"!ccps"` 0x97f23）。
- 同族：`CloseEmulatorScan`(0xB504→loc_1BDC3C)、`CloseAntiBlackModule`(0xB559)、`CloseUserTagScan`、`CloseDevInfoCollect(:)`、`CloseDevInfoCollectEx:`；另有 `EnabledConnector:`、`SetSecToken:`、`GetSdkAntiData`、`gcloud_connector_t`(0x1bd730) 等云控通道命令。
- 反向强制开关 `sub_25EC24`：`"force_antiprofiler"`(0x25ec68) 经 `sub_22DA98(sub_22D820(),"force_antiprofiler",0,1)` 读取云控布尔，为真则 `sub_25ED6C` 强制开启 anti-profiler；同时 `*(BYTE*)(a1+24)=0; *(BYTE*)(a1+25)=1` 做一次性去重。
- 处置含义：关闭模块只是**置一个"已关闭"标志字节**（`ctx+0x3B5`/`+0x3B6`），**已采集数据仍会经 GP3/GP4 通道上报**；`!cap` 日志表明存在权限/来源校验，未通过时只记日志、不阻断开关生效。

## 附：ptrace / prctl 请求码清单

| 常量 | 值 | 出现地址 | 语义 |
|---|---|---|---|
| PTRACE_TRACEME | 0 | 未使用 | 不做自陷（避免暴露） |
| PTRACE_PEEKDATA/POKEDATA | 2/5 | 未使用 | 不用 ptrace 读写内存 |
| PTRACE_CONT | 7 | 0x2625c8 / 0x2628f0 | 恢复目标 |
| PTRACE_ATTACH | 0x10 | 0x262404 / 0x26b2a0 / 0x269a88 | 反附着目标进程 |
| PTRACE_DETACH | 0x11 | 0x26296c / 0x262b20 / 0x269a34 / 0x269A28 / 0x26b358 | 安全解绑 |
| PTRACE_SYSCALL | 0x18 | 0x2698d4 / 0x269aec | syscall 单步 |
| PTRACE_SETOPTIONS | 0x4200 | 0x262514（data=14） | TRACEFORK\|VFORK\|CLONE |
| PTRACE_GETREGSET | 0x4204 | 0x269314(NT=1) / 0x26b614(0x402/0x403) | 读寄存器/硬件断点 |
| PTRACE_SETREGSET | 0x4205 | 0x2693c8(NT=1) / 0x269424(0x404) | 回写寄存器/改 syscall |
| NT_PRSTATUS | 1 | 0x269314 / 0x2693c8 | 通用寄存器组(len 272) |
| NT_ARM_HW_BREAK | 0x402 | 0x26b614 | 执行断点寄存器 |
| NT_ARM_HW_WATCH | 0x403 | 0x26b614 | 观察点寄存器 |
| NT_ARM_SYSTEM_CALL | 0x404 | 0x269424 | syscall 号(len 4) |
| PR_SET_DUMPABLE | 4 | 0x261844 / 0x26bf98 | 允许被 ptrace/dump |
| PR_SET_VMA + ANON_NAME | 0x53564D41 + 0 | 0x253CB8 等 7 处 | 给匿名映射命名 |
| PR_SET_PTRACER | 0x59616D61 | 未使用 | 未做白名单声明 |
| __WALL / __WALL\|WUNTRACED | 0x40000000 / 0x40000002 | 0x262664 等 | waitpid 等任意线程 |
