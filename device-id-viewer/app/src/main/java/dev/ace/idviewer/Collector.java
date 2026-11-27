package dev.ace.idviewer;

import android.app.ActivityManager;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.ConfigurationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.hardware.Sensor;
import android.hardware.SensorManager;
import android.hardware.camera2.CameraCharacteristics;
import android.hardware.camera2.CameraManager;
import android.media.AudioManager;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.opengl.EGL14;
import android.opengl.EGLConfig;
import android.opengl.EGLContext;
import android.opengl.EGLDisplay;
import android.opengl.EGLSurface;
import android.opengl.GLES20;
import android.os.BatteryManager;
import android.os.Build;
import android.os.StatFs;
import android.provider.Settings;
import android.system.Os;
import android.system.StructStatVfs;
import android.system.StructUtsname;
import android.util.DisplayMetrics;
import android.util.Range;
import android.util.SizeF;
import android.view.Display;
import android.view.WindowManager;
import android.webkit.WebSettings;

import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * 按 docs/devinfo_deep.md 的 ACE 17 槽 / QIMEI 注册字段 / TDM 26 字段，
 * 在普通应用权限范围内做等价采集。
 */
final class Collector {

    private static final String GAME_PKG = "com.tencent.tmgp.sgame";
    private static final String QIMEI_CACHE =
            "/data/data/" + GAME_PKG + "/files/com.tencent.qimei.sdk.QimeiSDK";

    private final Context ctx;
    private final Map<String, String> props;
    private String androidId;
    private String bootId;
    private String[] macInfo;
    private DisplayMetrics displayMetrics;

    Collector(Context context) {
        this.ctx = context;
        this.props = loadProps();
    }

    Report collect() {
        androidId = readAndroidId();
        bootId = Util.readFile("/proc/sys/kernel/random/boot_id", 128);
        macInfo = readMac();
        displayMetrics = readDisplayMetrics();

        Report report = new Report();
        report.deviceSummary = Util.nz(Build.MANUFACTURER) + " " + Util.nz(Build.MODEL)
                + " · Android " + Util.nz(Build.VERSION.RELEASE)
                + " (API " + Build.VERSION.SDK_INT + ")";

        collectOverview(report);
        collectAceSlots(report);
        collectIds(report);
        collectQimeiRegistration(report);
        collectTdm(report);
        collectNotes(report);
        return report;
    }

    // ---------------------------------------------------------------- 总览

    private void collectOverview(Report report) {
        Report.Section s = report.section("设备概览", "Build / 系统");
        s.add("厂商", Util.nz(Build.MANUFACTURER), Report.OK);
        s.add("品牌", Util.nz(Build.BRAND), Report.OK);
        s.add("型号", Util.nz(Build.MODEL), Report.OK);
        s.add("设备代号", Util.nz(Build.DEVICE), Report.OK);
        s.add("产品名", Util.nz(Build.PRODUCT), Report.OK);
        s.add("主板", Util.nz(Build.BOARD), Report.OK);
        s.add("硬件", Util.nz(Build.HARDWARE), Report.OK);
        s.add("Build ID", Util.nz(Build.ID), Report.OK);
        s.add("Build 类型 / 标签", Util.nz(Build.TYPE) + " / " + Util.nz(Build.TAGS), Report.OK);
        s.add("Fingerprint", Util.nz(Build.FINGERPRINT), Report.OK);
        s.add("Android 版本", Util.nz(Build.VERSION.RELEASE), Report.OK);
        s.add("API 级别", String.valueOf(Build.VERSION.SDK_INT), Report.OK);
        s.add("安全补丁", Util.nz(Build.VERSION.SECURITY_PATCH), Report.OK);
        s.add("支持的 ABI", join(", ", Build.SUPPORTED_ABIS), Report.OK);
        s.add("Bootloader", Util.nz(Build.BOOTLOADER), Report.OK);
        s.add("基带", Util.nz(Build.getRadioVersion()), Report.OK);
        s.add("屏幕", displayMetrics.widthPixels + "×" + displayMetrics.heightPixels
                + " @ " + displayMetrics.densityDpi + " dpi", Report.OK);
    }

    // ---------------------------------------------------------------- ACE 17 槽

    private void collectAceSlots(Report report) {
        Report.Section s = report.section("ACE 17 槽设备画像",
                "docs/devinfo_deep.md §2.2；值为普通应用权限下的等价复现");

        s.add("1  BrandErr", Util.nz(Build.BRAND), Report.OK);
        s.add("2  ModelErr", Util.nz(Build.MODEL), Report.OK);
        s.add("3  ERR（SDK_INT）", String.valueOf(Build.VERSION.SDK_INT), Report.OK);

        String[] battery = readBattery();
        s.add("4  BatteryErr", battery[0], battery[1], Report.LIMITED);

        String[] gpu = readGpu();
        s.add("5  GPUErr", gpu[0], gpu[1], Report.OK);

        s.add("6  SysMaxVolumesErr", String.valueOf(readMaxVolume()),
                "AudioManager.getStreamMaxVolume(STREAM_MUSIC)", Report.OK);
        s.add("7  （保留）", "—", "ACE 槽位表空缺", Report.NA);

        String[] camera = readCamera();
        s.add("8  CameraErr", camera[0], camera[1], Report.LIMITED);

        String[] sensor = readSensors();
        s.add("9  SensorErr", sensor[0], sensor[1], Report.LIMITED);

        String[] kernel = readKernel();
        s.add("10 KernelErr", kernel[0], kernel[1], Report.OK);

        s.add("11 FingerPrintErr", Util.nz(Build.FINGERPRINT), Report.OK);

        String radio = Build.getRadioVersion();
        s.add("12 BaseBandErr", Util.nz(radio),
                radio == null ? "Build.getRadioVersion() 返回 null" : "Build.getRadioVersion()",
                radio == null ? Report.LIMITED : Report.OK);

        String[] inode = readLibcInode();
        s.add("13 LibcInodeErr", inode[0], inode[1], Report.OK);

        String[] fs = readVendorStatfs();
        s.add("14 FileSystemErr", fs[0], fs[1], Report.OK);

        s.add("15 FileFirstTimeErr", "N/A",
                "ACE 记录其私有路径的首见时间，无公开 API 可复现", Report.NA);

        String[] apps = readAppInfo();
        s.add("16 AppInfoErr", apps[0], apps[1], Report.OK);

        s.add("17 FakeToken（x/q/Q/o）", "x:N/A;q:N/A;Q:N/A;o:N/A",
                "ACE 槽 17 实际为 fake token（docs/devinfo_deep.md §2.5）；"
                        + "xid/q16/q36/OAID 位于游戏 / TDM 私有域，普通应用不可读。"
                        + "AndroidID 仅作 o 的兜底，且 Android 8+ 按签名密钥隔离，与游戏进程内的值不同。",
                Report.LIMITED);
    }

    private String[] readBattery() {
        try {
            Intent intent = ctx.registerReceiver(null, new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
            if (intent == null) return new String[]{"N/A", "未取到 ACTION_BATTERY_CHANGED"};
            String tech = intent.getStringExtra(BatteryManager.EXTRA_TECHNOLOGY);
            int current = intent.getIntExtra("max_charging_current", Integer.MIN_VALUE);
            String currentValue;
            if (current != Integer.MIN_VALUE) {
                currentValue = String.valueOf(current);
            } else {
                BatteryManager bm = (BatteryManager) ctx.getSystemService(Context.BATTERY_SERVICE);
                long now = bm == null ? Long.MIN_VALUE
                        : bm.getLongProperty(BatteryManager.BATTERY_PROPERTY_CURRENT_NOW);
                currentValue = now == Long.MIN_VALUE
                        ? "N/A" : String.valueOf(now / 1000L);
            }
            return new String[]{Util.nz(tech, "unknown") + ":" + currentValue,
                    "ACE 为 technology:maxChargingCurrent；此处优先取同名 extra，"
                            + "缺省回落到 CURRENT_NOW（µA → mA）"};
        } catch (Throwable t) {
            return new String[]{"N/A", "读取失败: " + t.getClass().getSimpleName()};
        }
    }

    private int readMaxVolume() {
        try {
            AudioManager am = (AudioManager) ctx.getSystemService(Context.AUDIO_SERVICE);
            return am == null ? -1 : am.getStreamMaxVolume(AudioManager.STREAM_MUSIC);
        } catch (Throwable t) {
            return -1;
        }
    }

    private String[] readGpu() {
        EGLDisplay display = EGL14.eglGetDisplay(EGL14.EGL_DEFAULT_DISPLAY);
        if (display == null || display == EGL14.EGL_NO_DISPLAY) {
            return gpuFallback("eglGetDisplay 失败");
        }
        EGLContext context = null;
        EGLSurface surface = null;
        try {
            int[] version = new int[2];
            if (!EGL14.eglInitialize(display, version, 0, version, 1)) {
                return gpuFallback("eglInitialize 失败");
            }
            int[] configAttribs = {EGL14.EGL_RENDERABLE_TYPE, EGL14.EGL_OPENGL_ES2_BIT, EGL14.EGL_NONE};
            EGLConfig[] configs = new EGLConfig[1];
            int[] numConfigs = new int[1];
            if (!EGL14.eglChooseConfig(display, configAttribs, 0, configs, 0, 1, numConfigs, 0)
                    || numConfigs[0] == 0) {
                return gpuFallback("eglChooseConfig 失败");
            }
            int[] contextAttribs = {EGL14.EGL_CONTEXT_CLIENT_VERSION, 2, EGL14.EGL_NONE};
            context = EGL14.eglCreateContext(display, configs[0], EGL14.EGL_NO_CONTEXT, contextAttribs, 0);
            if (context == null || context == EGL14.EGL_NO_CONTEXT) {
                return gpuFallback("eglCreateContext 失败");
            }
            int[] surfaceAttribs = {EGL14.EGL_WIDTH, 1, EGL14.EGL_HEIGHT, 1, EGL14.EGL_NONE};
            surface = EGL14.eglCreatePbufferSurface(display, configs[0], surfaceAttribs, 0);
            if (surface == null || surface == EGL14.EGL_NO_SURFACE) {
                return gpuFallback("eglCreatePbufferSurface 失败");
            }
            if (!EGL14.eglMakeCurrent(display, surface, surface, context)) {
                return gpuFallback("eglMakeCurrent 失败");
            }
            String glVersion = GLES20.glGetString(GLES20.GL_VERSION);
            String vendor = GLES20.glGetString(GLES20.GL_VENDOR);
            String renderer = GLES20.glGetString(GLES20.GL_RENDERER);
            if (glVersion == null) return gpuFallback("glGetString 返回 null");
            return new String[]{glVersion,
                    "GL_VENDOR=" + Util.nz(vendor) + "; GL_RENDERER=" + Util.nz(renderer)};
        } catch (Throwable t) {
            return gpuFallback(t.getClass().getSimpleName());
        } finally {
            if (display != EGL14.EGL_NO_DISPLAY) {
                EGL14.eglMakeCurrent(display, EGL14.EGL_NO_SURFACE, EGL14.EGL_NO_SURFACE, EGL14.EGL_NO_CONTEXT);
                if (surface != null && surface != EGL14.EGL_NO_SURFACE) {
                    EGL14.eglDestroySurface(display, surface);
                }
                if (context != null && context != EGL14.EGL_NO_CONTEXT) {
                    EGL14.eglDestroyContext(display, context);
                }
                EGL14.eglTerminate(display);
            }
        }
    }

    private String[] gpuFallback(String reason) {
        try {
            ActivityManager am = (ActivityManager) ctx.getSystemService(Context.ACTIVITY_SERVICE);
            ConfigurationInfo ci = am == null ? null : am.getDeviceConfigurationInfo();
            String ver = ci == null ? "N/A" : ci.getGlEsVersion();
            return new String[]{"OpenGL ES " + ver,
                    "未能创建 GL 上下文（" + reason + "），改用 ConfigurationInfo 近似"};
        } catch (Throwable t) {
            return new String[]{"N/A", "GL 查询失败: " + reason};
        }
    }

    private String[] readCamera() {
        try {
            CameraManager cm = (CameraManager) ctx.getSystemService(Context.CAMERA_SERVICE);
            if (cm == null) return new String[]{"N/A", "CameraManager 不可用"};
            String[] ids = cm.getCameraIdList();
            if (ids == null || ids.length == 0) return new String[]{"0", "无摄像头"};
            StringBuilder sb = new StringBuilder();
            for (String id : ids) {
                CameraCharacteristics c = cm.getCameraCharacteristics(id);
                Integer white = c.get(CameraCharacteristics.SENSOR_INFO_WHITE_LEVEL);
                Range<Integer> ae = c.get(CameraCharacteristics.CONTROL_AE_COMPENSATION_RANGE);
                Long maxFrame = c.get(CameraCharacteristics.SENSOR_INFO_MAX_FRAME_DURATION);
                SizeF size = c.get(CameraCharacteristics.SENSOR_INFO_PHYSICAL_SIZE);
                sb.append(id).append(":white=").append(white == null ? "?" : white)
                        .append(",ae=").append(ae == null ? "?" : ae.toString())
                        .append(",maxFrame=").append(maxFrame == null ? "?" : maxFrame)
                        .append(",size=").append(size == null ? "?" : size.toString())
                        .append("; ");
            }
            return new String[]{ids.length + ":" + sb,
                    "ACE 格式为 %d:%s；此处列出每颗摄像头的等价 Camera2 特性"};
        } catch (Throwable t) {
            return new String[]{"N/A", "读取失败（可能无权限或摄像头被占用）: "
                    + t.getClass().getSimpleName()};
        }
    }

    private String[] readSensors() {
        try {
            SensorManager sm = (SensorManager) ctx.getSystemService(Context.SENSOR_SERVICE);
            if (sm == null) return new String[]{"N/A", "SensorManager 不可用"};
            List<Sensor> list = sm.getSensorList(Sensor.TYPE_ALL);
            if (list == null) return new String[]{"0:0:N/A", "getSensorList 返回 null"};
            Set<Integer> types = new HashSet<>();
            StringBuilder names = new StringBuilder();
            for (Sensor sensor : list) {
                types.add(sensor.getType());
                if (names.length() < 200) {
                    names.append(sensor.getName()).append('(').append(sensor.getType()).append(") ");
                }
            }
            return new String[]{list.size() + ":" + types.size() + ":"
                    + Util.truncate(names.toString().trim(), 220),
                    "ACE 格式为 %d:%d:%s（数量:类型数:名称摘要）"};
        } catch (Throwable t) {
            return new String[]{"N/A", "读取失败: " + t.getClass().getSimpleName()};
        }
    }

    private String[] readKernel() {
        try {
            StructUtsname u = Os.uname();
            return new String[]{u.sysname + "," + u.nodename + "," + u.release,
                    "version=" + u.version + "; machine=" + u.machine};
        } catch (Throwable t) {
            return new String[]{"N/A", "uname 失败: " + t.getClass().getSimpleName()};
        }
    }

    private String[] readLibcInode() {
        String[] paths = {"/system/lib/libc.so", "/system/lib64/libc.so"};
        for (String path : paths) {
            String out = Util.exec("ls", "-i", path);
            if (out != null) {
                String[] parts = out.trim().split("\\s+");
                if (parts.length > 0 && parts[0].matches("\\d+")) {
                    return new String[]{parts[0], "stat " + path + " 的 st_ino（ls -i 读取）"};
                }
            }
            if (Build.VERSION.SDK_INT >= 27) {
                try {
                    return new String[]{String.valueOf(Os.stat(path).st_ino),
                            "stat " + path + " 的 st_ino"};
                } catch (Throwable ignored) {
                }
            }
        }
        return new String[]{"N/A", "无法 stat /system/lib*/libc.so"};
    }

    private String[] readVendorStatfs() {
        try {
            StructStatVfs v = Os.statvfs("/vendor/");
            String value = String.format(Locale.US, "%d:%d:%08x:%08x",
                    v.f_bsize & 0xFFFFFFFFL,
                    v.f_blocks & 0xFFFFFFFFL,
                    v.f_bavail & 0xFFFFFFFFL,
                    v.f_bfree & 0xFFFFFFFFL);
            return new String[]{value,
                    "bsize:blocks:bavail:bfree；原始值 " + v.f_bsize + ":" + v.f_blocks
                            + ":" + v.f_bavail + ":" + v.f_bfree + "，按 ACE 的 %u 截断到 32 位"};
        } catch (Throwable t) {
            return new String[]{"N/A", "statvfs(/vendor/) 失败: " + t.getClass().getSimpleName()};
        }
    }

    private String[] readAppInfo() {
        try {
            PackageManager pm = ctx.getPackageManager();
            List<PackageInfo> apps = pm.getInstalledPackages(0);
            int total = apps == null ? 0 : apps.size();
            List<String> hits = new ArrayList<>();
            if (apps != null) {
                for (PackageInfo p : apps) {
                    if (p == null || p.packageName == null) continue;
                    long crc = Util.crc32(p.packageName);
                    if (crc == 394722921L || crc == 875655884L) {
                        hits.add(p.packageName);
                    }
                }
            }
            return new String[]{"apps=" + total + "; crc32命中="
                    + (hits.isEmpty() ? "无" : hits.toString()),
                    "ACE 槽 16 遍历已装应用并比对包名哈希常量 394722921 / 875655884；"
                            + "此处按 CRC32 推测复现"};
        } catch (Throwable t) {
            return new String[]{"N/A", "应用列表读取失败: " + t.getClass().getSimpleName()};
        }
    }

    // ---------------------------------------------------------------- 设备 ID

    private void collectIds(Report report) {
        Report.Section s = report.section("设备 ID（QIMEI / TDM 相关）", "本应用可见值与受限状态");

        if (androidId == null) {
            s.add("AndroidID（本应用 SSAID）", "N/A", "Settings.Secure.ANDROID_ID 读取失败", Report.NA);
            s.add("AndroidID CRC32", "N/A", null, Report.NA);
        } else {
            s.add("AndroidID（本应用 SSAID）", androidId,
                    "Android 8+ SSAID 按应用签名密钥隔离，游戏进程内读到的值与这里不同", Report.LIMITED);
            s.add("AndroidID CRC32", Util.crc32Hex(androidId),
                    "等价于 ACE 对 AndroidID 做 CRC32 后以 %x 输出（槽 17 旧分支）", Report.OK);
        }

        s.add("OAID", "不可读",
                "需厂商 MSA SDK 或系统级权限；普通应用没有公开读取接口", Report.LIMITED);
        s.add("IMEI", "不可读",
                "Android 10+ 非系统 / 非特权应用无法读取（READ_PRIVILEGED_PHONE_STATE）", Report.LIMITED);

        String serial = readSerial();
        s.add("Serial", serial,
                serial.equals("不可读")
                        ? "Build.getSerial() 对普通应用返回 unknown 或抛 SecurityException"
                        : "Build.getSerial() / Build.SERIAL", serial.equals("不可读")
                        ? Report.LIMITED : Report.OK);

        s.add("MAC", macInfo[0], macInfo[1],
                macInfo[0].equals("不可读") || macInfo[1].contains("占位值")
                        ? Report.LIMITED : Report.OK);

        s.add("QIMEI q16", "不可读",
                "游戏私有缓存: " + QIMEI_CACHE
                        + "（需 root）；或使用仓库 tools/hook_devinfo.js 在进程内读取", Report.LIMITED);
        s.add("QIMEI q36", "不可读",
                "与 q16 同源，SharedPreferences 中的 A3 / A153 缓存（需 root 或 Frida）", Report.LIMITED);
        s.add("xid", "不可读",
                "TDM / 游戏私有域，随 openid 体系由服务端分配", Report.LIMITED);

        s.add("boot_id", Util.nz(bootId),
                "每次开机变化；ACE fake token 的 bt 字段" + (bootId == null ? "（本机不可读）" : ""),
                bootId == null ? Report.NA : Report.OK);

        s.add("UUID（TDM）", "不可读", "TDM 内部生成 / 维护，无公开接口", Report.NA);
        s.add("TuringTicket", "不可读", "TDM 设备证书票据，服务端下发", Report.NA);
    }

    private String readSerial() {
        try {
            if (Build.VERSION.SDK_INT >= 26) {
                String s = Build.getSerial();
                if (s == null || s.isEmpty() || "unknown".equalsIgnoreCase(s)) return "不可读";
                return s;
            }
            return Util.nz(Build.SERIAL, "不可读");
        } catch (Throwable t) {
            return "不可读";
        }
    }

    // ---------------------------------------------------------------- QIMEI 注册

    private void collectQimeiRegistration(Report report) {
        Report.Section s = report.section("QIMEI 注册 JSON 字段",
                "docs/devinfo_deep.md §3.4；getprop 读取，设备级取值");
        addProp(s, "ro.product.brand", "注册 JSON 4 / brd");
        addProp(s, "ro.product.board", "注册 JSON 12 / bod");
        addProp(s, "ro.product.brand", "注册 JSON 13 / brd");
        addProp(s, "ro.product.device", "注册 JSON 14 / dv");
        addProp(s, "ro.product.first_api_level", "注册 JSON 15 / firstLevel");
        addProp(s, "ro.product.manufacturer", "注册 JSON 16 / manufact");
        addProp(s, "ro.product.name", "注册 JSON 17 / name");
        addProp(s, "ro.build.host", "注册 JSON 18 / package");
        addProp(s, "ro.product.model", "Build.MODEL 的系统属性");
        addProp(s, "ro.build.version.release", "Android 版本");
        addProp(s, "ro.build.version.sdk", "API 级别");
        addProp(s, "ro.build.fingerprint", "系统指纹");
        addProp(s, "ro.boot.hardware", "启动硬件");
        addProp(s, "ro.soc.model", "SoC 型号");
        addProp(s, "ro.product.cpu.abilist", "ABI 列表");
        addProp(s, "ro.build.version.security_patch", "安全补丁");
        addProp(s, "ro.build.type", "Build 类型");
        addProp(s, "ro.build.tags", "Build 标签");
        addProp(s, "ro.debuggable", "可调试标记");
        addProp(s, "ro.secure", "secure 标记");
        s.add("getprop 总数", String.valueOf(props.size()), null, Report.OK);
    }

    private void addProp(Report.Section s, String key, String meaning) {
        String value = prop(key);
        s.add(key + "  (" + meaning + ")", Util.nz(value),
                value == null ? "getprop 无此键" : null,
                value == null || value.isEmpty() ? Report.NA : Report.OK);
    }

    // ---------------------------------------------------------------- TDM 26 字段

    private void collectTdm(Report report) {
        Report.Section s = report.section("TDM 26 字段（可见部分）",
                "docs/devinfo_deep.md §4.1；私有域字段标注为受限");

        s.add("All", "—", "TDM 聚合查询名，不落到单一值", Report.NA);
        s.add("AllSyn", "—", "TDM 聚合查询名，不落到单一值", Report.NA);
        s.add("AndroidID", Util.nz(androidId),
                "本应用 SSAID；游戏侧取值不同（Android 8+ 签名密钥隔离）", Report.LIMITED);
        s.add("AppVersion", appVersion(),
                "此处为本应用版本；游戏侧为 " + GAME_PKG + " 的版本", Report.OK);
        s.add("Brand", Util.nz(Build.BRAND), Report.OK);
        s.add("BundleId", ctx.getPackageName(), "此处为本应用包名；游戏侧为 " + GAME_PKG, Report.OK);
        s.add("CpuCore", String.valueOf(Runtime.getRuntime().availableProcessors()), Report.OK);
        s.add("CpuFreq", readCpuFreq(), Report.OK);
        s.add("CPUName", readCpuName(), Report.OK);
        s.add("DataSign", "不可读", "TDM 内部签名", Report.NA);
        s.add("DeviceID", "不可读", "TDM 内部设备 ID，无公开接口", Report.LIMITED);
        s.add("IDFA", "不适用", "IDFA 为 iOS 广告标识", Report.NA);
        s.add("MacAddr", macInfo[0], macInfo[1],
                macInfo[0].equals("不可读") || macInfo[1].contains("占位值")
                        ? Report.LIMITED : Report.OK);
        s.add("Model", Util.nz(Build.MODEL), Report.OK);
        s.add("OAID", "不可读", "需厂商 MSA SDK 或系统级权限", Report.LIMITED);
        s.add("QIMEI36", "不可读", "游戏私有缓存 / 服务端下发", Report.LIMITED);
        s.add("QIMEI", "不可读", "游戏私有缓存 / 服务端下发", Report.LIMITED);
        s.add("ScreenHeight", String.valueOf(displayMetrics.heightPixels), Report.OK);
        s.add("ScreenWidth", String.valueOf(displayMetrics.widthPixels), Report.OK);
        s.add("SysVersion", "Android " + Build.VERSION.RELEASE + " (API " + Build.VERSION.SDK_INT + ")",
                Report.OK);
        s.add("TotalMem", Util.fmtBytes(readTotalMem()), Report.OK);
        s.add("TotalSpace", Util.fmtBytes(readTotalSpace()), Report.OK);
        s.add("TuringTicket", "不可读", "TDM 设备证书票据，服务端下发", Report.NA);
        s.add("UserAgent", Util.nz(readUserAgent()),
                "WebView 默认 UA；TDM 可能使用相同值", Report.OK);
        s.add("UUID", "不可读", "TDM 内部生成 / 维护", Report.NA);
        s.add("xid", "不可读", "TDM / 游戏私有域", Report.LIMITED);
    }

    private String readCpuName() {
        String hardware = cpuInfoValue("Hardware");
        String model = cpuInfoValue("model name");
        String processor = cpuInfoValue("Processor");
        LinkedHashSet<String> parts = new LinkedHashSet<>();
        if (hardware != null && !hardware.isEmpty()) parts.add(hardware);
        if (model != null && !model.isEmpty()) parts.add(model);
        if (processor != null && !processor.isEmpty()) parts.add(processor);
        if (Build.VERSION.SDK_INT >= 31 && Build.SOC_MODEL != null && !Build.SOC_MODEL.isEmpty()) {
            parts.add(Build.SOC_MODEL);
        }
        if (parts.isEmpty()) {
            return Util.nz(Build.HARDWARE) + " (" + (Build.SUPPORTED_ABIS.length > 0
                    ? Build.SUPPORTED_ABIS[0] : "?") + ")";
        }
        StringBuilder sb = new StringBuilder();
        for (String p : parts) {
            if (sb.length() > 0) sb.append(" / ");
            sb.append(p);
        }
        return sb.toString();
    }

    private String readCpuFreq() {
        long max = -1;
        for (int i = 0; i < 16; i++) {
            String v = Util.readFile("/sys/devices/system/cpu/cpu" + i
                    + "/cpufreq/cpuinfo_max_freq", 64);
            if (v == null) continue;
            try {
                long khz = Long.parseLong(v.trim());
                if (khz > max) max = khz;
            } catch (NumberFormatException ignored) {
            }
        }
        if (max <= 0) return "不可读";
        return String.format(Locale.US, "%.2f GHz (%d kHz)", max / 1000000.0, max);
    }

    private String cpuInfoValue(String key) {
        String text = Util.readFile("/proc/cpuinfo", 64 * 1024);
        if (text == null) return null;
        for (String line : text.split("\n")) {
            int idx = line.indexOf(':');
            if (idx <= 0) continue;
            if (line.substring(0, idx).trim().equalsIgnoreCase(key)) {
                return line.substring(idx + 1).trim();
            }
        }
        return null;
    }

    private long readTotalMem() {
        try {
            ActivityManager am = (ActivityManager) ctx.getSystemService(Context.ACTIVITY_SERVICE);
            ActivityManager.MemoryInfo mi = new ActivityManager.MemoryInfo();
            if (am == null) return 0;
            am.getMemoryInfo(mi);
            return mi.totalMem;
        } catch (Throwable t) {
            return 0;
        }
    }

    private long readTotalSpace() {
        try {
            return new StatFs(ctx.getFilesDir().getAbsolutePath()).getTotalBytes();
        } catch (Throwable t) {
            return 0;
        }
    }

    private String readUserAgent() {
        try {
            return WebSettings.getDefaultUserAgent(ctx);
        } catch (Throwable t) {
            return System.getProperty("http.agent");
        }
    }

    private String appVersion() {
        try {
            return ctx.getPackageManager().getPackageInfo(ctx.getPackageName(), 0).versionName;
        } catch (Throwable t) {
            return "1.0";
        }
    }

    // ---------------------------------------------------------------- 说明

    private void collectNotes(Report report) {
        Report.Section s = report.section("读取说明与限制");
        s.add("只读", "仅采集并展示，不修改任何系统标识或游戏数据", Report.OK);
        s.add("AndroidID 作用域",
                "Android 8+ SSAID 按签名密钥隔离；本应用与游戏进程读到的值不同，ACE 实际读取发生在游戏进程内",
                Report.LIMITED);
        s.add("QIMEI q16 / q36",
                "服务端下发并缓存在游戏私有目录；普通应用不可读。可在仓库 tools/hook_devinfo.js 中观察真实值",
                Report.LIMITED);
        s.add("OAID / IMEI / Serial / MAC",
                "受 Android 权限与隐私策略限制，普通应用通常只能得到占位值或异常", Report.LIMITED);
        s.add("ACE 槽位格式",
                "槽 4/8/9/15 等按 docs/devinfo_deep.md 的格式做等价复现，不保证与 ACE 字节级一致",
                Report.LIMITED);
        s.add("槽 16 哈希",
                "包名 CRC32 与常量 394722921 / 875655884 的比对为推测复现，真实哈希算法未确认",
                Report.LIMITED);
    }

    // ---------------------------------------------------------------- 基础读取

    private Map<String, String> loadProps() {
        Map<String, String> map = new HashMap<>();
        String dump = Util.exec("getprop");
        if (dump == null) return map;
        for (String line : dump.split("\n")) {
            int sep = line.indexOf("]: [");
            if (line.startsWith("[") && sep > 1 && line.endsWith("]")) {
                String key = line.substring(1, sep);
                String value = line.substring(sep + 4, line.length() - 1);
                map.put(key, value);
            }
        }
        return map;
    }

    private String prop(String key) {
        String v = props.get(key);
        if (v != null) return v;
        v = Util.exec("getprop", key);
        return (v == null || v.isEmpty()) ? null : v;
    }

    private String readAndroidId() {
        try {
            return Settings.Secure.getString(ctx.getContentResolver(), Settings.Secure.ANDROID_ID);
        } catch (Throwable t) {
            return null;
        }
    }

    private String[] readMac() {
        String mac = null;
        try {
            WifiManager wm = (WifiManager) ctx.getApplicationContext()
                    .getSystemService(Context.WIFI_SERVICE);
            WifiInfo wi = wm == null ? null : wm.getConnectionInfo();
            if (wi != null) mac = wi.getMacAddress();
        } catch (Throwable ignored) {
        }
        if (mac == null || mac.isEmpty()) {
            mac = Util.readFile("/sys/class/net/wlan0/address", 64);
        }
        if (mac == null || mac.isEmpty()) {
            try {
                NetworkInterface ni = NetworkInterface.getByName("wlan0");
                byte[] hw = ni == null ? null : ni.getHardwareAddress();
                if (hw != null) {
                    StringBuilder sb = new StringBuilder();
                    for (byte b : hw) {
                        if (sb.length() > 0) sb.append(':');
                        sb.append(String.format(Locale.US, "%02X", b & 0xFF));
                    }
                    mac = sb.toString();
                }
            } catch (Throwable ignored) {
            }
        }
        if (mac == null || mac.isEmpty()) {
            return new String[]{"不可读", "Android 6+ 对普通应用隐藏 Wi-Fi MAC"};
        }
        boolean masked = "02:00:00:00:00:00".equalsIgnoreCase(mac);
        return new String[]{mac,
                masked ? "系统返回了随机化占位值 02:00:00:00:00:00" : "WifiInfo / sysfs 读取"};
    }

    private DisplayMetrics readDisplayMetrics() {
        DisplayMetrics dm = new DisplayMetrics();
        try {
            WindowManager wm = (WindowManager) ctx.getSystemService(Context.WINDOW_SERVICE);
            Display display = wm == null ? null : wm.getDefaultDisplay();
            if (display != null) {
                display.getRealMetrics(dm);
                return dm;
            }
        } catch (Throwable ignored) {
        }
        return ctx.getResources().getDisplayMetrics();
    }

    private static String join(String sep, String[] arr) {
        if (arr == null) return "N/A";
        StringBuilder sb = new StringBuilder();
        for (String s : arr) {
            if (sb.length() > 0) sb.append(sep);
            sb.append(s);
        }
        return sb.toString();
    }
}
