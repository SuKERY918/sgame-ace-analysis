package dev.ace.idviewer;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.zip.CRC32;

final class Util {

    private Util() {
    }

    static String nz(String s) {
        return nz(s, "N/A");
    }

    static String nz(String s, String fallback) {
        return (s == null || s.trim().isEmpty()) ? fallback : s;
    }

    static long crc32(String s) {
        CRC32 crc = new CRC32();
        crc.update(s.getBytes(StandardCharsets.UTF_8));
        return crc.getValue();
    }

    static String crc32Hex(String s) {
        return String.format(Locale.US, "%08x", crc32(s));
    }

    static String fmtBytes(long bytes) {
        if (bytes <= 0) return "N/A";
        double gb = bytes / 1024.0 / 1024.0 / 1024.0;
        return String.format(Locale.US, "%.2f GB", gb);
    }

    /** 执行系统命令，失败返回 null。 */
    static String exec(String... cmd) {
        Process process = null;
        try {
            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(true);
            process = pb.start();
            String out = readAll(process.getInputStream());
            process.waitFor();
            return out.trim();
        } catch (Throwable t) {
            return null;
        } finally {
            if (process != null) process.destroy();
        }
    }

    private static String readAll(InputStream in) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) != -1) bos.write(buf, 0, n);
        return new String(bos.toByteArray(), StandardCharsets.UTF_8);
    }

    static String readFile(String path, int maxBytes) {
        File f = new File(path);
        if (!f.canRead()) return null;
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(f);
            byte[] data = new byte[maxBytes];
            int n = fis.read(data);
            if (n <= 0) return "";
            return new String(data, 0, n, StandardCharsets.UTF_8).trim();
        } catch (Throwable t) {
            return null;
        } finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (IOException ignored) {
                }
            }
        }
    }

    static String truncate(String s, int max) {
        if (s == null) return null;
        return s.length() <= max ? s : s.substring(0, max) + "…";
    }
}
