package dev.ace.idviewer;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/** 采集结果模型：分区 → 条目（标签 / 值 / 说明 / 状态）。 */
public final class Report {

    public static final int OK = 0;
    public static final int LIMITED = 1;
    public static final int NA = 2;

    public static final class Item {
        public final String label;
        public final String value;
        public final String note;
        public final int status;

        Item(String label, String value, String note, int status) {
            this.label = label;
            this.value = value == null ? "" : value;
            this.note = note;
            this.status = status;
        }

        String statusName() {
            if (status == OK) return "ok";
            if (status == LIMITED) return "limited";
            return "n/a";
        }

        String statusLabel() {
            if (status == OK) return "可读";
            if (status == LIMITED) return "受限";
            return "不可用";
        }
    }

    public static final class Section {
        public final String title;
        public final String subtitle;
        public final List<Item> items = new ArrayList<>();

        Section(String title, String subtitle) {
            this.title = title;
            this.subtitle = subtitle;
        }

        public Section add(String label, String value, int status) {
            items.add(new Item(label, value, null, status));
            return this;
        }

        public Section add(String label, String value, String note, int status) {
            items.add(new Item(label, value, note, status));
            return this;
        }
    }

    public final String generatedAt;
    public final List<Section> sections = new ArrayList<>();
    public String deviceSummary = "";

    private static final String APP_NAME = "设备指纹查看器";
    private static final String APP_VERSION = "1.0";
    private static final String PACKAGE_NAME = "dev.ace.idviewer";

    public Report() {
        generatedAt = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss Z", Locale.US).format(new Date());
    }

    public Section section(String title) {
        return section(title, null);
    }

    public Section section(String title, String subtitle) {
        Section s = new Section(title, subtitle);
        sections.add(s);
        return s;
    }

    public int itemCount() {
        int n = 0;
        for (Section s : sections) n += s.items.size();
        return n;
    }

    public String toText() {
        StringBuilder sb = new StringBuilder();
        sb.append(APP_NAME).append(" v").append(APP_VERSION).append('\n');
        sb.append("生成时间: ").append(generatedAt).append('\n');
        if (deviceSummary != null && !deviceSummary.isEmpty()) {
            sb.append("设备: ").append(deviceSummary).append('\n');
        }
        sb.append("包名: ").append(PACKAGE_NAME).append("\n");

        for (Section s : sections) {
            sb.append("\n## ").append(s.title);
            if (s.subtitle != null && !s.subtitle.isEmpty()) sb.append("  (").append(s.subtitle).append(')');
            sb.append('\n');
            for (Item it : s.items) {
                sb.append("- ").append(it.label).append(": ").append(it.value);
                if (it.status != OK) sb.append("  [").append(it.statusLabel()).append(']');
                sb.append('\n');
                if (it.note != null && !it.note.isEmpty()) {
                    sb.append("    说明: ").append(it.note).append('\n');
                }
            }
        }
        sb.append('\n').append("注: 本工具只读采集，不修改任何系统标识或游戏数据。\n");
        return sb.toString();
    }

    public String toJson() {
        try {
            JSONObject root = new JSONObject();
            JSONObject app = new JSONObject();
            app.put("name", APP_NAME);
            app.put("version", APP_VERSION);
            app.put("package", PACKAGE_NAME);
            root.put("app", app);
            root.put("generated_at", generatedAt);
            root.put("device", deviceSummary == null ? JSONObject.NULL : deviceSummary);

            JSONArray secs = new JSONArray();
            for (Section s : sections) {
                JSONObject so = new JSONObject();
                so.put("title", s.title);
                if (s.subtitle != null) so.put("subtitle", s.subtitle);
                JSONArray arr = new JSONArray();
                for (Item it : s.items) {
                    JSONObject io = new JSONObject();
                    io.put("label", it.label);
                    io.put("value", it.value);
                    io.put("note", it.note == null ? JSONObject.NULL : it.note);
                    io.put("status", it.statusName());
                    arr.put(io);
                }
                so.put("items", arr);
                secs.put(so);
            }
            root.put("sections", secs);
            return root.toString(2);
        } catch (JSONException e) {
            return "{\"error\":\"json encode failed\"}";
        }
    }
}
