package dev.ace.idviewer;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.ContentValues;
import android.content.Intent;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.util.TypedValue;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends Activity {

    private LinearLayout container;
    private TextView statusView;
    private Button refreshBtn;
    private Button copyBtn;
    private Button exportBtn;
    private Button shareBtn;

    private Report report;
    private final ExecutorService io = Executors.newSingleThreadExecutor();
    private volatile boolean loading;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        container = (LinearLayout) findViewById(R.id.container);
        statusView = (TextView) findViewById(R.id.status);
        refreshBtn = (Button) findViewById(R.id.btn_refresh);
        copyBtn = (Button) findViewById(R.id.btn_copy);
        exportBtn = (Button) findViewById(R.id.btn_export);
        shareBtn = (Button) findViewById(R.id.btn_share);

        refreshBtn.setOnClickListener(v -> load());
        copyBtn.setOnClickListener(v -> copyReport());
        exportBtn.setOnClickListener(v -> exportReport());
        shareBtn.setOnClickListener(v -> shareReport());

        copyBtn.setEnabled(false);
        exportBtn.setEnabled(false);
        shareBtn.setEnabled(false);
        load();
    }

    private void load() {
        if (loading) return;
        loading = true;
        refreshBtn.setEnabled(false);
        statusView.setTextColor(0xFF7D8FA3);
        statusView.setText("正在采集设备信息…");
        container.removeAllViews();

        io.execute(() -> {
            Report result = null;
            String error = null;
            try {
                result = new Collector(getApplicationContext()).collect();
            } catch (Throwable t) {
                error = t.getClass().getSimpleName() + ": " + t.getMessage();
            }
            final Report rep = result;
            final String err = error;
            runOnUiThread(() -> {
                if (isFinishing() || isDestroyed()) return;
                loading = false;
                refreshBtn.setEnabled(true);
                if (rep == null) {
                    statusView.setTextColor(0xFFFF6B6B);
                    statusView.setText("采集失败: " + err);
                    return;
                }
                report = rep;
                render(rep);
                copyBtn.setEnabled(true);
                exportBtn.setEnabled(true);
                shareBtn.setEnabled(true);
            });
        });
    }

    private void render(Report rep) {
        container.removeAllViews();
        for (Report.Section section : rep.sections) {
            addSection(section);
        }
        statusView.setTextColor(0xFF37D0A0);
        statusView.setText("已采集 " + rep.itemCount() + " 项 · "
                + new SimpleDateFormat("HH:mm:ss", Locale.US).format(new Date()));
    }

    private void addSection(Report.Section section) {
        TextView header = new TextView(this);
        header.setText(section.title);
        header.setTextSize(13f);
        header.setTextColor(0xFF37D0A0);
        header.setTypeface(Typeface.DEFAULT_BOLD);
        header.setPadding(dp(3), dp(18), dp(3), dp(4));
        container.addView(header);

        if (section.subtitle != null && !section.subtitle.isEmpty()) {
            TextView sub = new TextView(this);
            sub.setText(section.subtitle);
            sub.setTextSize(10f);
            sub.setTextColor(0xFF6B7A8C);
            sub.setPadding(dp(3), 0, dp(3), dp(6));
            container.addView(sub);
        }

        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackgroundResource(R.drawable.bg_card);
        card.setPadding(dp(12), dp(2), dp(12), dp(2));
        card.setClipToOutline(true);

        for (int i = 0; i < section.items.size(); i++) {
            addRow(card, section.items.get(i), i == section.items.size() - 1);
        }
        container.addView(card, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
    }

    private void addRow(LinearLayout card, final Report.Item item, boolean last) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.VERTICAL);
        row.setPadding(dp(2), dp(10), dp(2), dp(10));

        TypedValue tv = new TypedValue();
        if (getTheme().resolveAttribute(android.R.attr.selectableItemBackground, tv, true)) {
            row.setBackgroundResource(tv.resourceId);
        }
        row.setClickable(true);
        row.setOnClickListener(v -> {
            copyToClipboard(item.label, item.value);
            Toast.makeText(this, "已复制: " + item.label, Toast.LENGTH_SHORT).show();
        });

        TextView label = new TextView(this);
        label.setText(item.label);
        label.setTextSize(11f);
        label.setTextColor(0xFF8FA3B8);
        row.addView(label);

        TextView value = new TextView(this);
        value.setText(item.value);
        value.setTextSize(13f);
        value.setTypeface(Typeface.MONOSPACE);
        value.setTextColor(statusColor(item.status));
        value.setLineSpacing(dp(2), 1f);
        LinearLayout.LayoutParams valueLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        valueLp.topMargin = dp(3);
        row.addView(value, valueLp);

        if (item.note != null && !item.note.isEmpty()) {
            TextView note = new TextView(this);
            note.setText(item.note);
            note.setTextSize(10f);
            note.setTextColor(0xFF6B7A8C);
            note.setLineSpacing(dp(1), 1f);
            LinearLayout.LayoutParams noteLp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            noteLp.topMargin = dp(4);
            row.addView(note, noteLp);
        }

        card.addView(row, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        if (!last) {
            View divider = new View(this);
            divider.setBackgroundColor(0xFF1B2632);
            card.addView(divider, new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, dp(1)));
        }
    }

    private int statusColor(int status) {
        if (status == Report.OK) return 0xFFE6EDF3;
        if (status == Report.LIMITED) return 0xFFF0B429;
        return 0xFF7D8FA3;
    }

    private void copyReport() {
        if (report == null) return;
        copyToClipboard("device-fingerprint", report.toText());
        Toast.makeText(this, "完整报告已复制", Toast.LENGTH_SHORT).show();
    }

    private void copyToClipboard(String label, String value) {
        ClipboardManager cm = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
        if (cm != null) cm.setPrimaryClip(ClipData.newPlainText(label, value));
    }

    private void exportReport() {
        final Report rep = report;
        if (rep == null) return;
        statusView.setText("正在导出…");
        io.execute(() -> {
            String stamp = new SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(new Date());
            String txtName = "device_fingerprint_" + stamp + ".txt";
            String jsonName = "device_fingerprint_" + stamp + ".json";
            final String p1 = saveDownload(txtName, "text/plain", rep.toText());
            final String p2 = saveDownload(jsonName, "application/json", rep.toJson());
            runOnUiThread(() -> {
                if (isFinishing() || isDestroyed()) return;
                statusView.setTextColor(0xFF37D0A0);
                statusView.setText("已导出 " + stamp);
                Toast.makeText(this, p1 + "\n" + p2, Toast.LENGTH_LONG).show();
            });
        });
    }

    private String saveDownload(String name, String mime, String content) {
        byte[] data = content.getBytes(StandardCharsets.UTF_8);
        if (Build.VERSION.SDK_INT >= 29) {
            try {
                // 使用字符串 URI / 列名，避免在 API 24 上解析 MediaStore.Downloads 新类
                Uri collection = Uri.parse("content://media/external/downloads");
                ContentValues values = new ContentValues();
                values.put("_display_name", name);
                values.put("mime_type", mime);
                values.put("relative_path", Environment.DIRECTORY_DOWNLOADS + "/DeviceFingerprint");
                values.put("is_pending", 1);
                Uri uri = getContentResolver().insert(collection, values);
                if (uri != null) {
                    OutputStream os = getContentResolver().openOutputStream(uri);
                    if (os != null) {
                        os.write(data);
                        os.close();
                    }
                    ContentValues done = new ContentValues();
                    done.put("is_pending", 0);
                    getContentResolver().update(uri, done, null, null);
                    return "下载/DeviceFingerprint/" + name;
                }
            } catch (Throwable ignored) {
            }
        }
        try {
            File dir = getExternalFilesDir("exports");
            if (dir == null) dir = new File(getFilesDir(), "exports");
            if (!dir.exists() && !dir.mkdirs()) return "保存失败（无法创建目录）";
            File file = new File(dir, name);
            FileOutputStream fos = new FileOutputStream(file);
            fos.write(data);
            fos.close();
            return file.getAbsolutePath();
        } catch (Throwable t) {
            return "保存失败: " + t.getClass().getSimpleName();
        }
    }

    private void shareReport() {
        if (report == null) return;
        try {
            Intent intent = new Intent(Intent.ACTION_SEND);
            intent.setType("text/plain");
            intent.putExtra(Intent.EXTRA_SUBJECT, "设备指纹报告");
            intent.putExtra(Intent.EXTRA_TEXT, report.toText());
            startActivity(Intent.createChooser(intent, "分享设备指纹报告"));
        } catch (Throwable t) {
            Toast.makeText(this, "分享失败: " + t.getClass().getSimpleName(), Toast.LENGTH_SHORT).show();
        }
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        io.shutdownNow();
    }
}
