#!/system/bin/sh
MODDIR=${0%/*}
[ -d "$MODDIR" ] || MODDIR=/data/adb/modules/YUNAI_auto_2

# 1) 反调试检测：只跳过开机脚本，不再删除自身模块
#    （原版 detect 到就直接 rm -rf 整个模块目录，重启后模块会凭空消失）
if grep -q "frida" /proc/self/maps 2>/dev/null || grep -q "^TracerPid:[[:space:]]*[1-9]" /proc/self/status 2>/dev/null; then
    echo "[YUNAI] debugger/frida detected at $(date), skip boot scripts" >> /data/local/tmp/yunai_guard.log 2>/dev/null
    exit 1
fi

# 2) 解密 token 落盘（原来的 export 只在当前进程有效，等于没做）
if [ -f "$MODDIR/identity.token.enc" ] && command -v openssl >/dev/null 2>&1; then
    openssl enc -d -aes-256-cbc -pbkdf2 -in "$MODDIR/identity.token.enc" -k "YUNAI_2024_VIP" \
        > /data/adb/YUNAI_TOKEN 2>/dev/null && chmod 600 /data/adb/YUNAI_TOKEN 2>/dev/null
fi

exit 0
