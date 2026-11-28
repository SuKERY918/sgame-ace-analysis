#!/system/bin/sh
# T3 远程验证
# 用法：t3_verify.sh <卡密>
# 返回：OK:<到期时间> 或 ERR:<原因>

CARD="$1"
[ -z "$CARD" ] && { echo "ERR:缺少卡密"; exit 1; }

# ========= 配置区（按需修改） =========
API_BASE="https://替换成你的T3接口地址"
CARD_FIELD="card"          # 卡密参数名
TIMEOUT="10"
# =====================================

# 找可用网络工具
BB=""
for p in /data/adb/modules/YUNAI_auto_2/bin/busybox-arm64-v8a \
         /data/adb/ksu/bin/busybox \
         /data/adb/magisk/busybox \
         /system/bin/busybox; do
  [ -x "$p" ] && { BB="$p"; break; }
done

URL="$API_BASE?${CARD_FIELD}=$(echo "$CARD" | sed 's/[^A-Za-z0-9@._-]//g')"

if [ -n "$BB" ]; then
  RESP=$("$BB" wget -q -O - -T "$TIMEOUT" "$URL" 2>/dev/null)
elif command -v curl >/dev/null 2>&1; then
  RESP=$(curl -s -m "$TIMEOUT" "$URL" 2>/dev/null)
else
  echo "ERR:无网络工具（busybox/curl 均不可用）"; exit 1
fi

[ -z "$RESP" ] && { echo "ERR:接口无响应"; exit 1; }

# 宽松匹配成功（适配多种返回格式）
case "$RESP" in
  *'"code":200'*|*'"code": 200'*|*'"status":"ok"'*|*'"success":true'*|*'"ok":true'*|*OK*|*ok*|*success*|*"1"*)
    # 尝试提取到期时间
    EXP=$(echo "$RESP" | grep -oE '"(expire|expires|expire_at|end_time)"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | grep -oE '"[^"]*"$' | tr -d '"')
    [ -z "$EXP" ] && EXP="未知"
    echo "OK:$EXP"
    ;;
  *)
    # 提取错误信息
    MSG=$(echo "$RESP" | grep -oE '"(msg|message|error)"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | grep -oE '"[^"]*"$' | tr -d '"')
    [ -z "$MSG" ] && MSG=$(echo "$RESP" | head -c 80)
    echo "ERR:$MSG"
    ;;
esac
