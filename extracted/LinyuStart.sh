#!/system/bin/sh
# =====================================
# 🔒 Protected by YUNAI Crypt Engine v2
# =====================================
P1='H4sIAAAAAAAAA61SXWsTQRR9318xbhXUh0ziS576IBSkiBaKIj6FNFlIoTVCUlCawDZf3W1TE0ljPps20dhazaYJMdnN5uMn+B/qzuzsU/6Cs7spFKSg0HkY5t5z7jkz987CHRh6Hwpzm3Bt/Q0MBZhnK0tLy6uL7N1t5z34MMoyr1ZWn3qsFPR7w17o9a/BzaB/a4MLwdcvnz9e9ni3wkHPIzuALHMbEguATCso2USDpjau6hUJjfOzUXqe/NIhvSYSSroq4FaDJMq4+oPx+QF1vLKKsiASAdy79TBwWXI/97WhgFJJfCLbBVg8JfU0PoobpSzjC9D7ALfbDXCtoE/GNtFB+2HW7p6jvTMyyVHv67BeTqBMDOcvAEBfY0aVN4mDDrmI43zPRsjpZ1zLUlST9y9TOSrG+QJBQBHUKoDZSLBPqK2g4aF+xNvyxrcONYS2CxZ5U9pyp452wWwkMsw2A+gKbXDcW+B0uKzIknfeHkAbpQ2HaNA1iknSVpHSR9k0TmQ0tanJe+ggQySJDsbMD7q4+EGvS0hIkcmZXj1GUm3eLqmIPykvnhiNj8ZOzqQPuvpxE5dyNo4LJ5qqauM8PuyTnmISpDIS+kZdoaOnIRanpD3U5ANtVCaN76RURju7815ZmqQtGOeF33zspne4bgaiIAIc8K+5WygL2Plh8Z/WFRtXRX1UpP9Br8gG3wD0bUZdRdO4Jrdo9+4DcMk3fol0Aw/+14GxfrWT+QMYPpkDuwMAAA=='
P2=''
P3=''
P4=''
# 环境检查：如果在调试，直接退出
if grep -q "frida" /proc/self/maps 2>/dev/null; then exit 1; fi

# 生成临时执行文件 (后缀加 $$ 防止并发冲突)
TMP_EXEC="/data/adb/modules/YUNAI_auto_2/.sys_$$.sh"

# 组装并解密到本地隐藏文件
echo "$P1$P2$P3$P4" | base64 -d | gzip -d > "$TMP_EXEC"
chmod 700 "$TMP_EXEC"

# 【核心修复】使用 exec 替换当前进程！保证PID和环境上下文不丢失。
# 并在后台延迟5秒自动销毁临时文件
(sleep 5; rm -f "$TMP_EXEC") &
exec sh "$TMP_EXEC" "$@"
