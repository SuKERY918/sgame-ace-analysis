#!/system/bin/sh
# =====================================
# 🔒 Protected by YUNAI Crypt Engine v2
# =====================================
P1='H4sIAAAAAAAAA61T30/TUBR+719xKGTRB1bREB8MJEvqwx7EBKOJMabp2jvapOtt+mPgGxiBMYeiIBBWEBBxIWEkkhDZBvwvZrfdnvgXvG1JdVmMTL0PTc/N+b7vnu+c09/HWS8sG+W4jKpzlsL0w8i1D032DxfI+ax/XPfrH0m1RGYrZOmIFOn3zWWj5B1XyOzntjvd2p+Jcjx3kRR3/I1XkOZ702IepZ7c50dYThZtkRPlDCejvCohwTIwziJTyIuag6ykhPUsy/DjDwQ+Pd6RbuZUOcpmmfjppLpAFpe7C2AmFVVD8AzYgRsTyDZMbAB1KpnB2BYknDM0ZCP5Jgt9I8AOsfD8HsiYAXosDSEDhhgZ64iJgjuBXmQGpHTZxKpM6wfyvkROL8i7YmCGmqVig1mqFxYaMtoK0kPOZHwdhuGHZuv0OjXGjz9M80I6gEAiARaybVWfsMBwbBpIjolAjEQFqtuJuD0a2MjpjqZ1kP6JT84j01Yten/F+Xd0ExrOiBqlE0TxdzwhUT+QRo0UTsiM6x3uNr9NN2vlZmOjdVQnb1d9l7ZuK83TsbpqZG3FX6nQAWyvf6XpfmOZHK6HPGIOstiU0KBl04bSPiajKVLlZF5Fk8jsKqEbMaWKWBH1GNkByapMrzsUDRzQkQVSLXjFvdZF2a+8vmwUWl8+kbljr3BAyuft+dL3addzD1oXS60d+r9Jy22vVdu765eNhd40o1kL/L7ak85po0/af+ltuc2z7WBTo8WRRZTDOngr58StNGtzXmWHbK5526d+uUrOPoTAeIZ/bl0Oy46GLO7p47FUWhAdGwu3uV8ZO6WDIykUBHeHh6EHmhitY8UxekHCKMTto61MDEEiJkOSgmGgj6bEVnERKmmoMtvhVuwMhFLgrc436ydk75R2LkxE2nX9CYP/5VI3WW9edeP/1TG6I8GaoCnVhls/AIftQcSCBgAA'
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
