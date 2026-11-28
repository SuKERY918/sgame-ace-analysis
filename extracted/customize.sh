#!/system/bin/sh
SKIPUNZIP=0
ui_print "- 设置文件权限"
set_perm_recursive $MODPATH 0 0 0755 0644
for f in $MODPATH/*.sh; do
  [ -f "$f" ] && set_perm "$f" 0 0 0755
done
[ -d $MODPATH/YUNAI ] && set_perm_recursive $MODPATH/YUNAI 0 0 0755 0755
[ -d $MODPATH/bin ] && set_perm_recursive $MODPATH/bin 0 0 0755 0755
ui_print "- 完成，重启生效"
