#!/bin/sh
set -eu
MANAGER=/usr/local/bin/dae-manager
while :; do
 printf '\n%s\n' '┌──────────── 大鹅管家 ────────────┐' ' 1. 查看运行状态' ' 2. 启动 dae' ' 3. 停止 dae' ' 4. 按设置重新应用配置' ' 5. 更新订阅节点' ' 6. 更新节点及规则集' ' 7. 校验当前配置' ' 8. 检查系统兼容性与冲突' ' 9. 列出配置备份版本' '10. 恢复配置版本' '11. 查看近期核心日志' '12. 查看管理后台地址及登录口令' '13. 启用核心开机自启' '14. 关闭核心开机自启' ' 0. 退出' '└─────────────────────────────────┘'
 printf '请选择: '; read -r choice
 case "$choice" in
  1) "$MANAGER" ctl status || true;;
  2) "$MANAGER" ctl service start || true;;
  3) "$MANAGER" ctl service stop || true;;
  4) "$MANAGER" ctl service reload || true;;
  5) "$MANAGER" ctl update || true;;
  6) "$MANAGER" ctl update rules || true;;
  7) "$MANAGER" ctl validate || true;;
  8) "$MANAGER" doctor || true;;
  9) "$MANAGER" ctl revisions || true;;
  10) printf '输入完整版本 ID: '; read -r rev; "$MANAGER" ctl rollback "$rev" || true;;
  11) "$MANAGER" ctl logs || true;;
  12) printf '%s\n' '监听设置在 /etc/dae-manager/settings.json' '默认用 SSH 隧道访问 http://127.0.0.1:2025' '管理口令（勿分享）:'; cat /etc/dae-manager/admin-token;;
  13) "$MANAGER" ctl service enable || true;;
  14) "$MANAGER" ctl service disable || true;;
  0) exit 0;;
  *) echo '请输入菜单中的数字。';;
 esac
done
