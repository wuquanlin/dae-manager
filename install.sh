#!/bin/sh
# Local bundle installer. No eval, remote shell scripts, or unverified binaries.
set -eu
umask 077
BASE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
STATE=/etc/dae-manager
LISTEN=127.0.0.1:2025
LAN=
SOURCE=
START=0
RESUME=0
CORE_VERSION=v2.1.1
HELPER_VERSION=v1.19.33
for argument in "$@"; do
 case "$argument" in
  --source=*) SOURCE=${argument#*=};;
  --listen=*) LISTEN=${argument#*=};;
  --lan=*) LAN=${argument#*=};;
  --dae-version=*) CORE_VERSION=${argument#*=};;
  --helper-version=*) HELPER_VERSION=${argument#*=};;
  --start) START=1;;
  --resume) RESUME=1;;
  -h|--help) printf '%s\n' '用法: sh install.sh --source=/root/config.yaml [--lan=br-lan] [--listen=127.0.0.1:2025] [--start]' '默认安装并启动管理后台；核心由菜单手动启动。--start 会启用并启动核心。'; exit 0;;
  *) printf '未知参数: %s\n' "$argument" >&2; exit 1;;
 esac
done
[ "$(id -u)" = 0 ] || { echo '请使用 root 或 sudo 运行。' >&2; exit 1; }
[ "$(uname -s)" = Linux ] || { echo 'dae 核心仅支持 Linux。' >&2; exit 1; }
[ -n "$SOURCE" ] && [ -f "$SOURCE" ] || { echo '请提供 --source=/绝对路径/config.yaml' >&2; exit 1; }
if [ -f "$STATE/settings.json" ]; then
 [ "$RESUME" -eq 1 ] && [ -f "$STATE/INSTALLING" ] || { echo '已经初始化。中断安装可用 --resume；正常更新请用菜单。' >&2; exit 1; }
fi
case "$(uname -m)" in
 x86_64) ARCH=amd64;; aarch64|arm64) ARCH=arm64;; armv7*) ARCH=armv7;; armv6*) ARCH=armv6;; armv5*) ARCH=armv5;; i?86) ARCH=386;;
 mipsel) ARCH=mipsle;; mips64el) ARCH=mips64le;;
 mips|mips64)
  ELF=/bin/sh; [ ! -f /bin/busybox ] || ELF=/bin/busybox
  ENDIAN=$(od -An -tu1 -j5 -N1 "$ELF" | tr -d ' ')
  if [ "$(uname -m)" = mips64 ]; then ARCH=mips64; else ARCH=mips; fi
  [ "$ENDIAN" != 1 ] || ARCH=${ARCH}le;;
 *) echo '安装包暂未包含此 CPU 架构。可按 README 从源码编译。' >&2; exit 1;;
esac
BIN="$BASE/bin/dae-manager-linux-$ARCH"
PROBE="$BASE/bin/dae-helper-linux-$ARCH"
[ -f "$PROBE" ] || { echo "缺少 dae-helper，请使用完整发布包。" >&2; exit 1; }
[ -f "$BIN" ] || { printf '缺少 %s，请使用完整发布包。\n' "$BIN" >&2; exit 1; }
command -v sha256sum >/dev/null || { echo '缺少 sha256sum，无法校验安装包。' >&2; exit 1; }
(cd "$BASE" && sha256sum -c SHA256SUMS) || { echo '安装包校验失败。' >&2; exit 1; }
chmod 755 "$BIN"
if [ -f /etc/openwrt_release ] && [ -x /sbin/procd ]; then INIT=procd
elif command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then INIT=systemd
else echo '当前仅支持 procd 或 systemd；其他 Linux 可使用源码和自己的 supervisor。' >&2; exit 1; fi
for EXISTING in /etc/init.d/dae-managed /etc/init.d/dae-manager /etc/systemd/system/dae-managed.service /etc/systemd/system/dae-manager.service /usr/local/bin/dae /usr/local/bin/dae-manager /usr/local/bin/daectl /usr/local/lib/dae-manager/mihomo /usr/local/lib/dae-manager/dae-helper; do
 if [ "$RESUME" -eq 1 ] && [ -f "$STATE/INSTALLING" ]; then continue; fi
 [ ! -e "$EXISTING" ] || { printf '检测到已有文件 %s，拒绝覆盖。请按 README 处理现有安装。\n' "$EXISTING" >&2; exit 1; }
done
if [ -z "$LAN" ] && command -v uci >/dev/null 2>&1; then LAN=$(uci -q get network.lan.device || true); fi
echo '正在检测系统、内核及 eBPF 条件…'
"$BIN" doctor
KERNEL=$(uname -r | cut -d- -f1); MAJOR=$(printf '%s' "$KERNEL" | cut -d. -f1); MINOR=$(printf '%s' "$KERNEL" | cut -d. -f2)
if [ "$MAJOR" -lt 5 ] || { [ "$MAJOR" -eq 5 ] && [ "$MINOR" -lt 17 ]; }; then echo '内核过旧；请先安装支持 dae 的固件或升级 Linux 内核。不会自动刷机。' >&2; exit 1; fi
if [ "$START" -eq 1 ] && [ ! -r /sys/kernel/btf/vmlinux ]; then echo '尚未发现标准 BTF，拒绝自动启动。先安装匹配当前内核的 vmlinux-btf/兼容固件，再通过菜单检查。' >&2; exit 1; fi
mkdir -p /usr/local/bin /usr/local/lib/dae-manager "$STATE" /tmp/dae-manager
chmod 700 "$STATE" /tmp/dae-manager
touch "$STATE/INSTALLING"
cp "$BIN" /usr/local/bin/dae-manager.new
mv /usr/local/bin/dae-manager.new /usr/local/bin/dae-manager
chmod 755 /usr/local/bin/dae-manager
cp "$PROBE" /usr/local/lib/dae-manager/dae-helper
chmod 755 /usr/local/lib/dae-manager/dae-helper
cp "$BASE/menu.sh" /usr/local/bin/daectl
chmod 755 /usr/local/bin/daectl
if [ ! -f "$STATE/settings.json" ]; then /usr/local/bin/dae-manager --state "$STATE" init --source "$SOURCE" --listen "$LISTEN" --lan "$LAN"; fi
if [ -d "$BASE/personal/cache" ]; then
 mkdir -p "$STATE/cache"
 cp -R "$BASE/personal/cache/." "$STATE/cache/"
 find "$STATE/cache" -type f -exec chmod 600 {} \;
fi
echo '下载官方 dae 核心（版本固定，可通过参数选择），校验 SHA-256…'
if [ ! -x /usr/local/bin/dae ]; then /usr/local/bin/dae-manager --state "$STATE" core --arch "$ARCH" --version "$CORE_VERSION"; fi
echo '下载 MRS 解码辅助程序；它只参与格式转换，不作为第二个代理启动…'
if [ ! -x /usr/local/lib/dae-manager/mihomo ]; then /usr/local/bin/dae-manager --state "$STATE" helper --arch "$ARCH" --version "$HELPER_VERSION"; fi
echo '拉取节点与规则集，转换并执行 dae 原生校验…'
/usr/local/bin/dae-manager --state "$STATE" prepare
if [ "$INIT" = procd ]; then
 cp "$BASE/services/dae-manager.procd" /etc/init.d/dae-manager
 cp "$BASE/services/dae-managed.procd" /etc/init.d/dae-managed
 chmod 755 /etc/init.d/dae-manager /etc/init.d/dae-managed
 /etc/init.d/dae-manager enable
 /etc/init.d/dae-manager start
 if [ "$START" -eq 1 ]; then /etc/init.d/dae-managed enable; /etc/init.d/dae-managed start; fi
else
 cp "$BASE/services/dae-manager.service" /etc/systemd/system/dae-manager.service
 cp "$BASE/services/dae-managed.service" /etc/systemd/system/dae-managed.service
 systemctl daemon-reload
 systemctl enable --now dae-manager.service
 if [ "$START" -eq 1 ]; then systemctl enable --now dae-managed.service; fi
fi
rm -f "$STATE/INSTALLING"
printf '\n%s\n' '安装完成。运行 daectl 进入菜单。' "后台监听: $LISTEN" "口令: $STATE/admin-token" '默认只监听回环地址，请通过 SSH 隧道访问。网络/DNS 接入与验收步骤见 README。'
