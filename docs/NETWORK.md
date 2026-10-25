# 网络接入与恢复

## 安装器的职责

安装器部署管理器与 dae，注册 `dae-manager` 和 `dae-managed` 两个服务，默认只启动管理器。网络网关、DNS、转发和 NAT 由管理员按拓扑配置。其他代理服务必须先停止或隔离，不能同时接管相同流量。

推荐先用独立 Linux 虚拟机和一台测试客户端。容器共享宿主内核，不能通过更换容器镜像补齐 BPF/BTF 能力。PVE 虚拟机也必须检查来宾内核与 LAN 桥接设置。

## DNS 链路

默认：现有 DNS 服务 → `127.0.0.1:5353` 管理器前置 → `127.0.0.1:5354` dae。前置层处理静态 hosts，其余查询进入 dae 以建立域名与 IP 的映射。

dae 必须运行后才可将业务 DNS 接入这条链路。不要将 DNS 服务指向自身，不要保留意外绕过的备用上游。

OpenWrt 示例，仅适用于已确认使用本机 dnsmasq 的部署。先备份 `/etc/config/dhcp`，确认能通过 SSH/LuCI 恢复，再运行：

```sh
cp /etc/config/dhcp /root/dhcp.before-dae
uci set dhcp.@dnsmasq[0].noresolv='1'
uci -q delete dhcp.@dnsmasq[0].server || true
uci add_list dhcp.@dnsmasq[0].server='127.0.0.1#5353'
uci commit dhcp
/etc/init.d/dnsmasq restart
```

普通 Linux 可在 dnsmasq 中使用 `no-resolv` 与 `server=127.0.0.1#5353`。systemd-resolved、Unbound、MosDNS 等应先画清现有链路，不要直接套用 UCI 命令。

## 网关、IPv6 和路由

- 客户端默认网关应指向实际承担透明代理的设备，DNS 也需接入；仅能打开后台不代表流量经过 dae。
- dae 设备的默认路由指向真实上游网关；避免指回自身或测试客户端形成环路。
- 按主路由/旁路由拓扑核对 IP forwarding、NAT、防火墙、LAN/WAN、桥接/VLAN/PPPoE 接口。
- 核对 IPv6 RA、DHCPv6、默认路由、AAAA 与防火墙。源 YAML 的 IPv6 开关不会修改整个网络。
- 客户端自带 DoH/DoT、VPN、硬编码 DNS/IP 和 flow offload 需单独检查。

## 日常维护

```sh
daectl
dae-manager ctl status
dae-manager ctl update
dae-manager ctl update rules
dae-manager ctl validate
dae-manager ctl revisions
dae-manager ctl rollback 版本ID
```

数据目录 `/etc/dae-manager` 包含订阅和节点凭据，应私密备份。`current` 指向生效版本，`revisions/` 保留版本快照；核心日志在 `/tmp/dae-manager/dae.log`，审计在数据目录。

核心升级前备份数据并停止 `dae-managed`；用 `dae-manager core --version=指定版本` 下载校验后，运行 `dae-manager validate`，启动并实测。旧核心保存在 `/usr/local/bin/dae.previous`。系统内核升级要重新确认 BTF/kmod 匹配。

管理器本身暂未提供一键在线升级。不要重复运行初装脚本覆盖已有安装；先停止管理器，备份旧程序和数据，再替换对应架构的管理器、helper、菜单及服务定义，校验后重启。早期版本升级前请阅读变更记录。

## 回退原网络

1. 停止并取消核心自启：`dae-manager ctl service stop`、`dae-manager ctl service disable`。
2. 恢复备份的 DNS、DHCP、网关和防火墙配置，再恢复原代理服务。
3. 验证 DNS、内外网和管理通道，确认稳定后再停管理器，避免提前停 DNS 前置。
4. 卸载时先停止/禁用两个服务，移除对应服务定义及已安装程序；保留私密数据备份。本版不提供一键删库式卸载。
