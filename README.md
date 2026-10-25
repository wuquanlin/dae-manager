# 大鹅管家 · DAE Manager

[![CI](https://github.com/wuquanlin/dae-manager/actions/workflows/ci.yml/badge.svg)](https://github.com/wuquanlin/dae-manager/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/wuquanlin/dae-manager)](https://github.com/wuquanlin/dae-manager/releases/latest)

用于 Linux / OpenWrt 的 **dae 安装脚本、中文终端菜单和 Web 管理后台**。支持从 Mihomo 配置迁移、定时更新订阅、查看策略与日志，以及编辑和验证 dae 原生配置。

这是独立社区项目，与 dae、Mihomo、ShellClash 官方无隶属关系。当前版本 **0.2.3，属于早期发布版**：已经进行 Debian 虚拟机实测，仍需根据自己的内核、网络和节点验收。不能保证 Mihomo 配置完全等价或所有设备开箱即用。

## 能做什么

- 识别系统、CPU、内核和 systemd/procd，检查 BPF/BTF 条件，下载官方 dae 并校验 SHA-256。
- 迁移 Mihomo 节点、嵌套策略组、顺序路由、规则源、DNS 策略和 hosts，明确报告转换差异。
- 支持 MRS 解码、自定义 geosite/geoip DAT；GitHub 等 HTTP 规则源可跟随订阅刷新。
- 每日定时拉取节点，保留手动策略选择；失败保留旧配置，支持版本回退。
- 直观显示服务状态、策略出口、组内节点；区分核心健康检查值与手动测速结果。
- 在“节点与策略”管理订阅链接；拉取时弹窗显示进度、节点清单和增删改结果，可关闭后重新查看。
- 按域名、IP、关键字、DNS / 分流类别搜索日志；支持轮转日志和 Netflix 域名关联。
- 编辑 dae 草稿，保存或校验后应用；展示已加载配置，防止旧草稿覆盖新版本。
- Web 资源内嵌于 Go 二进制，目标设备无需 Node、Python、Go 或数据库。

## 支持哪些环境

| 项目 | 要求与说明 |
|---|---|
| 系统 | Linux；安装器支持 systemd 和 OpenWrt / ImmortalWrt procd |
| 内核 | >= 5.17，且具备 dae 所需的 BPF、BTF、cgroup、kprobe、TC、stream parser 等功能；版本号本身不能保证兼容 |
| 架构 | 发布包包含 amd64、arm64、386、ARMv5/6/7、MIPS/MIPSel、MIPS64/MIPS64el；最终还受上游 dae 附件与内核支持限制 |
| 存储与内存 | 建议至少 512 MiB RAM、300 MiB 可用存储，并为 geodata、规则解码与版本快照留余量 |
| 虚拟化 | 建议先用独立 Linux 虚拟机测试；容器共享宿主内核，必须另行确认 eBPF、权限与网络接管条件 |
| Windows / macOS | 可访问后台；核心须部署在 Linux。WSL 可用于开发，不能据此保证透明代理兼容 |

安装器下载的是 **dae 程序**，不会升级 Linux 内核、刷固件或自动修改网关。小闪存路由器应先检查空间，优先下载对应架构的小包。

## 快速安装（推荐 Release）

先备份原网络配置，并准备自己的 Mihomo YAML，例如 `/root/config.yaml`。**仓库不含订阅、可用代理节点或个人配置。**

以 Linux amd64、v0.2.3 为例，在目标设备运行；其他架构替换文件名中的 `amd64`：

```sh
curl -fL -o dae-manager-v0.2.3-linux-amd64.tar.gz \
  https://github.com/wuquanlin/dae-manager/releases/download/v0.2.3/dae-manager-v0.2.3-linux-amd64.tar.gz
curl -fL -o SHA256SUMS \
  https://github.com/wuquanlin/dae-manager/releases/download/v0.2.3/SHA256SUMS
grep '  dae-manager-v0.2.3-linux-amd64.tar.gz$' SHA256SUMS > selected.sha256
sha256sum -c selected.sha256
tar -xzf dae-manager-v0.2.3-linux-amd64.tar.gz
cd dae-manager-v0.2.3
sudo sh install.sh --source=/root/config.yaml --lan=br-lan
```

OpenWrt 一般使用 root，无需 `sudo`；`--lan` 可省略，由 UCI 读取 LAN 设备。普通 Linux 将 `br-lan` 替换为实际 LAN/桥接网卡；仅代理本机时可省略。PPPoE 应核对逻辑接口。

安装会注册并启动管理后台，**默认不启动核心**。请先完成 DNS 接入、网卡和其他代理冲突检查，再通过后台或 `daectl` 启动核心。`--start` 供已完成网络规划的设备使用。

默认下载 dae `v2.1.1` 和用于 MRS 解码的 Mihomo `v1.19.33`；后者不会作为代理服务运行。可用 `--dae-version=` 和 `--helper-version=` 指定版本，新版本需重新验证。网络或转换中断时修复原因，再运行相同安装命令并添加 `--resume`；该参数只恢复未完成的安装。

## 登录和日常管理

默认监听 `127.0.0.1:2025`，在自己的电脑建立 SSH 隧道：

```sh
ssh -N -L 2025:127.0.0.1:2025 root@你的Linux设备地址
```

浏览器打开 <http://127.0.0.1:2025>。设备上运行 `daectl` 可打开中文菜单并查看口令；随机口令保存在 `/etc/dae-manager/admin-token`，没有通用默认密码。

需要 LAN 直接访问可在安装时指定 `--listen=设备LAN地址:2025`，并限制到可信管理网段。HTTP 会明文传输口令和配置，优先使用 SSH 隧道或 HTTPS 反向代理。

| 位置 | 用法 |
|---|---|
| 运行概览 | 查看核心/自启状态、启动停止、校验和最近操作结果 |
| 节点与策略 | 编辑已有 HTTP 订阅链接、拉取新节点、查看结果、选择策略出口、同步核心延迟或手动测速 |
| 分流规则 | 查看可读名称、原生表达式及转换差异 |
| 日志检索 | 按域名、客户端 IP、关键字和类别检索；先确认 DNS 和流量经过本机 |
| 配置与版本 | 编辑 dae 草稿、保存、校验并应用、查看运行配置及回滚 |
| 系统设置 | 调整调度时间、是否同步规则、日志级别、应用方式 |

默认每天 **04:15（Asia/Shanghai，可修改）** 更新节点。默认受控重启应用配置，会短暂断流；可在设置中选择热重载，须验证实际流量稳定性。保存订阅链接只保存待应用内容，点击拉取或到达计划时间后才下载并应用。

## 网络和 DNS 接入

典型 DNS 链路为：

```text
客户端 → dnsmasq:53 → 管理器 127.0.0.1:5353（hosts）
                     → dae 127.0.0.1:5354（DNS 分流）→ 上游 DNS
```

将现有 DNS 服务的唯一上游接到管理器前置 DNS，避免回环与备用上游绕过。安装器不会替你修改 DHCP、dnsmasq、网关、转发、NAT 或防火墙。旁路由必须单独配置客户端网关、DNS 和宿主机上游；修改前保留可用的管理通道。详见 [网络接入与恢复](docs/NETWORK.md)。

配置中的 `ipv6: false` 不能自动禁用整个局域网 IPv6；客户端 DoH/DoT、应用硬编码 IP 和 IPv6 都需单独验收。

## 从 GitHub 拉取和构建

在 Linux 上使用 **Go >= 1.26** 和 Python 3；当前发布使用 Go 1.27.3：

```sh
git clone https://github.com/wuquanlin/dae-manager.git
cd dae-manager
go mod download
(cd helper && go mod download)
go test -race ./...
(cd helper && go test -race ./...)
python3 scripts/build.py --arch amd64
cd dist/public/dae-manager-v0.2.3
sudo sh install.sh --source=/root/config.yaml --lan=br-lan
```

不传 `--arch` 构建全部十种架构。脚本生成各架构安装包、完整包、含 vendored 依赖的对应源码包及 SHA256SUMS。构建过程与目标设备安装分开：**不要直接在只有源码、没有 `bin/` 的根目录运行安装器。**

集成测试可设置 `DAE_TEST_BINARY`、`MRS_TEST_BINARY`、`DAE_MANAGER_HELPER` 为对应 Linux 程序路径。详见 [贡献指南](CONTRIBUTING.md)。

## 文档、边界和许可

- [兼容性与迁移差异](docs/COMPATIBILITY.md) · [验收及回退](docs/ACCEPTANCE.md)
- [验证范围与已知问题](docs/VALIDATION.md) · [测速数值说明](docs/LATENCY.md)
- [管理 API](docs/API.md) · [版本记录](CHANGELOG.md) · [安全说明](SECURITY.md)

原生语法校验通过不等于节点可用、视频解锁成功或 DNS 无泄漏。fallback / load-balance 等策略存在语义差异，详见兼容性报告。日志归类与部分出口来自日志推断，并非核心提供的完整连接 API。

管理器主体使用 [MIT](LICENSE)。独立 `dae-helper` 链接上游 AGPL 组件，按 [AGPL-3.0](helper/LICENSE) 分发；其源码、构建脚本和锁定依赖均公开，Release 同时提供含依赖的对应源码包。dae、Mihomo 及规则数据保留各自许可证，见 [第三方说明](THIRD-PARTY.md)。
