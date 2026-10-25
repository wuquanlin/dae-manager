# 第三方组件

管理器为独立 Go 程序，通过命令行调用 dae 和 Mihomo。0.2.1 新增独立 dae-helper，链接 dae 官方配置解析器和对应版本 outbound 库，执行配置清单解析与手动测试。dae-helper 按 AGPL-3.0 分发，源码及锁定依赖在 helper/，许可证在 helper/LICENSE 和 licenses/；不依赖已归档的 dae-wing。

安装脚本从官方发布附件下载并校验以下程序。通用发布包不包含这两个代理程序的二进制：

- [dae v2.1.1](https://github.com/daeuniverse/dae/releases/tag/v2.1.1)：AGPL-3.0；[对应源代码](https://github.com/daeuniverse/dae/tree/v2.1.1)。
- [Mihomo v1.19.33](https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.33)：GPL-3.0；[对应源代码](https://github.com/MetaCubeX/mihomo/tree/v1.19.33)。仅用于 MRS 格式解码，不启动其代理服务。
- 官方 dae ZIP 中的 geodata：来源和更新节奏由上游附件决定。转换使用用户原规则集生成的自定义 DAT，GEOIP/GEOSITE 条件仍使用对应 geodata。

管理器链接的依赖（精确版本见 go.mod/go.sum）：

- [gopkg.in/yaml.v3](https://github.com/go-yaml/yaml/tree/v3.0.1)：MIT / Apache-2.0。
- [regexp2](https://github.com/dlclark/regexp2/tree/v1.11.5)：MIT。
- [miekg/dns](https://github.com/miekg/dns/tree/v1.1.72)：BSD-3-Clause。
- golang.org/x/net、x/sys、x/sync 及 Go 标准库：BSD-3-Clause。

公开发布或重新分发前，请同时保留这些依赖的许可证，遵守对应源代码与数据的许可条件。公开包不包含用户配置或订阅缓存。

独立 dae-helper 的锁定上游：

- [dae 源码 dbae2e82](https://github.com/daeuniverse/dae/tree/dbae2e82d3ed5324e1648548720f8bbc8cde3882)：AGPL-3.0。
- [outbound 源码 cc86ced2](https://github.com/olicesx/outbound/tree/cc86ced2e683)：AGPL-3.0；与 dae v2.1.1 的 replace 一致。
- 完整依赖与校验和见 helper/go.mod、helper/go.sum；构建不修改锁定依赖，Go >= 1.26，发布使用 Go 1.27.3、CGO_ENABLED=0。构建方法见 scripts/build.py。

## 对应源码与再分发

Release 的 `dae-manager-v版本-corresponding-source.tar.gz` 包含两个模块的源代码、锁定文件、构建脚本和 vendored 依赖，及依赖许可证。构建方法与工具链记录在包内 BUILD-INFO.txt。独立 helper 按 AGPL-3.0（上游许可条件适用）提供；再分发其修改版本时应同时遵守对应源码和网络交互等许可义务。管理器与 helper 通过独立进程命令行通信。
