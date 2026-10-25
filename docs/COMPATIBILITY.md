# Mihomo → dae 兼容性

基线：官方 dae v2.1.1 发布二进制，Mihomo v1.19.33 规则解码器。

| 项目 | 处理方式 | 边界 |
|---|---|---|
| VLESS TCP/WS/TLS/Reality | 转标准 URI，保留 UUID、SNI、Reality 公钥/短 ID、flow、WS Host/path | XHTTP、复杂 HTTP、WS early data 等不支持时阻止转换；不能保证传输实现与 Mihomo 一致 |
| Hysteria2 | 密码、SNI、证书指纹、obfs、跳端口范围、带宽字段 | 跳端口间隔由 dae 默认值决定；需实际连通性测试 |
| AnyTLS | 密码、SNI、insecure | 上游实现的 ALPN、指纹及会话参数可能与 Mihomo 不同 |
| VMess/SS/Trojan/TUIC/SOCKS/HTTP | 常见字段有转换路径 | 这些协议尚未全部完成实网覆盖；不接受 SS 插件或未支持传输 |
| 节点源 | HTTP Mihomo YAML、inline、部分 URI 订阅 | YAML 优先；URI 订阅不能等价处理所有 provider override，建议使用 YAML；不自动读取任意本地 provider path |
| select | 后台保存用户选择，解析所选子组，生成 dae 出口并按设置应用配置 | 不提供 Clash 的 selector API；原始 store-selected 选择不在 YAML 中，需要在后台重新选择 |
| url-test | 候选节点由管理器按源正则筛选；dae min_moving_avg 策略 | 候选组保留；算法与 Mihomo URL-test 不完全相同 |
| fallback | min_moving_avg，并明确警告 | 不等价于原顺序优先 |
| load-balance | random，并明确警告 | 不等价于一致性哈希 |
| LOOKAHEAD 正则 | regexp2 + 100ms 上限，转换时筛选具体节点 | 避免把 Mihomo 分组正则直接交给不兼容引擎 |
| MRS 域名/IP 规则 | 官方解码 → 自定义 DAT → dae ext 引用 | 保留准确规则来源，拒绝空数据及未知格式；不按名字替换成其他 geosite |
| classical/text/YAML 规则 | 仅含 DOMAIN/SUFFIX/KEYWORD/REGEX 和目标 IP-CIDR 的集合自动打包为域名/IP DAT；其他支持的条件保持展开 | GEOSITE/GEOIP、端口、NETWORK、PROCESS-NAME、源 IP 保持原条件，未知逻辑组合等阻止应用 |
| 规则顺序、MATCH | 保留源顺序，classical 展开，MATCH → fallback | MATCH 后有规则时阻止转换 |
| no-resolve | 保留 IP 匹配，标记差异 | 不复制 Mihomo 触发/抑制解析的完整机制 |
| nameserver-policy | 精确域名、通配后缀、geosite、域名 RULE-SET | 重叠策略采用生成后的显式顺序，需要实机对照；不支持 DNS 上游绑定非 DIRECT 代理 |
| 多 DNS 上游列表 | 使用列表第一项；保留其余源 YAML | 未复制并行、自动回退和负载行为；应选择可靠主上游 |
| proxy-server-nameserver / default-nameserver | 报告为差异 | 不声称逐节点解析已等价；保证系统 DNS/bootstrap 可用 |
| DNS #DIRECT | 去除 Mihomo 参数并生成专用直连路由条件 | 端点域名和最终解析 IP 的直连行为需实测，不能仅凭配置断言无泄漏 |
| 静态 hosts | 管理器前置 DNS 5353 → dae DNS 5354 | 需将 dnsmasq 唯一上游指向前置层；不自动改系统 hosts |
| IPv6=false | DNS 优先 IPv4，前置层对 AAAA 返回 NOERROR 空答案 | 不禁用操作系统 IPv6、RA、已有 IPv6 地址或客户端自带加密 DNS |
| TUN / 入站端口 | 不迁移 | dae 通过 eBPF 接管；原 7890/7891/7893 HTTP/SOCKS 服务不会出现 |
| sniffer | 使用 dae 的 domain 拨号机制 | 原 sniff 端口、force-domain/skip-domain 不完全等价 |
| TLS 校验/指纹/ALPN/UDP/TFO | 能映射的写入 URI，其余列入报告 | 特别是某些 VLESS 实现不读取 skip-cert-verify；管理器不为此全局关闭证书校验 |
| Zashboard/external-controller | 由本管理后台替代 | 不兼容 Clash REST API，不假造延迟、连接列表或内核直连流量统计 |

## 转换报告

安装后的转换报告在 `current/report.json`，也可通过后台查看。导入数量不代表连通成功数量；未支持的字段和语义差异应逐项确认。

## 自定义混合规则集 DAT（v0.1.4）

自定义代理与直连规则集 继续使用 GitHub 上可读的 classical 文本源。管理器下载后将完整域名、域名后缀、关键词、正则分别保留为对应 geosite 类型，将 IPv4/IPv6 目标前缀编入 geoip DAT。两类分别存入 rules-site.dat 与 rules-ip.dat；每个混合集合生成相邻的两个引用，出口及相对于其他源规则的优先级保持。含源 IP、端口等条件的集合继续展开。

开启“同时更新规则集”时先立即拉取并验证一次，之后跟随每日更新；任何拉取、解析或原生校验错误都不会替换当前配置。GitHub 保存源文本，DAT 在设备上生成，此流程不向 GitHub 推送二进制产物。
