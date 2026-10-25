# 为什么不同核心的延迟差很多

延迟需要同时说明测试 URL、协议、连接是否复用以及所计入的阶段。一个数字不能直接代表线路质量。

| 字段 | 含义 |
|---|---|
| 核心健康检查 | 从当前 dae 进程的健康检查日志读取，保留网络类型和原值；同步按钮不会要求核心立即重测 |
| 手动首次请求 ms | 独立 outbound 测试首次 HTTP 请求的总耗时，可能包含 TCP、代理握手、TLS 和首包等待 |
| dial_ms / tls_ms / response_ms | 首次请求阶段耗时，受协议与实现影响 |
| warm_ms | 第二次请求确认复用连接时的耗时；仅 warm_reused=true 才显示为复用结果 |

测试中同一节点的 TCP 大约 130ms，首次 HTTPS 可达到 500–800ms，而确认连接复用后的请求可回到约 130–150ms。这是一次环境下的示例，不能保证其他节点有相同比例；也不能把首次请求数值简单除以常数。

Mihomo 的 unified-delay 开关、sing-box 的具体版本、URL 和计时方法会影响可比性。比较时应固定设备、节点、URL、并发和连接状态，并分别记录冷请求与复用请求。

- [Mihomo v1.19.33 URLTest 实现](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/adapter/adapter.go)
- [sing-box v1.12.0 URLTest 实现](https://github.com/SagerNet/sing-box/blob/v1.12.0/common/urltest/urltest.go)

“手动测试延迟”不会把结果写回 dae 的内部健康分数；核心分数缺失或失败时不会伪造数值。节点更新、进程重启后需要重新积累健康记录。
