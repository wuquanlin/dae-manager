# 本地管理 API

默认 `http://127.0.0.1:2025`。不会启动已归档 dae-wing，也不依赖 GraphQL。API 仅管理自己的 `dae-managed` 服务和数据目录。

## 鉴权

机器调用：`Authorization: Bearer <admin-token 文件中的口令>`。浏览器可 `POST /api/login`，JSON `{"token":"…"}`，获得 12 小时 HttpOnly / SameSite=Strict Cookie。所有写请求还需 `X-DAE-Request: 1`；有 Origin 时必须与 Host 一致。TLS 连接中的会话 Cookie 设置 Secure。

不要在 URL 或 shell 命令行中附带口令。终端菜单调用 `dae-manager ctl ...` 时由程序读取本机私密文件，避免把口令写入历史。

| 方法 | 路径 | 功能 / JSON |
|---|---|---|
| GET | /api/status | 进程、内存、累计 CPU 时间、核心版本、配置版本和调度状态 |
| GET | /api/report | 节点名称与类型、组、规则、来源条目数、兼容性说明；不含 URI/密码 |
| GET | /api/doctor | Linux/BTF/BPF/其他代理进程检查 |
| GET | /api/source | 当前完整源 YAML，含私密数据，必须鉴权 |
| PUT | /api/source | `{"source":"完整 YAML"}`；重新下载、转换、校验、应用 |
| GET | /api/config | 生效 dae 配置，含私密节点 URI，必须鉴权 |
| POST | /api/update | `{"rules":false}`；true 同步规则源 |
| POST | /api/select | `{"group":"原组名","choice":"原选项名"}` |
| POST | /api/validate | 校验生效配置 |
| POST | /api/service | `{"action":"start|stop|restart|reload|enable|disable"}` |
| GET | /api/job | 最近后台任务，state 为 running/success/failed |
| GET | /api/revisions | 配置版本清单 |
| POST | /api/rollback | `{"revision":"版本ID"}`；恢复源配置、选择和运行设置并按设置应用配置 |
| PUT | /api/settings | lan、wan、log_level、update_time、timezone、auto_update、refresh_rules、apply_mode（restart/reload；省略保留原值） |
| GET | /api/logs | q、category、level、source、limit 参数 |
| POST | /api/logout | 删除当前浏览器会话 |

写配置和服务操作通常返回 **202** 与任务 ID，必须继续读取 `/api/job`，不能把 HTTP 202 当作配置已经生效。失败信息保留在任务和审计中。

同一进程使用互斥锁，跨进程使用 flock；同时操作返回 409 或任务失败。所有外部程序通过固定参数数组执行，不把 YAML 或 API 输入拼入 shell。

## 日志查询

例：`/api/logs?q=google.com%20192.0.2.1&category=dns&level=debug&source=core&limit=200`。

多个关键字同时匹配，忽略大小写。category 为 all/dns/routing/system；source 为 core/audit；单次最多返回 1000 条，搜索最近三个核心轮转文件及 DNS 前置记录，较新记录在前。分类和日志级别基于文本推断，不是 dae 的结构化遥测。日志可能包含访问域名/IP，应保护管理口令与备份。

## 暂不提供

任意命令执行、任意文件读写、API 修改二进制路径、远程更新管理器、WAN 暴露、Clash 兼容 API、伪造实时延迟/直连连接列表。这些能力不能由本 API 接口自动推断为已支持。

## 名称显示（v0.1.3）

`GET /api/report` 附加 `display_names` 字典，将规则集、策略组、单节点出口和内置出口编号映射到名称。原 `rules[].expression`、`resolved` 等字段保持原样，可用于排查；管理界面默认显示名称，并提供折叠的原生表达式及名称/编号检索。已有配置版本无需重新生成。

开启 refresh_rules 时会先拉取规则源并生成候选版本，通过原生校验后才保存设置并应用；之后的每日更新同步规则。已有 refresh_rules=true 的普通设置变更使用缓存，不重复下载。

## 0.2.1 原生编辑、运行状态与测速

- GET /api/status：process、service.active、service.autostart、gateway、operations（各类操作的最近完成/失败结果）。
- GET /api/dae/config：draft（已保存草稿）、running（已确认加载的快照）、active（下次启动配置）、pid、revision、note、validation_error（仅对应当前草稿的最近原生校验诊断，可能含私密配置，仅鉴权用户可读）。
- PUT /api/dae/config：`{"config":"...","apply":false}` 保存草稿；apply=true 先原生校验再事务切换，运行中按 apply_mode 应用，停止时启动。返回后台任务。
- GET /api/telemetry?sync=1：重新读取本次核心进程的轮转健康检查日志，包含 core[nodeID][tcp4/udp4/tcp6/udp6]、exits[groupID][network]、manual[nodeID]、synced 和 pid。缺失数据留空；失败 ms 为 null。sync 不触发核心内部测速。
- POST /api/nodes/test：`{"ids":[]}` 测试全部主文件节点；ids=[nodeID] 测单个/指定多个。后台任务，进度在 /api/job，结果逐个保存。使用核心对应 outbound 库的独立 HTTPS/TCP 测试，未写入核心健康分数。
- /api/logs：支持最近三个 .log / .log.gz 核心轮转文件和 DNS 前置记录。Netflix 按域名别名/当前 DAT 规则识别，IP 只标为推断。

原 /api/source 保留用于订阅迁移输入；Web 不再以 Mihomo 编辑器展示。自动更新的三方合并以 baseline-config.dae 为基线，有冲突时不激活新版本。运行配置不是草稿。

编辑器保存 base_revision，草稿基于旧运行版本时拒绝直接应用，防止覆盖刚刚切换的策略。重新载入当前配置后可重新编辑、校验与应用。

## 0.2.2 测速阶段

manual[nodeID] 保留原 ms（首次请求耗时），新增 warm_ms、warm_reused、warm_message、dial_ms、tls_ms、response_ms、url、http。仅 warm_reused=true 表示第二次请求实际复用连接；未成功则不生成 warm_ms，保留首次成功结果。旧记录不含阶段数据，需要重新测速。核心日志原始值不做换算。

## 0.2.3 订阅链接与更新结果

- GET /api/subscriptions 返回 items[name,url,active_url,host,count,pending,conflict]、source_hash、saved_at 和说明。url字段为完整私密订阅，需认证，UI默认用password输入隐藏；不要写入公共日志。source_hash 覆盖生效源配置与待应用草稿，用于并发修改检测，并非单纯源文件SHA。
- PUT /api/subscriptions：`{"items":[{"name":"Airport1","url":"https://example/feed"}],"source_hash":"GET返回值","pull":false,"rules":false}`。提交所有现有HTTP订阅；只允许改URL。pull=false只保存待应用记录，pull=true保存后拉取，rules决定是否同时刷新规则集；返回后台任务。源配置变化或待应用记录被其他客户端改过时拒绝旧版本。
- GET /api/update/result 返回最近一次拉取的job_id、started/finished、state/stage/message/error、nodes_complete、applied、validation、previous/candidate/active_revision、nodes、removed、providers及变化计数。Nodes仅包含name/id/type/provider/change，无URI。未完整读取不会推断移除。结果持久化，后台重启后可查。

每日任务同样使用已保存的待应用订阅，成功应用后清除待应用记录。Node新增fingerprint只表示参数摘要，用于区分同名节点的参数更新，不包含URI。原/api/source仍保留完整迁移输入导入功能；新订阅接口不重置手动选择。
