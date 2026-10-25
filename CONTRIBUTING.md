# 贡献指南

请在 Linux 上开发，使用 Go >= 1.26；发布构建使用 Go 1.27.3。前端为原生 HTML/CSS/JavaScript，无 Node 构建依赖。

```sh
go mod download
(cd helper && go mod download)
go test -race -count=1 ./...
go vet ./...
(cd helper && go test -race -count=1 ./... && go vet ./...)
node --check web/app.js
sh -n install.sh
sh -n menu.sh
python3 scripts/check_public.py
python3 scripts/build.py --arch amd64
```

可用以下环境变量启用原生集成测试（路径必须为 Linux 可执行文件）：

```sh
export DAE_TEST_BINARY=/path/to/dae
export MRS_TEST_BINARY=/path/to/mihomo
export DAE_MANAGER_HELPER=/path/to/dae-helper
go test -race -count=1 ./...
```

不配置这些变量时，依赖官方二进制的测试会跳过。可通过管理器的 `core` / `helper` 子命令下载并验证上游程序；参考 CI 流程。

核心管理、配置切换、订阅失败恢复等变更应补充行为测试。请不要把真实订阅、节点、管理口令、内网截图、设备备份或访问日志提交到 Git。示例使用保留域名及文档 IP；`examples/` 的节点是无效占位符。

提 Issue 时说明管理器版本、dae 版本、系统/内核/架构、应用方式、复现步骤和已脱敏的日志。安全问题见 SECURITY.md。提交 PR 前确认两种模块的许可证要求；helper 的修改受 AGPL-3.0 约束。

## 发布维护

`scripts/build.py` 从明确的公开文件清单创建干净暂存目录，不复用旧迁移包。输出位于 `dist/public/`。发布资产包括各架构二进制包、全部架构包、对应源码包（含两个模块的 vendor）、SHA256SUMS。

对应源码包在两个模块根目录使用 `go build -mod=vendor` 构建，不需要再下载模块；需要对应 Go 工具链。精确工具链见包内 BUILD-INFO.txt。helper 的依赖替换严格以 go.mod/go.sum 为准。

维护者确认测试与包清单后创建版本 tag、发布 Release，上传本次生成的公开资产。不要上传整个 dist 或 private 目录。GitHub Actions 的 Build release 工作流仅手动构建并保存工件，不自动发布。
