package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Process struct {
	PID        int     `json:"pid"`
	RSS        int64   `json:"rss_bytes"`
	CPUSeconds float64 `json:"cpu_seconds"`
	Uptime     float64 `json:"uptime_seconds"`
}

func command(ctx context.Context, name string, args ...string) ([]byte, error) {
	tc, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return exec.CommandContext(tc, name, args...).CombinedOutput()
}
func (m *Manager) coreProcess() Process {
	if m.processProbe != nil {
		return m.processProbe()
	}
	dirs, _ := os.ReadDir("/proc")
	s := m.settings()
	want, _ := filepath.Abs(s.Dae)
	config := filepath.Join(m.Root, "current", "config.dae")
	for _, d := range dirs {
		pid, e := strconv.Atoi(d.Name())
		if e != nil {
			continue
		}
		root := filepath.Join("/proc", d.Name())
		b, e := os.ReadFile(filepath.Join(root, "cmdline"))
		if e != nil {
			continue
		}
		args := strings.Split(string(b), "\x00")
		found := false
		for _, a := range args {
			if a == config {
				found = true
			}
		}
		if !found {
			continue
		}
		exe, _ := os.Readlink(filepath.Join(root, "exe"))
		if exe != want && exe != want+" (deleted)" {
			continue
		}
		p := Process{PID: pid}
		stat, _ := os.ReadFile(filepath.Join(root, "stat"))
		at := strings.LastIndex(string(stat), ")")
		if at < 0 {
			return p
		}
		fields := strings.Fields(string(stat)[at+1:])
		if len(fields) > 21 {
			ut, _ := strconv.ParseFloat(fields[11], 64)
			st, _ := strconv.ParseFloat(fields[12], 64)
			start, _ := strconv.ParseFloat(fields[19], 64)
			rss, _ := strconv.ParseInt(fields[21], 10, 64)
			up, _ := os.ReadFile("/proc/uptime")
			var uptime float64
			fmt.Sscan(string(up), &uptime)
			p.RSS = rss * int64(os.Getpagesize())
			p.CPUSeconds = (ut + st) / 100
			p.Uptime = max(0, uptime-start/100)
		}
		return p
	}
	return Process{}
}
func (m *Manager) reload(ctx context.Context) error {
	if m.reloadAction != nil {
		return m.reloadAction(ctx)
	}
	// Read the revision being applied: settings are committed after activation.
	s := m.settings()
	_ = readJSON(filepath.Join(m.currentDir(), "settings.json"), &s)
	if s.applyMode() == "restart" {
		m.audit("apply_restart", "使用受控重启应用配置；现有连接会短暂中断")
		return m.service(ctx, "restart")
	}
	p := m.coreProcess()
	if p.PID == 0 {
		return fmt.Errorf("未找到本管理器的 dae 进程")
	}
	out, e := command(ctx, m.settings().Dae, "reload", fmt.Sprint(p.PID))
	if e != nil {
		_ = atomicWrite(filepath.Join(m.Root, "last-reload-error.txt"), out, 0600)
		return fmt.Errorf("dae 重载失败")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(time.Second):
	}
	if m.coreProcess().PID == 0 {
		return fmt.Errorf("重载后核心退出")
	}
	m.recordRunning()
	return nil
}
func (m *Manager) service(ctx context.Context, action string) error {
	if !in(action, []string{"start", "stop", "restart", "reload", "enable", "disable"}) {
		return fmt.Errorf("不支持的服务操作")
	}
	if action == "reload" {
		return m.reload(ctx)
	}
	if action == "enable" || action == "disable" {
		var err error
		if _, e := os.Stat("/etc/init.d/dae-managed"); e == nil {
			_, err = command(ctx, "/etc/init.d/dae-managed", action)
		} else {
			_, err = command(ctx, "systemctl", action, "dae-managed.service")
		}
		if err != nil {
			return fmt.Errorf("无法修改开机自启状态")
		}
		m.audit("autostart", action)
		return nil
	}
	if action != "stop" {
		for _, check := range doctor() {
			if check.State == "error" {
				return fmt.Errorf("系统兼容性检查失败：%s；请先修复内核功能", check.Name)
			}
		}
		if _, e := m.report(); e != nil {
			return fmt.Errorf("请先生成并应用配置")
		}
		if e := m.validate(ctx, m.currentDir()); e != nil {
			return e
		}
	}
	var e error
	if _, err := os.Stat("/etc/init.d/dae-managed"); err == nil {
		_, e = command(ctx, "/etc/init.d/dae-managed", action)
	} else {
		_, e = command(ctx, "systemctl", action, "dae-managed.service")
	}
	if e != nil {
		return fmt.Errorf("服务操作失败，请查看系统服务日志")
	}
	// Ensure start/restart really produces a surviving managed process.
	for i := 0; i < 20; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
		running := m.coreProcess().PID > 0
		if action == "stop" && !running {
			m.audit("service", action)
			return nil
		}
		if action != "stop" && running {
			time.Sleep(time.Second)
			if m.coreProcess().PID > 0 {
				m.audit("service", action)
				m.recordRunning()
				return nil
			}
		}
	}
	return fmt.Errorf("服务未达到目标状态，请检查 BTF、网卡和冲突")
}

type Check struct {
	Name   string `json:"name"`
	State  string `json:"state"`
	Detail string `json:"detail"`
}

func doctor() []Check {
	kernel, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	v := strings.TrimSpace(string(kernel))
	var major, minor int
	fmt.Sscanf(v, "%d.%d", &major, &minor)
	state := "ok"
	if major < 5 || major == 5 && minor < 17 {
		state = "error"
	}
	out := []Check{{"Linux 内核", state, v + "；dae 透明代理要求 >= 5.17"}}
	if _, e := os.Stat("/sys/kernel/btf/vmlinux"); e == nil {
		out = append(out, Check{"BTF", "ok", "内核已提供 /sys/kernel/btf/vmlinux"})
	} else {
		out = append(out, Check{"BTF", "warning", "内核未暴露标准 BTF；需匹配内核的 vmlinux-btf 或重编译固件。不能仅按内核版本保证兼容。"})
	}
	cfg, known := kernelConfig()
	for _, option := range []string{"CONFIG_BPF", "CONFIG_BPF_SYSCALL", "CONFIG_BPF_JIT", "CONFIG_CGROUPS", "CONFIG_KPROBES", "CONFIG_NET_INGRESS", "CONFIG_NET_EGRESS", "CONFIG_NET_SCH_INGRESS", "CONFIG_NET_CLS_BPF", "CONFIG_NET_CLS_ACT", "CONFIG_BPF_STREAM_PARSER", "CONFIG_KPROBE_EVENTS", "CONFIG_BPF_EVENTS"} {
		st, detail := "unknown", "内核未提供配置文件，启动测试才能最终确认"
		if known {
			st = "error"
			detail = "内核功能缺失"
			if strings.Contains(cfg, option+"=y") || strings.Contains(cfg, option+"=m") {
				st = "ok"
				detail = "已配置（模块可能仍需安装）"
			}
		}
		out = append(out, Check{option, st, detail})
	}
	for _, service := range []string{"mihomo", "clash", "sing-box", "xray", "dae"} {
		if b, e := exec.Command("pidof", service).Output(); e == nil && len(strings.TrimSpace(string(b))) > 0 {
			out = append(out, Check{"代理进程：" + service, "warning", "已运行；启用 dae 之前检查透明代理、DNS 和网卡冲突，不自动停止现有代理。"})
		}
	}
	return out
}
func kernelConfig() (string, bool) {
	if b, e := os.ReadFile("/proc/config.gz"); e == nil {
		if text, e := gunzip(b); e == nil {
			return string(text), true
		}
	}
	k, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	b, e := os.ReadFile("/boot/config-" + strings.TrimSpace(string(k)))
	return string(b), e == nil
}
