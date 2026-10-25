package main

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type releaseAsset struct {
	Name   string `json:"name"`
	URL    string `json:"browser_download_url"`
	Digest string `json:"digest"`
}
type release struct {
	Tag    string         `json:"tag_name"`
	Assets []releaseAsset `json:"assets"`
}

func getRelease(ctx context.Context, repo, version string) (release, error) {
	url := "https://api.github.com/repos/" + repo + "/releases/latest"
	if version != "" && version != "latest" {
		for _, c := range version {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune(".-_", c)) {
				return release{}, fmt.Errorf("版本号无效")
			}
		}
		url = "https://api.github.com/repos/" + repo + "/releases/tags/" + version
	}
	b, e := fetch(ctx, url, nil)
	if e != nil {
		return release{}, e
	}
	var r release
	e = json.Unmarshal(b, &r)
	return r, e
}
func verifiedAsset(ctx context.Context, a releaseAsset) ([]byte, error) {
	if !strings.HasPrefix(a.URL, "https://github.com/") || !strings.HasPrefix(a.Digest, "sha256:") {
		return nil, fmt.Errorf("发布附件缺少可信 SHA-256 摘要")
	}
	b, e := fetch(ctx, a.URL, nil)
	if e != nil {
		return nil, e
	}
	if "sha256:"+digest(b) != a.Digest {
		return nil, fmt.Errorf("SHA-256 校验失败")
	}
	return b, nil
}
func daeArch(arch string) string {
	switch arch {
	case "amd64":
		return "x86_64"
	case "386":
		return "x86_32"
	case "arm":
		return "armv7"
	case "mips":
		return "mips32"
	case "mipsle":
		return "mips32le"
	case "mips64le":
		return "mips64le"
	case "ppc64":
		return "powerpc64"
	case "ppc64le":
		return "powerpc64le"
	}
	return arch
}
func mihomoArch(arch string) string {
	switch arch {
	case "amd64":
		return "amd64-compatible"
	case "386":
		return "386"
	case "mips":
		return "mips-softfloat"
	case "mipsle":
		return "mipsle-softfloat"
	case "arm", "armv7":
		return "armv7"
	case "armv6":
		return "armv6"
	case "armv5":
		return "armv5"
	}
	return arch
}
func gunzip(b []byte) ([]byte, error) {
	r, e := gzip.NewReader(bytes.NewReader(b))
	if e != nil {
		return nil, e
	}
	defer r.Close()
	const max = 128 << 20
	out, e := io.ReadAll(io.LimitReader(r, max+1))
	if len(out) > max {
		return nil, fmt.Errorf("解压内容过大")
	}
	return out, e
}
func installCore(ctx context.Context, root, bin, arch, version string) error {
	if arch == "" {
		arch = runtime.GOARCH
	}
	r, e := getRelease(ctx, "daeuniverse/dae", version)
	if e != nil {
		return e
	}
	assetName := "dae-linux-" + daeArch(arch) + ".zip"
	var asset releaseAsset
	for _, a := range r.Assets {
		if a.Name == assetName {
			asset = a
		}
	}
	if asset.Name == "" {
		return fmt.Errorf("dae %s 未发布架构 %s 的二进制", r.Tag, arch)
	}
	b, e := verifiedAsset(ctx, asset)
	if e != nil {
		return e
	}
	zr, e := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if e != nil {
		return e
	}
	coreFound := false
	for _, f := range zr.File {
		base := filepath.Base(f.Name)
		var dest string
		if base == "dae-linux-"+daeArch(arch) {
			dest = bin
			coreFound = true
		} else if in(base, []string{"geoip.dat", "geosite.dat"}) {
			dest = filepath.Join(root, "geodata", base)
		} else {
			continue
		}
		if f.UncompressedSize64 > 128<<20 {
			return fmt.Errorf("附件解压尺寸异常")
		}
		rd, e := f.Open()
		if e != nil {
			return e
		}
		body, e := io.ReadAll(io.LimitReader(rd, 128<<20))
		rd.Close()
		if e != nil {
			return e
		}
		mode := os.FileMode(0600)
		if dest == bin {
			mode = 0755
			if old, e := os.ReadFile(bin); e == nil {
				if e = atomicWrite(bin+".previous", old, 0755); e != nil {
					return e
				}
			}
		}
		if e = atomicWrite(dest, body, mode); e != nil {
			return e
		}
	}
	if !coreFound {
		return fmt.Errorf("发布附件中未找到 dae 程序")
	}
	out, e := command(ctx, bin, "--version")
	if e != nil {
		if old, err := os.ReadFile(bin + ".previous"); err == nil {
			_ = atomicWrite(bin, old, 0755)
		}
		return fmt.Errorf("下载程序无法运行，已尝试恢复旧版本；请检查 CPU 架构")
	}
	meta := M{"version": r.Tag, "asset": asset.Name, "sha256": asset.Digest, "native_version": strings.TrimSpace(string(out))}
	return writeJSON(filepath.Join(root, "core-release.json"), meta)
}
func installMihomo(ctx context.Context, bin, arch, version string) error {
	if arch == "" {
		arch = runtime.GOARCH
	}
	r, e := getRelease(ctx, "MetaCubeX/mihomo", version)
	if e != nil {
		return e
	}
	name := "mihomo-linux-" + mihomoArch(arch) + "-" + r.Tag + ".gz"
	for _, a := range r.Assets {
		if a.Name == name {
			b, e := verifiedAsset(ctx, a)
			if e != nil {
				return e
			}
			body, e := gunzip(b)
			if e != nil {
				return e
			}
			return atomicWrite(bin, body, 0755)
		}
	}
	return fmt.Errorf("Mihomo 未发布架构 %s 的辅助解码程序", arch)
}
