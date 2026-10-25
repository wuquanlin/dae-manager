#!/usr/bin/env python3
"""Build clean public Linux bundles and vendored corresponding source (stdlib + Go)."""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
from check_public import ROOT, check, public_files

GO = os.environ.get('GO', 'go')
VERSION = re.search(r'const Version = "([^"]+)"', (ROOT / 'model.go').read_text()).group(1)
NAME = 'dae-manager-v' + VERSION
DIST = ROOT / 'dist' / 'public'
TARGETS = {'amd64': ('amd64', ''), 'arm64': ('arm64', ''), 'armv7': ('arm', '7'),
           'armv6': ('arm', '6'), 'armv5': ('arm', '5'), '386': ('386', ''),
           'mips': ('mips', ''), 'mipsle': ('mipsle', ''),
           'mips64': ('mips64', ''), 'mips64le': ('mips64le', '')}


def run(args, cwd=ROOT, **kwargs):
    return subprocess.run(args, cwd=cwd, check=True, **kwargs)


def copy_sources(destination, files):
    for file in files:
        target = destination / file.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(file, target)
        target.chmod(0o755 if file.suffix == '.sh' else 0o644)


def archive(folder, path, predicate=None):
    with tarfile.open(path, 'w:gz') as out:
        for file in sorted(folder.rglob('*')):
            if not file.is_file() or (predicate and not predicate(file)):
                continue
            info = out.gettarinfo(str(file), arcname=folder.name + '/' + file.relative_to(folder).as_posix())
            info.uid = info.gid = 0
            info.uname = info.gname = 'root'
            with file.open('rb') as stream:
                out.addfile(info, stream)


def manifest(folder, files):
    (folder / 'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest() + '  ' +
        p.relative_to(folder).as_posix() + '\n' for p in sorted(files)), encoding='ascii')


def licenses(destination):
    for folder in [ROOT, ROOT / 'helper']:
        text = subprocess.check_output([GO, 'list', '-m', '-json', 'all'], cwd=folder, text=True)
        decoder = json.JSONDecoder()
        while text.strip():
            module, end = decoder.raw_decode(text.lstrip())
            text = text.lstrip()[end:].lstrip()
            if module.get('Main'):
                continue
            effective = module.get('Replace', module)
            if not effective.get('Dir'):
                continue
            for file in Path(effective['Dir']).iterdir():
                if file.is_file() and file.name.upper().startswith(('LICENSE', 'COPYING', 'NOTICE')):
                    target = destination / 'licenses' / effective['Path'].replace('/', '_') / file.name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(file, target)
                    target.chmod(0o644)
    goroot = Path(subprocess.check_output([GO, 'env', 'GOROOT'], text=True).strip())
    (destination / 'licenses').mkdir(exist_ok=True)
    shutil.copyfile(goroot / 'LICENSE', destination / 'licenses' / 'Go-LICENSE')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--arch', action='append', choices=TARGETS, help='Repeat to select architectures; default all')
    args = parser.parse_args()
    selected = args.arch or list(TARGETS)
    files = public_files()
    check(files)
    DIST.mkdir(parents=True, exist_ok=True)
    artifacts = []
    with tempfile.TemporaryDirectory(prefix='dae-build-') as temp:
        package = Path(temp) / NAME
        copy_sources(package, files)
        (package / 'bin').mkdir()

        def build(name):
            arch, arm = TARGETS[name]
            env = dict(os.environ, GOOS='linux', GOARCH=arch, CGO_ENABLED='0', GOMIPS='softfloat', GOAMD64='v1')
            if arm:
                env['GOARM'] = arm
            for module, binary in [(ROOT, 'dae-manager'), (ROOT / 'helper', 'dae-helper')]:
                target = package / 'bin' / (binary + '-linux-' + name)
                run([GO, 'build', '-mod=readonly', '-trimpath', '-buildvcs=false', '-ldflags=-s -w', '-o', str(target), '.'], cwd=module, env=env)
                target.chmod(0o755)
            print('built', name, flush=True)

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            list(pool.map(build, selected))
        licenses(package)
        manifest(package, [f for f in package.rglob('*') if f.is_file()])
        full = DIST / (NAME + '-linux.tar.gz')
        archive(package, full)
        artifacts.append(full)
        for name in selected:
            with tempfile.TemporaryDirectory(prefix='dae-arch-') as arch_temp:
                single = Path(arch_temp) / NAME
                copy_sources(single, files)
                shutil.copytree(package / 'licenses', single / 'licenses')
                (single / 'bin').mkdir()
                for binary in ['dae-manager', 'dae-helper']:
                    filename = binary + '-linux-' + name
                    shutil.copy2(package / 'bin' / filename, single / 'bin' / filename)
                manifest(single, [f for f in single.rglob('*') if f.is_file()])
                output = DIST / (NAME + '-linux-' + name + '.tar.gz')
                archive(single, output)
                artifacts.append(output)
        # Publish complete corresponding source, including exact vendored dependencies.
        with tempfile.TemporaryDirectory(prefix='dae-source-') as source_temp:
            source = Path(source_temp) / (NAME + '-source')
            copy_sources(source, files)
            env = dict(os.environ, GOOS='linux', GOARCH='amd64', CGO_ENABLED='0')
            for folder in [source, source / 'helper']:
                run([GO, 'mod', 'vendor'], cwd=folder, env=env)
            info = subprocess.check_output([GO, 'version'], text=True).strip()
            (source / 'BUILD-INFO.txt').write_text(
                f'{NAME}\nToolchain: {info}\nCGO_ENABLED=0\n'
                'Manager: go build -mod=vendor -trimpath -buildvcs=false -ldflags="-s -w" .\n'
                'Helper: cd helper && go build -mod=vendor -trimpath -buildvcs=false -ldflags="-s -w" .\n'
                'Set GOOS=linux, GOARCH and GOARM for the target architecture.\n'
                'All module source dependencies are vendored. Go toolchain source: https://go.dev/dl/\n', encoding='utf-8')
            shutil.copytree(package / 'licenses', source / 'licenses')
            manifest(source, [f for f in source.rglob('*') if f.is_file()])
            output = DIST / (NAME + '-corresponding-source.tar.gz')
            archive(source, output)
            artifacts.append(output)
        # Keep an unpacked installer from this build, replacing only our generated package folder.
        unpacked = DIST / NAME
        if unpacked.exists():
            if unpacked.resolve().parent != DIST.resolve():
                raise SystemExit('Unexpected generated output path')
            shutil.rmtree(unpacked)
        shutil.move(str(package), str(unpacked))
    manifest(DIST, artifacts)
    for file in artifacts:
        print('release', file.name, file.stat().st_size, flush=True)
    print('checksums', DIST / 'SHA256SUMS', flush=True)


if __name__ == '__main__':
    main()
