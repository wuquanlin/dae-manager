#!/usr/bin/env python3
"""Enumerate explicitly public source files; reject obvious accidental private data."""
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
ROOT_NAMES = {'go.mod', 'go.sum', 'LICENSE', '.gitignore', '.gitattributes',
              'README.md', 'CHANGELOG.md', 'CONTRIBUTING.md', 'SECURITY.md', 'THIRD-PARTY.md',
              'install.sh', 'menu.sh'}
DIRECTORIES = {'web': {'.js', '.html', '.css'}, 'services': {'.service', '.procd'},
               'helper': {'.go', '.mod', '.sum', ''}, 'docs': {'.md'},
               'examples': {'.yaml'}, '.github/workflows': {'.yml'}}
SCRIPTS = {'build.py', 'check_public.py'}

def public_files():
    files = [p for p in ROOT.iterdir() if p.is_file() and (p.name in ROOT_NAMES or p.suffix == '.go')]
    for directory, suffixes in DIRECTORIES.items():
        # Only immediate files; never descend into vendor, caches or upstream checkouts.
        folder = ROOT / directory
        if folder.exists():
            files.extend(p for p in folder.iterdir() if p.is_file() and p.suffix in suffixes)
    files.extend(ROOT / 'scripts' / n for n in SCRIPTS)
    return sorted(files)

def check(files):
    patterns = {
        'private key': r'-----BEGIN (?:OPENSSH |RSA |EC |DSA )?PRIVATE KEY-----',
        'credential URL': r'https?://[^\s/]+:[^\s/]+@',
        'GitHub credential': r'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})',
        'local user path': r'[A-Z]:[\\/]Users[\\/][^\s]+',
        'private deployment address': r'192[.]168[.]6[.][0-9]+',
    }
    for file in files:
        data = file.read_text(encoding='utf-8')
        for label, pattern in patterns.items():
            if re.search(pattern, data, re.I):
                raise SystemExit(f'Refusing public file {file.relative_to(ROOT)}: {label}')
        rel = file.relative_to(ROOT)
        if any(part in {'private', 'tools', 'dist', 'personal', 'upstream'} for part in rel.parts):
            raise SystemExit(f'Private path in publication: {rel}')

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--staged', action='store_true', help='Also require staged paths to match public allowlist')
    args = parser.parse_args()
    files = public_files()
    check(files)
    if args.staged:
        allowed = {p.relative_to(ROOT).as_posix() for p in files}
        staged = subprocess.check_output(['git', 'diff', '--cached', '--name-only', '-z'], cwd=ROOT).decode().split('\0')
        unexpected = set(filter(None, staged)) - allowed
        if unexpected:
            raise SystemExit('Unexpected staged paths: ' + ', '.join(sorted(unexpected)))
    print(f'Public source check passed ({len(files)} files). This is a safeguard, not a substitute for review.')
