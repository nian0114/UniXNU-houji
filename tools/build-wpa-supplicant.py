#!/usr/bin/env python3
"""Cross-compile Ath12kWifi's wpa_supplicant 2.12 + native XNU control backend for iOS 16 arm64."""
import argparse
from pathlib import Path
import shlex
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--module', type=Path, required=True, help='Path to prepared Ath12kWifi checkout')
    parser.add_argument('--out', type=Path, required=True, help='Output directory for unixnu-wpa_supplicant')
    parser.add_argument('--triple', default='arm64-apple-ios16.0')
    parser.add_argument('--jobs', type=int, default=8)
    args = parser.parse_args()

    module = args.module.resolve()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)

    subprocess.run(['python3', str(module / 'tools/prepare-supplicant.py')], check=True)
    clang = subprocess.check_output(['xcrun', '-f', 'clang'], text=True).strip()
    sdk = subprocess.check_output(['xcrun', '--sdk', 'iphoneos', '--show-sdk-path'], text=True).strip()

    link = ['-target', args.triple, '-isysroot', sdk]
    flags = [
        '-O2', '-g0', '-Wall', '-MMD', '-Werror=implicit-function-declaration',
        '-I' + str(module / 'include'),
        '-I' + str(module / 'userspace'),
        '-I' + str(module / 'out/wpa-src/wpa_supplicant'),
        *link,
    ]
    cmd = [
        'make', f'-j{args.jobs}', 'wpa_supplicant', 'V=1',
        f'CC={clang}', f'BUILDDIR={out}',
        f'EXTRA_CFLAGS={shlex.join(flags)}', f'LDFLAGS={shlex.join(link)}',
    ]
    wpa_dir = module / 'out/wpa-src/wpa_supplicant'
    (wpa_dir / 'wpa_supplicant').unlink(missing_ok=True)
    res = subprocess.run(cmd, cwd=wpa_dir, capture_output=True, text=True)
    if res.returncode != 0:
        print(res.stdout[-4000:])
        print(res.stderr[-4000:])
        raise SystemExit(res.returncode)

    dst = out / 'unixnu-wpa_supplicant'
    shutil.copy2(wpa_dir / 'wpa_supplicant', dst)
    subprocess.run(['codesign', '-f', '-s', '-', '--identifier', 'org.unixnu.wpa_supplicant', str(dst)], check=True)
    print(f'PASS: built and ad-hoc signed {dst} ({dst.stat().st_size} bytes)')


if __name__ == '__main__':
    main()
