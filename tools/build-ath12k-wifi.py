#!/usr/bin/env python3
"""Compile pinned Ath12kWifi module into a symbol-isolated static library (libnw_wifi.a) for houji XNU."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile

KEEP_SYMS = {
    '_nw_wifi_start', '_nw_wifi_step', '_nw_wifi_stop', '_nw_wifi_stats',
    '_nw_wifi_set_events', '_nw_wifi_scan', '_nw_wifi_scan_frequencies',
    '_nw_wifi_bss_count', '_nw_wifi_bss_get', '_nw_wifi_connect',
    '_nw_wifi_disconnect', '_nw_wifi_tx', '_nw_wifi_status_get',
    '_nw_wifi_where', '_nw_wifi_power', '_nw_wifi_tx_packet',
    '_nw_wifi_link_state', '_nw_wifi_tx_reasons', '_nw_wifi_buffer_stats_get',
    '_nw_wifi_buffer_pool_configure', '_nw_wifi_buffer_pool_trim',
    '_nw_wifi_irq_mode', '_nw_wifi_irq_pending', '_nw_wifi_wait_ms',
    '_nw_wifi_poll', '_nw_wifi_set_platform',
    '_nw_wifi_control_transport_set', '_nw_wifi_control_attach',
    '_nw_wifi_control_detach', '_nw_wifi_control_receive',
    '_nw_wifi_control_writable', '_nw_wifi_control_stats_get',
}


def find_llvm_bin():
    for candidate in (Path('/opt/homebrew/opt/llvm/bin'), Path('/usr/local/opt/llvm/bin')):
        if (candidate / 'llvm-nm').is_file() and (candidate / 'llvm-objcopy').is_file():
            return candidate
    return None


def stage_regulatory_sources(module, out):
    patch = Path(__file__).resolve().parents[1] / 'kernel/patches/ath12k-wcn7850-regulatory.patch'
    source = module / 'out/ath12k-src'
    overrides = out / 'ath12k-regulatory'
    names = ('mac.c', 'reg.c')
    overrides.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='ath12k-patch-', dir=out) as directory:
        temporary = Path(directory)
        for name in names:
            shutil.copyfile(source / name, temporary / name)
        subprocess.run(['patch', '-p1', '-F', '0', '-f', '-i', str(patch)], cwd=temporary, check=True)
        for name in names:
            updated = temporary / name
            destination = overrides / name
            if not destination.exists() or destination.read_bytes() != updated.read_bytes():
                updated.replace(destination)
    return {name: overrides / name for name in names}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--module', type=Path, required=True, help='Path to prepared Ath12kWifi checkout')
    parser.add_argument('--out', type=Path, required=True, help='Output directory for objects and libnw_wifi.a')
    parser.add_argument('--fakeroot', type=Path, help='Also install libnw_wifi.a in the XNU fakeroot library directory')
    parser.add_argument('--triple', default='arm64-apple-macos13.0', help='Clang target triple matching XNU')
    parser.add_argument('--jobs', type=int, default=8)
    args = parser.parse_args()

    module = args.module.resolve()
    out = args.out.resolve()
    raw = out / 'raw'
    raw.mkdir(parents=True, exist_ok=True)
    regulatory_sources = stage_regulatory_sources(module, out)

    clang = subprocess.run(['xcrun', '-f', 'clang'], check=True, capture_output=True, text=True).stdout.strip()
    libtool = subprocess.run(['xcrun', '-f', 'libtool'], check=True, capture_output=True, text=True).stdout.strip()
    resource = subprocess.run([clang, '-print-resource-dir'], check=True, capture_output=True, text=True).stdout.strip() + '/include'
    llvm = find_llvm_bin()

    flags = [
        '-target', args.triple, '-mkernel', '-O2', '-g0', '-ffreestanding',
        '-fno-builtin', '-fno-common', '-fno-strict-aliasing', '-fwrapv',
        '-fno-stack-protector', '-Wno-incompatible-pointer-types', '-Wno-error',
        '-fno-delete-null-pointer-checks', '-mgeneral-regs-only',
        '-momit-leaf-frame-pointer', '-std=gnu11', '-w',
        '-DCONFIG_ATH12K_DEBUG', '-DCONFIG_CFG80211=1', '-DCONFIG_MAC80211=1',
        '-DCONFIG_MAC80211_STA_HASH_MAX_SIZE=0', '-DCONFIG_MAC80211_RC_DEFAULT=""',
        '-nostdinc', '-isystem', str(module / 'shim/libc'), '-isystem', resource,
        '-include', 'lx_pci.h',
        '-I', str(module / 'shim/include'), '-I', str(module / 'include'),
        '-I', str(module / 'out/pinned'), '-I', str(module / 'src'),
        '-I', str(module / 'out'),
    ]
    trees = {
        'ath12k': ['-I', str(module / 'out/ath12k-src'), '-I', str(module / 'out/ath12k-src/wifi7')],
        'mhi': ['-I', str(module / 'out/mhi-src')],
        'qmi': ['-I', str(module / 'out/os-src')],
        'mac80211': ['-I', str(module / 'out/mac80211')],
        'cfg80211': ['-I', str(module / 'out/cfg80211')],
        'generated': ['-I', str(module / 'out/cfg80211')],
        'crypto': ['-I', str(module / 'shim/crypto'), '-I', str(module / 'out/crypto')],
    }

    jobs = []
    for line in (module / 'tools/sources.txt').read_text().splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        tree, _, name = line.partition(':') if ':' in line else ('', '', line)
        if tree == 'ath12k':
            src = regulatory_sources.get(name, module / 'out/ath12k-src' / name)
        elif tree == 'mhi':
            src = module / 'out/mhi-src' / name
        elif tree == 'qmi':
            src = module / 'out/os-src' / name
        elif tree in ('mac80211', 'cfg80211', 'crypto'):
            src = module / 'out' / tree / name
        elif tree == 'generated':
            src = module / 'out' / name
        else:
            src = module / name
        obj = out / (('w7_' if '/wifi7/' in str(src) else tree + '_' if tree else '') + src.stem + '.o')
        extra = trees.get(tree, trees['ath12k'] if name.startswith('src/') else [])
        if name.startswith('src/nw_cfg80211_'):
            extra = trees['cfg80211']
        if name == 'src/nw_fils.c':
            extra = trees['mac80211']
        if name == 'src/nw_crypto_mac80211.c':
            extra = trees['crypto'] + trees['mac80211']
        if tree == 'crypto' and name == 'aes-siv.c':
            extra = [*extra, '-Daes_siv_encrypt=nw_aes_siv_encrypt', '-Daes_siv_decrypt=nw_aes_siv_decrypt']
        jobs.append((src, obj, extra))

    def build_one(job):
        src, obj, extra = job
        raw_obj = raw / obj.name
        dep = raw_obj.with_suffix('.d')
        ident = raw_obj.with_suffix('.inputs.json')
        cmd = [clang, '-c', *extra, *flags, '-MD', '-MF', str(dep), str(src), '-o', str(raw_obj)]
        if raw_obj.exists() and ident.exists():
            rec = json.loads(ident.read_text())
            if (rec.get('command') == cmd and
                    rec.get('object_sha256') == hashlib.sha256(raw_obj.read_bytes()).hexdigest() and
                    all(Path(p).is_file() and hashlib.sha256(Path(p).read_bytes()).hexdigest() == d
                        for p, d in rec.get('dependencies', {}).items())):
                return raw_obj
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            sys.stderr.write(res.stderr)
            raise SystemExit(f'compile failed: {src}')
        hdrs = shlex.split(dep.read_text().replace('\\\n', '').partition(':')[2])
        ident.write_text(json.dumps({
            'command': cmd,
            'object_sha256': hashlib.sha256(raw_obj.read_bytes()).hexdigest(),
            'dependencies': {str(Path(p).absolute()): hashlib.sha256(Path(p).read_bytes()).hexdigest()
                             for p in hdrs if Path(p).is_file()},
        }, sort_keys=True) + '\n')
        return raw_obj

    with ThreadPoolExecutor(args.jobs) as pool:
        raw_objs = list(pool.map(build_one, jobs))

    objs = [o for _, o, _ in jobs]
    mapping = out / 'rename.txt'
    if llvm is not None:
        names = set()
        for o in raw_objs:
            res = subprocess.run([str(llvm / 'llvm-nm'), '-g', '--defined-only', str(o)],
                                 check=True, capture_output=True, text=True)
            for line in res.stdout.splitlines():
                parts = line.split()
                if len(parts) == 3 and parts[2] not in KEEP_SYMS:
                    names.add(parts[2])
        mapping.write_text(''.join(f'{n} _nwk{n}\n' for n in sorted(names)))
        def rename_one(pair):
            src_o, dst_o = pair
            shutil.copyfile(src_o, dst_o)
            subprocess.run([str(llvm / 'llvm-objcopy'), f'--redefine-syms={mapping}', str(dst_o)], check=True)
        with ThreadPoolExecutor(args.jobs) as pool:
            list(pool.map(rename_one, zip(raw_objs, objs)))
    else:
        nm = subprocess.run(['xcrun', '-f', 'nm'], check=True, capture_output=True, text=True).stdout.strip()
        names = set()
        for o in raw_objs:
            res = subprocess.run([nm, '-g', '--defined-only', str(o)],
                                 check=True, capture_output=True, text=True)
            for line in res.stdout.splitlines():
                parts = line.split()
                if len(parts) == 3 and parts[2] not in KEEP_SYMS:
                    names.add(parts[2])
        mapping.write_text(''.join(f'{n} _nwk{n}\n' for n in sorted(names)))
        for src_o, dst_o in zip(raw_objs, objs):
            shutil.copyfile(src_o, dst_o)
        rel_objs = ' '.join(shlex.quote(o.name) for o in objs)
        subprocess.run([
            'docker', 'run', '--rm', '-v', f'{out}:/work', '-w', '/work',
            'houji-uefi-env:latest', 'bash', '-lc',
            f'printf "%s\\n" {rel_objs} | xargs -P {args.jobs} -n 1 llvm-objcopy --redefine-syms=rename.txt'
        ], check=True)

    archive = out / 'libnw_wifi.a'
    subprocess.run([libtool, '-static', '-o', str(archive), *[str(o) for o in objs]], check=True)
    if args.fakeroot:
        library_dir = args.fakeroot.resolve() / 'usr/local/lib/kernel'
        library_dir.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(archive, library_dir / archive.name)
    print(f'PASS: built {archive} ({len(objs)} objects, {len(names)} renamed symbols, {archive.stat().st_size} bytes)')


if __name__ == '__main__':
    main()
