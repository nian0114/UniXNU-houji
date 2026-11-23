#!/usr/bin/env python3
"""Build a verified 32 GiB HFSX iOS 16.7.16 (20H392) root volume on macOS.

Must run as root in a local terminal so HFSX/APFS mounts preserve genuine iOS
numeric UIDs/GIDs (0, 33, 272, 501). Streams one IPSW DMG at a time to bound
temporary host disk consumption. Never accesses a phone.
"""
import argparse
import glob
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import stat
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
BUILD_VERSION = '20H392'
PRODUCT_VERSION = '16.7.16'
ROOT_GIB = 32
ROOT_BLOCKS = ROOT_GIB * 262144
ROOT_BYTES = ROOT_GIB * 1024**3
VOLUME_UUID = bytes.fromhex('1e38300864ba2b7b')
MOBILE_UID = 501
LOGD_UID = 272
INSTALLD_UID = 33
KEYBOARD_DYLIB_LOAD = '/usr/lib/HoujiKeyboardGeometry.dylib'


def find_gnu_rsync():
    for candidate in ('/opt/homebrew/bin/rsync', '/usr/local/bin/rsync', shutil.which('rsync')):
        if not candidate or not Path(candidate).is_file():
            continue
        ver = subprocess.run([candidate, '--version'], capture_output=True, text=True)
        if 'openrsync' not in (ver.stdout + ver.stderr):
            return candidate
    raise RuntimeError('GNU rsync is required (openrsync lacks full HFS hardlink/numeric-id semantics)')


def sha256_file(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        while chunk := stream.read(8 * 1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def attach_dmg_readonly(dmg_path):
    raw = subprocess.check_output([
        'hdiutil', 'attach', '-readonly', '-nobrowse', '-owners', 'on',
        '-noverify', '-noautofsck', '-plist', str(dmg_path),
    ])
    info = plistlib.loads(raw)
    devs = [e['dev-entry'] for e in info['system-entities'] if 'dev-entry' in e]
    mounts = [e['mount-point'] for e in info['system-entities'] if 'mount-point' in e]
    if not devs or not mounts:
        raise RuntimeError(f'Failed to mount DMG: {dmg_path}')
    base_disks = sorted({re.match(r'(/dev/disk\d+)', d).group(1) for d in devs})
    return base_disks, Path(mounts[0])


def detach_disks(disks):
    for disk in reversed(disks):
        subprocess.run(['hdiutil', 'detach', '-force', disk], capture_output=True)


def extract_ipsw_member(archive, member_path, dest):
    entry = archive.getinfo(member_path)
    written = 0
    with archive.open(entry) as src, dest.open('wb') as out:
        while chunk := src.read(8 * 1024 * 1024):
            out.write(chunk)
            written += len(chunk)
    if written != entry.file_size:
        raise RuntimeError('Incomplete IPSW member extraction: ' + member_path)


def inject_weak_dylib(before_bytes):
    hdr = struct.unpack_from('<8I', before_bytes, 0)
    if hdr[:4] != (0xFEEDFACF, 0x0100000C, 0, 2):
        return None
    offset, first_sect, previous = 32, len(before_bytes), None
    for _ in range(hdr[4]):
        cmd, size = struct.unpack_from('<II', before_bytes, offset)
        if size < 8 or size % 8 != 0:
            return None
        if cmd == 0x19:
            nsects = struct.unpack_from('<I', before_bytes, offset + 64)[0]
            for i in range(nsects):
                sect_off = struct.unpack_from('<I', before_bytes, offset + 72 + i * 80 + 48)[0]
                if sect_off:
                    first_sect = min(first_sect, sect_off)
        elif cmd == 0x2C:
            if struct.unpack_from('<I', before_bytes, offset + 16)[0] != 0:
                return None
        elif cmd in (0x0C, 0x80000018):
            name_at = struct.unpack_from('<I', before_bytes, offset + 8)[0]
            name = before_bytes[offset + name_at:offset + size].split(b'\0', 1)[0]
            if name.endswith(b'/HoujiKeyboardGeometry.dylib'):
                previous = (offset, size)
        offset += size
    if offset != 32 + hdr[5]:
        return None
    name_bytes = KEYBOARD_DYLIB_LOAD.encode('ascii') + b'\0'
    cmd_size = (24 + len(name_bytes) + 7) & ~7
    modified = bytearray(before_bytes)
    if previous:
        offset, room = previous
        if cmd_size > room:
            return None
        cmd_size = room
    else:
        if offset + cmd_size > first_sect or before_bytes[offset:offset + cmd_size] != bytes(cmd_size):
            return None
        struct.pack_into('<II', modified, 16, hdr[4] + 1, hdr[5] + cmd_size)
    lc = struct.pack('<6I', 0x80000018, cmd_size, 24, 0, 0x10000, 0x10000) + name_bytes
    modified[offset:offset + cmd_size] = lc.ljust(cmd_size, b'\0')
    if modified[first_sect:] != before_bytes[first_sect:]:
        raise RuntimeError('Mach-O section payload unexpectedly changed')
    return bytes(modified)


def patch_system_apps_keyboard(mount_root, scratch_dir):
    patched_count = 0
    ent_dir = scratch_dir / 'entitlements'
    ent_dir.mkdir(parents=True, exist_ok=True)
    for base in (mount_root / 'Applications', mount_root / 'System/Library/CoreServices'):
        if not base.is_dir():
            continue
        for bundle in sorted(base.rglob('*.app')):
            if bundle.is_symlink():
                continue
            info_path = bundle / 'Info.plist'
            if not info_path.is_file() or info_path.is_symlink():
                continue
            info = plistlib.loads(info_path.read_bytes())
            if info.get('CFBundlePackageType') != 'APPL':
                continue
            exe_name = info.get('CFBundleExecutable')
            if not exe_name:
                continue
            exe = bundle / exe_name
            if not exe.is_file() or exe.is_symlink():
                continue
            ent_raw = subprocess.run(
                ['codesign', '-d', '--entitlements', ':-', str(exe)],
                capture_output=True,
            ).stdout
            before = exe.read_bytes()
            updated = inject_weak_dylib(before)
            if updated is None:
                continue
            st_exe = exe.stat()
            st_info = info_path.stat()
            if st_exe.st_nlink > 1:
                exe.unlink()
            exe.write_bytes(updated)
            os.chown(exe, st_exe.st_uid, st_exe.st_gid)
            os.chmod(exe, stat.S_IMODE(st_exe.st_mode))

            if st_info.st_nlink > 1:
                info_path.unlink()
            info['CADisableMinimumFrameDurationOnPhone'] = True
            info_path.write_bytes(plistlib.dumps(info, fmt=plistlib.FMT_BINARY, sort_keys=False))
            os.chown(info_path, st_info.st_uid, st_info.st_gid)
            os.chmod(info_path, stat.S_IMODE(st_info.st_mode))

            cs_dir = bundle / '_CodeSignature'
            cr = cs_dir / 'CodeResources'
            if cr.exists() and not cr.is_symlink() and cr.stat().st_nlink > 1:
                cr.unlink()

            sign_cmd = ['codesign', '--force', '--sign', '-', '--pagesize', '4096', '--timestamp=none']
            if ent_raw.strip():
                ent_file = ent_dir / f'{patched_count}.plist'
                ent_file.write_bytes(ent_raw)
                sign_cmd += ['--entitlements', str(ent_file), '--generate-entitlement-der']
            subprocess.run(sign_cmd + [str(bundle)], check=True, capture_output=True)
            if cs_dir.is_dir():
                for item in [cs_dir, *cs_dir.rglob('*')]:
                    if not item.is_symlink():
                        os.chown(item, 0, 0)
            patched_count += 1
    return patched_count


def apply_sweet_and_houji_tweaks(mount_root, metal_dir, compat_dir, sysapps_dir, power_dir, scratch_dir):
    # 1. Cryptex dyld shared cache + non-overlapping cryptex files
    dsc_src = mount_root / 'private/preboot/Cryptexes/OS/System/Library/Caches/com.apple.dyld'
    dsc_dst = mount_root / 'System/Library/Caches/com.apple.dyld'
    dsc_dst.mkdir(parents=True, exist_ok=True)
    os.chown(dsc_dst, 0, 0)
    os.chmod(dsc_dst, 0o755)
    for item in sorted(dsc_src.iterdir()):
        target = dsc_dst / item.name
        if not target.exists() and not target.is_symlink():
            os.link(item, target)

    for cryptex in ('OS', 'App'):
        croot = mount_root / 'private/preboot/Cryptexes' / cryptex
        if not croot.is_dir():
            continue
        for dirpath, _, filenames in os.walk(croot, followlinks=False):
            rel_dir = Path(dirpath).relative_to(croot)
            if str(rel_dir).startswith('System/Library/Caches/com.apple.dyld'):
                continue
            for fn in filenames:
                src = Path(dirpath) / fn
                rel = rel_dir / fn
                dst = mount_root / rel
                if dst.exists() or dst.is_symlink():
                    continue
                dst.parent.mkdir(parents=True, exist_ok=True)
                if src.is_symlink():
                    os.symlink(os.readlink(src), dst)
                    os.lchown(dst, 0, 0)
                else:
                    os.link(src, dst)

    # 2. logd stores (272:272) + system keybag (0:0)
    db = mount_root / 'private/var/db'
    for sub, mode in (('diagnostics', 0o751), ('uuidtext', 0o755), ('diagnostics/timesync', 0o755)):
        d = db / sub
        d.mkdir(parents=True, exist_ok=True)
        os.chown(d, LOGD_UID, LOGD_UID)
        os.chmod(d, mode)
        mig = d / '.migrated'
        mig.write_bytes(b'')
        os.chown(mig, LOGD_UID, LOGD_UID)
        os.chmod(mig, 0o644)

    keybags = mount_root / 'private/var/keybags'
    keybags.mkdir(parents=True, exist_ok=True)
    os.chown(keybags, 0, 0)
    os.chmod(keybags, 0o700)
    kb = keybags / 'systembag.kb'
    kb.write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        '<plist version="1.0"><dict><key>KeyBagKeys</key><data>U1dFRVQ=</data></dict></plist>\n'
    )
    os.chown(kb, 0, 0)
    os.chmod(kb, 0o600)

    # 3. Containers
    cbase = mount_root / 'private/var/containers'
    cbase.mkdir(parents=True, exist_ok=True)
    os.chown(cbase, 0, 0)
    os.chmod(cbase, 0o755)
    for sub, uid in (('Bundle', INSTALLD_UID), ('Data', 0), ('Data/System', 0), ('Shared', 0), ('Shared/SystemGroup', 0), ('Temp', 0)):
        d = cbase / sub
        d.mkdir(parents=True, exist_ok=True)
        os.chown(d, uid, uid)
        os.chmod(d, 0o755)

    # 4. launchd.plist: _PanicOnCrash -> _PanicOnCrasX, drop missing-radio/SEP/NFC daemons
    disabled_daemons = {
        'com.apple.CommCenter',
        'com.apple.DumpBasebandCrash',
        'com.apple.bluetoothd',
        'com.apple.bluetoothuserd',
        'com.apple.fairplayd.H2',
        'com.apple.nfcd',
        'com.apple.seld',
        'com.apple.biometrickitd.pearl',
        'com.apple.wifiFirmwareLoader',
        'com.apple.wifid',
        'com.apple.wifip2pd',
        'com.apple.wifivelocityd',
        'com.apple.wifi.hostapd',
        'com.apple.wifi.wapic',
    }
    ld_path = mount_root / 'System/Library/xpc/launchd.plist'
    ld_st = ld_path.stat()
    ld_plist = plistlib.loads(ld_path.read_bytes())
    jobs = ld_plist['LaunchDaemons']
    for job in jobs.values():
        if isinstance(job, dict) and '_PanicOnCrash' in job:
            job['_PanicOnCrasX'] = job.pop('_PanicOnCrash')
    for k in [k for k, j in jobs.items() if isinstance(j, dict) and j.get('Label') in disabled_daemons]:
        del jobs[k]
    ld_path.write_bytes(plistlib.dumps(ld_plist, fmt=plistlib.FMT_BINARY, sort_keys=False))
    os.chown(ld_path, ld_st.st_uid, ld_st.st_gid)
    os.chmod(ld_path, stat.S_IMODE(ld_st.st_mode))

    # 5. Audio / MediaToolbox crash-loop guards
    va_src = mount_root / 'Library/Audio/Plug-Ins/HAL/VirtualAudio.plugin'
    va_dst = mount_root / 'Library/Audio/Plug-Ins/HAL.disabled'
    if va_src.exists():
        va_dst.mkdir(parents=True, exist_ok=True)
        os.chown(va_dst, 0, 0)
        shutil.move(str(va_src), str(va_dst / va_src.name))
    for conf_str in glob.glob(str(mount_root / 'System/Library/Frameworks/MediaToolbox.framework/*/SubServerConfiguration.plist')):
        conf = Path(conf_str)
        st = conf.stat()
        cdata = plistlib.loads(conf.read_bytes())
        cdata['StartRecorderServer'] = False
        conf.write_bytes(plistlib.dumps(cdata, fmt=plistlib.FMT_XML))
        os.chown(conf, st.st_uid, st.st_gid)
        os.chmod(conf, stat.S_IMODE(st.st_mode))

    # 6. Skip-Setup & SpringBoard preferences (501:501, 0600)
    prefs_dir = mount_root / 'private/var/mobile/Library/Preferences'
    for parent in (
        mount_root / 'private/var/mobile',
        mount_root / 'private/var/mobile/Library',
        prefs_dir,
        mount_root / 'private/var/mobile/Library/Logs',
    ):
        parent.mkdir(parents=True, exist_ok=True)
        os.chown(parent, MOBILE_UID, MOBILE_UID)
        os.chmod(parent, 0o755)

    def merge_pref(name, values):
        p = prefs_dir / f'{name}.plist'
        cur = plistlib.loads(p.read_bytes()) if p.exists() else {}
        cur.update(values)
        p.write_bytes(plistlib.dumps(cur, fmt=plistlib.FMT_BINARY))
        os.chown(p, MOBILE_UID, MOBILE_UID)
        os.chmod(p, 0o600)

    merge_pref('com.apple.migration', {
        'LastSystemVersion': BUILD_VERSION,
        'DMUserDataDisposition': {'SyntheticDidUpgrade': False, 'buildVersion': BUILD_VERSION},
    })
    merge_pref('com.apple.springboard', {
        'BKNoWatchdogs': True,
        'FBLaunchWatchdogExceptions': {'com.apple.purplebuddy': 100.0},
        'MCForceShowCloudConfigurationUI': False,
        'SBDisableAutoDim': True,
        'SBDontDimOrLockOnAC': True,
        'SBDisableIdleSleep': True,
    })
    merge_pref('com.apple.purplebuddy', {
        'SetupDone': True,
        'SetupFinishedAllSteps': True,
        'SetupVersion': 11,
        'daemonizeNeedsToRun': False,
    })
    merge_pref('com.apple.purplebuddy.notbackedup', {
        k: False for k in (
            'ShouldRunDiagnosticsMiniBuddy', 'ShouldRunHSA2MiniBuddy',
            'ShouldRunKeychainSyncMiniBuddy', 'ShouldRunMesaMiniBuddy',
            'ShouldRunPaymentMiniBuddy', 'ShouldRunStandardMiniBuddy',
            'SilentICDPUpgrade',
        )
    })
    merge_pref('com.apple.managedconfiguration.notbackedup', {
        'LockdownActivationIndicatesCloudConfigurationAvailable': False,
    })

    # 7. Install NativeAdrenoMetal.bundle + Turnip + NativeAdrenoMetal.clients
    ext_dir = mount_root / 'System/Library/Extensions'
    bundle_dst = ext_dir / 'NativeAdrenoMetal.bundle'
    if bundle_dst.exists():
        shutil.rmtree(bundle_dst)
    shutil.copytree(metal_dir / 'NativeAdrenoMetal.bundle', bundle_dst, copy_function=shutil.copyfile)
    for item in [bundle_dst, *bundle_dst.rglob('*')]:
        os.chown(item, 0, 0)
        os.chmod(item, 0o755 if item.is_dir() or item.name in ('NativeAdrenoMetal', 'libvulkan_freedreno.dylib') else 0o644)
    subprocess.run(['codesign', '--verify', '--strict', str(bundle_dst / 'libvulkan_freedreno.dylib')], check=True)
    subprocess.run(['codesign', '--verify', '--strict', str(bundle_dst)], check=True)

    clients_dst = ext_dir / 'NativeAdrenoMetal.clients'
    shutil.copyfile(metal_dir / 'NativeAdrenoMetal.clients', clients_dst)
    os.chown(clients_dst, 0, 0)
    os.chmod(clients_dst, 0o644)

    # 8. Install /usr/lib/HoujiKeyboardGeometry.dylib + patch APPL bundles
    dylib_dst = mount_root / KEYBOARD_DYLIB_LOAD.lstrip('/')
    shutil.copyfile(compat_dir / 'HoujiKeyboardGeometry.dylib', dylib_dst)
    os.chown(dylib_dst, 0, 0)
    os.chmod(dylib_dst, 0o755)
    subprocess.run(['codesign', '--verify', '--strict', str(dylib_dst)], check=True)
    patched_apps = patch_system_apps_keyboard(mount_root, scratch_dir)

    # 8b. Move the 32 untouched stock staged apps into /Applications (preserving CS_PLATFORM_BINARY)
    spec_rs = importlib.util.spec_from_file_location('restore_sysapps', ROOT / 'tools/restore-system-apps.py')
    mod_rs = importlib.util.module_from_spec(spec_rs)
    spec_rs.loader.exec_module(mod_rs)
    catalog = json.loads((ROOT / 'userland/apps/system-apps.json').read_text())
    mod_rs.restore(mount_root, catalog, apply=True)

    # 9. Register houji-system-apps and houji-power-probe in launchd cache
    spec_sa = importlib.util.spec_from_file_location('reg_sysapps', ROOT / 'tools/register-system-apps.py')
    reg_sa = importlib.util.module_from_spec(spec_sa)
    spec_sa.loader.exec_module(reg_sa)
    reg_sa.register(mount_root, sysapps_dir)
    for rel, mode in (('usr/libexec/houji-system-apps', 0o755), ('System/Library/LaunchDaemons/moe.houji.system-apps.plist', 0o644)):
        p = mount_root / rel
        os.chown(p, 0, 0)
        os.chmod(p, mode)

    power_bin_dst = mount_root / 'usr/libexec/houji-power-probe'
    shutil.copyfile(power_dir / 'houji-power-probe', power_bin_dst)
    os.chown(power_bin_dst, 0, 0)
    os.chmod(power_bin_dst, 0o755)
    power_plist_dst = mount_root / 'System/Library/LaunchDaemons/moe.houji.power-probe.plist'
    shutil.copyfile(ROOT / 'userland/power/moe.houji.power-probe.plist', power_plist_dst)
    os.chown(power_plist_dst, 0, 0)
    os.chmod(power_plist_dst, 0o644)

    spec_pp = importlib.util.spec_from_file_location('reg_power', ROOT / 'tools/register-power-probe.py')
    reg_pp = importlib.util.module_from_spec(spec_pp)
    spec_pp.loader.exec_module(reg_pp)
    reg_pp.register(mount_root, (ROOT / 'userland/power/moe.houji.power-probe.plist').read_bytes())

    return patched_apps


def verify_houji_hfs_header(image_path):
    with image_path.open('rb') as f:
        page = f.read(4096)
    h = page[1024:]
    total_blocks = struct.unpack_from('>I', h, 44)[0]
    block_size = struct.unpack_from('>I', h, 40)[0]
    if h[:4] != b'HX\x00\x05' or block_size != 4096 or total_blocks != ROOT_BLOCKS or h[104:112] != VOLUME_UUID:
        raise RuntimeError(
            f'HFSX header failed kernel validator: sig={h[:4]!r} blk={block_size} total={total_blocks} id={h[104:112].hex()}'
        )


def upgrade_existing_root(mount_root, metal_dir):
    # 1. Remove missing-radio/SEP/NFC crash-loop & XPC-blocking daemons from launchd.plist
    disabled_daemons = {
        'com.apple.CommCenter',
        'com.apple.DumpBasebandCrash',
        'com.apple.bluetoothd',
        'com.apple.bluetoothuserd',
        'com.apple.fairplayd.H2',
        'com.apple.nfcd',
        'com.apple.seld',
        'com.apple.biometrickitd.pearl',
        'com.apple.wifiFirmwareLoader',
        'com.apple.wifid',
        'com.apple.wifip2pd',
        'com.apple.wifivelocityd',
        'com.apple.wifi.hostapd',
        'com.apple.wifi.wapic',
    }
    ld_path = mount_root / 'System/Library/xpc/launchd.plist'
    ld_st = ld_path.stat()
    ld_plist = plistlib.loads(ld_path.read_bytes())
    jobs = ld_plist['LaunchDaemons']
    removed_daemons = 0
    for k in [k for k, j in jobs.items() if isinstance(j, dict) and j.get('Label') in disabled_daemons]:
        del jobs[k]
        removed_daemons += 1
    ld_path.write_bytes(plistlib.dumps(ld_plist, fmt=plistlib.FMT_BINARY, sort_keys=False))
    os.chown(ld_path, ld_st.st_uid, ld_st.st_gid)
    os.chmod(ld_path, stat.S_IMODE(ld_st.st_mode))

    # 2. Install shader-primed NativeAdrenoMetal.bundle + clients
    ext_dir = mount_root / 'System/Library/Extensions'
    bundle_dst = ext_dir / 'NativeAdrenoMetal.bundle'
    if bundle_dst.exists():
        shutil.rmtree(bundle_dst)
    shutil.copytree(metal_dir / 'NativeAdrenoMetal.bundle', bundle_dst, copy_function=shutil.copyfile)
    for item in [bundle_dst, *bundle_dst.rglob('*')]:
        os.chown(item, 0, 0)
        os.chmod(item, 0o755 if item.is_dir() or item.name in ('NativeAdrenoMetal', 'libvulkan_freedreno.dylib') else 0o644)
    subprocess.run(['codesign', '--verify', '--strict', str(bundle_dst / 'libvulkan_freedreno.dylib')], check=True)
    subprocess.run(['codesign', '--verify', '--strict', str(bundle_dst)], check=True)

    # 3. Restore all 32 staged stock apps into /Applications untouched
    spec_rs = importlib.util.spec_from_file_location('restore_sysapps', ROOT / 'tools/restore-system-apps.py')
    mod_rs = importlib.util.module_from_spec(spec_rs)
    spec_rs.loader.exec_module(mod_rs)
    catalog = json.loads((ROOT / 'userland/apps/system-apps.json').read_text())
    res = mod_rs.restore(mount_root, catalog, apply=True)
    return {'removed_daemons': removed_daemons, 'restored_staged_apps': res['moved']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ipsw', type=Path)
    parser.add_argument('--upgrade-in-place', action='store_true',
                        help='Upgrade an existing 32 GiB HFSX image in place without re-extracting IPSW')
    parser.add_argument('--metal-build', type=Path, default=ROOT / 'out/metal')
    parser.add_argument('--compat-build', type=Path, default=ROOT / 'out/userland-compat')
    parser.add_argument('--system-apps-build', type=Path, default=ROOT / 'out/system-apps')
    parser.add_argument('--power-probe-build', type=Path, default=ROOT / 'out/power-probe')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()

    if os.geteuid() != 0:
        raise SystemExit('Run with sudo in your local terminal so HFSX numeric UIDs/GIDs are preserved.')
    out = args.output.resolve()
    if args.upgrade_in_place:
        if not out.is_file():
            raise SystemExit(f'Existing HFSX image not found: {out}')
        with tempfile.TemporaryDirectory(prefix='houji-hfsx-upg-', dir=str(out.parent)) as tmp:
            mount_point = Path(tmp) / 'root_mnt'
            mount_point.mkdir()
            subprocess.run([
                'hdiutil', 'attach', '-nobrowse', '-owners', 'on',
                '-imagekey', 'diskimage-class=CRawDiskImage',
                '-mountpoint', str(mount_point), str(out),
            ], check=True)
            try:
                upg_stats = upgrade_existing_root(mount_point, args.metal_build.resolve())
                os.sync()
            finally:
                subprocess.run(['hdiutil', 'detach', str(mount_point)], check=True)
        with out.open('r+b') as f:
            f.seek(1024 + 104)
            f.write(VOLUME_UUID)
            f.seek(ROOT_BYTES - 1024 + 104)
            f.write(VOLUME_UUID)
            f.flush()
            os.fsync(f.fileno())
        verify_houji_hfs_header(out)
        ro_out = subprocess.check_output(
            ['hdiutil', 'attach', '-nomount', '-readonly', '-imagekey', 'diskimage-class=CRawDiskImage', str(out)],
            text=True,
        )
        ro_disk = re.search(r'(/dev/disk\d+)', ro_out).group(1)
        try:
            subprocess.run(['/sbin/fsck_hfs', '-fn', ro_disk.replace('/dev/disk', '/dev/rdisk')], check=True)
        finally:
            subprocess.run(['hdiutil', 'detach', ro_disk], check=True)
        digest = sha256_file(out)
        report_path = out.with_suffix('.json')
        report = {
            'status': 'PASS',
            'bytes': ROOT_BYTES,
            'blocks_4k': ROOT_BLOCKS,
            'volume_uuid_hex': VOLUME_UUID.hex(),
            'sha256': digest,
            **upg_stats,
            'fsck_hfs': 'PASS',
        }
        report_path.write_text(json.dumps(report, indent=2) + '\n')
        sudo_uid = int(os.environ.get('SUDO_UID', '0'))
        sudo_gid = int(os.environ.get('SUDO_GID', '0'))
        if sudo_uid:
            os.chown(out, sudo_uid, sudo_gid)
            os.chown(report_path, sudo_uid, sudo_gid)
        print(json.dumps(report, indent=2))
        return

    if not args.ipsw:
        raise SystemExit('--ipsw is required unless --upgrade-in-place is set')
    if out.exists():
        raise SystemExit(f'Output image already exists: {out}')
    rsync_bin = find_gnu_rsync()

    import zipfile
    with zipfile.ZipFile(args.ipsw) as zf:
        bm = plistlib.loads(zf.read('BuildManifest.plist'))
        if bm.get('ProductVersion') != PRODUCT_VERSION or bm.get('ProductBuildVersion') != BUILD_VERSION:
            raise ValueError('Expected iOS 16.7.16 (20H392) IPSW')
        ident = next(
            i for i in bm['BuildIdentities']
            if i['Info']['DeviceClass'] == 'd22ap' and i['Info'].get('RestoreBehavior') == 'Erase'
        )
        os_member = ident['Manifest']['OS']['Info']['Path']
        sysos_member = ident['Manifest']['Cryptex1,SystemOS']['Info']['Path']
        appos_member = ident['Manifest']['Cryptex1,AppOS']['Info']['Path']

    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open('wb') as stream:
        stream.truncate(ROOT_BYTES)

    attach_out = subprocess.check_output(
        ['hdiutil', 'attach', '-nomount', '-imagekey', 'diskimage-class=CRawDiskImage', str(out)],
        text=True,
    )
    raw_disk = re.search(r'(/dev/disk\d+)', attach_out).group(1)
    try:
        subprocess.run(['/sbin/newfs_hfs', '-s', '-J', '-b', '4096', '-v', 'iOSRoot', raw_disk.replace('/dev/disk', '/dev/rdisk')], check=True)
    finally:
        subprocess.run(['hdiutil', 'detach', raw_disk], check=True)

    with tempfile.TemporaryDirectory(prefix='houji-hfsx-', dir=str(out.parent)) as tmp:
        tmp_dir = Path(tmp)
        mount_point = tmp_dir / 'root_mnt'
        mount_point.mkdir()
        subprocess.run([
            'hdiutil', 'attach', '-nobrowse', '-owners', 'on',
            '-imagekey', 'diskimage-class=CRawDiskImage',
            '-mountpoint', str(mount_point), str(out),
        ], check=True)
        try:
            with zipfile.ZipFile(args.ipsw) as zf:
                for label, member, rel_dest in (
                    ('OS', os_member, ''),
                    ('Cryptex1,SystemOS', sysos_member, 'private/preboot/Cryptexes/OS'),
                    ('Cryptex1,AppOS', appos_member, 'private/preboot/Cryptexes/App'),
                ):
                    dmg_tmp = tmp_dir / f'{label.replace(",", "_")}.dmg'
                    print(f'[1/4] Extracting {label} ({member}) ...', flush=True)
                    extract_ipsw_member(zf, member, dmg_tmp)
                    disks, dmg_mnt = attach_dmg_readonly(dmg_tmp)
                    try:
                        dst_dir = mount_point / rel_dest if rel_dest else mount_point
                        dst_dir.mkdir(parents=True, exist_ok=True)
                        print(f'[2/4] Copying {label} -> /{rel_dest} ...', flush=True)
                        subprocess.run([rsync_bin, '-aH', '--numeric-ids', f'{dmg_mnt}/', f'{dst_dir}/'], check=True)
                    finally:
                        detach_disks(disks)
                        dmg_tmp.unlink(missing_ok=True)

            print('[3/4] Applying iOS 16 bring-up tweaks and houji GPU/userland bundles ...', flush=True)
            patched_apps = apply_sweet_and_houji_tweaks(
                mount_point,
                args.metal_build.resolve(),
                args.compat_build.resolve(),
                args.system_apps_build.resolve(),
                args.power_probe_build.resolve(),
                tmp_dir,
            )
            os.sync()
        finally:
            subprocess.run(['hdiutil', 'detach', str(mount_point)], check=True)

    with out.open('r+b') as f:
        f.seek(1024 + 104)
        f.write(VOLUME_UUID)
        f.seek(ROOT_BYTES - 1024 + 104)
        f.write(VOLUME_UUID)
        f.flush()
        os.fsync(f.fileno())

    verify_houji_hfs_header(out)
    print('[4/4] Running fsck_hfs -fn verification ...', flush=True)
    ro_out = subprocess.check_output(
        ['hdiutil', 'attach', '-nomount', '-readonly', '-imagekey', 'diskimage-class=CRawDiskImage', str(out)],
        text=True,
    )
    ro_disk = re.search(r'(/dev/disk\d+)', ro_out).group(1)
    try:
        subprocess.run(['/sbin/fsck_hfs', '-fn', ro_disk.replace('/dev/disk', '/dev/rdisk')], check=True)
    finally:
        subprocess.run(['hdiutil', 'detach', ro_disk], check=True)

    print('Computing SHA-256 of 32 GiB HFSX image ...', flush=True)
    digest = sha256_file(out)
    report = {
        'status': 'PASS',
        'bytes': ROOT_BYTES,
        'blocks_4k': ROOT_BLOCKS,
        'volume_uuid_hex': VOLUME_UUID.hex(),
        'sha256': digest,
        'patched_system_apps': patched_apps,
        'fsck_hfs': 'PASS',
    }
    report_path = out.with_suffix('.json')
    report_path.write_text(json.dumps(report, indent=2) + '\n')
    sudo_uid = int(os.environ.get('SUDO_UID', '0'))
    sudo_gid = int(os.environ.get('SUDO_GID', '0'))
    if sudo_uid:
        os.chown(out, sudo_uid, sudo_gid)
        os.chown(report_path, sudo_uid, sudo_gid)
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
