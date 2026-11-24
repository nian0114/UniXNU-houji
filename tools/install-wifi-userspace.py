#!/usr/bin/env python3
"""Install unixnu-wpa_supplicant and restore com.apple.wifid in an offline iOS 16 HFSX root image."""
import argparse
import os
from pathlib import Path
import plistlib
import shutil
import stat
import subprocess
import tempfile

VOLUME_UUID = bytes.fromhex('1e38300864ba2b7b')
ROOT_BYTES = 32 * 1024 * 1024 * 1024


def install_into_root(mount_root: Path, supplicant_bin: Path):
    # 1. Install /usr/libexec/unixnu-wpa_supplicant (0755, root:wheel)
    dst_bin = mount_root / 'usr/libexec/unixnu-wpa_supplicant'
    shutil.copyfile(supplicant_bin, dst_bin)
    os.chown(dst_bin, 0, 0)
    os.chmod(dst_bin, 0o755)
    subprocess.run(['codesign', '--verify', '--strict', str(dst_bin)], check=True)

    # 2. Install /private/var/ngpu/etc/wifi/wpa_supplicant.conf
    conf_dir = mount_root / 'private/var/ngpu/etc/wifi'
    conf_dir.mkdir(parents=True, exist_ok=True)
    for d in (mount_root / 'private/var/ngpu', mount_root / 'private/var/ngpu/etc', conf_dir):
        os.chown(d, 0, 0)
        os.chmod(d, 0o755)
    conf = conf_dir / 'wpa_supplicant.conf'
    conf.write_text('# Networks arrive from the native Wi-Fi control channel.\nap_scan=1\n')
    os.chown(conf, 0, 0)
    os.chmod(conf, 0o600)

    # 3. Install /System/Library/LaunchDaemons/org.unixnu.wifi.supplicant.plist
    sup_job = {
        'Label': 'org.unixnu.wifi.supplicant',
        'ProgramArguments': [
            '/usr/libexec/unixnu-wpa_supplicant',
            '-Dsheng', '-ien0',
            '-c/private/var/ngpu/etc/wifi/wpa_supplicant.conf',
            '-q', '-s',
        ],
        'RunAtLoad': True,
        'KeepAlive': True,
        'ThrottleInterval': 3,
        'UserName': 'root',
        'Umask': 0o77,
        'ProcessType': 'Interactive',
    }
    sup_plist_rel = 'System/Library/LaunchDaemons/org.unixnu.wifi.supplicant.plist'
    sup_plist = mount_root / sup_plist_rel
    sup_plist.write_bytes(plistlib.dumps(sup_job, fmt=plistlib.FMT_BINARY, sort_keys=False))
    os.chown(sup_plist, 0, 0)
    os.chmod(sup_plist, 0o644)

    # 4. Read stock /System/Library/LaunchDaemons/com.apple.wifid.plist (neutralize _PanicOnCrash)
    wifid_rel = 'System/Library/LaunchDaemons/com.apple.wifid.plist'
    wifid_plist = mount_root / wifid_rel
    if not wifid_plist.is_file():
        raise FileNotFoundError(f'Missing stock {wifid_plist}')
    wifid_job = plistlib.loads(wifid_plist.read_bytes())
    if '_PanicOnCrash' in wifid_job:
        wifid_job['_PanicOnCrasX'] = wifid_job.pop('_PanicOnCrash')

    # 5. Update /System/Library/xpc/launchd.plist preserving ownership/mode
    cache = mount_root / 'System/Library/xpc/launchd.plist'
    st = cache.stat()
    ld = plistlib.loads(cache.read_bytes())
    jobs = ld['LaunchDaemons']
    jobs['/' + sup_plist_rel] = sup_job
    jobs['/' + wifid_rel] = wifid_job
    cache.write_bytes(plistlib.dumps(ld, fmt=plistlib.FMT_BINARY, sort_keys=False))
    os.chown(cache, st.st_uid, st.st_gid)
    os.chmod(cache, stat.S_IMODE(st.st_mode))
    return len(jobs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True, help='Path to 32 GiB HFSX image to update')
    parser.add_argument('--supplicant', type=Path, required=True, help='Signed unixnu-wpa_supplicant binary')
    args = parser.parse_args()

    img = args.image.resolve()
    sup = args.supplicant.resolve()
    if img.stat().st_size != ROOT_BYTES:
        raise ValueError(f'Expected 32 GiB HFSX image, got {img.stat().st_size}')

    with tempfile.TemporaryDirectory(prefix='houji-wifi-hfsx-', dir=str(img.parent)) as tmp:
        mp = Path(tmp) / 'mnt'
        mp.mkdir()
        subprocess.run([
            'hdiutil', 'attach', '-nobrowse', '-owners', 'on',
            '-imagekey', 'diskimage-class=CRawDiskImage',
            '-mountpoint', str(mp), str(img),
        ], check=True)
        try:
            total_jobs = install_into_root(mp, sup)
            os.sync()
        finally:
            subprocess.run(['hdiutil', 'detach', str(mp)], check=True)

    with img.open('r+b') as f:
        f.seek(1024 + 104)
        f.write(VOLUME_UUID)
        f.seek(ROOT_BYTES - 1024 + 104)
        f.write(VOLUME_UUID)
        f.flush()
        os.fsync(f.fileno())
    print(f'PASS: installed unixnu-wpa_supplicant and restored com.apple.wifid in {img} ({total_jobs} launchd jobs)')


if __name__ == '__main__':
    main()
