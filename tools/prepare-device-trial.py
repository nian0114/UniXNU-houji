#!/usr/bin/env python3
"""Build rescue recovery, back up critical device partitions, and bind trial headers."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import uuid
import zipfile
import zlib

ROOT = Path(__file__).resolve().parents[1]
SKIP_BY_NAME = {'userdata', 'super', 'cust', 'opconfig', 'prism', 'optics'}
FILE_BYTES = 65536
LOG_MAGIC = b'HJXNU001'


def load_lib_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'tools/lib' / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def c_guid_initializer(u):
    b = u.bytes_le
    d1, d2, d3 = struct.unpack_from('<IHH', b, 0)
    tail = ','.join(f'0x{x:02X}' for x in b[8:])
    return f'{{0x{d1:08X},0x{d2:04X},0x{d3:04X},{{{tail}}}}}'


def make_rescue_recovery(orangefox_zip, lz4_bin, avbtool_py, avb_key, output):
    if output.exists():
        raise FileExistsError(output)
    rescue_mod = load_lib_module('rescue_ramdisk', 'make-rescue-ramdisk.py')
    with tempfile.TemporaryDirectory(prefix='houji-ofrp-') as td:
        td_path = Path(td)
        with zipfile.ZipFile(orangefox_zip) as zf:
            rec_bytes = zf.read('recovery.img')
        if rec_bytes[:8] != b'ANDROID!' or struct.unpack_from('<I', rec_bytes, 40)[0] != 4:
            raise ValueError('Expected Android boot header v4 recovery.img')
        part_size = len(rec_bytes)
        rsize = struct.unpack_from('<I', rec_bytes, 12)[0]
        comp_in = td_path / 'in.lz4'
        cpio_in = td_path / 'in.cpio'
        cpio_out = td_path / 'out.cpio'
        comp_out = td_path / 'out.lz4'
        comp_in.write_bytes(rec_bytes[4096:4096 + rsize])
        subprocess.run([lz4_bin, '-d', '-f', str(comp_in), str(cpio_in)], check=True)
        entries = rescue_mod.transform(rescue_mod.parse(cpio_in.read_bytes()))
        packed_cpio = rescue_mod.encode(entries)
        cpio_out.write_bytes(packed_cpio)
        subprocess.run([lz4_bin, '-l', '-9', '-f', str(cpio_out), str(comp_out)], check=True)
        comp = comp_out.read_bytes()
        hdr = bytearray(rec_bytes[:4096])
        struct.pack_into('<I', hdr, 12, len(comp))
        cend = (4096 + len(comp) + 4095) & ~4095
        raw_boot = bytes(hdr) + comp + bytes(cend - 4096 - len(comp))
        staged_rec = td_path / 'recovery.img'
        staged_rec.write_bytes(raw_boot)
        subprocess.run([
            sys.executable, str(avbtool_py), 'add_hash_footer',
            '--image', str(staged_rec),
            '--partition_name', 'recovery',
            '--partition_size', str(part_size),
            '--algorithm', 'SHA256_RSA4096',
            '--key', str(avb_key),
            '--rollback_index', '1725494400',
            '--prop', 'com.android.build.recovery.fingerprint:Xiaomi/twrp_houji/houji:99.87.36/AP2A.240905.003/eng.runner.20260919.114714:eng/test-keys',
            '--prop', 'com.android.build.boot.os_version:99.87.36',
            '--prop', 'com.android.build.boot.security_patch:2099-12-31',
        ], check=True)
        subprocess.run([
            sys.executable, str(avbtool_py), 'verify_image',
            '--image', str(staged_rec),
            '--key', str(avb_key),
        ], check=True)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(staged_rec.read_bytes())
    rebuilt = output.read_bytes()
    report = {
        'bytes': len(rebuilt),
        'sha256': hashlib.sha256(rebuilt).hexdigest(),
        'avb_verified': True,
        'automatic_userdata_mount': False,
        'logfs_mount': 'read-only (/dev/logfs)',
    }
    output.with_suffix('.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


def adb_exec(adb_bin, serial, cmd, timeout=180):
    base = [adb_bin] + (['-s', serial] if serial else []) + ['exec-out', cmd]
    res = subprocess.run(base, capture_output=True, timeout=timeout)
    if res.returncode != 0:
        raise RuntimeError(f'ADB command failed ({cmd}): {res.stderr.decode(errors="replace")}')
    return res.stdout


def verify_rescue_environment(adb_bin, serial):
    out = adb_exec(adb_bin, serial, 'id -u; getprop ro.product.device; getprop ro.houji.native_rescue').decode().splitlines()
    if out[:3] != ['0', 'houji', '1']:
        raise RuntimeError(f'Expected houji native rescue recovery (got {out})')
    mounts = adb_exec(adb_bin, serial, 'cat /proc/mounts').decode().splitlines()
    if any(len(line.split()) >= 2 and line.split()[1] == '/data' for line in mounts):
        raise RuntimeError('/data (userdata) is mounted; aborting')


def backup_device(adb_bin, serial, output_dir):
    if output_dir.exists():
        raise FileExistsError(output_dir)
    verify_rescue_environment(adb_bin, serial)
    os.umask(0o077)
    gpt_dir = output_dir / 'gpt'
    part_dir = output_dir / 'partitions'
    gpt_dir.mkdir(parents=True)
    part_dir.mkdir(parents=True)

    disks_meta = []
    for disk_name in ('sda', 'sdb', 'sdc', 'sdd', 'sde', 'sdf'):
        dev = f'/dev/block/{disk_name}'
        sz_txt = adb_exec(adb_bin, serial, f'blockdev --getsize64 {dev}').decode().strip()
        total_bytes = int(sz_txt)
        total_lbas = total_bytes // 4096
        prim1 = adb_exec(adb_bin, serial, f'dd if={dev} bs=4096 count=6 status=none')
        prim2 = adb_exec(adb_bin, serial, f'dd if={dev} bs=4096 count=6 status=none')
        back_start = total_lbas - 5
        back1 = adb_exec(adb_bin, serial, f'dd if={dev} bs=4096 skip={back_start} count=5 status=none')
        back2 = adb_exec(adb_bin, serial, f'dd if={dev} bs=4096 skip={back_start} count=5 status=none')
        if prim1 != prim2 or back1 != back2 or len(prim1) != 24576 or len(back1) != 20480:
            raise RuntimeError(f'Unstable GPT read on {dev}')
        (gpt_dir / f'{disk_name}-primary.bin').write_bytes(prim1)
        (gpt_dir / f'{disk_name}-backup.bin').write_bytes(back1)
        disks_meta.append({
            'device': dev,
            'bytes': total_bytes,
            'lbas_4k': total_lbas,
            'backup_start_lba': back_start,
            'primary_sha256': hashlib.sha256(prim1).hexdigest(),
            'backup_sha256': hashlib.sha256(back1).hexdigest(),
        })
        print(f'Backed up GPT: {disk_name} ({total_bytes // (1024*1024)} MiB)', flush=True)

    listing = adb_exec(
        adb_bin, serial,
        'for p in /dev/block/by-name/*; do n=$(basename "$p"); t=$(readlink -f "$p"); s=$(blockdev --getsize64 "$t"); echo "$n $t $s"; done'
    ).decode().splitlines()

    parts_meta = []
    for row in sorted(listing):
        name, target, sz_str = row.split()
        size = int(sz_str)
        if name in SKIP_BY_NAME or size > 256 * 1024 * 1024:
            continue
        raw1 = adb_exec(adb_bin, serial, f'dd if={target} bs=1048576 status=none', timeout=300)
        if len(raw1) != size:
            raw1 = adb_exec(adb_bin, serial, f'cat {target}', timeout=300)
        dev_sha = adb_exec(adb_bin, serial, f'sha256sum {target}', timeout=300).decode().split()[0]
        local_sha = hashlib.sha256(raw1).hexdigest()
        if len(raw1) != size or local_sha != dev_sha:
            raise RuntimeError(f'Partition backup mismatch on {name}: size={len(raw1)}/{size} sha={local_sha}/{dev_sha}')
        (part_dir / f'{name}.img').write_bytes(raw1)
        parts_meta.append({'partition': name, 'target': target, 'bytes': size, 'sha256': local_sha})
        print(f'Backed up partition: {name:24s} ({size // 1024:7d} KiB) sha256={local_sha[:12]}', flush=True)

    manifest = {
        'captured_at': datetime.datetime.now().astimezone().isoformat(),
        'disks': disks_meta,
        'partitions': parts_meta,
    }
    (output_dir / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(f'Backup complete: {len(disks_meta)} LUN GPTs and {len(parts_meta)} partitions verified in {output_dir}')


def bind_trial(adb_bin, serial, kernel_tree, bootloader_tree, uefi_tree, output_dir):
    if output_dir.exists():
        raise FileExistsError(output_dir)
    verify_rescue_environment(adb_bin, serial)
    os.umask(0o077)
    output_dir.mkdir(parents=True)

    # 1. Read live LUN0 (sda) GPT header + entries
    gpt_raw = adb_exec(adb_bin, serial, 'dd if=/dev/block/sda bs=4096 skip=1 count=3 status=none')
    if len(gpt_raw) != 12288 or gpt_raw[:8] != b'EFI PART':
        raise RuntimeError('Invalid LUN0 GPT header')
    hdr = gpt_raw[:4096]
    entries = gpt_raw[4096:12288]
    rev, hsz, hcrc, rsv, mylba, altlba = struct.unpack_from('<IIIIQQ', hdr, 8)
    disk_guid = uuid.UUID(bytes_le=hdr[56:72])
    pelba, nent, esz, ecrc = struct.unpack_from('<QIII', hdr, 72)
    hdr_zero = bytearray(hdr[:92])
    hdr_zero[16:20] = b'\0\0\0\0'
    if (zlib.crc32(hdr_zero) & 0xFFFFFFFF) != hcrc or (zlib.crc32(entries) & 0xFFFFFFFF) != ecrc:
        raise RuntimeError('LUN0 GPT CRC self-check failed')

    logfs_ent = entries[12 * 128:13 * 128]
    logfs_guid = uuid.UUID(bytes_le=logfs_ent[16:32])
    logfs_start, logfs_end = struct.unpack_from('<QQ', logfs_ent, 32)
    logfs_name = logfs_ent[56:].decode('utf-16le').rstrip('\0')
    if logfs_name != 'logfs' or logfs_start != 4096 or logfs_end != 6143:
        raise RuntimeError(f'Unexpected logfs GPT entry: {logfs_name} [{logfs_start}, {logfs_end}]')

    ud_ent = entries[32 * 128:33 * 128]
    ud_start, ud_end = struct.unpack_from('<QQ', ud_ent, 32)
    ud_name = ud_ent[56:].decode('utf-16le').rstrip('\0')
    if ud_name != 'userdata' or ud_start != 2260480 or (ud_end - ud_start + 1) < 32 * 262144:
        raise RuntimeError(f'Unexpected userdata GPT entry: {ud_name} [{ud_start}, {ud_end}]')

    # 2. Prepare /dev/logfs/XnuLog.bin and clear any previous UniXNU.log
    log_mod = load_lib_module('prep_log', 'prepare-xnu-log.py')
    run_id = uuid.uuid4().bytes
    initial = bytearray(FILE_BYTES)
    initial[:8] = LOG_MAGIC
    struct.pack_into('<II', initial, 8, 0, 1)
    initial[16:32] = run_id
    init_file = output_dir / 'XnuLog.initial.bin'
    init_file.write_bytes(initial)

    remote_tmp = f'/tmp/houji-xnu-log-{run_id.hex()}.bin'
    subprocess.run([adb_bin] + (['-s', serial] if serial else []) + ['push', str(init_file), remote_tmp], check=True)
    adb_exec(adb_bin, serial, (
        f'set -e; mount -o remount,rw /dev/logfs; '
        f'rm -f /dev/logfs/UniXNU.log; '
        f'if [ -e /dev/logfs/XnuLog.bin ]; then dd if={remote_tmp} of=/dev/logfs/XnuLog.bin bs=4096 count=16 conv=notrunc,fsync status=none; '
        f'else cat {remote_tmp} > /dev/logfs/XnuLog.bin; fi; '
        f'rm -f {remote_tmp}; sync; mount -o remount,ro /dev/logfs; sync; blockdev --flushbufs /dev/block/by-name/logfs'
    ))
    logfs_raw = adb_exec(adb_bin, serial, 'dd if=/dev/block/by-name/logfs bs=1048576 status=none')
    (output_dir / 'logfs-after.bin').write_bytes(logfs_raw)
    layout = log_mod.layout(logfs_raw)
    rebuilt = b''.join(logfs_raw[(lba - 4096) * 4096:(lba - 4096 + 1) * 4096] for lba in layout['lbas'])
    if rebuilt != bytes(initial):
        raise RuntimeError('On-disk FAT12 clusters do not match XnuLog.bin bytes')
    init_crc = zlib.crc32(initial) & 0xFFFFFFFF

    # 3. Pre-arm no-wipe boot-recovery BCB in misc[:864]
    misc_before = adb_exec(adb_bin, serial, 'cat /dev/block/by-name/misc')
    if len(misc_before) != 4194304:
        raise RuntimeError('Unexpected misc partition size')
    (output_dir / 'misc-before.bin').write_bytes(misc_before)
    prefix = bytearray(864)
    prefix[:14] = b'boot-recovery\0'
    prefix[64:74] = b'recovery\n\0'
    if misc_before[:864] not in (bytes(864), bytes(prefix)):
        raise RuntimeError('Foreign BCB command present in misc[:864]; refusing to overwrite')
    misc_after = bytes(prefix) + misc_before[864:]
    misc_file = output_dir / 'misc-armed.bin'
    misc_file.write_bytes(misc_after)
    subprocess.run([adb_bin] + (['-s', serial] if serial else []) + ['push', str(misc_file), '/tmp/houji-misc-armed.bin'], check=True)
    adb_exec(adb_bin, serial, 'set -e; dd if=/tmp/houji-misc-armed.bin of=/dev/block/by-name/misc bs=4096 count=1 conv=notrunc,fsync status=none; rm -f /tmp/houji-misc-armed.bin; sync; blockdev --flushbufs /dev/block/by-name/misc')
    if adb_exec(adb_bin, serial, 'cat /dev/block/by-name/misc') != misc_after:
        raise RuntimeError('misc BCB readback verification failed')

    # 4. Update local untracked build trees (.deps/kernel, .deps/bootloader, .deps/uefi)
    alloc_hdr = (
        '// Generated from verified FAT allocation; one explicitly bound trial.\n'
        'static const uint8_t kHoujiLogRunId[16] = {' + ','.join(map(str, run_id)) + '};\n'
        'static const uint16_t kHoujiLogClusters[16] = {' + ','.join(map(str, layout['clusters'])) + '};\n'
        'static const uint32_t kHoujiLogLbas[16] = {' + ','.join(map(str, layout['lbas'])) + '};\n'
        f'static const uint32_t kHoujiLogInitialCrc = 0x{init_crc:08x}U;\n'
    )
    zap_hdr = (
        '/* Generated fixed current-trial bytes; copy the SAME header into loader and XNU. */\n'
        '#ifndef HOUJI_ZAP_TRIAL_H\n'
        '#define HOUJI_ZAP_TRIAL_H\n'
        '#include <stdint.h>\n'
        'static const uint8_t kHoujiZapTrial[16] = {' + ','.join(map(str, run_id)) + '};\n'
        '#endif\n'
    )
    (kernel_tree / 'iokit/Kernel/houji-ufs-root/HoujiLogAllocation.h').write_text(alloc_hdr)
    (kernel_tree / 'iokit/Kernel/houji-ufs-root/HoujiZapTrial.h').write_text(zap_hdr)
    (bootloader_tree / 'DarwinBootPkg/Driver/HoujiZapTrial.h').write_text(zap_hdr)

    disk_bytes_c = ','.join(f'0x{b:02x}' for b in disk_guid.bytes_le)
    gpt_check_path = kernel_tree / 'iokit/Kernel/houji-ufs-root/HoujiGptCheck.h'
    gpt_txt = gpt_check_path.read_text()
    gpt_txt = re.sub(r'disk\[16\]=\{[^}]+\}', f'disk[16]={{{disk_bytes_c}}}', gpt_txt)
    gpt_txt = re.sub(r'houjiLe64\(h\+32\)!=0x[0-9A-Fa-f]+', f'houjiLe64(h+32)!=0x{altlba:X}', gpt_txt)
    gpt_txt = re.sub(r'0x631FC7EA', f'0x{hcrc:08X}', gpt_txt, flags=re.I)
    gpt_txt = re.sub(r'0x9F1BB496', f'0x{ecrc:08X}', gpt_txt, flags=re.I)
    gpt_check_path.write_text(gpt_txt)

    logfs_test_path = uefi_tree / 'Platforms/Xiaomi/houjiPkg/Application/HoujiStorageProbe/LogFsTest.h'
    lt_txt = logfs_test_path.read_text()
    lt_txt = re.sub(r'CONST EFI_GUID Disk = \{[^;]+\};', f'CONST EFI_GUID Disk = {c_guid_initializer(disk_guid)};', lt_txt)
    lt_txt = re.sub(r'CONST EFI_GUID Part = \{[^;]+\};', f'CONST EFI_GUID Part = {c_guid_initializer(logfs_guid)};', lt_txt)
    lt_txt = re.sub(r'M->LastBlock != 0x[0-9A-Fa-f]+', f'M->LastBlock != 0x{altlba:X}', lt_txt)
    lt_txt = re.sub(r'0x631FC7EA', f'0x{hcrc:08X}', lt_txt, flags=re.I)
    lt_txt = re.sub(r'0x9F1BB496', f'0x{ecrc:08X}', lt_txt, flags=re.I)
    logfs_test_path.write_text(lt_txt)

    summary = {
        'run_id': run_id.hex(),
        'disk_guid': str(disk_guid),
        'logfs_guid': str(logfs_guid),
        'lun0_alt_lba': hex(altlba),
        'gpt_header_crc32': f'{hcrc:08x}',
        'gpt_entries_crc32': f'{ecrc:08x}',
        'xnu_log_clusters': layout['clusters'],
        'xnu_log_lbas': layout['lbas'],
        'xnu_log_initial_crc32': f'{init_crc:08x}',
        'misc_bcb_armed': True,
    }
    (output_dir / 'trial-binding.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary, indent=2))


def main():
    global tempfile
    import tempfile
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='cmd', required=True)

    rec = sub.add_parser('make-rescue-recovery')
    rec.add_argument('--orangefox-zip', type=Path, required=True)
    rec.add_argument('--lz4', default='lz4')
    rec.add_argument('--avbtool', type=Path, required=True)
    rec.add_argument('--avb-key', type=Path, required=True)
    rec.add_argument('--output', type=Path, required=True)

    bkp = sub.add_parser('backup')
    bkp.add_argument('--adb', default='adb')
    bkp.add_argument('--serial')
    bkp.add_argument('--output', type=Path, required=True)

    bnd = sub.add_parser('bind-trial')
    bnd.add_argument('--adb', default='adb')
    bnd.add_argument('--serial')
    bnd.add_argument('--kernel-tree', type=Path, default=ROOT / '.deps/kernel')
    bnd.add_argument('--bootloader-tree', type=Path, default=ROOT / '.deps/bootloader')
    bnd.add_argument('--uefi-tree', type=Path, default=ROOT / '.deps/uefi')
    bnd.add_argument('--output', type=Path, required=True)

    args = parser.parse_args()
    if args.cmd == 'make-rescue-recovery':
        make_rescue_recovery(args.orangefox_zip, args.lz4, args.avbtool, args.avb_key, args.output)
    elif args.cmd == 'backup':
        backup_device(args.adb, args.serial, args.output)
    else:
        bind_trial(args.adb, args.serial, args.kernel_tree, args.bootloader_tree, args.uefi_tree, args.output)


if __name__ == '__main__':
    main()
