#!/usr/bin/env python3
"""Build and round-trip verify the 64 MiB FAT32 HOUJIESP RAM payload."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import zlib

PAYLOAD_BYTES = 64 * 1024 * 1024
OEM_DXES = (
    'SmemDxe.efi', 'DALSys.efi', 'HWIODxeDriver.efi', 'ChipInfo.efi',
    'PlatformInfoDxeDriver.efi', 'ULogDxe.efi', 'ShmBridgeDxeLA.efi',
    'ScmDxeCompat.efi', 'CmdDbDxe.efi', 'PwrUtilsDxe.efi', 'NpaDxe.efi',
    'RpmhDxe.efi', 'VcsDxe.efi', 'ClockDxe.efi', 'HALIOMMU.efi',
    'ICBDxe.efi', 'UFSDxeReadOnly.efi',
)
GPU_FIRMWARE_FILES = ('gmu_gen70900.bin', 'gen70900_sqe.fw', 'gen70900_aqe.fw')


def validate_kernel(kernel_bytes):
    if len(kernel_bytes) < 32 or struct.unpack_from('<IIII', kernel_bytes, 0) != (0xFEEDFACF, 0x0100000C, 0, 2):
        raise ValueError('Expected plain ARM64 MH_EXECUTE Mach-O kernel')
    if b'SM8650 houji CPU' not in kernel_bytes and b'HOUJI CPU:' not in kernel_bytes:
        raise ValueError('Kernel does not contain expected houji CPU driver markers')
    if any(v in kernel_bytes for v in (b'vermeer_ufs_', b'vermeer_usb_')):
        raise ValueError('Foreign board symbols present in kernel')


def make_config(mode, boot_args):
    if mode == 'ram-xnu':
        return (
            'version = 1\n'
            '[boot]\n'
            'default = "xnu"\n'
            'timeout = 3\n'
            'fallback_timeout = 120\n'
            'rotate = 0\n'
            '[ui]\n'
            'title = "Xiaomi 14 UniXNU RAM Bring-Up"\n'
            '[[driver]]\n'
            'path = "/Drivers/DarwinBoot.efi"\n'
            'connect = true\n'
            '[[entry]]\n'
            'id = "xnu"\n'
            'title = "Darwin 22.6.0 - XNU RAM Console"\n'
            'type = "xnu"\n'
            'path = "/Payloads/kernel.macho"\n'
            f'args = {json.dumps(boot_args)}\n'
            '[[entry]]\n'
            'id = "restart"\n'
            'title = "Restart"\n'
            'type = "action"\n'
            'action = "reset"\n'
        )
    return (
        'version = 1\n'
        '[boot]\n'
        'default = "ios"\n'
        'timeout = 3\n'
        'fallback_timeout = 120\n'
        'rotate = 0\n'
        '[ui]\n'
        'title = "Xiaomi 14 UniXNU iOS 16"\n'
        '[[entry]]\n'
        'id = "ios"\n'
        'title = "Boot iOS 16.7.16 (Native UFS)"\n'
        'type = "efi"\n'
        'path = "/Payloads/StorageProbe.efi"\n'
        'args = "--xnu-ufs-read"\n'
        '[[entry]]\n'
        'id = "restart"\n'
        'title = "Restart"\n'
        'type = "action"\n'
        'action = "reset"\n'
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('ram-xnu', 'native-ufs'), required=True)
    parser.add_argument('--kernel', type=Path, required=True)
    parser.add_argument('--adt', type=Path, required=True)
    parser.add_argument('--darwinboot', type=Path, required=True)
    parser.add_argument('--boot-args', default='-v serial=3 debug=0x14e keepsyms=1 cpus=1 wfi=1 sweetfb_hz=60')
    parser.add_argument('--storage-probe', type=Path, help='HoujiStorageProbe.efi (required for native-ufs)')
    parser.add_argument('--partition-dxe', type=Path, help='PartitionDxe.efi (required for native-ufs)')
    parser.add_argument('--oem-services-dir', type=Path, help='Staged OEM runtime DXE directory (required for native-ufs)')
    parser.add_argument('--gpu-firmware-dir', type=Path, help='Extracted Adreno 750 firmware directory (required for native-ufs)')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()

    if len(args.boot_args.encode('ascii')) > 512 or '\0' in args.boot_args or '\n' in args.boot_args:
        raise ValueError('Invalid boot arguments')
    validate_kernel(args.kernel.read_bytes())

    files = {
        'Payloads/kernel.macho': args.kernel,
        'Payloads/kernel.macho.adt': args.adt,
        'Drivers/DarwinBoot.efi': args.darwinboot,
    }
    if args.mode == 'native-ufs':
        if not all((args.storage_probe, args.partition_dxe, args.oem_services_dir, args.gpu_firmware_dir)):
            parser.error('native-ufs requires --storage-probe, --partition-dxe, --oem-services-dir, and --gpu-firmware-dir')
        files['Payloads/StorageProbe.efi'] = args.storage_probe
        files['Drivers/PartitionDxe.efi'] = args.partition_dxe
        for dxe in OEM_DXES:
            candidate = args.oem_services_dir / dxe
            if not candidate.is_file():
                raise FileNotFoundError(f'Missing staged OEM DXE: {candidate}')
            files[f'Drivers/{dxe}'] = candidate
        for fw in GPU_FIRMWARE_FILES:
            candidate = args.gpu_firmware_dir / fw
            if not candidate.is_file():
                raise FileNotFoundError(f'Missing GPU firmware file: {candidate}')
            files[f'Payloads/{fw}'] = candidate

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('wb') as stream:
        stream.truncate(PAYLOAD_BYTES)

    def mtool(tool, *tool_args):
        subprocess.run([tool, '-i', str(args.output), *map(str, tool_args)], check=True)

    mtool('mformat', '-F', '-v', 'HOUJIESP', '-N', '0x484f554a', '::')
    mtool('mmd', '::/EFI', '::/EFI/UniXNU', '::/Payloads', '::/Drivers')

    with tempfile.TemporaryDirectory(prefix='houji-esp-') as tmp:
        tmp_dir = Path(tmp)
        cfg_path = tmp_dir / 'unixnu.toml'
        cfg_path.write_text(make_config(args.mode, args.boot_args))
        files['EFI/UniXNU/unixnu.toml'] = cfg_path
        hashes = {}
        for rel_dest, src in sorted(files.items()):
            mtool('mcopy', '-o', src, '::/' + rel_dest)
            roundtrip = tmp_dir / ('rt-' + rel_dest.replace('/', '_'))
            mtool('mcopy', '-o', '::/' + rel_dest, roundtrip)
            raw = roundtrip.read_bytes()
            if raw != src.read_bytes():
                raise ValueError('FAT32 round-trip mismatch: ' + rel_dest)
            hashes[rel_dest] = hashlib.sha256(raw).hexdigest()

    data = args.output.read_bytes()
    if len(data) != PAYLOAD_BYTES or data[71:90] != b'HOUJIESP   FAT32   ':
        raise ValueError('Unexpected FAT32 boot sector or image size')
    crc = zlib.crc32(data)
    report = {
        'mode': args.mode,
        'bytes': len(data),
        'sha256': hashlib.sha256(data).hexdigest(),
        'crc32': f'{crc:08x}',
        'files': hashes,
        'contains_xnu': True,
        'physical_storage': args.mode == 'native-ufs',
    }
    args.output.with_suffix('.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
