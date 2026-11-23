#!/usr/bin/env python3
"""Stage OEM UEFI inputs into local untracked directories; no device access."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import uuid

ROOT = Path(__file__).resolve().parents[1]
FOUNDATION_DRIVERS = (
    'SmemDxe', 'DALSys', 'HWIODxeDriver', 'ChipInfo',
    'PlatformInfoDxeDriver', 'ULogDxe', 'ShmBridgeDxeLA', 'ScmDxeCompat',
    'CmdDbDxe', 'PwrUtilsDxe', 'NpaDxe', 'RpmhDxe', 'VcsDxe', 'ClockDxe',
    'HALIOMMU', 'ICBDxe',
)


def load_lib_module(name, filename):
    path = ROOT / 'tools/lib' / filename
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def find_modules(dump_root, wanted):
    matches = {}
    for ui in dump_root.rglob('*.ui'):
        name = ui.read_bytes().decode('utf-16le').rstrip('\0')
        if name not in wanted:
            continue
        if name in matches:
            raise ValueError('Ambiguous OEM driver: ' + name)
        matches[name] = ui.parent
    missing = sorted(set(wanted) - set(matches))
    if missing:
        raise ValueError('Missing OEM drivers: ' + ', '.join(missing))
    return matches


def stage_fv_vendor_pkg(dump_root, vendor_output, drivers):
    for name in drivers:
        if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*', name):
            raise ValueError('Invalid driver name: ' + name)
    matches = find_modules(dump_root, set(drivers))
    manifest = []
    for name in sorted(drivers):
        directory = matches[name]
        guid = str(uuid.UUID(directory.name.removeprefix('file-'))).upper()
        pe = list(directory.glob('*.pe'))
        deps = list(directory.glob('*.dxe.depex'))
        if len(pe) != 1 or len(deps) > 1 or pe[0].read_bytes()[:2] != b'MZ':
            raise ValueError('Unexpected OEM section layout: ' + name)
        out = vendor_output / 'HoujiVendorPkg' / name
        out.mkdir(parents=True, exist_ok=True)
        # EDK2 FDF binary rules expect DXE_DEPEX before PE32.
        items = ([(deps[0], '.depex', 'DXE_DEPEX')] if deps else []) + [(pe[0], '.efi', 'PE32')]
        binaries = []
        record = {'name': name, 'guid': guid, 'inputs': []}
        for src, suffix, kind in items:
            dest = out / (name + suffix)
            shutil.copyfile(src, dest)
            binaries.append(f'  {kind}|{dest.name}|*')
            record['inputs'].append({
                'file': src.name,
                'bytes': src.stat().st_size,
                'sha256': hashlib.sha256(src.read_bytes()).hexdigest(),
            })
        inf = (
            f'[Defines]\n'
            f'  INF_VERSION = 0x0001001B\n'
            f'  BASE_NAME = {name}\n'
            f'  FILE_GUID = {guid}\n'
            f'  MODULE_TYPE = DXE_DRIVER\n'
            f'  VERSION_STRING = 1.0\n'
            f'  ENTRY_POINT = EfiEntry\n\n'
            f'[Binaries.AARCH64]\n' + '\n'.join(binaries) + '\n\n[Depex]\n  TRUE\n'
        )
        (out / (name + '.inf')).write_text(inf)
        manifest.append(record)
    (vendor_output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')


def stage_runtime_services(dump_root, services_output):
    wanted = set(FOUNDATION_DRIVERS) | {'UFSDxe'}
    matches = find_modules(dump_root, wanted)
    services_output.mkdir(parents=True, exist_ok=True)
    scm_patcher = load_lib_module('patch_scm', 'patch-scm-trace.py')
    ufs_patcher = load_lib_module('patch_ufs', 'patch-ufs-readonly.py')
    records = {}
    for name in FOUNDATION_DRIVERS:
        pe = list(matches[name].glob('*.pe'))
        if len(pe) != 1:
            raise ValueError('Expected one PE section for ' + name)
        raw = pe[0].read_bytes()
        if name == 'ScmDxeCompat':
            patched, _, _ = scm_patcher.create(raw)
            target = services_output / 'ScmDxeCompat.efi'
            target.write_bytes(patched)
        else:
            target = services_output / f'{name}.efi'
            target.write_bytes(raw)
        records[target.name] = {
            'bytes': target.stat().st_size,
            'sha256': hashlib.sha256(target.read_bytes()).hexdigest(),
        }
    ufs_pe = list(matches['UFSDxe'].glob('*.pe'))
    if len(ufs_pe) != 1:
        raise ValueError('Expected one PE section for UFSDxe')
    ufs_ro = ufs_patcher.patch(ufs_pe[0].read_bytes())
    ufs_target = services_output / 'UFSDxeReadOnly.efi'
    ufs_target.write_bytes(ufs_ro)
    records[ufs_target.name] = {
        'bytes': ufs_target.stat().st_size,
        'sha256': hashlib.sha256(ufs_ro).hexdigest(),
    }
    (services_output / 'manifest.json').write_text(json.dumps(records, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dump', type=Path, required=True, help='Extracted uefi.elf firmware volume dump')
    parser.add_argument('--vendor-output', type=Path, help='Output directory for HoujiVendorPkg')
    parser.add_argument('--driver', action='append', default=[], help='FV DXE driver name (default: EnvDxeEnhanced)')
    parser.add_argument('--services-output', type=Path, help='Output directory for native-boot OEM runtime DXEs')
    args = parser.parse_args()
    if not args.vendor_output and not args.services_output:
        parser.error('Specify --vendor-output and/or --services-output')
    if args.vendor_output:
        drivers = args.driver or ['EnvDxeEnhanced']
        stage_fv_vendor_pkg(args.dump, args.vendor_output, drivers)
        print(f'Staged FV vendor package ({", ".join(drivers)}) -> {args.vendor_output}')
    if args.services_output:
        stage_runtime_services(args.dump, args.services_output)
        print(f'Staged 17 runtime OEM/guarded DXEs -> {args.services_output}')


if __name__ == '__main__':
    main()
