#!/usr/bin/env python3
"""Stage RAM payload CRC identity or pack a verified Android v4 boot.img."""
import argparse
import importlib.util
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]


def load_lib_script(name, filename):
    path = ROOT / 'tools/lib' / filename
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='cmd', required=True)

    st = sub.add_parser('stage-payload', help='Write PayloadIdentity.h into HoujiRamDiskDxe before UEFI build')
    st.add_argument('--payload', type=Path, required=True)
    st.add_argument('--uefi', type=Path, required=True)

    pk = sub.add_parser('pack', help='Pack BootShim + SILICIUM_UEFI.fd + optional payload + DTB into boot.img')
    pk.add_argument('--uefi', type=Path, required=True)
    pk.add_argument('--dtb', type=Path, required=True)
    pk.add_argument('--output', type=Path, required=True)
    pk.add_argument('--ramdisk', type=Path)
    pk.add_argument('--payload-in-image', action='store_true')

    args = parser.parse_args()
    if args.cmd == 'stage-payload':
        mod = load_lib_script('stage_ram_payload', 'stage-ram-payload.py')
        sys.argv = ['stage-ram-payload.py', '--payload', str(args.payload), '--uefi', str(args.uefi)]
        mod.main()
    else:
        mod = load_lib_script('pack_uefi', 'pack-uefi.py')
        argv = ['pack-uefi.py', '--uefi', str(args.uefi), '--dtb', str(args.dtb), '--output', str(args.output)]
        if args.ramdisk:
            argv += ['--ramdisk', str(args.ramdisk)]
        if args.payload_in_image:
            argv.append('--payload-in-image')
        sys.argv = argv
        mod.main()


if __name__ == '__main__':
    main()
