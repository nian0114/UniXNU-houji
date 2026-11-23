#!/usr/bin/env python3
"""Build houji Apple Device Tree (ADT) payloads for RAM-only and native GUI boots."""
import argparse
import copy
import ctypes
import hashlib
import json
from pathlib import Path
import runpy
import struct
import subprocess
import sys
import tempfile
import uuid
import zipfile
import zlib

ROOT = Path(__file__).resolve().parents[1]
DEVICE_NAMESPACE = uuid.UUID('777656f0-55e0-558f-b5ab-3976c89a40f2')
DEV_BOARD_VALUES = {
    'certificate-production-status': 0,
    'effective-production-status-ap': 0,
    'certificate-security-mode': 1,
    'effective-security-mode-sep': 1,
}
HPA_PROPERTY = 'houji,gpu-power-handoff'
HPA_BYTES = 1376
HZR_PROPERTY = 'houji,gpu-zap-reservation'
HZR_BYTES = 512


def lzfse_decode(src):
    if sys.platform == 'darwin':
        lib = ctypes.CDLL('/usr/lib/libcompression.dylib')
        lib.compression_decode_buffer.argtypes = [
            ctypes.c_void_p, ctypes.c_size_t,
            ctypes.c_void_p, ctypes.c_size_t,
            ctypes.c_void_p, ctypes.c_int,
        ]
        lib.compression_decode_buffer.restype = ctypes.c_size_t
        cap = max(len(src) * 8, 1 << 20)
        while cap <= (64 << 20):
            dst = ctypes.create_string_buffer(cap)
            written = lib.compression_decode_buffer(dst, cap, src, len(src), None, 0x801)
            if 0 < written < cap:
                return dst.raw[:written]
            cap *= 2
        raise RuntimeError('LZFSE payload exceeded decode buffer ceiling')
    return subprocess.run(['lzfse', '-decode'], input=src, capture_output=True, check=True).stdout


def unwrap_d22ap_adt(ipsw_path, adt_mod):
    expected_sha = '480e8b0888949b4128b7aa2cd254497581c69e1bafa596a760b2fa955a8a6368'
    with zipfile.ZipFile(ipsw_path) as archive:
        matches = [n for n in archive.namelist() if n.endswith('DeviceTree.d22ap.im4p')]
        if len(matches) != 1:
            raise ValueError('Expected exactly one DeviceTree.d22ap.im4p in IPSW')
        raw = archive.read(matches[0])
    if hashlib.sha256(raw).hexdigest() != expected_sha:
        raise ValueError('DeviceTree.d22ap.im4p SHA-256 differs from board.toml pin')
    tag, start, end = adt_mod.der(raw, 0)
    if tag != 0x30:
        raise ValueError('Invalid IM4P DER sequence')
    items, cursor = [], start
    while cursor < end:
        item_tag, vs, ve = adt_mod.der(raw, cursor)
        items.append((item_tag, raw[vs:ve]))
        cursor = ve
    if items[0][1] != b'IM4P' or any(t == 0x04 for t, _ in items[4:]):
        raise ValueError('Unexpected or encrypted IM4P container')
    payload = items[3][1]
    if payload[:4] == b'bvx2':
        payload = lzfse_decode(payload)
    parsed, used = adt_mod.parse(payload)
    if used != len(payload) or parsed.name != 'device-tree':
        raise ValueError('Unwrapped D22AP product tree failed round-trip validation')
    return payload


def nvram_proxy():
    def header(name, size):
        raw = bytearray(struct.pack('<BBH12s', 0x70, 0, size // 16, name))
        checksum = sum(raw)
        while checksum > 255:
            checksum = (checksum & 255) + (checksum >> 8)
        raw[1] = checksum
        return raw

    image = bytearray(8192)
    image[:16] = header(b'nvram', 32)
    image[32:48] = header(b'common', 2064)
    image[2096:2112] = header(b'free', len(image) - 2096)
    struct.pack_into('<I', image, 16, zlib.adler32(image[20:]))
    return {
        'nvram-bank-size': struct.pack('<I', len(image)),
        'nvram-bank-count': struct.pack('<I', 1),
        'nvram-current-bank': bytes(4),
        'nvram-proxy-data': bytes(image),
    }


def update_props(node, values):
    node.props = [(k, f, v) for k, f, v in node.props if k not in values]
    node.props.extend((k, 0, v) for k, v in values.items())


def walk_nodes(node):
    yield node
    for child in node.children:
        yield from walk_nodes(child)


def strict_validate(blob, expect_power_slot, expect_zap_slot):
    offset = 0
    chosen_seen = 0
    power_seen = 0
    zap_seen = 0

    def check_node(depth):
        nonlocal offset, chosen_seen, power_seen, zap_seen
        if depth > 64 or len(blob) - offset < 8:
            raise ValueError('ADT node bounds/depth error')
        prop_count, child_count = struct.unpack_from('<II', blob, offset)
        offset += 8
        if prop_count > 256 or prop_count > (len(blob) - offset) // 36:
            raise ValueError('ADT property count out of bounds')
        keys = set()
        node_name = None
        for _ in range(prop_count):
            raw_key = blob[offset:offset + 32]
            if b'\0' not in raw_key:
                raise ValueError('Unterminated ADT property key')
            key_head, key_tail = raw_key.split(b'\0', 1)
            if not key_head or any(key_tail):
                raise ValueError(f'Non-canonical property key bytes: {raw_key!r}')
            key = key_head.decode('ascii')
            if key in keys:
                raise ValueError('Duplicate ADT property: ' + key)
            keys.add(key)
            length, = struct.unpack_from('<I', blob, offset + 32)
            offset += 36
            if length & 0x80000000:
                raise ValueError('Unexpected ADT placeholder flag on ' + key)
            padded = (length + 3) & ~3
            if padded > len(blob) - offset or any(blob[offset + length:offset + padded]):
                raise ValueError('ADT property padding error on ' + key)
            val = blob[offset:offset + length]
            if key == 'name':
                if b'\0' not in val:
                    raise ValueError('Unterminated node name')
                nh, nt = val.split(b'\0', 1)
                if not nh or nt:
                    raise ValueError(f'Non-canonical node name: {val!r}')
                node_name = nh.decode('ascii')
            if key == HPA_PROPERTY:
                if depth != 1 or length != HPA_BYTES or any(val):
                    raise ValueError('Invalid houji,gpu-power-handoff slot')
                power_seen += 1
            if key == HZR_PROPERTY:
                if depth != 1 or length != HZR_BYTES or any(val):
                    raise ValueError('Invalid houji,gpu-zap-reservation slot')
                zap_seen += 1
            offset += padded
        if node_name is None or (depth == 0 and node_name != 'device-tree'):
            raise ValueError('Missing or invalid root node name')
        if node_name == 'chosen':
            if depth != 1:
                raise ValueError('/chosen must be at depth 1')
            chosen_seen += 1
        for _ in range(child_count):
            check_node(depth + 1)

    check_node(0)
    if offset != len(blob) or chosen_seen != 1:
        raise ValueError('ADT trailing bytes or missing /chosen')
    if power_seen != (1 if expect_power_slot else 0):
        raise ValueError('Unexpected houji,gpu-power-handoff count')
    if zap_seen != (1 if expect_zap_slot else 0):
        raise ValueError('Unexpected houji,gpu-zap-reservation count')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', choices=('ram', 'desktop'), required=True)
    parser.add_argument('--reference', type=Path, required=True, help='ios-vermeer-lab checkout at d68e05df...')
    parser.add_argument('--ipsw', type=Path, required=True, help='Local iPhone10,3 16.7.16 (20H392) IPSW')
    parser.add_argument('--live-fdt', type=Path, help='Extracted houji FDT (required for desktop 8-CPU profile)')
    parser.add_argument('--platform-seed', default='houji-development-unit',
                        help='Seed string hashed into RFC4122 UUIDv5 platform identity')
    parser.add_argument('--memory-mib', type=int, choices=(2048, 8192))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()

    rev = subprocess.check_output(['git', '-C', str(args.reference), 'rev-parse', 'HEAD'], text=True).strip()
    if rev != 'd68e05df683f863f054b0f9c063c54d2b1342b2a':
        raise ValueError('Reference ios-vermeer-lab checkout must be at d68e05df683f863f054b0f9c063c54d2b1342b2a')

    sys.path.insert(0, str(args.reference / 'tools'))
    import adt  # type: ignore

    product_bytes = unwrap_d22ap_adt(args.ipsw, adt)
    with tempfile.NamedTemporaryFile(prefix='d22ap-', suffix='.adt') as tmp_prod:
        tmp_prod.write(product_bytes)
        tmp_prod.flush()
        ref_mod = runpy.run_path(str(args.reference / 'tools/mkvermeeradt.py'))
        tree = ref_mod['build'](ios=True, gui=True, product_adt=Path(tmp_prod.name))

    memory_mib = args.memory_mib or (8192 if args.profile == 'desktop' else 2048)
    platform_uuid = uuid.uuid5(DEVICE_NAMESPACE, args.platform_seed)

    update_props(tree, {
        'compatible': b'D22AP\0iPhone10,3\0xiaomi,houji\0qcom,sm8650\0AppleARM\0',
        'model': b'iPhone10,3\0',
        'manufacturer': b'Xiaomi\0',
        'target-type': b'D22\0',
        'target-sub-type': b'D22AP\0',
        'physical-model': b'Xiaomi 14\0',
    })

    chosen = next(c for c in tree.children if c.name == 'chosen')
    chosen.props = [(k, f, v) for k, f, v in chosen.props if k != 'unique-chip-id']
    update_props(chosen, {
        'dram-base': bytes(8),
        'dram-size': bytes(8),
        'darwinboot-memory-size': struct.pack('<Q', memory_mib * 1024**2),
        'firmware-version': b'houji-darwin22-uefi\0',
        'houji,platform-uuid': platform_uuid.bytes,
        **nvram_proxy(),
    })

    for key, val in DEV_BOARD_VALUES.items():
        update_props(chosen, {key: struct.pack('<I', val)})

    wifi_mac = bytearray(hashlib.sha256(b'houji-native-ios-development-wifi-v1' + platform_uuid.bytes).digest()[:6])
    wifi_mac[0] = (wifi_mac[0] & 0xFE) | 0x02
    update_props(chosen, {'mac-address-wifi0': bytes(wifi_mac)})

    cpus = next(c for c in tree.children if c.name == 'cpus')
    update_props(cpus.children[0], {'compatible': b'qcom,kryo\0ARM,v8\0'})

    fb = next(c for c in tree.children if c.name == 'sweet-fbcon')
    update_props(fb, {
        'reg': struct.pack('<QQ', 0xFC400000, 4800 * 2670),
        'width': struct.pack('<I', 1200),
        'height': struct.pack('<I', 2670),
        'stride': struct.pack('<I', 4800),
    })
    armio = next(c for c in tree.children if c.name == 'arm-io')
    disp0 = next(c for c in armio.children if c.name == 'disp0')
    update_props(disp0, {
        'canvas-width': struct.pack('<I', 1200),
        'canvas-height': struct.pack('<I', 2670),
    })

    if args.profile == 'desktop':
        if not args.live_fdt:
            raise ValueError('--live-fdt is required for --profile desktop')
        sys.path.insert(0, str(ROOT / 'tools/lib'))
        import fdt  # type: ignore

        hw_tree, hw_used = fdt.parse(args.live_fdt.read_bytes())
        if hw_used != args.live_fdt.stat().st_size:
            raise ValueError('Incomplete live FDT')
        hw_nodes = dict(hw_tree.walk())
        if fdt.strings(hw_nodes['/soc/psci'].properties['method']) != ['smc']:
            raise ValueError('Expected PSCI SMC conduit in live FDT')
        if fdt.cells(hw_nodes['/soc/interrupt-controller@17100000'].properties['redistributor-stride']) != [0, 0x40000]:
            raise ValueError('Unexpected GICv3 redistributor stride in live FDT')

        cpus.children[0].props = [(k, f, v) for k, f, v in cpus.children[0].props if k != 'clock-frequency']
        base_props = [(k, v) for k, _, v in cpus.children[0].props if k not in ('name', 'AAPL,phandle')]
        handles = [int.from_bytes(n.prop('AAPL,phandle'), 'little') for n in walk_nodes(tree) if n.prop('AAPL,phandle')]
        next_handle = max(handles) + 1

        for idx in range(8):
            hw_cpu = hw_nodes[f'/cpus/cpu@{idx * 0x100:x}'].properties
            affinity = fdt.cells(hw_cpu['reg'])
            domain = fdt.cells(hw_cpu['qcom,freq-domain'])
            capacity = fdt.cells(hw_cpu['capacity-dmips-mhz'])
            l2 = fdt.cells(hw_cpu['next-level-cache'])
            expected_cap = 1024 if idx < 2 else 1792 if idx < 7 else 1894
            if (affinity != [0, idx * 0x100] or
                    domain[1] != (0, 0, 3, 3, 3, 1, 1, 2)[idx] or
                    capacity != [expected_cap] or
                    fdt.strings(hw_cpu['enable-method']) != ['psci']):
                raise ValueError(f'Unexpected SM8650 CPU{idx} hardware topology in FDT')
            if idx >= 1:
                cpu_node = adt.Node()
                cpu_node.props = [
                    ('name', 0, f'cpu{idx}\0'.encode('ascii')),
                    ('AAPL,phandle', 0, struct.pack('<I', next_handle)),
                ] + [(k, 0, copy.deepcopy(v)) for k, v in base_props]
                next_handle += 1
                cpus.children.append(cpu_node)
            cpu_node = cpus.children[idx]
            cluster_type = ord('E') if idx < 2 else ord('P')
            cluster_id = 0 if idx < 2 else 1
            cluster_core_id = idx if idx < 2 else idx - 2
            update_props(cpu_node, {
                'reg': struct.pack('<I', idx * 0x100),
                'cpu-id': struct.pack('<I', idx),
                'cluster-type': struct.pack('<I', cluster_type),
                'cluster-id': struct.pack('<I', cluster_id),
                'cluster-core-id': struct.pack('<I', cluster_core_id),
                'capacity-dmips-mhz': struct.pack('<I', capacity[0]),
                'houji,freq-domain': struct.pack('<I', domain[1]),
                'l2-cache-id': struct.pack('<I', l2[0]),
                'l3-cache-id': struct.pack('<I', 8),
                'state': b'running\0' if idx == 0 else b'waiting\0',
            })

        gic = next(c for c in armio.children if c.name == 'gic')
        update_props(gic, {'redistributor-stride': struct.pack('<Q', 0x40000)})
        tree.children.append(ref_mod['node']('psci', [('compatible', b'arm,psci-1.0\0'), ('method', b'smc\0')]))
        update_props(chosen, {
            'houji,smp-enabled': struct.pack('<I', 1),
            HPA_PROPERTY: bytes(HPA_BYTES),
        })

    update_props(chosen, {HZR_PROPERTY: bytes(HZR_BYTES)})
    tree.children += [ref_mod['node']('options'), ref_mod['node']('aliases')]

    blob = adt.serialize(tree)
    strict_validate(blob, expect_power_slot=(args.profile == 'desktop'), expect_zap_slot=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(blob)
    report = {
        'profile': args.profile,
        'bytes': len(blob),
        'sha256': hashlib.sha256(blob).hexdigest(),
        'cpus': 8 if args.profile == 'desktop' else 1,
        'memory_mib': memory_mib,
        'canvas': [1200, 2670],
        'has_gpu_power_handoff_slot': args.profile == 'desktop',
        'has_gpu_zap_reservation_slot': True,
    }
    args.output.with_suffix('.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
