#!/usr/bin/env python3
"""Write a verified 32 GiB HFSX image into the prefix of userdata via rescue ADB.

Never modifies GPT or any partition outside /dev/block/by-name/userdata [0, 32 GiB).
Coalesces contiguous all-zero 128 MiB chunks into on-device /dev/zero writes and
verifies every written chunk plus the complete 32 GiB SHA-256 on readback.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import time

CHUNK_MIB = 128
CHUNK_BYTES = CHUNK_MIB * 1024 * 1024
TOTAL_CHUNKS = 256
ROOT_BYTES = TOTAL_CHUNKS * CHUNK_BYTES
ROOT_BLOCKS_4K = ROOT_BYTES // 4096
VOLUME_UUID = bytes.fromhex('1e38300864ba2b7b')
ZERO_CHUNK_SHA = hashlib.sha256(bytes(CHUNK_BYTES)).hexdigest()


def adb_run(adb_bin, serial, cmd, timeout=300):
    args = [adb_bin] + (['-s', serial] if serial else []) + ['exec-out', cmd]
    res = subprocess.run(args, capture_output=True, timeout=timeout)
    if res.returncode != 0:
        raise RuntimeError(f'ADB command failed ({cmd}): {res.stderr.decode(errors="replace")}')
    return res.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adb', default='adb')
    parser.add_argument('--serial')
    parser.add_argument('--lz4', default='lz4')
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--diff-only', action='store_true',
                        help='Scan on-device 128 MiB chunk hashes first and write only changed chunks')
    args = parser.parse_args()

    if args.report.exists():
        raise FileExistsError(args.report)
    img = args.image.resolve()
    if img.stat().st_size != ROOT_BYTES:
        raise ValueError(f'Expected 32 GiB ({ROOT_BYTES} bytes) HFSX image')

    with img.open('rb') as f:
        hdr = f.read(4096)[1024:]
    if (hdr[:4] != b'HX\x00\x05' or
            struct.unpack_from('>I', hdr, 40)[0] != 4096 or
            struct.unpack_from('>I', hdr, 44)[0] != ROOT_BLOCKS_4K or
            hdr[104:112] != VOLUME_UUID):
        raise ValueError('Image failed houji HFSX volume header check')

    meta_path = img.with_suffix('.json')
    expected_whole_sha = json.loads(meta_path.read_text())['sha256'] if meta_path.is_file() else None

    ident = adb_run(
        args.adb, args.serial,
        'id -u; getprop ro.product.device; getprop ro.houji.native_rescue; '
        'readlink -f /dev/block/by-name/userdata; blockdev --getsize64 /dev/block/by-name/userdata'
    ).decode().splitlines()
    if ident[:4] != ['0', 'houji', '1', '/dev/block/sda33'] or int(ident[4]) < ROOT_BYTES:
        raise RuntimeError(f'Unexpected rescue/userdata identity: {ident}')

    mounts = adb_run(args.adb, args.serial, 'cat /proc/mounts').decode().splitlines()
    if any(len(line.split()) >= 2 and line.split()[1] in ('/data', '/sdcard') for line in mounts):
        raise RuntimeError('/data or /sdcard is mounted; unmount before writing userdata')

    print('Scanning 256 x 128 MiB host chunks ...', flush=True)
    chunk_shas = []
    whole = hashlib.sha256()
    with img.open('rb') as stream:
        for _ in range(TOTAL_CHUNKS):
            buf = stream.read(CHUNK_BYTES)
            if len(buf) != CHUNK_BYTES:
                raise RuntimeError('Short read on host image')
            whole.update(buf)
            chunk_shas.append(hashlib.sha256(buf).hexdigest())
    host_sha = whole.hexdigest()
    if expected_whole_sha and host_sha != expected_whole_sha:
        raise RuntimeError(f'Host image SHA-256 differs from {meta_path}: {host_sha} != {expected_whole_sha}')

    zero_indices = [i for i, s in enumerate(chunk_shas) if s == ZERO_CHUNK_SHA]
    data_indices = [i for i, s in enumerate(chunk_shas) if s != ZERO_CHUNK_SHA]
    print(f'Host SHA-256={host_sha}: {len(data_indices)} data chunks ({len(data_indices) * CHUNK_MIB} MiB), '
          f'{len(zero_indices)} zero chunks ({len(zero_indices) * CHUNK_MIB} MiB)', flush=True)

    t0 = time.monotonic()
    if args.diff_only:
        print('Hashing current 256 x 128 MiB chunks on device ...', flush=True)
        dev_shas_raw = adb_run(
            args.adb, args.serial,
            'set -e; i=0; while [ $i -lt 256 ]; do '
            'dd if=/dev/block/by-name/userdata bs=4194304 skip=$((i*32)) count=32 status=none | sha256sum; '
            'i=$((i+1)); done',
            timeout=600,
        ).decode().splitlines()
        if len(dev_shas_raw) != TOTAL_CHUNKS:
            raise RuntimeError(f'Expected 256 device chunk hashes, got {len(dev_shas_raw)}')
        dev_shas = [line.split()[0] for line in dev_shas_raw]
        zero_indices = [i for i in zero_indices if dev_shas[i] != ZERO_CHUNK_SHA]
        data_indices = [i for i in data_indices if dev_shas[i] != chunk_shas[i]]
        print(f'Diff sync: only {len(data_indices)} data chunks and {len(zero_indices)} zero chunks changed!', flush=True)

    # Coalesce contiguous zero-chunk runs for fast internal UFS zeroing
    idx = 0
    while idx < len(zero_indices):
        start_c = zero_indices[idx]
        end_c = start_c + 1
        while idx + 1 < len(zero_indices) and zero_indices[idx + 1] == end_c:
            idx += 1
            end_c += 1
        seek_4m = start_c * 32
        count_4m = (end_c - start_c) * 32
        print(f'Zeroing chunks [{start_c}..{end_c - 1}] ({(end_c - start_c) * CHUNK_MIB} MiB) on device ...', flush=True)
        adb_run(
            args.adb, args.serial,
            f'dd if=/dev/zero of=/dev/block/by-name/userdata bs=4194304 seek={seek_4m} count={count_4m} conv=notrunc,fsync status=none',
            timeout=300,
        )
        idx += 1

    # Stream and verify each non-zero 128 MiB chunk
    tmp_lz4 = args.report.parent / '.tmp-userdata-chunk.lz4'
    args.report.parent.mkdir(parents=True, exist_ok=True)
    try:
        with img.open('rb') as stream:
            for pos, cidx in enumerate(data_indices, 1):
                stream.seek(cidx * CHUNK_BYTES)
                raw = stream.read(CHUNK_BYTES)
                comp = subprocess.run([args.lz4, '-1', '-q', '-c'], input=raw, capture_output=True, check=True).stdout
                tmp_lz4.write_bytes(comp)
                push_cmd = [args.adb] + (['-s', args.serial] if args.serial else []) + ['push', str(tmp_lz4), '/tmp/houji-chunk.lz4']
                subprocess.run(push_cmd, check=True, capture_output=True, timeout=180)
                seek_4m = cidx * 32
                got_sha = adb_run(
                    args.adb, args.serial,
                    f'set -e -o pipefail; lz4 -d -q -c /tmp/houji-chunk.lz4 | '
                    f'dd of=/dev/block/by-name/userdata bs=4194304 seek={seek_4m} count=32 conv=notrunc,fsync status=none; '
                    f'rm -f /tmp/houji-chunk.lz4; '
                    f'dd if=/dev/block/by-name/userdata bs=4194304 skip={seek_4m} count=32 status=none | sha256sum',
                    timeout=300,
                ).decode().split()[0]
                if got_sha != chunk_shas[cidx]:
                    raise RuntimeError(f'Chunk {cidx} readback SHA-256 mismatch: {got_sha} != {chunk_shas[cidx]}')
                if pos % 5 == 0 or pos == len(data_indices):
                    print(f'  [{pos}/{len(data_indices)}] chunk {cidx:3d} verified ({got_sha[:12]})', flush=True)
    finally:
        tmp_lz4.unlink(missing_ok=True)

    print('Flushing block buffers and verifying full 32 GiB on-device SHA-256 ...', flush=True)
    full_sha = adb_run(
        args.adb, args.serial,
        'set -e -o pipefail; sync; blockdev --flushbufs /dev/block/by-name/userdata; '
        'dd if=/dev/block/by-name/userdata bs=4194304 count=8192 status=none | sha256sum',
        timeout=600,
    ).decode().split()[0]
    if full_sha != host_sha:
        raise RuntimeError(f'Full 32 GiB readback SHA-256 mismatch: {full_sha} != {host_sha}')

    elapsed = round(time.monotonic() - t0, 2)
    result = {
        'status': 'PASS',
        'bytes': ROOT_BYTES,
        'sha256': full_sha,
        'data_chunks': len(data_indices),
        'zero_chunks': len(zero_indices),
        'full_32gib_readback_verified': True,
        'seconds': elapsed,
    }
    args.report.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
