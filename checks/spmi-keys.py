#!/usr/bin/env python3
"""Host policy check for Houji's read-only SPMI v7 button poller (no PMIC hardware)."""
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / 'kernel/overlay/iokit/Kernel/houji-ufs-root/HoujiSpmiKeysPolicy.h'
POLLER = ROOT / 'kernel/overlay/iokit/Kernel/houji-ufs-root/HoujiSpmiKeys.inc'
DRIVER = ROOT / 'kernel/overlay/iokit/Kernel/houji-ufs-root/HoujiTouchDriver.inc'


def main():
    poller_text = POLLER.read_text()
    driver_text = DRIVER.read_text()
    assert 'HoujiSpmiKeysPolicy.h' in poller_text
    assert 'count > 512u' not in poller_text, 'SPMI v7 bus 0 has 896 APIDs; must not clamp at 512'
    assert '& 7u' not in poller_text, 'SPMI v7 EE owner field is 4 bits (& 0xf), not 3 bits'
    assert 'houjiKeysReport()' in driver_text, 'houji_touch_driver_report must emit cached key telemetry'

    unit = '#include <assert.h>\n#include <stdint.h>\n#include <stdio.h>\n'
    unit += '#include ' + json.dumps(str(POLICY)) + '\n'
    unit += r'''
static uint16_t find_apid(const uint32_t *maps, const uint32_t *cnfg, unsigned count,
                          uint16_t target_ppid, uint8_t *owner_out) {
  uint16_t found = HOUJI_SPMI_APID_NONE;
  uint8_t found_owner = 0xffu;
  for (unsigned i = 0; i < count; i++) {
    if (houji_spmi_ppid_from_map(maps[i]) != target_ppid) continue;
    uint8_t owner = houji_spmi_owner_from_cnfg(cnfg[i]);
    if (houji_spmi_should_pick_apid(found, owner)) {
      found = (uint16_t)i;
      found_owner = owner;
    }
  }
  if (owner_out) *owner_out = found_owner;
  return found;
}

int main(void) {
  unsigned count = 0;
  /* SM8650 SPMI v7 bus 0 advertises 0x380 (896) APIDs. */
  assert(houji_spmi_v7_valid(0x70000001u, 0x380u, &count) && count == 896u);
  assert(houji_spmi_v7_valid(0x70010000u, 0x400u, &count) && count == 1024u);
  assert(houji_spmi_v7_valid(0x70010000u, 0x7ffu, &count) && count == 1024u);
  assert(!houji_spmi_v7_valid(0x50000000u, 0x380u, &count));
  assert(!houji_spmi_v7_valid(0x70000001u, 0x0u, &count));

  /* APIDs >= 512 must be discovered, and 4-bit EE 8 must not alias EE 0. */
  uint32_t maps[1024] = {0};
  uint32_t cnfg[1024] = {0};
  maps[512] = (HOUJI_SPMI_PPID_PON << 8);
  cnfg[512] = 0u; /* EE 0 */
  maps[700] = (HOUJI_SPMI_PPID_PON << 8);
  cnfg[700] = 8u; /* EE 8: must NOT overwrite EE 0 */
  maps[600] = (HOUJI_SPMI_PPID_VOL_UP << 8);
  cnfg[600] = 3u;
  maps[895] = (HOUJI_SPMI_PPID_VOL_UP << 8);
  cnfg[895] = 0u; /* EE 0 overrides non-0 */

  uint8_t pon_ee = 0xffu, vol_ee = 0xffu;
  assert(find_apid(maps, cnfg, 896u, HOUJI_SPMI_PPID_PON, &pon_ee) == 512u && pon_ee == 0u);
  assert(find_apid(maps, cnfg, 896u, HOUJI_SPMI_PPID_VOL_UP, &vol_ee) == 895u && vol_ee == 0u);
  assert(find_apid(maps, cnfg, 896u, 0x299u, &vol_ee) == HOUJI_SPMI_APID_NONE && vol_ee == 0xffu);

  /* Observer offset (EE0) and 1-byte EXT_READL command encoding. */
  assert(houji_spmi_obs_offset(0u) == 0u);
  assert(houji_spmi_obs_offset(895u) == 0x20u * 895u);
  assert(houji_spmi_obs_offset(1023u) < 0x8000u);
  assert(houji_spmi_ext_readl_cmd(HOUJI_SPMI_REG_RT_STS) == ((1u << 27) | (0x10u << 4)));

  /* Status decode: pending=0, clean DONE=1, any error or missing DONE=-1. */
  assert(houji_spmi_obs_status(0x0u) == 0);
  assert(houji_spmi_obs_status(0x1u) == 1);
  assert(houji_spmi_obs_status(0x2u) == -1);
  assert(houji_spmi_obs_status(0x4u) == -1);
  assert(houji_spmi_obs_status(0x8u) == -1);
  assert(houji_spmi_obs_status(0x3u) == -1);
  assert(houji_spmi_obs_status(0x5u) == -1);
  assert(houji_spmi_obs_status(0x9u) == -1);

  /* Button decode: power=pon bit7, vol-=pon bit6, vol+=gpio6 bit0 active-low. */
  int b[3] = {-1, -1, -1};
  houji_spmi_decode_buttons(0x00u, 0x01u, b);
  assert(b[0] == 0 && b[1] == 0 && b[2] == 0);
  houji_spmi_decode_buttons(0x80u, 0x01u, b);
  assert(b[0] == 1 && b[1] == 0 && b[2] == 0);
  houji_spmi_decode_buttons(0x40u, 0x01u, b);
  assert(b[0] == 0 && b[1] == 0 && b[2] == 1);
  houji_spmi_decode_buttons(0x00u, 0x00u, b);
  assert(b[0] == 0 && b[1] == 1 && b[2] == 0);
  houji_spmi_decode_buttons(0xc0u, 0x00u, b);
  assert(b[0] == 1 && b[1] == 1 && b[2] == 1);

  puts("PASS: SPMI v7 1024-APID scan, 4-bit EE owner mask, observer status, and button decode verified; no PMIC hardware");
  return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix='houji-spmi-keys-') as temporary:
        src = Path(temporary) / 'spmi_keys.c'
        exe = Path(temporary) / 'spmi_keys'
        src.write_text(unit)
        subprocess.run(['clang', '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', str(src), '-o', str(exe)], check=True)
        subprocess.run([str(exe)], check=True, timeout=10)


if __name__ == '__main__':
    main()
