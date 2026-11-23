#!/usr/bin/env python3
"""Host policy check for Houji Stage 1 PCIe RC0 + QMP PHY + WCN7850 probe (no hardware)."""
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / 'kernel/overlay/iokit/Kernel/houji-ufs-root/wifi/HoujiWifiPciePolicy.h'
PHY_TABLE = ROOT / 'kernel/overlay/iokit/Kernel/houji-ufs-root/wifi/HoujiWifiPhyTable.h'
PROBE = ROOT / 'kernel/overlay/iokit/Kernel/houji-ufs-root/wifi/HoujiWifiPcie.inc'
DRIVER = ROOT / 'kernel/overlay/iokit/Kernel/houji-ufs-root/HoujiTouchDriver.inc'
UEFI_WIFI = ROOT / 'uefi/overlay/Platforms/Xiaomi/houjiPkg/Application/HoujiStorageProbe/WifiHandoff.h'
UEFI_MAIN = ROOT / 'uefi/overlay/Platforms/Xiaomi/houjiPkg/Application/HoujiStorageProbe/HoujiStorageProbe.c'


def main():
    probe_text = PROBE.read_text()
    driver_text = DRIVER.read_text()
    uefi_wifi_text = UEFI_WIFI.read_text()
    uefi_main_text = UEFI_MAIN.read_text()

    # Static wiring and safety invariants
    assert 'HoujiWifiPciePolicy.h' in probe_text
    assert 'HoujiWifiPhyTable.h' in probe_text
    assert 'PE_parse_boot_argn("houji_wifi"' in probe_text
    assert 'gg_pin_owned(' in probe_text, 'Must check TLMM GPIO ownership before writing'
    assert 'panic(' not in probe_text, 'Stage 1 Wi-Fi probe must never panic'
    assert 'houjiWifiPcieStart()' in driver_text
    assert 'houji_wifi_pcie_snapshot()' in driver_text
    assert '#include "WifiHandoff.h"' in uefi_main_text
    assert 'PrepareWifiHandoff()' in uefi_main_text
    for rail in ('ldob15', 'ldoc3', 'ldok6', 'smpc1', 'smpc2', 'smpc3', 'smpc6', 'smpi4', 'ldoi1', 'ldoe3', 'ldoi3'):
        assert f'"{rail}"' in uefi_wifi_text, f'Missing RPMh rail {rail} in WifiHandoff.h'
    for clk in ('gcc_pcie_0_gdsc', 'gcc_pcie_0_phy_gdsc', 'gcc_cnoc_pcie_sf_axi_clk',
                'gcc_pcie_0_cfg_ahb_clk', 'gcc_pcie_0_mstr_axi_clk', 'gcc_pcie_0_slv_axi_clk',
                'tcsr_pcie_0_clkref_en'):
        assert f'"{clk}"' in uefi_wifi_text, f'Missing PCIe0 clock/domain {clk} in WifiHandoff.h'

    unit = '#include <assert.h>\n#include <stdint.h>\n#include <stdio.h>\n'
    unit += '#include ' + json.dumps(str(POLICY)) + '\n'
    unit += '#include ' + json.dumps(str(PHY_TABLE)) + '\n'
    unit += r'''
int main(void) {
  /* 1. Verify exact 115-entry houji.dtb QMP PHY table bounds and alignment. */
  assert(HOUJI_WIFI_PHY_SEQ_COUNT == 115u);
  assert(houji_wifi_phy_seq[0].offset == HOUJI_PHY_POWER_DOWN_CTRL && houji_wifi_phy_seq[0].value == 0x03u);
  assert(houji_wifi_phy_seq[113].offset == HOUJI_PHY_SW_RESET && houji_wifi_phy_seq[113].value == 0x00u);
  assert(houji_wifi_phy_seq[114].offset == HOUJI_PHY_START_CTRL && houji_wifi_phy_seq[114].value == 0x03u);
  for (unsigned i = 0; i < HOUJI_WIFI_PHY_SEQ_COUNT; i++) {
    assert(houji_wifi_phy_seq[i].offset < HOUJI_PCIE0_PHY_SIZE);
    assert((houji_wifi_phy_seq[i].offset & 3u) == 0u);
    assert(houji_wifi_phy_seq[i].delay_us <= 100u);
  }

  /* 2. TLMM GPIO physical addresses and owner-preserving CFG encoding. */
  assert(houji_wifi_tlmm_phys(HOUJI_TLMM_GPIO_WLAN_EN) == 0x0f110000u);
  assert(houji_wifi_tlmm_phys(HOUJI_TLMM_GPIO_PERST)   == 0x0f15e000u);
  assert(houji_wifi_tlmm_phys(HOUJI_TLMM_GPIO_CLKREQ)  == 0x0f15f000u);
  assert(houji_wifi_tlmm_phys(HOUJI_TLMM_GPIO_WAKE)    == 0x0f160000u);
  uint32_t cfg = houji_wifi_tlmm_cfg(0x12340000u, 3u, 1u, 7u, 1u);
  assert((cfg & 0xfffffc00u) == 0x12340000u);
  assert((cfg & 3u) == 3u && ((cfg >> 2) & 0xfu) == 1u && ((cfg >> 6) & 7u) == 7u && ((cfg >> 9) & 1u) == 1u);

  /* 3. iATU Outbound CFG0 (Region 0) and MEM (Region 1) encoding & validation. */
  houji_iatu_window w = {0};
  assert(houji_wifi_cfg0_target(1u, 0u, 0u) == 0x01000000u);
  assert(houji_wifi_encode_iatu(0u, HOUJI_IATU_TYPE_CFG0, HOUJI_PCIE0_ECAM_BASE,
                                HOUJI_PCIE0_ECAM_SIZE, houji_wifi_cfg0_target(1u, 0u, 0u), &w));
  assert(w.offset == 0x000u && w.ctrl1 == 4u && w.ctrl2 == 0x80000000u);
  assert(w.lower_base == 0x60100000u && w.limit == 0x6010ffffu && w.lower_target == 0x01000000u);

  assert(houji_wifi_encode_iatu(1u, HOUJI_IATU_TYPE_MEM, HOUJI_PCIE0_MMIO_BASE,
                                HOUJI_PCIE0_MMIO_SIZE, HOUJI_PCIE0_MMIO_BASE, &w));
  assert(w.offset == 0x200u && w.ctrl1 == 0u && w.ctrl2 == 0x80000000u);
  assert(w.lower_base == 0x60300000u && w.limit == 0x63ffffffu && w.lower_target == 0x60300000u);

  /* Invalid iATU requests rejected. */
  assert(!houji_wifi_encode_iatu(8u, HOUJI_IATU_TYPE_MEM, 0x60300000u, 0x1000u, 0x60300000u, &w));
  assert(!houji_wifi_encode_iatu(0u, 99u, 0x60300000u, 0x1000u, 0x60300000u, &w));
  assert(!houji_wifi_encode_iatu(0u, HOUJI_IATU_TYPE_MEM, 0x60300001u, 0x1000u, 0x60300000u, &w));
  assert(!houji_wifi_encode_iatu(0u, HOUJI_IATU_TYPE_MEM, 0x60300000u, 0u, 0x60300000u, &w));

  /* 4. RC Memory Base/Limit encoding. */
  assert(houji_wifi_rc_mem_base_limit(HOUJI_PCIE0_MMIO_BASE, HOUJI_PCIE0_MMIO_LIMIT) == 0x63f06030u);

  /* 5. Link status decode (LTSSM L0 + XMLH_LINK_UP + Gen3 x2). */
  houji_pcie_link_info li = houji_wifi_decode_link(0x00000111u, 0x00000400u, (0x0023u << 16));
  assert(li.ltssm_state == 0x11u && li.xmlh_link_up == 1u && li.in_l0 == 1u);
  assert(li.link_speed == 3u && li.link_width == 2u);
  li = houji_wifi_decode_link(0x00000102u, 0x00000000u, 0u);
  assert(li.in_l0 == 0u && li.xmlh_link_up == 0u && li.ltssm_state == 0x02u);

  /* 6. WCN7850 PCI ID validation (accept 17cb:1107 only, reject 0000/ffff/others). */
  assert(houji_wifi_is_wcn7850_id(0x110717cbu) == 1);
  assert(houji_wifi_is_wcn7850_id(0xffffffffu) == 0);
  assert(houji_wifi_is_wcn7850_id(0x00000000u) == 0);
  assert(houji_wifi_is_wcn7850_id(0x110317cbu) == 0);
  assert(houji_wifi_is_wcn7850_id(0x1107ffffu) == 0);

  /* 7. BAR0 natural alignment, size, and range validation inside 0x60300000..0x63ffffff. */
  uint32_t bar_base = 0u, bar_sz = 0u;
  unsigned is64 = 0u;
  /* 2 MiB 64-bit memory BAR (WCN7850 BAR0 mask = 0xffe00004) aligns up from 0x60300000 to 0x60400000. */
  assert(!houji_wifi_validate_bar0(0xffe00004u, 0x60300000u, &bar_sz, &is64));
  assert(houji_wifi_assign_bar0(0xffe00004u, &bar_base, &bar_sz, &is64) &&
         bar_base == 0x60400000u && bar_sz == 0x200000u && is64 == 1u);
  assert(houji_wifi_assign_bar0(0xfff00004u, &bar_base, &bar_sz, &is64) &&
         bar_base == 0x60300000u && bar_sz == 0x100000u && is64 == 1u);
  assert(houji_wifi_assign_bar0(0xffff0000u, &bar_base, &bar_sz, &is64) &&
         bar_base == 0x60300000u && bar_sz == 0x10000u && is64 == 0u);
  assert(!houji_wifi_assign_bar0(0xffffffffu, &bar_base, &bar_sz, &is64));
  assert(!houji_wifi_assign_bar0(0xfff00001u, &bar_base, &bar_sz, &is64)); /* reject IO BAR */
  assert(!houji_wifi_validate_bar0(0xfff00004u, 0x60200000u, &bar_sz, &is64)); /* below window */
  assert(!houji_wifi_validate_bar0(0xfff00004u, 0x64000000u, &bar_sz, &is64)); /* above window */

  puts("PASS: Stage 1 Wi-Fi PCIe policy, 115-entry QMP PHY table, iATU, and BAR0 checks verified; no PCIe hardware");
  return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix='houji-wifi-pcie-') as temporary:
        src = Path(temporary) / 'wifi_pcie.c'
        exe = Path(temporary) / 'wifi_pcie'
        src.write_text(unit)
        subprocess.run(['clang', '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', str(src), '-o', str(exe)], check=True)
        subprocess.run([str(exe)], check=True, timeout=10)


if __name__ == '__main__':
    main()
