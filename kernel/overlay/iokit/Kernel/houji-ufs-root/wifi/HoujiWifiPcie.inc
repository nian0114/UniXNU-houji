// SPDX-License-Identifier: BSD-2-Clause-Patent
// Stage 1 Xiaomi 14 (houji / SM8650) PCIe RC0 + QMP PHY bring-up and WCN7850
// (17cb:1107) ECAM / read-only BAR0 MHI probe.
// Requires UEFI WifiHandoff (houji_wifi=1). Runs in a background kernel thread,
// never panics, never writes PMIC/GCC registers, and exposes a lock-free cached
// snapshot for periodic XnuLog checkpoints.
#include "HoujiWifiPciePolicy.h"
#include "HoujiWifiPhyTable.h"

static struct {
  OSSharedPtr<IOMemoryMap> gpioMaps[6];
  OSSharedPtr<IOMemoryMap> parfMap, phyMap, dbiMap, iatuMap, ecamMap, bar0Map, gccMap, tcsrMap;
  uintptr_t gpio[6]; // 0=WLAN_EN(16), 1=PERST#(94), 2=CLKREQ#(95), 3=WAKE#(96), 4=SW_CTRL(18), 5=WLAN_SW(19)
  uintptr_t parf, phy, dbi, iatu, ecam, bar0, gcc, tcsr;
  bool started;
  uint32_t stage, error;
  uint32_t phyStatus, phyReady;
  uint32_t parfSysCtrl, parfLtssm, maxLtssm, parfPmStts, elbiStts, dbiLinkSts, dbiDbg0, dbiDbg1;
  uint32_t gpioInMask, clkreqOrigCfg, tcsrClkRef;
  uint32_t rcId, epId, epClass, epSubsys;
  uint32_t bar0Base, bar0Size, bar0Is64;
  uint32_t mhiRegLen, mhiVer, mhiCfg, mhiStatus;
} hwWifi;

static int hwWifiWaitChan;

static uint32_t hwWifiRead32(uintptr_t base, uint32_t off) {
  uint32_t v = *(volatile uint32_t *)(base + off);
  __asm__ volatile("dmb oshld" ::: "memory");
  return v;
}

static void hwWifiWrite32(uintptr_t base, uint32_t off, uint32_t val) {
  *(volatile uint32_t *)(base + off) = val;
  __asm__ volatile("dsb osh" ::: "memory");
}

static void hwWifiSleepMs(unsigned ms) {
  uint64_t deadline;
  clock_interval_to_deadline(ms, NSEC_PER_MSEC, &deadline);
  (void)assert_wait_deadline(&hwWifiWaitChan, THREAD_UNINT, deadline);
  thread_block(THREAD_CONTINUE_NULL);
}

static void hwWifiSetStage(uint32_t stage) {
  __atomic_store_n(&hwWifi.stage, stage, __ATOMIC_RELEASE);
}

static int hwWifiProgIatu(unsigned region, uint32_t type, uint32_t cpuBase,
                          uint32_t size, uint32_t pciTarget) {
  houji_iatu_window w;
  if (!houji_wifi_encode_iatu(region, type, cpuBase, size, pciTarget, &w)) return 1;
  hwWifiWrite32(hwWifi.iatu, w.offset + HOUJI_IATU_LOWER_BASE, w.lower_base);
  hwWifiWrite32(hwWifi.iatu, w.offset + HOUJI_IATU_UPPER_BASE, w.upper_base);
  hwWifiWrite32(hwWifi.iatu, w.offset + HOUJI_IATU_LIMIT, w.limit);
  hwWifiWrite32(hwWifi.iatu, w.offset + HOUJI_IATU_LOWER_TARGET, w.lower_target);
  hwWifiWrite32(hwWifi.iatu, w.offset + HOUJI_IATU_UPPER_TARGET, w.upper_target);
  hwWifiWrite32(hwWifi.iatu, w.offset + HOUJI_IATU_REGION_CTRL1, w.ctrl1);
  hwWifiWrite32(hwWifi.iatu, w.offset + HOUJI_IATU_REGION_CTRL2, w.ctrl2);
  for (unsigned i = 0; i < 200; i++) {
    if (hwWifiRead32(hwWifi.iatu, w.offset + HOUJI_IATU_REGION_CTRL2) & HOUJI_IATU_ENABLE) {
      return 0;
    }
    IODelay(10);
  }
  return 2;
}

static uint32_t hwWifiSampleGpioIn(void) {
  uint32_t mask = 0u;
  for (unsigned i = 0; i < 6; i++) {
    if (hwWifi.gpio[i] && (hwWifiRead32(hwWifi.gpio[i], 4) & 1u)) {
      mask |= (1u << i);
    }
  }
  return mask;
}

static uint32_t hwWifiRun(void) {
  // Stage 1: Map and validate TLMM GPIOs (WLAN_EN=16, PERST#=94, CLKREQ#=95, WAKE#=96)
  // plus read-only observation of SW_CTRL=18, WLAN_SW_CTRL=19, and TCSR_PCIE_0_CLKREF_EN.
  hwWifiSetStage(HOUJI_WIFI_STAGE_GPIO);
  static const uint32_t kPins[6] = {
    HOUJI_TLMM_GPIO_WLAN_EN,
    HOUJI_TLMM_GPIO_PERST,
    HOUJI_TLMM_GPIO_CLKREQ,
    HOUJI_TLMM_GPIO_WAKE,
    HOUJI_TLMM_GPIO_SW_CTRL,
    HOUJI_TLMM_GPIO_WLAN_SW,
  };
  uint32_t origCfg[4] = {0};
  for (unsigned i = 0; i < 4; i++) {
    hwWifi.gpio[i] = mapPhys(houji_wifi_tlmm_phys(kPins[i]), 0x1000, hwWifi.gpioMaps[i]);
    if (!hwWifi.gpio[i]) return 10u + i;
    origCfg[i] = hwWifiRead32(hwWifi.gpio[i], 0);
    if (origCfg[i] == 0xffffffffu || !gg_pin_owned(origCfg[i])) return 20u + i;
  }
  __atomic_store_n(&hwWifi.clkreqOrigCfg, origCfg[2], __ATOMIC_RELAXED);
  for (unsigned i = 4; i < 6; i++) {
    hwWifi.gpio[i] = mapPhys(houji_wifi_tlmm_phys(kPins[i]), 0x1000, hwWifi.gpioMaps[i]);
  }
  hwWifi.tcsr = mapPhys(HOUJI_TCSR_PCIE0_CLKREF_PA, 0x1000, hwWifi.tcsrMap);
  if (hwWifi.tcsr) {
    __atomic_store_n(&hwWifi.tcsrClkRef,
                     hwWifiRead32(hwWifi.tcsr, HOUJI_TCSR_PCIE0_CLKREF_OFF),
                     __ATOMIC_RELAXED);
  }

  // Clean power-on edge: hold PERST# LOW and WLAN_EN LOW for 10 ms first.
  uint32_t perstIo = hwWifiRead32(hwWifi.gpio[1], 4) & ~2u;
  hwWifiWrite32(hwWifi.gpio[1], 4, perstIo);
  hwWifiWrite32(hwWifi.gpio[1], 0, houji_wifi_tlmm_cfg(origCfg[1], 1u, 0u, 0u, 1u));

  uint32_t wlanIo = hwWifiRead32(hwWifi.gpio[0], 4) & ~2u;
  hwWifiWrite32(hwWifi.gpio[0], 4, wlanIo);
  hwWifiWrite32(hwWifi.gpio[0], 0, houji_wifi_tlmm_cfg(origCfg[0], 3u, 0u, 7u, 1u));

  // Configure CLKREQ# (gpio95 -> func 1 pcie0_clk_req_n, pull-up) and WAKE# (gpio96 -> input pull-up).
  hwWifiWrite32(hwWifi.gpio[2], 0, houji_wifi_tlmm_cfg(origCfg[2], 3u, 1u, 0u, 0u));
  hwWifiWrite32(hwWifi.gpio[3], 0, houji_wifi_tlmm_cfg(origCfg[3], 3u, 0u, 0u, 0u));
  hwWifiSleepMs(10);

  // Rising edge on WLAN_EN (gpio16 HIGH) and wait 120 ms for WCN7850 PMU/XO/EP boot.
  hwWifiWrite32(hwWifi.gpio[0], 4, wlanIo | 2u);
  hwWifiSleepMs(120);

  // Stage 2: Map PARF & QMP PHY, configure PARF with verified SM8650 relative DBI/ATU offsets.
  hwWifiSetStage(HOUJI_WIFI_STAGE_PHY);
  hwWifi.parf = mapPhys(HOUJI_PCIE0_PARF_BASE, HOUJI_PCIE0_PARF_SIZE, hwWifi.parfMap);
  hwWifi.phy  = mapPhys(HOUJI_PCIE0_PHY_BASE, HOUJI_PCIE0_PHY_SIZE, hwWifi.phyMap);
  if (!hwWifi.parf || !hwWifi.phy) return 30u;

  uint32_t sysCtrl = hwWifiRead32(hwWifi.parf, HOUJI_PARF_SYS_CTRL);
  uint32_t initMhi = hwWifiRead32(hwWifi.parf, HOUJI_PARF_MHI_CLK_RST_CTRL);
  if (sysCtrl == 0xffffffffu) return 31u;

  uint32_t phyCtrl = hwWifiRead32(hwWifi.parf, HOUJI_PARF_PHY_CTRL);
  hwWifiWrite32(hwWifi.parf, HOUJI_PARF_PHY_CTRL, phyCtrl & ~HOUJI_PARF_PHY_CTRL_TEST_PWR_DOWN);

  hwWifiWrite32(hwWifi.parf, HOUJI_PARF_MHI_CLK_RST_CTRL,
                initMhi | HOUJI_PARF_MHI_A7_AXI_CLK_EN |
                HOUJI_PARF_MHI_MSTR_AXI_CLK_EN | HOUJI_PARF_MHI_BYPASS);

  // Verified on SM8650 silicon: DBI base=0x0 and ATU base=0x1000 are relative offsets
  // inside the 64 MiB slave window (0x60000000..0x63ffffff).
  hwWifiWrite32(hwWifi.parf, HOUJI_PARF_SLV_ADDR_SPACE_V2, HOUJI_PCIE0_SLV_SPACE_SIZE);
  hwWifiWrite32(hwWifi.parf, HOUJI_PARF_SLV_ADDR_SPACE_V2_HI, 0u);
  hwWifiWrite32(hwWifi.parf, HOUJI_PARF_DBI_BASE_ADDR_V2, 0x00000000u);
  hwWifiWrite32(hwWifi.parf, HOUJI_PARF_DBI_BASE_ADDR_V2_HI, 0u);
  hwWifiWrite32(hwWifi.parf, HOUJI_PARF_ATU_BASE_ADDR, 0x00001000u);
  hwWifiWrite32(hwWifi.parf, HOUJI_PARF_ATU_BASE_ADDR_HI, 0u);
  hwWifiWrite32(hwWifi.parf, HOUJI_PARF_DEVICE_TYPE, HOUJI_PARF_DEVICE_TYPE_RC);

  uint32_t pmCtrl = hwWifiRead32(hwWifi.parf, HOUJI_PARF_PM_CTRL);
  hwWifiWrite32(hwWifi.parf, HOUJI_PARF_PM_CTRL, pmCtrl | HOUJI_PARF_PM_CTRL_REQ_NOT_ENTR_L1);

  sysCtrl |= HOUJI_PARF_SYS_CTRL_L1_CLK_RMV_DIS |
             HOUJI_PARF_SYS_CTRL_L23_CLK_RMV_DIS |
             HOUJI_PARF_SYS_CTRL_AUX_PWR_DET |
             HOUJI_PARF_SYS_CTRL_CORE_CLK_CGC_DIS |
             HOUJI_PARF_SYS_CTRL_MSTR_ACLK_CGC_DIS |
             HOUJI_PARF_SYS_CTRL_SLV_ACLK_CGC_DIS |
             HOUJI_PARF_SYS_CTRL_MST_WAKEUP_EN |
             HOUJI_PARF_SYS_CTRL_SLV_WAKEUP_EN;
  hwWifiWrite32(hwWifi.parf, HOUJI_PARF_SYS_CTRL, sysCtrl);
  hwWifiWrite32(hwWifi.parf, HOUJI_PARF_Q2A_FLUSH, 0u);
  __atomic_store_n(&hwWifi.parfSysCtrl, sysCtrl, __ATOMIC_RELAXED);

  // Hold QMP PHY PCS in SW reset briefly, then replay exact houji.dtb 115-entry sequence.
  hwWifiWrite32(hwWifi.phy, HOUJI_PHY_SW_RESET, 0x01u);
  IODelay(10);
  for (unsigned i = 0; i < HOUJI_WIFI_PHY_SEQ_COUNT; i++) {
    hwWifiWrite32(hwWifi.phy, houji_wifi_phy_seq[i].offset, houji_wifi_phy_seq[i].value);
    if (houji_wifi_phy_seq[i].delay_us) {
      IODelay(houji_wifi_phy_seq[i].delay_us);
    }
  }

  // Poll PHY PCS_STATUS (0x214) bit 6 == 0 (PHYSTATUS ready), bounded to 50 ms.
  uint32_t phySt = 0xffffffffu;
  uint32_t phyReady = 0u;
  for (unsigned i = 0; i < 500; i++) {
    phySt = hwWifiRead32(hwWifi.phy, HOUJI_PHY_PCS_STATUS);
    if (phySt != 0xffffffffu && (phySt & HOUJI_PHY_STATUS_BIT) == 0u) {
      phyReady = 1u;
      break;
    }
    IODelay(100);
  }
  __atomic_store_n(&hwWifi.phyStatus, phySt, __ATOMIC_RELAXED);
  __atomic_store_n(&hwWifi.phyReady, phyReady, __ATOMIC_RELAXED);
  IOLog("HOUJI WIFI PCIE: PHY status=%08x ready=%u\n", phySt, phyReady);
  if (!phyReady) return 32u;

  // Stage 3: Configure DBI Root Complex, release PERST#, enable LTSSM, poll link L0.
  hwWifiSetStage(HOUJI_WIFI_STAGE_LINK);
  hwWifi.dbi  = mapPhys(HOUJI_PCIE0_DBI_BASE, HOUJI_PCIE0_DBI_SIZE, hwWifi.dbiMap);
  hwWifi.iatu = mapPhys(HOUJI_PCIE0_IATU_BASE, HOUJI_PCIE0_IATU_SIZE, hwWifi.iatuMap);
  if (!hwWifi.dbi || !hwWifi.iatu) return 40u;

  hwWifiSleepMs(2);
  uint32_t rcId = hwWifiRead32(hwWifi.dbi, HOUJI_DBI_VENDOR_DEVICE);
  __atomic_store_n(&hwWifi.rcId, rcId, __ATOMIC_RELAXED);
  if (rcId == 0xffffffffu || rcId == 0u) return 41u;

  // Enable DBI read-only register writes to configure Type 1 RC bridge and 2-lane link.
  uint32_t misc1 = hwWifiRead32(hwWifi.dbi, HOUJI_DBI_MISC_CONTROL_1);
  hwWifiWrite32(hwWifi.dbi, HOUJI_DBI_MISC_CONTROL_1, misc1 | HOUJI_DBI_RO_WR_EN);

  uint32_t clsRev = hwWifiRead32(hwWifi.dbi, HOUJI_DBI_CLASS_REV);
  hwWifiWrite32(hwWifi.dbi, HOUJI_DBI_CLASS_REV, (clsRev & 0xffu) | 0x06040000u);
  hwWifiWrite32(hwWifi.dbi, HOUJI_DBI_BUS_NUMBERS, 0x00010100u);
  hwWifiWrite32(hwWifi.dbi, HOUJI_DBI_MEM_BASE_LIMIT,
                houji_wifi_rc_mem_base_limit(HOUJI_PCIE0_MMIO_BASE, HOUJI_PCIE0_MMIO_LIMIT));
  hwWifiWrite32(hwWifi.dbi, HOUJI_DBI_PREF_BASE_LIMIT, 0x0000fff0u);

  // Configure 2-lane mode (houji PCIe0 PHY has Lane 0 + Lane 1) and direct speed change.
  uint32_t plc = hwWifiRead32(hwWifi.dbi, HOUJI_DBI_PORT_LINK_CTRL);
  plc = (plc & ~(0x3fu << 16)) | (0x3u << 16); // LINK_CAPABLE = 2 lanes
  hwWifiWrite32(hwWifi.dbi, HOUJI_DBI_PORT_LINK_CTRL, plc);
  uint32_t lws = hwWifiRead32(hwWifi.dbi, HOUJI_DBI_LINK_WIDTH_SPEED);
  lws = (lws & ~(0x1ffu << 8)) | (2u << 8) | (1u << 17); // NUM_LANES=2, DIRECT_SPEED_CHANGE
  hwWifiWrite32(hwWifi.dbi, HOUJI_DBI_LINK_WIDTH_SPEED, lws);

  uint32_t rcCmd = hwWifiRead32(hwWifi.dbi, HOUJI_DBI_COMMAND);
  hwWifiWrite32(hwWifi.dbi, HOUJI_DBI_COMMAND, (rcCmd & ~0xffffu) | 0x0007u);
  hwWifiWrite32(hwWifi.dbi, HOUJI_DBI_MISC_CONTROL_1, misc1 & ~HOUJI_DBI_RO_WR_EN);

  // Deassert PERST# HIGH and wait 50 ms before enabling LTSSM.
  hwWifiWrite32(hwWifi.gpio[1], 4, perstIo | 2u);
  hwWifiSleepMs(50);

  uint32_t ltssm = hwWifiRead32(hwWifi.parf, HOUJI_PARF_LTSSM);
  hwWifiWrite32(hwWifi.parf, HOUJI_PARF_LTSSM, ltssm | HOUJI_PARF_LTSSM_EN);

  houji_pcie_link_info linkInfo = {0};
  uint32_t elbiSt = 0, dbiLink = 0, dbg0 = 0, dbg1 = 0, maxLtssm = 0;
  for (unsigned ms = 0; ms < 500; ms++) {
    if (ms == 200) {
      // Fallback: also assert ELBI_SYS_CTRL LT_ENABLE in case this silicon requires both.
      uint32_t elbiCtrl = hwWifiRead32(hwWifi.dbi, HOUJI_PCIE0_ELBI_OFFSET + HOUJI_ELBI_SYS_CTRL);
      hwWifiWrite32(hwWifi.dbi, HOUJI_PCIE0_ELBI_OFFSET + HOUJI_ELBI_SYS_CTRL,
                    elbiCtrl | HOUJI_ELBI_LT_ENABLE);
    }
    ltssm   = hwWifiRead32(hwWifi.parf, HOUJI_PARF_LTSSM);
    elbiSt  = hwWifiRead32(hwWifi.dbi, HOUJI_PCIE0_ELBI_OFFSET + HOUJI_ELBI_SYS_STTS);
    dbiLink = hwWifiRead32(hwWifi.dbi, HOUJI_DBI_EXP_LINK_CTRL_STS);
    dbg0    = hwWifiRead32(hwWifi.dbi, HOUJI_DBI_PORT_DEBUG0);
    dbg1    = hwWifiRead32(hwWifi.dbi, HOUJI_DBI_PORT_DEBUG1);
    linkInfo = houji_wifi_decode_link_dwc(ltssm, elbiSt, dbiLink, dbg0, dbg1);
    if (linkInfo.ltssm_state > maxLtssm) maxLtssm = linkInfo.ltssm_state;
    if (linkInfo.in_l0) break;
    hwWifiSleepMs(1);
  }
  __atomic_store_n(&hwWifi.parfLtssm, ltssm, __ATOMIC_RELAXED);
  __atomic_store_n(&hwWifi.maxLtssm, maxLtssm, __ATOMIC_RELAXED);
  __atomic_store_n(&hwWifi.parfPmStts, hwWifiRead32(hwWifi.parf, HOUJI_PARF_PM_STTS), __ATOMIC_RELAXED);
  __atomic_store_n(&hwWifi.elbiStts, elbiSt, __ATOMIC_RELAXED);
  __atomic_store_n(&hwWifi.dbiLinkSts, dbiLink, __ATOMIC_RELAXED);
  __atomic_store_n(&hwWifi.dbiDbg0, dbg0, __ATOMIC_RELAXED);
  __atomic_store_n(&hwWifi.dbiDbg1, dbg1, __ATOMIC_RELAXED);
  __atomic_store_n(&hwWifi.gpioInMask, hwWifiSampleGpioIn(), __ATOMIC_RELAXED);
  if (!linkInfo.in_l0) return 42u;

  // Stage 4: Program unrolled outbound iATU Region 0 (CFG0) & Region 1 (MEM), enumerate WCN7850.
  hwWifiSetStage(HOUJI_WIFI_STAGE_ENUM);
  if (hwWifiProgIatu(0u, HOUJI_IATU_TYPE_CFG0, HOUJI_PCIE0_ECAM_BASE,
                     HOUJI_PCIE0_ECAM_SIZE, houji_wifi_cfg0_target(1u, 0u, 0u))) {
    return 50u;
  }
  if (hwWifiProgIatu(1u, HOUJI_IATU_TYPE_MEM, HOUJI_PCIE0_MMIO_BASE,
                     HOUJI_PCIE0_MMIO_SIZE, HOUJI_PCIE0_MMIO_BASE)) {
    return 51u;
  }

  hwWifi.ecam = mapPhys(HOUJI_PCIE0_ECAM_BASE, 0x1000, hwWifi.ecamMap);
  if (!hwWifi.ecam) return 52u;

  uint32_t epId     = hwWifiRead32(hwWifi.ecam, 0x00u);
  uint32_t epClass  = hwWifiRead32(hwWifi.ecam, 0x08u);
  uint32_t epSubsys = hwWifiRead32(hwWifi.ecam, 0x2cu);
  __atomic_store_n(&hwWifi.epId, epId, __ATOMIC_RELAXED);
  __atomic_store_n(&hwWifi.epClass, epClass, __ATOMIC_RELAXED);
  __atomic_store_n(&hwWifi.epSubsys, epSubsys, __ATOMIC_RELAXED);
  IOLog("HOUJI WIFI PCIE: EP id=%08x class=%08x subsys=%08x\n", epId, epClass, epSubsys);
  if (!houji_wifi_is_wcn7850_id(epId)) return 53u;

  // Stage 5: Size and assign BAR0 inside 0x60300000..0x63ffffff, read-only MHI probe (no BME/DMA).
  uint32_t epCmdOrig = hwWifiRead32(hwWifi.ecam, 0x04u);
  hwWifiWrite32(hwWifi.ecam, 0x04u, epCmdOrig & ~0x0007u);
  hwWifiWrite32(hwWifi.ecam, 0x10u, 0xffffffffu);
  uint32_t barMask = hwWifiRead32(hwWifi.ecam, 0x10u);
  uint32_t barBase = 0u;
  uint32_t barSize = 0u;
  unsigned barIs64 = 0u;
  if (!houji_wifi_assign_bar0(barMask, &barBase, &barSize, &barIs64)) {
    IOLog("HOUJI WIFI PCIE: invalid BAR0 mask=%08x\n", barMask);
    return 60u;
  }
  hwWifiWrite32(hwWifi.ecam, 0x10u, barBase);
  if (barIs64) {
    hwWifiWrite32(hwWifi.ecam, 0x14u, 0u);
  }
  // Enable Memory Space ONLY (bit 1); keep Bus Master (bit 2) disabled in Stage 1.
  hwWifiWrite32(hwWifi.ecam, 0x04u, (epCmdOrig & ~0x0007u) | 0x0002u);

  __atomic_store_n(&hwWifi.bar0Base, barBase, __ATOMIC_RELAXED);
  __atomic_store_n(&hwWifi.bar0Size, barSize, __ATOMIC_RELAXED);
  __atomic_store_n(&hwWifi.bar0Is64, barIs64, __ATOMIC_RELAXED);

  hwWifi.bar0 = mapPhys(barBase, 0x1000, hwWifi.bar0Map);
  if (!hwWifi.bar0) return 61u;

  uint32_t mhiRegLen = hwWifiRead32(hwWifi.bar0, HOUJI_MHI_REGLEN_OFF);
  uint32_t mhiVer    = hwWifiRead32(hwWifi.bar0, HOUJI_MHI_VER_OFF);
  uint32_t mhiCfg    = hwWifiRead32(hwWifi.bar0, HOUJI_MHI_CFG_OFF);
  uint32_t mhiStatus = hwWifiRead32(hwWifi.bar0, HOUJI_MHI_STATUS_OFF);
  __atomic_store_n(&hwWifi.mhiRegLen, mhiRegLen, __ATOMIC_RELAXED);
  __atomic_store_n(&hwWifi.mhiVer, mhiVer, __ATOMIC_RELAXED);
  __atomic_store_n(&hwWifi.mhiCfg, mhiCfg, __ATOMIC_RELAXED);
  __atomic_store_n(&hwWifi.mhiStatus, mhiStatus, __ATOMIC_RELAXED);

  hwWifiSetStage(HOUJI_WIFI_STAGE_BAR0_READY);
  IOLog("HOUJI WIFI PCIE: stage=5 WCN7850 ready bar0=%08x size=%x 64b=%u mhi-len=%08x mhi-ver=%08x mhi-cfg=%08x mhi-st=%08x\n",
        barBase, barSize, barIs64, mhiRegLen, mhiVer, mhiCfg, mhiStatus);
  return 0u;
}

static void hwWifiThread(void *, wait_result_t) {
  hwWifiSleepMs(1500);
  uint32_t err = hwWifiRun();
  __atomic_store_n(&hwWifi.error, err, __ATOMIC_RELEASE);
  if (err) {
    IOLog("HOUJI WIFI PCIE: probe stopped stage=%u error=%u; desktop unaffected\n",
          __atomic_load_n(&hwWifi.stage, __ATOMIC_ACQUIRE), err);
  }
  thread_terminate(current_thread());
}

static void houjiWifiPcieStart(void) {
  int enabled = 0;
  PE_parse_boot_argn("houji_wifi", &enabled, sizeof(enabled));
  if (enabled != 1 || hwWifi.started) return;
  hwWifi.started = true;
  thread_t thread;
  kern_return_t kr = kernel_thread_start(hwWifiThread, nullptr, &thread);
  if (kr == KERN_SUCCESS) {
    thread_deallocate(thread);
  } else {
    __atomic_store_n(&hwWifi.error, (uint32_t)kr, __ATOMIC_RELEASE);
  }
}

extern "C" void houji_wifi_pcie_snapshot(void) {
  if (!hwWifi.started) return;
  houji_pcie_link_info link = houji_wifi_decode_link_dwc(
    __atomic_load_n(&hwWifi.parfLtssm, __ATOMIC_RELAXED),
    __atomic_load_n(&hwWifi.elbiStts, __ATOMIC_RELAXED),
    __atomic_load_n(&hwWifi.dbiLinkSts, __ATOMIC_RELAXED),
    __atomic_load_n(&hwWifi.dbiDbg0, __ATOMIC_RELAXED),
    __atomic_load_n(&hwWifi.dbiDbg1, __ATOMIC_RELAXED));
  IOLog("HOUJI WIFI PCIE: stage=%u err=%u phy-ready=%u phy=%08x ltssm=%02x(max=%02x) link=Gen%u/x%u rc=%08x id=%08x bar0=%08x/%x mhi-ver=%08x mhi-st=%08x\n",
        __atomic_load_n(&hwWifi.stage, __ATOMIC_ACQUIRE),
        __atomic_load_n(&hwWifi.error, __ATOMIC_ACQUIRE),
        __atomic_load_n(&hwWifi.phyReady, __ATOMIC_RELAXED),
        __atomic_load_n(&hwWifi.phyStatus, __ATOMIC_RELAXED),
        link.ltssm_state,
        __atomic_load_n(&hwWifi.maxLtssm, __ATOMIC_RELAXED),
        link.link_speed, link.link_width,
        __atomic_load_n(&hwWifi.rcId, __ATOMIC_RELAXED),
        __atomic_load_n(&hwWifi.epId, __ATOMIC_RELAXED),
        __atomic_load_n(&hwWifi.bar0Base, __ATOMIC_RELAXED),
        __atomic_load_n(&hwWifi.bar0Size, __ATOMIC_RELAXED),
        __atomic_load_n(&hwWifi.mhiVer, __ATOMIC_RELAXED),
        __atomic_load_n(&hwWifi.mhiStatus, __ATOMIC_RELAXED));
  uint32_t gm = __atomic_load_n(&hwWifi.gpioInMask, __ATOMIC_RELAXED);
  IOLog("HOUJI WIFI DIAG: gpio(16=%u 94=%u 95=%u 96=%u 18=%u 19=%u) tcsr=%08x parf-ltssm=%08x pm=%08x elbi=%08x dbi-lnk=%08x dbg0=%08x dbg1=%08x\n",
        (gm >> 0) & 1u, (gm >> 1) & 1u, (gm >> 2) & 1u,
        (gm >> 3) & 1u, (gm >> 4) & 1u, (gm >> 5) & 1u,
        __atomic_load_n(&hwWifi.tcsrClkRef, __ATOMIC_RELAXED),
        __atomic_load_n(&hwWifi.parfLtssm, __ATOMIC_RELAXED),
        __atomic_load_n(&hwWifi.parfPmStts, __ATOMIC_RELAXED),
        __atomic_load_n(&hwWifi.elbiStts, __ATOMIC_RELAXED),
        __atomic_load_n(&hwWifi.dbiLinkSts, __ATOMIC_RELAXED),
        __atomic_load_n(&hwWifi.dbiDbg0, __ATOMIC_RELAXED),
        __atomic_load_n(&hwWifi.dbiDbg1, __ATOMIC_RELAXED));
}
