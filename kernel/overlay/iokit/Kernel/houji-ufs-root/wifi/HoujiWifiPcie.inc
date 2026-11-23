// SPDX-License-Identifier: BSD-2-Clause-Patent
// Stage 1 Xiaomi 14 (houji / SM8650) PCIe RC0 + QMP PHY bring-up and WCN7850
// (17cb:1107) ECAM / read-only BAR0 MHI probe.
// Requires UEFI WifiHandoff (houji_wifi=1). Runs in a background kernel thread,
// never panics, never writes PMIC/GCC registers, and exposes a lock-free cached
// snapshot for periodic XnuLog checkpoints.
#include "HoujiWifiPciePolicy.h"
#include "HoujiWifiPhyTable.h"

static struct {
  OSSharedPtr<IOMemoryMap> gpioMaps[4];
  OSSharedPtr<IOMemoryMap> parfMap, phyMap, dbiMap, iatuMap, ecamMap, bar0Map;
  uintptr_t gpio[4]; // 0=WLAN_EN(16), 1=PERST#(94), 2=CLKREQ#(95), 3=WAKE#(96)
  uintptr_t parf, phy, dbi, iatu, ecam, bar0;
  bool started;
  uint32_t stage, error;
  uint32_t phyStatus, phyReady;
  uint32_t parfSysCtrl, parfLtssm, elbiStts, dbiLinkSts;
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

static uint32_t hwWifiRun(void) {
  // Stage 1: Map and validate TLMM GPIOs (WLAN_EN=16, PERST#=94, CLKREQ#=95, WAKE#=96).
  hwWifiSetStage(HOUJI_WIFI_STAGE_GPIO);
  static const uint32_t kPins[4] = {
    HOUJI_TLMM_GPIO_WLAN_EN,
    HOUJI_TLMM_GPIO_PERST,
    HOUJI_TLMM_GPIO_CLKREQ,
    HOUJI_TLMM_GPIO_WAKE,
  };
  uint32_t origCfg[4] = {0};
  for (unsigned i = 0; i < 4; i++) {
    hwWifi.gpio[i] = mapPhys(houji_wifi_tlmm_phys(kPins[i]), 0x1000, hwWifi.gpioMaps[i]);
    if (!hwWifi.gpio[i]) return 10u + i;
    origCfg[i] = hwWifiRead32(hwWifi.gpio[i], 0);
    uint32_t io = hwWifiRead32(hwWifi.gpio[i], 4);
    IOLog("HOUJI WIFI PCIE: gpio%u orig cfg=%08x io=%08x owned=%u\n",
          kPins[i], origCfg[i], io, gg_pin_owned(origCfg[i]) ? 1u : 0u);
    if (origCfg[i] == 0xffffffffu || !gg_pin_owned(origCfg[i])) return 20u + i;
  }

  // Assert PERST# LOW before enabling WLAN_EN.
  uint32_t perstIo = hwWifiRead32(hwWifi.gpio[1], 4) & ~2u;
  hwWifiWrite32(hwWifi.gpio[1], 4, perstIo);
  hwWifiWrite32(hwWifi.gpio[1], 0, houji_wifi_tlmm_cfg(origCfg[1], 1u, 0u, 0u, 1u));

  // Configure CLKREQ# (gpio95 -> func 1 pcie0_clk_req_n, pull-up) and WAKE# (gpio96 -> input pull-up).
  hwWifiWrite32(hwWifi.gpio[2], 0, houji_wifi_tlmm_cfg(origCfg[2], 3u, 1u, 0u, 0u));
  hwWifiWrite32(hwWifi.gpio[3], 0, houji_wifi_tlmm_cfg(origCfg[3], 3u, 0u, 0u, 0u));

  // Drive WLAN_EN (gpio16) HIGH (16 mA drive, pull-up) and wait for WCN7850 PMU settling.
  uint32_t wlanIo = (hwWifiRead32(hwWifi.gpio[0], 4) & ~2u) | 2u;
  hwWifiWrite32(hwWifi.gpio[0], 4, wlanIo);
  hwWifiWrite32(hwWifi.gpio[0], 0, houji_wifi_tlmm_cfg(origCfg[0], 3u, 0u, 7u, 1u));
  hwWifiSleepMs(30);

  // Stage 2: Map PARF & QMP PHY, configure PARF, run 115-entry houji QMP PHY sequence.
  hwWifiSetStage(HOUJI_WIFI_STAGE_PHY);
  hwWifi.parf = mapPhys(HOUJI_PCIE0_PARF_BASE, HOUJI_PCIE0_PARF_SIZE, hwWifi.parfMap);
  hwWifi.phy  = mapPhys(HOUJI_PCIE0_PHY_BASE, HOUJI_PCIE0_PHY_SIZE, hwWifi.phyMap);
  if (!hwWifi.parf || !hwWifi.phy) return 30u;

  uint32_t sysCtrl = hwWifiRead32(hwWifi.parf, HOUJI_PARF_SYS_CTRL);
  __atomic_store_n(&hwWifi.parfSysCtrl, sysCtrl, __ATOMIC_RELAXED);
  IOLog("HOUJI WIFI PCIE: PARF initial sys=%08x pm=%08x phy_ctrl=%08x ltssm=%08x\n",
        sysCtrl,
        hwWifiRead32(hwWifi.parf, HOUJI_PARF_PM_CTRL),
        hwWifiRead32(hwWifi.parf, HOUJI_PARF_PHY_CTRL),
        hwWifiRead32(hwWifi.parf, HOUJI_PARF_LTSSM));
  if (sysCtrl == 0xffffffffu) return 31u;

  // Enable PARF clocks, RC mode, DBI base, slave address space, and clear PHY_TEST_PWR_DOWN.
  uint32_t mhiClk = hwWifiRead32(hwWifi.parf, HOUJI_PARF_MHI_CLK_RST_CTRL);
  hwWifiWrite32(hwWifi.parf, HOUJI_PARF_MHI_CLK_RST_CTRL,
                mhiClk | HOUJI_PARF_MHI_A7_AXI_CLK_EN | HOUJI_PARF_MHI_MSTR_AXI_CLK_EN);

  hwWifiWrite32(hwWifi.parf, HOUJI_PARF_SLV_ADDR_SPACE_V2, HOUJI_PCIE0_SLV_SPACE_SIZE);
  hwWifiWrite32(hwWifi.parf, HOUJI_PARF_SLV_ADDR_SPACE_V2_HI, 0u);
  hwWifiWrite32(hwWifi.parf, HOUJI_PARF_DBI_BASE_ADDR_V2, HOUJI_PCIE0_DBI_BASE);
  hwWifiWrite32(hwWifi.parf, HOUJI_PARF_DBI_BASE_ADDR_V2_HI, 0u);
  hwWifiWrite32(hwWifi.parf, HOUJI_PARF_DEVICE_TYPE, HOUJI_PARF_DEVICE_TYPE_RC);

  uint32_t pmCtrl = hwWifiRead32(hwWifi.parf, HOUJI_PARF_PM_CTRL);
  hwWifiWrite32(hwWifi.parf, HOUJI_PARF_PM_CTRL, pmCtrl | HOUJI_PARF_PM_CTRL_REQ_NOT_ENTR_L1);

  sysCtrl |= HOUJI_PARF_SYS_CTRL_AUX_PWR_DET |
             HOUJI_PARF_SYS_CTRL_CORE_CLK_CGC_DIS |
             HOUJI_PARF_SYS_CTRL_MSTR_ACLK_CGC_DIS |
             HOUJI_PARF_SYS_CTRL_SLV_DBI_WAKE_DIS |
             HOUJI_PARF_SYS_CTRL_MST_WAKEUP_EN |
             HOUJI_PARF_SYS_CTRL_SLV_WAKEUP_EN;
  hwWifiWrite32(hwWifi.parf, HOUJI_PARF_SYS_CTRL, sysCtrl);
  __atomic_store_n(&hwWifi.parfSysCtrl, sysCtrl, __ATOMIC_RELAXED);

  uint32_t phyCtrl = hwWifiRead32(hwWifi.parf, HOUJI_PARF_PHY_CTRL);
  hwWifiWrite32(hwWifi.parf, HOUJI_PARF_PHY_CTRL, phyCtrl & ~HOUJI_PARF_PHY_CTRL_TEST_PWR_DOWN);

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

  uint32_t rcId = hwWifiRead32(hwWifi.dbi, HOUJI_DBI_VENDOR_DEVICE);
  __atomic_store_n(&hwWifi.rcId, rcId, __ATOMIC_RELAXED);
  IOLog("HOUJI WIFI PCIE: RC DBI id=%08x\n", rcId);
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

  // Deassert PERST# HIGH and wait 20 ms per PCIe CEM timing before enabling LTSSM.
  hwWifiWrite32(hwWifi.gpio[1], 4, perstIo | 2u);
  hwWifiSleepMs(20);

  uint32_t ltssm = hwWifiRead32(hwWifi.parf, HOUJI_PARF_LTSSM);
  hwWifiWrite32(hwWifi.parf, HOUJI_PARF_LTSSM, ltssm | HOUJI_PARF_LTSSM_EN);

  houji_pcie_link_info linkInfo = {0};
  uint32_t elbiSt = 0, dbiLink = 0;
  for (unsigned ms = 0; ms < 250; ms++) {
    ltssm   = hwWifiRead32(hwWifi.parf, HOUJI_PARF_LTSSM);
    elbiSt  = hwWifiRead32(hwWifi.dbi, HOUJI_PCIE0_ELBI_OFFSET + HOUJI_ELBI_SYS_STTS);
    dbiLink = hwWifiRead32(hwWifi.dbi, HOUJI_DBI_EXP_LINK_CTRL_STS);
    linkInfo = houji_wifi_decode_link(ltssm, elbiSt, dbiLink);
    if (linkInfo.in_l0) break;
    hwWifiSleepMs(1);
  }
  __atomic_store_n(&hwWifi.parfLtssm, ltssm, __ATOMIC_RELAXED);
  __atomic_store_n(&hwWifi.elbiStts, elbiSt, __ATOMIC_RELAXED);
  __atomic_store_n(&hwWifi.dbiLinkSts, dbiLink, __ATOMIC_RELAXED);
  IOLog("HOUJI WIFI PCIE: link l0=%u xmlh=%u ltssm=0x%02x Gen%u/x%u (parf=%08x elbi=%08x dbi=%08x)\n",
        linkInfo.in_l0, linkInfo.xmlh_link_up, linkInfo.ltssm_state,
        linkInfo.link_speed, linkInfo.link_width, ltssm, elbiSt, dbiLink);
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
  houji_pcie_link_info link = houji_wifi_decode_link(
    __atomic_load_n(&hwWifi.parfLtssm, __ATOMIC_RELAXED),
    __atomic_load_n(&hwWifi.elbiStts, __ATOMIC_RELAXED),
    __atomic_load_n(&hwWifi.dbiLinkSts, __ATOMIC_RELAXED));
  IOLog("HOUJI WIFI PCIE: stage=%u err=%u phy-ready=%u phy=%08x ltssm=%02x link=Gen%u/x%u rc=%08x id=%08x bar0=%08x/%x mhi-ver=%08x mhi-st=%08x\n",
        __atomic_load_n(&hwWifi.stage, __ATOMIC_ACQUIRE),
        __atomic_load_n(&hwWifi.error, __ATOMIC_ACQUIRE),
        __atomic_load_n(&hwWifi.phyReady, __ATOMIC_RELAXED),
        __atomic_load_n(&hwWifi.phyStatus, __ATOMIC_RELAXED),
        link.ltssm_state, link.link_speed, link.link_width,
        __atomic_load_n(&hwWifi.rcId, __ATOMIC_RELAXED),
        __atomic_load_n(&hwWifi.epId, __ATOMIC_RELAXED),
        __atomic_load_n(&hwWifi.bar0Base, __ATOMIC_RELAXED),
        __atomic_load_n(&hwWifi.bar0Size, __ATOMIC_RELAXED),
        __atomic_load_n(&hwWifi.mhiVer, __ATOMIC_RELAXED),
        __atomic_load_n(&hwWifi.mhiStatus, __ATOMIC_RELAXED));
}
