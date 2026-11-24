// SPDX-License-Identifier: BSD-2-Clause-Patent
// Stage 2 Xiaomi 14 (houji / SM8650) Wi-Fi bring-up:
// - APPS SMMUv2 (0x15000000) Stage-1 4 KiB translation for PCIe0 RC0 (0x1400) & WCN7850 (0x1401)
// - Read-only modem_a FAT16 loader for /image/kiwi/amss20.bin (WCN7850 HW 2.0)
// - DWC built-in MSI receiver + EP MSI / Bus Master / ASPM-off setup
// - WCN7850 chipPowerUp (ath12k_pci_sw_reset) + MHI BHI/BHIe boot to MISSION_MODE (EE=2)
#include "HoujiWifiMhiPolicy.h"
#include "../ArmSmmu4K.h"
#include "../ArmSmmu4KAudit.h"
#include "../battery/FatVolume.h"
#include "../battery/HoujiFirmware.h"

static struct {
  OSSharedPtr<IOBufferMemoryDescriptor> dmaBuf;
  OSSharedPtr<IOBufferMemoryDescriptor> ptBuf;
  OSSharedPtr<IOMemoryMap> smmuMap;
  uintptr_t smmu;
  uint8_t *dmaVa;
  uint64_t *ptVa;
  uint64_t ptPa;
  HoujiWifiArena arena;
  uint32_t barWindow;

  /* Lock-free snapshot telemetry */
  uint32_t active;
  uint32_t smmuSlotRc, smmuSlotEp, smmuBank, smmuPages, smmuTablePages, smmuLeafPages;
  uint32_t smmuGfsr, smmuCbFsr;
  uint64_t smmuCbFar;
  uint32_t amssSize, amssCrc32, amssMagic, bhieSegs;
  uint32_t mhiPhase, mhiErr, mhiFailedPhase, mhiEe, mhiState;
  uint32_t bhiOff, bhieOff, bhiStatus, bhiErrcode, bhieStatus;
  uint32_t msiBits, msiCount, linkRecoveries, bootMs;
  uint32_t chipLtssm, chipWarmAfter, chipMhiBefore, chipMhiAfter;
} hwWifiMhi;

static uint32_t hwWifiCrc32(const uint8_t *data, uint32_t len) {
  uint32_t crc = 0xffffffffu;
  for (uint32_t i = 0; i < len; i++) {
    crc ^= data[i];
    for (unsigned b = 0; b < 8; b++) {
      crc = (crc & 1u) ? ((crc >> 1) ^ 0xedb88320u) : (crc >> 1);
    }
  }
  return crc ^ 0xffffffffu;
}

static uint32_t hwWifiSmmuRd32(void *ctx, uint32_t off) {
  return hwWifiRead32(reinterpret_cast<uintptr_t>(ctx), off);
}

static void hwWifiSmmuWr32(void *ctx, uint32_t off, uint32_t val) {
  hwWifiWrite32(reinterpret_cast<uintptr_t>(ctx), off, val);
  __asm__ volatile("dsb sy" ::: "memory");
}

static uint64_t hwWifiSmmuRd64(void *ctx, uint32_t off) {
  uintptr_t base = reinterpret_cast<uintptr_t>(ctx);
  uint32_t lo = hwWifiRead32(base, off);
  uint32_t hi = hwWifiRead32(base, off + 4u);
  return (uint64_t)lo | ((uint64_t)hi << 32);
}

static void hwWifiSmmuWr64(void *ctx, uint32_t off, uint64_t val) {
  uintptr_t base = reinterpret_cast<uintptr_t>(ctx);
  hwWifiWrite32(base, off, (uint32_t)val);
  hwWifiWrite32(base, off + 4u, (uint32_t)(val >> 32));
  __asm__ volatile("dsb sy" ::: "memory");
}

struct HoujiWifiPtAuditCtx {
  uint64_t basePa;
  size_t bytes;
  const uint64_t *va;
};

static int hwWifiPtReadDesc(void *cookie, uint64_t physical, uint64_t *out) {
  const HoujiWifiPtAuditCtx *c = static_cast<const HoujiWifiPtAuditCtx *>(cookie);
  if (!c || !out || physical < c->basePa || (physical & 7ULL) != 0ULL) return -1;
  uint64_t off = physical - c->basePa;
  if (off + 8ULL > c->bytes) return -1;
  *out = c->va[off / 8ULL];
  return 0;
}

static void hwWifiSampleSmmuFaults(void) {
  if (!hwWifiMhi.smmu) return;
  uint32_t bank  = __atomic_load_n(&hwWifiMhi.smmuBank, __ATOMIC_RELAXED);
  uint32_t pages = __atomic_load_n(&hwWifiMhi.smmuPages, __ATOMIC_RELAXED);
  uint32_t gfsr  = hwWifiRead32(hwWifiMhi.smmu, 0x48u);
  __atomic_store_n(&hwWifiMhi.smmuGfsr, gfsr, __ATOMIC_RELAXED);
  if (pages && bank < 128u && (pages + bank) * 4096u + 0x1000u <= HOUJI_APPS_SMMU_MAP_BYTES) {
    uint32_t cb = (pages + bank) * 4096u;
    uint32_t fsr = hwWifiRead32(hwWifiMhi.smmu, cb + 0x58u);
    uint64_t far = hwWifiSmmuRd64(reinterpret_cast<void *>(hwWifiMhi.smmu), cb + 0x60u);
    __atomic_store_n(&hwWifiMhi.smmuCbFsr, fsr, __ATOMIC_RELAXED);
    __atomic_store_n(&hwWifiMhi.smmuCbFar, far, __ATOMIC_RELAXED);
  }
}

static uint32_t hwWifiSetupSmmu(void) {
  constexpr size_t kTablePoolPages = 80u;
  constexpr size_t kTablePoolBytes = kTablePoolPages * 4096u;
  constexpr size_t kMaxRanges      = 32768u;

  hwWifiMhi.smmu = mapPhys(HOUJI_APPS_SMMU_BASE, HOUJI_APPS_SMMU_MAP_BYTES, hwWifiMhi.smmuMap);
  if (!hwWifiMhi.smmu) return 100u;

  HoujiWifiSmmuIo smmuIo = {
    reinterpret_cast<void *>(hwWifiMhi.smmu),
    hwWifiSmmuRd32,
    hwWifiSmmuWr32,
    hwWifiSmmuRd64,
    hwWifiSmmuWr64,
  };
  HoujiWifiSmmuPlan plan = houji_wifi_plan_smmu_s1(&smmuIo, HOUJI_WIFI_SID_RC0, HOUJI_WIFI_SID_WCN7850);
  if (plan.error) {
    IOLog("HOUJI WIFI MHI: SMMU plan failed: %s (idr0=%08x idr1=%08x idr2=%08x)\n",
          plan.error, plan.idr0, plan.idr1, plan.idr2);
    return 101u;
  }

  OSSharedPtr<IOBufferMemoryDescriptor> dmaBuf(
    IOBufferMemoryDescriptor::inTaskWithOptions(
      kernel_task, kIODirectionInOut | kIOMemoryMapperNone,
      HOUJI_WIFI_DMA_ARENA_BYTES, page_size),
    OSNoRetain);
  if (!dmaBuf || dmaBuf->prepare(kIODirectionInOut) != kIOReturnSuccess) return 102u;
  uint8_t *dmaVa = static_cast<uint8_t *>(dmaBuf->getBytesNoCopy());
  if (!dmaVa) return 103u;

  OSSharedPtr<IOBufferMemoryDescriptor> ptBuf(
    IOBufferMemoryDescriptor::inTaskWithOptions(
      kernel_task, kIODirectionInOut | kIOMemoryPhysicallyContiguous | kIOMemoryMapperNone,
      kTablePoolBytes, 4096u),
    OSNoRetain);
  if (!ptBuf || ptBuf->prepare(kIODirectionInOut) != kIOReturnSuccess) return 104u;
  uint64_t *ptVa = static_cast<uint64_t *>(ptBuf->getBytesNoCopy());
  IOByteCount ptSegLen = 0;
  addr64_t ptPa = ptBuf->getPhysicalSegment(0, &ptSegLen, kIOMemoryMapperNone);
  if (!ptVa || !ptPa || (ptPa & 0xfffULL) != 0ULL || ptSegLen < kTablePoolBytes) return 105u;

  ArmSmmu4KRange *ranges = static_cast<ArmSmmu4KRange *>(IOMallocData(kMaxRanges * sizeof(ArmSmmu4KRange)));
  if (!ranges) return 106u;

  size_t rangeCount = 0;
  IOByteCount off = 0;
  bool segOk = true;
  while (off < HOUJI_WIFI_DMA_ARENA_BYTES) {
    IOByteCount segLen = 0;
    addr64_t pa = dmaBuf->getPhysicalSegment(off, &segLen, kIOMemoryMapperNone);
    if (!pa || !segLen || (pa & 0xfffULL) != 0ULL || (segLen & 0xfffULL) != 0ULL) {
      segOk = false;
      break;
    }
    if (off + segLen > HOUJI_WIFI_DMA_ARENA_BYTES) {
      segLen = HOUJI_WIFI_DMA_ARENA_BYTES - off;
    }
    if (rangeCount > 0 &&
        ranges[rangeCount - 1].physical + ranges[rangeCount - 1].bytes == pa &&
        ranges[rangeCount - 1].iova + ranges[rangeCount - 1].bytes == HOUJI_WIFI_DMA_IOVA_BASE + off) {
      ranges[rangeCount - 1].bytes += segLen;
    } else {
      if (rangeCount >= kMaxRanges) {
        segOk = false;
        break;
      }
      ranges[rangeCount].iova         = HOUJI_WIFI_DMA_IOVA_BASE + off;
      ranges[rangeCount].physical     = pa;
      ranges[rangeCount].bytes        = segLen;
      ranges[rangeCount].permissions  = ArmSmmu4KRead | ArmSmmu4KWrite;
      ranges[rangeCount].writeback    = 1u;
      ranges[rangeCount].shareability = 3u;
      ++rangeCount;
    }
    off += segLen;
  }
  if (!segOk || off != HOUJI_WIFI_DMA_ARENA_BYTES || rangeCount == 0) {
    IOFreeData(ranges, kMaxRanges * sizeof(ArmSmmu4KRange));
    return 107u;
  }

  ArmSmmu4KConfig ptCfg = {};
  ptCfg.input_bits     = 32u;
  ptCfg.output_bits    = plan.pa_bits;
  ptCfg.table_physical = ptPa;
  ptCfg.leaf_budget    = HOUJI_WIFI_DMA_ARENA_BYTES / 4096u;
  ArmSmmu4KResult ptRes = {};
  ArmSmmu4KStatus st = ArmSmmu4KBuild(&ptCfg, ranges, rangeCount, ptVa, kTablePoolPages, &ptRes);
  if (st != ArmSmmu4KSuccess) {
    IOLog("HOUJI WIFI MHI: ArmSmmu4KBuild failed status=%u ranges=%zu\n", (unsigned)st, rangeCount);
    IOFreeData(ranges, kMaxRanges * sizeof(ArmSmmu4KRange));
    return 108u;
  }

  /* Pre-activation physical table audit before programming SMMU registers */
  unsigned char visited[kTablePoolPages];
  HoujiWifiPtAuditCtx auditCtx = { ptPa, kTablePoolBytes, ptVa };
  ArmSmmu4KTableIo auditIo = { &auditCtx, hwWifiPtReadDesc };
  ArmSmmu4KAuditRegion auditReg = {
    ranges, rangeCount, kTablePoolPages, kTablePoolPages * 512u + 16u, visited, sizeof(visited)
  };
  ArmSmmu4KTableAuditResult auditRes = {};
  st = ArmSmmu4KAuditTables(&auditIo, &ptCfg, &ptRes, &auditReg, ptRes.root_physical, &auditRes);
  IOFreeData(ranges, kMaxRanges * sizeof(ArmSmmu4KRange));
  if (st != ArmSmmu4KSuccess || !auditRes.complete) {
    IOLog("HOUJI WIFI MHI: ArmSmmu4KAuditTables failed status=%u complete=%u\n",
          (unsigned)st, auditRes.complete);
    return 109u;
  }

  cacheCivac(ptVa, ptRes.table_pages * 4096u);
  const char *progErr = houji_wifi_program_smmu_s1(
    &smmuIo, &plan, HOUJI_WIFI_SID_RC0, HOUJI_WIFI_SID_WCN7850,
    ptRes.root_physical, HOUJI_WIFI_SMMU_ASID);
  if (progErr) {
    IOLog("HOUJI WIFI MHI: SMMU program failed: %s (bank=%u slots=%u/%u)\n",
          progErr, plan.bank, plan.slot_rc, plan.slot_ep);
    return 110u;
  }

  if (!houji_wifi_arena_init(&hwWifiMhi.arena, dmaVa, HOUJI_WIFI_DMA_IOVA_BASE, HOUJI_WIFI_DMA_ARENA_BYTES)) {
    return 111u;
  }
  cacheCivac(dmaVa, HOUJI_WIFI_MSI_SINK_BYTES);

  hwWifiMhi.dmaBuf = dmaBuf;
  hwWifiMhi.ptBuf  = ptBuf;
  hwWifiMhi.dmaVa  = dmaVa;
  hwWifiMhi.ptVa   = ptVa;
  hwWifiMhi.ptPa   = ptPa;
  __atomic_store_n(&hwWifiMhi.smmuSlotRc, plan.slot_rc, __ATOMIC_RELAXED);
  __atomic_store_n(&hwWifiMhi.smmuSlotEp, plan.slot_ep, __ATOMIC_RELAXED);
  __atomic_store_n(&hwWifiMhi.smmuBank, plan.bank, __ATOMIC_RELAXED);
  __atomic_store_n(&hwWifiMhi.smmuPages, plan.pages, __ATOMIC_RELAXED);
  __atomic_store_n(&hwWifiMhi.smmuTablePages, (uint32_t)ptRes.table_pages, __ATOMIC_RELAXED);
  __atomic_store_n(&hwWifiMhi.smmuLeafPages, (uint32_t)ptRes.leaf_pages, __ATOMIC_RELAXED);
  hwWifiSampleSmmuFaults();

  IOLog("HOUJI WIFI MHI: SMMU ready bank=%u slots=%u/%u pages=%zu/%zu root=%010llx iova=%08llx..%08llx\n",
        plan.bank, plan.slot_rc, plan.slot_ep, ptRes.table_pages, ptRes.leaf_pages,
        (unsigned long long)ptRes.root_physical,
        (unsigned long long)HOUJI_WIFI_DMA_IOVA_BASE,
        (unsigned long long)(HOUJI_WIFI_DMA_IOVA_BASE + HOUJI_WIFI_DMA_ARENA_BYTES - 1ULL));
  return 0u;
}

struct HoujiWifiModemReader {
  uint8_t *scratch;
  uint64_t totalBytes;
};

static int hwWifiModemFatRead(void *ctx, uint64_t offset, void *to, size_t length) {
  HoujiWifiModemReader *r = static_cast<HoujiWifiModemReader *>(ctx);
  if (!r || !r->scratch || !to) return -1;
  if (length == 0) return 0;
  if (offset > r->totalBytes || length > r->totalBytes - offset) return -1;
  uint8_t *dst = static_cast<uint8_t *>(to);
  while (length > 0) {
    uint64_t lba = offset / 4096ULL;
    size_t inBlock = (size_t)(offset % 4096ULL);
    size_t wantBlocks = (inBlock + length + 4095u) / 4096u;
    if (wantBlocks > 32u) wantBlocks = 32u;
    if (!houji_modem_read(lba, (uint32_t)wantBlocks, r->scratch)) return -1;
    size_t avail = wantBlocks * 4096u - inBlock;
    size_t take = (length < avail) ? length : avail;
    memcpy(dst, r->scratch + inBlock, take);
    dst    += take;
    offset += take;
    length -= take;
  }
  return 0;
}

static uint32_t hwWifiLoadAmss20(uint8_t **outVa, uint64_t *outIova, uint32_t *outSize) {
  uint64_t partBlocks = 0;
  for (unsigned tries = 0; tries < 20; tries++) {
    if (houji_modem_partition(&partBlocks)) break;
    hwWifiSleepMs(500);
  }
  if (!partBlocks) return 120u;

  uint8_t *scratch = static_cast<uint8_t *>(IOMallocData(32u * 4096u));
  FatVolume *vol   = static_cast<FatVolume *>(IOMallocData(sizeof(FatVolume)));
  if (!scratch || !vol) {
    if (scratch) IOFreeData(scratch, 32u * 4096u);
    if (vol) IOFreeData(vol, sizeof(FatVolume));
    return 121u;
  }
  memset(vol, 0, sizeof(*vol));
  HoujiWifiModemReader reader = { scratch, partBlocks * 4096ULL };
  uint32_t err = 0u;
  FatFile file = {};
  if (fat_mount(vol, reader.totalBytes, hwWifiModemFatRead, &reader) != FatOk) {
    err = 122u;
  } else if (fat_open(vol, "image/kiwi/amss20.bin", &file) != FatOk) {
    err = 123u;
  } else if (file.size <= HOUJI_WCN7850_SBL_BYTES || file.size > 16u * 1024u * 1024u) {
    err = 124u;
  } else {
    uint64_t iova = 0;
    uint8_t *buf = static_cast<uint8_t *>(houji_wifi_arena_alloc(&hwWifiMhi.arena, file.size, &iova));
    if (!buf) {
      err = 125u;
    } else if (fat_read(vol, &file, 0u, buf, file.size) != FatOk) {
      houji_wifi_arena_free(&hwWifiMhi.arena, buf);
      err = 126u;
    } else {
      uint32_t magic = 0;
      memcpy(&magic, buf, 4u);
      uint32_t crc = hwWifiCrc32(buf, file.size);
      cacheCivac(buf, file.size);
      __atomic_store_n(&hwWifiMhi.amssSize, file.size, __ATOMIC_RELAXED);
      __atomic_store_n(&hwWifiMhi.amssCrc32, crc, __ATOMIC_RELAXED);
      __atomic_store_n(&hwWifiMhi.amssMagic, magic, __ATOMIC_RELAXED);
      *outVa   = buf;
      *outIova = iova;
      *outSize = file.size;
      IOLog("HOUJI WIFI MHI: loaded image/kiwi/amss20.bin size=%u magic=%08x crc32=%08x iova=%08llx\n",
            file.size, magic, crc, (unsigned long long)iova);
    }
  }
  IOFreeData(vol, sizeof(FatVolume));
  IOFreeData(scratch, 32u * 4096u);
  return err;
}

static void hwWifiSetupMsiAndBusMaster(void) {
  /* Enable DWC built-in MSI receiver targeting page 0 (0x10000000) of our SMMU arena */
  hwWifiWrite32(hwWifi.dbi, HOUJI_DBI_MSI_ADDR_LO, (uint32_t)HOUJI_WIFI_DMA_IOVA_BASE);
  hwWifiWrite32(hwWifi.dbi, HOUJI_DBI_MSI_ADDR_HI, 0u);
  hwWifiWrite32(hwWifi.dbi, HOUJI_DBI_MSI_INTR0_MASK, 0u);
  hwWifiWrite32(hwWifi.dbi, HOUJI_DBI_MSI_INTR0_STATUS, 0xffffffffu);
  hwWifiWrite32(hwWifi.dbi, HOUJI_DBI_MSI_INTR0_ENABLE, 0xffffffffu);

  /* Walk EP PCI capabilities: disable ASPM, cap MRRS=128B, configure MSI to 0x10000000 */
  uint8_t cap = (uint8_t)(hwWifiRead32(hwWifi.ecam, 0x34u) & 0xffu);
  for (unsigned guard = 0; cap >= 0x40u && cap < 0xfcu && guard < 48u; ++guard) {
    uint32_t w = hwWifiRead32(hwWifi.ecam, cap);
    uint8_t id = (uint8_t)(w & 0xffu);
    uint8_t next = (uint8_t)((w >> 8) & 0xffu);
    if (id == 0x10u) {
      uint32_t devctl = hwWifiRead32(hwWifi.ecam, cap + 0x08u);
      hwWifiWrite32(hwWifi.ecam, cap + 0x08u, devctl & ~0x7000u); /* MRRS = 128B */
      uint32_t lnkctl = hwWifiRead32(hwWifi.ecam, cap + 0x10u);
      hwWifiWrite32(hwWifi.ecam, cap + 0x10u, lnkctl & ~3u);      /* ASPM off */
    } else if (id == 0x05u) {
      uint32_t ctrl = (w >> 16) & 0xffffu;
      bool is64 = (ctrl & 0x80u) != 0u;
      uint32_t mmc = (ctrl >> 1) & 7u;
      uint32_t mme = (mmc > 5u) ? 5u : mmc;
      hwWifiWrite32(hwWifi.ecam, cap + 4u, (uint32_t)HOUJI_WIFI_DMA_IOVA_BASE);
      if (is64) {
        hwWifiWrite32(hwWifi.ecam, cap + 8u, 0u);
        hwWifiWrite32(hwWifi.ecam, cap + 12u, 0u);
      } else {
        hwWifiWrite32(hwWifi.ecam, cap + 8u, 0u);
      }
      ctrl = (ctrl & ~0x70u) | (mme << 4) | 1u;
      hwWifiWrite32(hwWifi.ecam, cap, (w & 0xffffu) | (ctrl << 16));
    }
    cap = next;
  }

  /* Enable Memory Space (bit 1) + Bus Master (bit 2) on WCN7850 */
  uint32_t cmd = hwWifiRead32(hwWifi.ecam, 0x04u);
  hwWifiWrite32(hwWifi.ecam, 0x04u, (cmd & 0xffffu) | 0x0006u);
}

static void hwWifiLinkRecover(uint32_t barBase) {
  if (hwWifiRead32(hwWifi.ecam, 0x00u) != HOUJI_WCN7850_ID_WORD) return;
  uint32_t curBar = hwWifiRead32(hwWifi.ecam, 0x10u);
  uint32_t curCmd = hwWifiRead32(hwWifi.ecam, 0x04u);
  if ((curBar & ~0xfu) != (barBase & ~0xfu) || (curCmd & 6u) != 6u) {
    hwWifiWrite32(hwWifi.ecam, 0x10u, barBase);
    hwWifiWrite32(hwWifi.ecam, 0x14u, 0u);
    hwWifiWrite32(hwWifi.ecam, 0x04u, (curCmd & 0xffffu) | 0x0006u);
    __atomic_fetch_add(&hwWifiMhi.linkRecoveries, 1u, __ATOMIC_RELAXED);
  }
}

static uint32_t hwWifiChipRead(uint32_t chipAddr) {
  uint32_t winReg = 0xffffffffu;
  uint32_t barOff = houji_wcn7850_bar_offset(chipAddr, &winReg);
  if (winReg != 0xffffffffu && winReg != hwWifiMhi.barWindow) {
    hwWifiWrite32(hwWifi.bar0, 0x310cu, winReg);
    (void)hwWifiRead32(hwWifi.bar0, 0x310cu);
    hwWifiMhi.barWindow = winReg;
  }
  return hwWifiRead32(hwWifi.bar0, barOff);
}

static void hwWifiChipWrite(uint32_t chipAddr, uint32_t val) {
  uint32_t winReg = 0xffffffffu;
  uint32_t barOff = houji_wcn7850_bar_offset(chipAddr, &winReg);
  if (winReg != 0xffffffffu && winReg != hwWifiMhi.barWindow) {
    hwWifiWrite32(hwWifi.bar0, 0x310cu, winReg);
    (void)hwWifiRead32(hwWifi.bar0, 0x310cu);
    hwWifiMhi.barWindow = winReg;
  }
  hwWifiWrite32(hwWifi.bar0, barOff, val);
}

/* Matches ath12k_pci_sw_reset(power_on) for WCN7850 HW 2.0 */
static void hwWifiChipPowerUp(void) {
  hwWifiMhi.barWindow = 0xffffffffu;
  uint32_t v = hwWifiChipRead(0x1e081b0u);
  for (unsigned i = 0; v != 0x111u && i < 5u; ++i) {
    if (v == 0xffffffffu) hwWifiSleepMs(5);
    hwWifiChipWrite(0x1e081b0u, 0x111u);
    v = hwWifiChipRead(0x1e081b0u);
  }
  __atomic_store_n(&hwWifiMhi.chipLtssm, v, __ATOMIC_RELAXED);

  v = hwWifiChipRead(0x1e40304u);
  hwWifiChipWrite(0x1e40304u, v | 0x10u);
  hwWifiSleepMs(5);

  hwWifiChipWrite(0x1e08228u, 0xffffffffu); /* Clear stale hot-reset IRQs */
  v = hwWifiChipRead(0x1f8031cu);
  hwWifiChipWrite(0x1f8031cu, v & ~0x4u);

  /* Clear BHIe vector doorbells and status before global reset */
  hwWifiChipWrite(0x360u, 0u);
  hwWifiChipWrite(0x368u, 0u);
  hwWifiChipWrite(0x394u, 0u);
  hwWifiChipWrite(0x39cu, 0u);

  (void)hwWifiChipRead(0x1f80500u);
  (void)hwWifiChipRead(0x1f80504u);
  hwWifiSleepMs(10);
  hwWifiChipWrite(0x1f80504u, 0u); /* Keep Q6 off warm-boot path */
  hwWifiSleepMs(10);
  __atomic_store_n(&hwWifiMhi.chipWarmAfter, hwWifiChipRead(0x1f80504u), __ATOMIC_RELAXED);
  (void)hwWifiChipRead(0x1f8060cu); /* Read-clear reset cause */

  v = hwWifiChipRead(0x3008u);
  hwWifiChipWrite(0x3008u, v | 1u);
  (void)hwWifiChipRead(0x3008u);
  hwWifiSleepMs(10);
  hwWifiChipWrite(0x3008u, v & ~1u);
  (void)hwWifiChipRead(0x3008u);
  hwWifiSleepMs(10);

  uint32_t restoreWin = (hwWifiMhi.barWindow == 0xffffffffu) ? 0x40000000u : hwWifiMhi.barWindow;
  hwWifiWrite32(hwWifi.bar0, 0x310cu, restoreWin);
  (void)hwWifiRead32(hwWifi.bar0, 0x310cu);

  __atomic_store_n(&hwWifiMhi.chipMhiBefore, hwWifiRead32(hwWifi.bar0, HOUJI_MHI_STATUS_OFF), __ATOMIC_RELAXED);
  hwWifiWrite32(hwWifi.bar0, HOUJI_MHI_CTRL_OFF, HOUJI_MHI_CTRL_RESET);
  hwWifiSleepMs(10);
  __atomic_store_n(&hwWifiMhi.chipMhiAfter, hwWifiRead32(hwWifi.bar0, HOUJI_MHI_STATUS_OFF), __ATOMIC_RELAXED);
}

static uint32_t hwWifiMhiBarRd(void *ctx, uint32_t reg) {
  return hwWifiRead32(reinterpret_cast<uintptr_t>(ctx), reg);
}

static void hwWifiMhiBarWr(void *ctx, uint32_t reg, uint32_t val) {
  hwWifiWrite32(reinterpret_cast<uintptr_t>(ctx), reg, val);
}

static uint32_t hwWifiRunStage2(uint32_t barBase, uint32_t barSize) {
  __atomic_store_n(&hwWifiMhi.active, 1u, __ATOMIC_RELEASE);

  /* Step 1: APPS SMMUv2 Stage-1 setup for SIDs 0x1400 & 0x1401 */
  uint32_t err = hwWifiSetupSmmu();
  if (err) return err;
  hwWifiSetStage(HOUJI_WIFI_STAGE_SMMU_READY);

  /* Step 2: Load /image/kiwi/amss20.bin from modem_a FAT16 into 8 MiB-aligned DMA buffer */
  uint8_t *amssVa = nullptr;
  uint64_t amssIova = 0;
  uint32_t amssSize = 0;
  err = hwWifiLoadAmss20(&amssVa, &amssIova, &amssSize);
  if (err) return err;
  hwWifiSetStage(HOUJI_WIFI_STAGE_FW_LOADED);

  /* Step 3: Allocate MHI contexts (16 KiB) and BHIe segment table (512 B) */
  constexpr uint32_t kCtxBytes = 16384u;
  uint64_t ctxIova = 0, tblIova = 0;
  uint8_t *ctxVa = static_cast<uint8_t *>(houji_wifi_arena_alloc(&hwWifiMhi.arena, kCtxBytes, &ctxIova));
  HoujiBhieEntry *tblVa = static_cast<HoujiBhieEntry *>(
    houji_wifi_arena_alloc(&hwWifiMhi.arena, HOUJI_WCN7850_MAX_SEGMENTS * sizeof(HoujiBhieEntry), &tblIova));
  if (!ctxVa || !tblVa) return 130u;

  uint32_t segs = houji_mhi_bhie_table(
    tblVa, HOUJI_WCN7850_MAX_SEGMENTS, amssIova, amssSize, HOUJI_WCN7850_SEG_BYTES);
  if (!segs) return 131u;
  __atomic_store_n(&hwWifiMhi.bhieSegs, segs, __ATOMIC_RELAXED);
  cacheCivac(tblVa, segs * sizeof(HoujiBhieEntry));

  /* Step 4: Configure DWC MSI receiver, EP MSI/ASPM/MRRS/BME, and WCN7850 chipPowerUp */
  hwWifiSetupMsiAndBusMaster();
  hwWifiChipPowerUp();
  hwWifiLinkRecover(barBase);
  hwWifiSleepMs(200);

  /* Refresh MHI header telemetry post-chipPowerUp */
  __atomic_store_n(&hwWifi.mhiRegLen, hwWifiRead32(hwWifi.bar0, HOUJI_MHI_REGLEN_OFF), __ATOMIC_RELAXED);
  __atomic_store_n(&hwWifi.mhiVer, hwWifiRead32(hwWifi.bar0, HOUJI_MHI_VER_OFF), __ATOMIC_RELAXED);
  __atomic_store_n(&hwWifi.mhiCfg, hwWifiRead32(hwWifi.bar0, HOUJI_MHI_CFG_OFF), __ATOMIC_RELAXED);
  __atomic_store_n(&hwWifi.mhiStatus, hwWifiRead32(hwWifi.bar0, HOUJI_MHI_STATUS_OFF), __ATOMIC_RELAXED);

  /* Step 5: Open MHI boot state machine, pre-program contexts, launch BHI/BHIe boot */
  HoujiMhiIo mhiIo = {
    reinterpret_cast<void *>(hwWifi.bar0),
    hwWifiMhiBarRd,
    hwWifiMhiBarWr,
    barSize,
  };
  HoujiMhiBoot boot;
  if (houji_mhi_boot_open(&boot, &mhiIo) != 0) {
    __atomic_store_n(&hwWifiMhi.mhiPhase, boot.phase, __ATOMIC_RELAXED);
    __atomic_store_n(&hwWifiMhi.mhiErr, boot.error, __ATOMIC_RELAXED);
    return 132u;
  }
  __atomic_store_n(&hwWifiMhi.bhiOff, boot.bhi, __ATOMIC_RELAXED);
  __atomic_store_n(&hwWifiMhi.bhieOff, boot.bhie, __ATOMIC_RELAXED);

  /* WCN7850 PBL requires MHI contexts programmed BEFORE BHI_IMGTXDB */
  uint64_t ackedRp[2] = {0ULL, 0ULL};
  houji_mhi_program_contexts(&mhiIo, ctxVa, ctxIova, kCtxBytes, nullptr);
  cacheCivac(ctxVa, kCtxBytes);

  uint64_t t0 = mach_absolute_time();
  uint32_t phase = houji_mhi_boot_begin(
    &boot, 0u, amssIova, HOUJI_WCN7850_SBL_BYTES,
    tblIova, segs * (uint32_t)sizeof(HoujiBhieEntry), 1u);

  uint32_t prevPhase = phase;
  unsigned phasePolls = 0u;
  uint32_t msiAccum = 0u, msiCount = 0u;

  while (phase != HoujiMhiDone && phase != HoujiMhiFailed) {
    hwWifiLinkRecover(barBase);
    uint32_t msiSt = hwWifiRead32(hwWifi.dbi, HOUJI_DBI_MSI_INTR0_STATUS);
    if (msiSt) {
      hwWifiWrite32(hwWifi.dbi, HOUJI_DBI_MSI_INTR0_STATUS, msiSt);
      msiAccum |= msiSt;
      ++msiCount;
    }

    cacheCivac(ctxVa, 8192u);
    (void)houji_mhi_ack_events(&mhiIo, ctxVa, ackedRp);
    cacheCivac(ctxVa, 8192u);

    phase = houji_mhi_boot_step(&boot);
    if (phase == HoujiMhiNeedContexts) {
      ackedRp[0] = 0ULL;
      ackedRp[1] = 0ULL;
      houji_mhi_program_contexts(&mhiIo, ctxVa, ctxIova, kCtxBytes, nullptr);
      cacheCivac(ctxVa, kCtxBytes);
      phase = houji_mhi_boot_contexts_done(&boot);
    }

    if (boot.ee == HoujiMhiEeSbl || phase >= HoujiMhiWaitSbl) {
      if (__atomic_load_n(&hwWifi.stage, __ATOMIC_RELAXED) < HOUJI_WIFI_STAGE_MHI_SBL) {
        hwWifiSetStage(HOUJI_WIFI_STAGE_MHI_SBL);
      }
    }

    if (phase != prevPhase) {
      prevPhase = phase;
      phasePolls = 0u;
    } else if (++phasePolls >= 4000u) {
      phase = houji_mhi_boot_timeout(&boot);
      break;
    }

    if ((phasePolls & 31u) == 0u) {
      __atomic_store_n(&hwWifiMhi.mhiPhase, boot.phase, __ATOMIC_RELAXED);
      __atomic_store_n(&hwWifiMhi.mhiEe, boot.ee, __ATOMIC_RELAXED);
      __atomic_store_n(&hwWifiMhi.mhiState, boot.state, __ATOMIC_RELAXED);
      __atomic_store_n(&hwWifiMhi.msiBits, msiAccum, __ATOMIC_RELAXED);
      __atomic_store_n(&hwWifiMhi.msiCount, msiCount, __ATOMIC_RELAXED);
      hwWifiSampleSmmuFaults();
    }
    hwWifiSleepMs(5);
  }

  uint64_t ns = 0;
  absolutetime_to_nanoseconds(mach_absolute_time() - t0, &ns);
  uint32_t bootMs = (uint32_t)(ns / 1000000ULL);
  uint32_t bhiSt   = hwWifiRead32(hwWifi.bar0, boot.bhi + HOUJI_BHI_STATUS);
  uint32_t bhiErr  = hwWifiRead32(hwWifi.bar0, boot.bhi + HOUJI_BHI_ERRCODE);
  uint32_t bhieSt  = hwWifiRead32(hwWifi.bar0, boot.bhie + HOUJI_BHIE_TXVECSTATUS);
  uint32_t mhiSt   = hwWifiRead32(hwWifi.bar0, HOUJI_MHI_STATUS_OFF);

  __atomic_store_n(&hwWifi.mhiStatus, mhiSt, __ATOMIC_RELAXED);
  __atomic_store_n(&hwWifiMhi.mhiPhase, boot.phase, __ATOMIC_RELAXED);
  __atomic_store_n(&hwWifiMhi.mhiErr, boot.error, __ATOMIC_RELAXED);
  __atomic_store_n(&hwWifiMhi.mhiFailedPhase, boot.failed_phase, __ATOMIC_RELAXED);
  __atomic_store_n(&hwWifiMhi.mhiEe, boot.ee, __ATOMIC_RELAXED);
  __atomic_store_n(&hwWifiMhi.mhiState, boot.state, __ATOMIC_RELAXED);
  __atomic_store_n(&hwWifiMhi.bhiStatus, bhiSt, __ATOMIC_RELAXED);
  __atomic_store_n(&hwWifiMhi.bhiErrcode, bhiErr, __ATOMIC_RELAXED);
  __atomic_store_n(&hwWifiMhi.bhieStatus, bhieSt, __ATOMIC_RELAXED);
  __atomic_store_n(&hwWifiMhi.msiBits, msiAccum, __ATOMIC_RELAXED);
  __atomic_store_n(&hwWifiMhi.msiCount, msiCount, __ATOMIC_RELAXED);
  __atomic_store_n(&hwWifiMhi.bootMs, bootMs, __ATOMIC_RELAXED);
  hwWifiSampleSmmuFaults();

  if (phase == HoujiMhiDone) {
    hwWifiSetStage(HOUJI_WIFI_STAGE_MISSION);
    IOLog("HOUJI WIFI MHI: stage=9 MISSION_MODE ee=%u state=%u ms=%u amss=%u crc=%08x segs=%u msi=%08x/%u smmu-fsr=%x/%x\n",
          boot.ee, boot.state, bootMs, amssSize,
          __atomic_load_n(&hwWifiMhi.amssCrc32, __ATOMIC_RELAXED), segs,
          msiAccum, msiCount,
          __atomic_load_n(&hwWifiMhi.smmuGfsr, __ATOMIC_RELAXED),
          __atomic_load_n(&hwWifiMhi.smmuCbFsr, __ATOMIC_RELAXED));
    return 0u;
  }

  IOLog("HOUJI WIFI MHI: boot failed phase=%u failed=%u err=%u ee=%u st=%u bhi=%08x/%08x bhie=%08x msi=%08x/%u smmu=%x/%x far=%llx ms=%u\n",
        boot.phase, boot.failed_phase, boot.error, boot.ee, boot.state,
        bhiSt, bhiErr, bhieSt, msiAccum, msiCount,
        __atomic_load_n(&hwWifiMhi.smmuGfsr, __ATOMIC_RELAXED),
        __atomic_load_n(&hwWifiMhi.smmuCbFsr, __ATOMIC_RELAXED),
        (unsigned long long)__atomic_load_n(&hwWifiMhi.smmuCbFar, __ATOMIC_RELAXED),
        bootMs);
  return 140u + boot.error;
}

static void hwWifiMhiSnapshot(void) {
  if (!__atomic_load_n(&hwWifiMhi.active, __ATOMIC_ACQUIRE)) return;
  IOLog("HOUJI WIFI MHI: phase=%u(fail=%u/e=%u) ee=%u st=%u amss=%u crc=%08x segs=%u bhi=%08x/%08x bhie=%08x msi=%08x/%u ms=%u\n",
        __atomic_load_n(&hwWifiMhi.mhiPhase, __ATOMIC_RELAXED),
        __atomic_load_n(&hwWifiMhi.mhiFailedPhase, __ATOMIC_RELAXED),
        __atomic_load_n(&hwWifiMhi.mhiErr, __ATOMIC_RELAXED),
        __atomic_load_n(&hwWifiMhi.mhiEe, __ATOMIC_RELAXED),
        __atomic_load_n(&hwWifiMhi.mhiState, __ATOMIC_RELAXED),
        __atomic_load_n(&hwWifiMhi.amssSize, __ATOMIC_RELAXED),
        __atomic_load_n(&hwWifiMhi.amssCrc32, __ATOMIC_RELAXED),
        __atomic_load_n(&hwWifiMhi.bhieSegs, __ATOMIC_RELAXED),
        __atomic_load_n(&hwWifiMhi.bhiStatus, __ATOMIC_RELAXED),
        __atomic_load_n(&hwWifiMhi.bhiErrcode, __ATOMIC_RELAXED),
        __atomic_load_n(&hwWifiMhi.bhieStatus, __ATOMIC_RELAXED),
        __atomic_load_n(&hwWifiMhi.msiBits, __ATOMIC_RELAXED),
        __atomic_load_n(&hwWifiMhi.msiCount, __ATOMIC_RELAXED),
        __atomic_load_n(&hwWifiMhi.bootMs, __ATOMIC_RELAXED));
  IOLog("HOUJI WIFI SMMU: bank=%u slots=%u/%u pt=%u/%u gfsr=%08x fsr=%08x far=%llx chip=%03x/%08x/%08x/%08x rec=%u\n",
        __atomic_load_n(&hwWifiMhi.smmuBank, __ATOMIC_RELAXED),
        __atomic_load_n(&hwWifiMhi.smmuSlotRc, __ATOMIC_RELAXED),
        __atomic_load_n(&hwWifiMhi.smmuSlotEp, __ATOMIC_RELAXED),
        __atomic_load_n(&hwWifiMhi.smmuTablePages, __ATOMIC_RELAXED),
        __atomic_load_n(&hwWifiMhi.smmuLeafPages, __ATOMIC_RELAXED),
        __atomic_load_n(&hwWifiMhi.smmuGfsr, __ATOMIC_RELAXED),
        __atomic_load_n(&hwWifiMhi.smmuCbFsr, __ATOMIC_RELAXED),
        (unsigned long long)__atomic_load_n(&hwWifiMhi.smmuCbFar, __ATOMIC_RELAXED),
        __atomic_load_n(&hwWifiMhi.chipLtssm, __ATOMIC_RELAXED),
        __atomic_load_n(&hwWifiMhi.chipWarmAfter, __ATOMIC_RELAXED),
        __atomic_load_n(&hwWifiMhi.chipMhiBefore, __ATOMIC_RELAXED),
        __atomic_load_n(&hwWifiMhi.chipMhiAfter, __ATOMIC_RELAXED),
        __atomic_load_n(&hwWifiMhi.linkRecoveries, __ATOMIC_RELAXED));
}
