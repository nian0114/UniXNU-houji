// SPDX-License-Identifier: BSD-2-Clause-Patent
// Stage 3 Xiaomi 14 (houji / SM8650) Ath12kWifi stack integration:
// - 128 MiB power-of-two aligned DMA arena over verified APPS SMMU 4 KiB translation
// - modem_a FAT16 firmware provider (amss20.bin, phy_ucode20.elf, bd_n3.elf, regdb_xiaomi.bin)
// - GICv3 SPI 141 (INTID 173) DWC iMSI interrupt handler with automatic 1 ms polling fallback
// - Automatic Stage 3 Wi-Fi scan on radio ready (stage >= 4) with XnuLog BSS evidence
#include <IOKit/IODeviceTreeSupport.h>
#include "nw_abi.h"
#include "../../../../pexpert/arm/HoujiSpi.h"

extern "C" void _disable_preemption(void);
extern "C" void _enable_preemption(void);

static constexpr unsigned kHwWifiDynBlocks = 16384u;
static constexpr uint32_t kHwWifiPcie0MsiIntid = 32u + 141u; /* SM8650 PCIe0 msi0 SPI 141 */

struct HwWifiDynBlock {
  uint32_t off;
  uint32_t size;
  uint8_t  used;
};

static struct {
  uint8_t *va;
  uint64_t iova;
  uint32_t totalBytes;
  uint32_t usedBytes;
  uint32_t peakBytes;
  uint32_t failures;
  unsigned count;
  HwWifiDynBlock *blocks;
  IOLock *lock;

  uint32_t pcieCap;
  uint32_t msiCap;
  uint32_t msiAttached;
  uint32_t msiIrqCount;
  uint32_t msiPending;
  uint32_t msiSeenBits;
  uint32_t msiWake;

  uint32_t active;
  int32_t  startErr;
  uint32_t scanRequested;
  uint32_t scanDoneCount;
  uint32_t bssLogged;
  uint32_t logLines;
  char lastNote[4][112];
  uint32_t noteIdx;
  char firstErr[4][112];
  uint32_t errCount;
} hwWifiStack;

struct HwWifiFwSlot {
  char name[32];
  uint8_t *data;
  size_t size;
  bool tried;
};
static HwWifiFwSlot hwWifiFwCache[10];

static bool hwWifiDynArenaInit(uint8_t *va, uint64_t iova, uint32_t bytes) {
  if (!va || bytes <= HOUJI_WIFI_MSI_SINK_BYTES) return false;
  if (!hwWifiStack.lock) hwWifiStack.lock = IOLockAlloc();
  if (!hwWifiStack.blocks) {
    hwWifiStack.blocks = static_cast<HwWifiDynBlock *>(
      IOMallocData(kHwWifiDynBlocks * sizeof(HwWifiDynBlock)));
  }
  if (!hwWifiStack.lock || !hwWifiStack.blocks) return false;
  hwWifiStack.va         = va;
  hwWifiStack.iova       = iova;
  hwWifiStack.totalBytes = bytes;
  hwWifiStack.blocks[0]  = { HOUJI_WIFI_MSI_SINK_BYTES, bytes - HOUJI_WIFI_MSI_SINK_BYTES, 0u };
  hwWifiStack.count      = 1u;
  hwWifiStack.usedBytes  = HOUJI_WIFI_MSI_SINK_BYTES;
  hwWifiStack.peakBytes  = HOUJI_WIFI_MSI_SINK_BYTES;
  hwWifiStack.failures   = 0u;
  memset(va, 0, bytes);
  return true;
}

static void *hwWifiNwDmaAlloc(size_t bytes, uint64_t *bus) {
  if (!bytes || bytes > hwWifiStack.totalBytes || !hwWifiStack.blocks) return nullptr;
  uint32_t n = (uint32_t)((bytes + 63u) & ~63u);
  if (n >= 4096u) n = (n + 4095u) & ~4095u;
  uint32_t align = 64u;
  if (n >= 4096u) {
    align = 4096u;
    while (align < n && align < 0x80000000u) align <<= 1;
  }
  IOLockLock(hwWifiStack.lock);
  for (unsigned i = 0u; i < hwWifiStack.count; ++i) {
    HwWifiDynBlock b = hwWifiStack.blocks[i];
    if (b.used) continue;
    uint64_t absStart = ((hwWifiStack.iova + b.off) + (uint64_t)align - 1ULL) & ~((uint64_t)align - 1ULL);
    uint32_t start = (uint32_t)(absStart - hwWifiStack.iova);
    uint32_t pad   = start - b.off;
    if (b.size < pad || b.size - pad < n) continue;
    unsigned hasTail = (b.size > pad + n) ? 1u : 0u;
    unsigned extra   = (pad ? 1u : 0u) + hasTail;
    if (hwWifiStack.count + extra > kHwWifiDynBlocks) continue;
    memmove(&hwWifiStack.blocks[i + extra], &hwWifiStack.blocks[i],
            (hwWifiStack.count - i) * sizeof(HwWifiDynBlock));
    hwWifiStack.count += extra;
    unsigned at = i;
    if (pad) { hwWifiStack.blocks[at++] = { b.off, pad, 0u }; }
    hwWifiStack.blocks[at] = { start, n, 1u };
    if (hasTail) { hwWifiStack.blocks[at + 1u] = { start + n, b.size - pad - n, 0u }; }
    hwWifiStack.usedBytes += n;
    if (hwWifiStack.usedBytes > hwWifiStack.peakBytes) hwWifiStack.peakBytes = hwWifiStack.usedBytes;
    IOLockUnlock(hwWifiStack.lock);
    uint8_t *ptr = hwWifiStack.va + start;
    memset(ptr, 0, n);
    if (bus) *bus = hwWifiStack.iova + start;
    return ptr;
  }
  ++hwWifiStack.failures;
  IOLockUnlock(hwWifiStack.lock);
  return nullptr;
}

static void hwWifiNwDmaFree(size_t, void *p, uint64_t) {
  if (!p || !hwWifiStack.blocks) return;
  uint8_t *ptr = static_cast<uint8_t *>(p);
  if (ptr < hwWifiStack.va || ptr >= hwWifiStack.va + hwWifiStack.totalBytes) return;
  uint32_t off = (uint32_t)(ptr - hwWifiStack.va);
  IOLockLock(hwWifiStack.lock);
  for (unsigned i = 0u; i < hwWifiStack.count; ++i) {
    if (hwWifiStack.blocks[i].off != off || !hwWifiStack.blocks[i].used) continue;
    hwWifiStack.usedBytes -= hwWifiStack.blocks[i].size;
    hwWifiStack.blocks[i].used = 0u;
    if (i + 1u < hwWifiStack.count && !hwWifiStack.blocks[i + 1u].used) {
      hwWifiStack.blocks[i].size += hwWifiStack.blocks[i + 1u].size;
      memmove(&hwWifiStack.blocks[i + 1u], &hwWifiStack.blocks[i + 2u],
              (hwWifiStack.count - i - 2u) * sizeof(HwWifiDynBlock));
      --hwWifiStack.count;
    }
    if (i > 0u && !hwWifiStack.blocks[i - 1u].used) {
      hwWifiStack.blocks[i - 1u].size += hwWifiStack.blocks[i].size;
      memmove(&hwWifiStack.blocks[i], &hwWifiStack.blocks[i + 1u],
              (hwWifiStack.count - i - 1u) * sizeof(HwWifiDynBlock));
      --hwWifiStack.count;
    }
    break;
  }
  IOLockUnlock(hwWifiStack.lock);
}

static uint64_t hwWifiNwDmaMap(void *p, size_t, int) {
  uint8_t *ptr = static_cast<uint8_t *>(p);
  if (!ptr || ptr < hwWifiStack.va || ptr >= hwWifiStack.va + hwWifiStack.totalBytes) return 0ULL;
  return hwWifiStack.iova + (uint64_t)(ptr - hwWifiStack.va);
}

static void hwWifiNwDmaSync(uint64_t, size_t, int) {
  __asm__ volatile("dsb ish" ::: "memory");
}

static uint64_t hwWifiNwNowNs(void) {
  uint64_t ns = 0;
  absolutetime_to_nanoseconds(mach_absolute_time(), &ns);
  return ns;
}

static uint64_t hwWifiNwBootNs(void) {
  uint64_t ns = 0;
  absolutetime_to_nanoseconds(mach_continuous_time(), &ns);
  return ns;
}

static uint64_t hwWifiNwNowMs(void) {
  return hwWifiNwNowNs() / 1000000ULL;
}

static void hwWifiNwSleepMs(unsigned int ms) {
  hwWifiSleepMs(ms);
}

static void hwWifiNwBusyDelayUs(unsigned int us) {
  IODelay(us);
}

static void hwWifiNwHalt(void) {
  IOLog("HOUJI WIFI NW: halt requested; suspending Wi-Fi worker only\n");
  for (;;) hwWifiSleepMs(1000);
}

static void *hwWifiNwAlloc(size_t n) {
  uint8_t *p = static_cast<uint8_t *>(IOMallocData(n + 16u));
  if (!p) return nullptr;
  *reinterpret_cast<size_t *>(p) = n + 16u;
  return p + 16u;
}

static void hwWifiNwFree(void *q) {
  if (!q) return;
  uint8_t *p = static_cast<uint8_t *>(q) - 16u;
  IOFreeData(p, *reinterpret_cast<size_t *>(p));
}

static bool hwWifiStrHas(const char *s, const char *sub) {
  for (; *s; ++s) {
    size_t k = 0;
    while (sub[k] && s[k] == sub[k]) ++k;
    if (!sub[k]) return true;
  }
  return false;
}

static void hwWifiNwLog(int level, const char *line) {
  if (!line) return;
  if (hwWifiStrHas(line, "chan scan list") || hwWifiStrHas(line, "mac channel [")) return;
  if (level >= 7 && (hwWifiStrHas(line, "htc rx completion") || hwWifiStrHas(line, "rx ce pipe") ||
                     hwWifiStrHas(line, "ext irq:") || hwWifiStrHas(line, "event mgmt rx") ||
                     hwWifiStrHas(line, "mgmt rx event") || hwWifiStrHas(line, "chan info vdev_id") ||
                     hwWifiStrHas(line, "scan event foreign channel"))) {
    return;
  }
  uint32_t n = __atomic_fetch_add(&hwWifiStack.logLines, 1u, __ATOMIC_RELAXED);
  if (level <= 6) {
    uint32_t slot = __atomic_fetch_add(&hwWifiStack.noteIdx, 1u, __ATOMIC_RELAXED) & 3u;
    snprintf(hwWifiStack.lastNote[slot], sizeof(hwWifiStack.lastNote[slot]), "%.108s", line);
    if (level <= 4) {
      uint32_t ec = __atomic_fetch_add(&hwWifiStack.errCount, 1u, __ATOMIC_RELAXED);
      if (ec < 4u) {
        snprintf(hwWifiStack.firstErr[ec], sizeof(hwWifiStack.firstErr[ec]), "%.108s", line);
      }
    }
    if (n < 120u || level <= 4) {
      IOLog("HOUJI WIFI NW[%d]: %.112s\n", level, line);
    }
  }
}

static void hwWifiMsiIrq(void *) {
  uint32_t st = hwWifiRead32(hwWifi.dbi, HOUJI_DBI_MSI_INTR0_STATUS);
  if (st) hwWifiWrite32(hwWifi.dbi, HOUJI_DBI_MSI_INTR0_STATUS, st);
  __atomic_fetch_add(&hwWifiStack.msiIrqCount, 1u, __ATOMIC_RELAXED);
  __atomic_fetch_or(&hwWifiStack.msiSeenBits, st, __ATOMIC_RELAXED);
  __atomic_fetch_or(&hwWifiStack.msiPending, st, __ATOMIC_RELEASE);
  static uint32_t emptySpins;
  emptySpins = st ? 0u : (emptySpins + 1u);
  if (emptySpins > 100000u) {
    hwWifiWrite32(hwWifi.dbi, HOUJI_DBI_MSI_INTR0_ENABLE, 0u);
    __atomic_store_n(&hwWifiStack.msiAttached, 0u, __ATOMIC_RELEASE);
  }
  __atomic_store_n(&hwWifiStack.msiWake, 1u, __ATOMIC_RELEASE);
  thread_wakeup(reinterpret_cast<event_t>(&hwWifiStack.msiWake));
}

static void hwWifiNwPoll(void) {
  uint32_t attached = __atomic_load_n(&hwWifiStack.msiAttached, __ATOMIC_ACQUIRE);
  nw_wifi_irq_mode(attached ? 1 : 0);
  uint32_t pending = __atomic_exchange_n(&hwWifiStack.msiPending, 0u, __ATOMIC_ACQ_REL);
  if (!attached) {
    uint32_t st = hwWifiRead32(hwWifi.dbi, HOUJI_DBI_MSI_INTR0_STATUS);
    if (st) {
      hwWifiWrite32(hwWifi.dbi, HOUJI_DBI_MSI_INTR0_STATUS, st);
      __atomic_fetch_or(&hwWifiStack.msiSeenBits, st, __ATOMIC_RELAXED);
      pending |= st;
    }
  }
  if (pending) nw_wifi_irq_pending(pending);
  nw_wifi_poll();
}

static bool hwWifiBoardMac(uint8_t mac[6]) {
  IORegistryEntry *chosen = IORegistryEntry::fromPath("/chosen", gIODTPlane);
  OSData *id = chosen ? OSDynamicCast(OSData, chosen->getProperty("unique-chip-id")) : nullptr;
  uint64_t seed = 0x686f756a69303134ULL; /* deterministic fallback if unique-chip-id absent */
  if (id && id->getLength() >= sizeof(seed)) {
    memcpy(&seed, id->getBytesNoCopy(), sizeof(seed));
  }
  OSSafeReleaseNULL(chosen);
  uint64_t h = 0xcbf29ce484222325ULL;
  for (unsigned i = 0; i < 8u; ++i) {
    h = (h ^ ((seed >> (8u * i)) & 0xffu)) * 0x100000001b3ULL;
  }
  for (unsigned i = 0; i < 6u; ++i) mac[i] = (uint8_t)(h >> (8u * i));
  mac[0] = (uint8_t)((mac[0] & 0xfeu) | 0x02u); /* locally administered unicast */
  return true;
}

static int hwWifiReadModemFileHeap(const char *relPath, uint8_t **outBuf, size_t *outSize) {
  uint64_t partBlocks = 0;
  for (unsigned tries = 0; tries < 20u; ++tries) {
    if (houji_modem_partition(&partBlocks)) break;
    hwWifiSleepMs(500);
  }
  if (!partBlocks) return -1;
  uint8_t *scratch = static_cast<uint8_t *>(IOMallocData(32u * 4096u));
  FatVolume *vol   = static_cast<FatVolume *>(IOMallocData(sizeof(FatVolume)));
  if (!scratch || !vol) {
    if (scratch) IOFreeData(scratch, 32u * 4096u);
    if (vol) IOFreeData(vol, sizeof(FatVolume));
    return -1;
  }
  memset(vol, 0, sizeof(*vol));
  HoujiWifiModemReader reader = { scratch, partBlocks * 4096ULL };
  int rc = -1;
  FatFile file = {};
  if (fat_mount(vol, reader.totalBytes, hwWifiModemFatRead, &reader) == FatOk &&
      fat_open(vol, relPath, &file) == FatOk &&
      file.size > 0u && file.size <= 16u * 1024u * 1024u) {
    uint8_t *buf = static_cast<uint8_t *>(IOMallocData(file.size));
    if (buf) {
      if (fat_read(vol, &file, 0u, buf, file.size) == FatOk) {
        *outBuf  = buf;
        *outSize = file.size;
        rc = 0;
      } else {
        IOFreeData(buf, file.size);
      }
    }
  }
  IOFreeData(vol, sizeof(FatVolume));
  IOFreeData(scratch, 32u * 4096u);
  return rc;
}

static int hwWifiNwFwGet(const char *path, const uint8_t **data, size_t *size) {
  if (!path || !data || !size) return -1;
  const char *base = path;
  for (const char *c = path; *c; ++c) {
    if (*c == '/') base = c + 1;
  }
  if (!strcmp(base, "wlan_mac.bin")) {
    static char macTxt[40];
    static size_t macLen;
    if (!macLen) {
      uint8_t m[6];
      hwWifiBoardMac(m);
      macLen = (size_t)snprintf(macTxt, sizeof(macTxt), "address=%02x%02x%02x%02x%02x%02x\n",
                                m[0], m[1], m[2], m[3], m[4], m[5]);
    }
    *data = reinterpret_cast<const uint8_t *>(macTxt);
    *size = macLen;
    return 0;
  }

  /* Map upstream ath12k WCN7850 HW 2.0 filenames to Xiaomi 14 modem_a /image/kiwi/ files */
  const char *modemRel = nullptr;
  if (!strcmp(base, "amss.bin")) {
    modemRel = "image/kiwi/amss20.bin";
  } else if (!strcmp(base, "m3.bin")) {
    modemRel = "image/kiwi/phy_ucode20.elf";
  } else if (!strcmp(base, "board.bin")) {
    modemRel = "image/kiwi/bd_n3.elf";
  } else if (!strcmp(base, "regdb.bin")) {
    modemRel = "image/kiwi/regdb_xiaomi.bin";
  } else {
    /* Reject board-2.bin / caldata.bin / firmware-2.bin cleanly so ath12k falls back to board.bin */
    return -1;
  }

  HwWifiFwSlot *slot = nullptr;
  for (auto &f : hwWifiFwCache) {
    if (f.tried && !strncmp(f.name, base, sizeof(f.name))) { slot = &f; break; }
  }
  if (!slot) {
    for (auto &f : hwWifiFwCache) {
      if (!f.tried) {
        slot = &f;
        strlcpy(f.name, base, sizeof(f.name));
        f.tried = true;
        break;
      }
    }
  }
  if (!slot) return -1;
  if (!slot->data && slot->size == 0) {
    if (hwWifiReadModemFileHeap(modemRel, &slot->data, &slot->size) != 0) {
      IOLog("HOUJI WIFI FW: failed to load %s (%s)\n", base, modemRel);
      return -1;
    }
    IOLog("HOUJI WIFI FW: loaded %s <- %s (%zu bytes)\n", base, modemRel, slot->size);
  }
  if (!slot->data) return -1;
  *data = slot->data;
  *size = slot->size;
  return 0;
}

static bool hwWifiFindEpCaps(void) {
  uint8_t cap = (uint8_t)(hwWifiRead32(hwWifi.ecam, 0x34u) & 0xffu);
  hwWifiStack.pcieCap = 0u;
  hwWifiStack.msiCap  = 0u;
  for (unsigned guard = 0; cap >= 0x40u && cap < 0xfcu && guard < 48u; ++guard) {
    uint32_t w = hwWifiRead32(hwWifi.ecam, cap);
    if ((w & 0xffu) == 0x10u) hwWifiStack.pcieCap = cap;
    if ((w & 0xffu) == 0x05u) hwWifiStack.msiCap  = cap;
    cap = (uint8_t)((w >> 8) & 0xffu);
  }
  return hwWifiStack.pcieCap != 0u && hwWifiStack.msiCap != 0u;
}

static int hwWifiNwCfgRead(int off, int size, uint32_t *v) {
  uint32_t o = (uint32_t)off;
  if (o & 0x80000000u) o = hwWifiStack.pcieCap + (o & 0x7fffffffu);
  uint32_t w = hwWifiRead32(hwWifi.ecam, o & ~3u);
  *v = (size == 4) ? w : (size == 2) ? ((w >> ((o & 2u) * 8u)) & 0xffffu) : ((w >> ((o & 3u) * 8u)) & 0xffu);
  return 0;
}

static int hwWifiNwCfgWrite(int off, int size, uint32_t v) {
  uint32_t o = (uint32_t)off;
  if (o & 0x80000000u) o = hwWifiStack.pcieCap + (o & 0x7fffffffu);
  if (size == 4) {
    hwWifiWrite32(hwWifi.ecam, o, v);
    return 0;
  }
  unsigned shift = ((size == 2) ? (o & 2u) : (o & 3u)) * 8u;
  uint32_t mask  = ((size == 2) ? 0xffffu : 0xffu) << shift;
  uint32_t cur   = hwWifiRead32(hwWifi.ecam, o & ~3u);
  hwWifiWrite32(hwWifi.ecam, o & ~3u, (cur & ~mask) | ((v << shift) & mask));
  return 0;
}

static int hwWifiNwMsiTarget(uint32_t *lo, uint32_t *hi, uint32_t *data) {
  *lo   = (uint32_t)HOUJI_WIFI_DMA_IOVA_BASE;
  *hi   = (uint32_t)(HOUJI_WIFI_DMA_IOVA_BASE >> 32);
  *data = 0u;
  return 0;
}

static void hwWifiOnScanDone(void) {
  __atomic_fetch_add(&hwWifiStack.scanDoneCount, 1u, __ATOMIC_RELAXED);
  int count = nw_wifi_bss_count();
  __atomic_store_n(&hwWifiStack.bssLogged, (uint32_t)(count > 0 ? count : 0), __ATOMIC_RELAXED);
  hwWifiSetStage(HOUJI_WIFI_STAGE_SCAN_DONE);
  IOLog("HOUJI WIFI SCAN: complete bss_count=%d beacons=%u\n", count, nw_wifi_stats.beacons);
  int limit = (count > 8) ? 8 : count;
  for (int i = 0; i < limit; ++i) {
    struct nw_bss_info bss = {};
    if (nw_wifi_bss_get(i, &bss) == 0) {
      char ssid[33];
      size_t sl = (bss.ssid_len <= 32u) ? bss.ssid_len : 32u;
      for (size_t k = 0; k < sl; ++k) {
        ssid[k] = (bss.ssid[k] >= 0x20 && bss.ssid[k] < 0x7f) ? (char)bss.ssid[k] : '?';
      }
      ssid[sl] = '\0';
      IOLog("HOUJI WIFI BSS[%d]: freq=%uMHz rssi=%ddBm caps=%04x ssid=\"%s\"\n",
            i, bss.freq_mhz, (int)bss.signal_dbm, bss.caps, ssid);
    }
  }
}

static void hwWifiMsiWait(unsigned ms) {
  if (__atomic_exchange_n(&hwWifiStack.msiWake, 0u, __ATOMIC_ACQ_REL)) return;
  assert_wait_timeout(reinterpret_cast<event_t>(&hwWifiStack.msiWake), THREAD_UNINT, ms, NSEC_PER_MSEC);
  if (__atomic_exchange_n(&hwWifiStack.msiWake, 0u, __ATOMIC_ACQ_REL)) {
    clear_wait(current_thread(), THREAD_AWAKENED);
    return;
  }
  thread_block(THREAD_CONTINUE_NULL);
  __atomic_store_n(&hwWifiStack.msiWake, 0u, __ATOMIC_RELEASE);
}

static int hwWifiCtrlSend(void *, uint64_t, const void *, size_t) {
  return NW_CONTROL_SEND_CLOSED;
}

static void hwWifiCtrlWake(void *) {
  __atomic_store_n(&hwWifiStack.msiWake, 1u, __ATOMIC_RELEASE);
  thread_wakeup(reinterpret_cast<event_t>(&hwWifiStack.msiWake));
}

static uint32_t hwWifiRunStack(uint32_t barBase, uint32_t barSize) {
  (void)barBase;
  __atomic_store_n(&hwWifiMhi.active, 1u, __ATOMIC_RELEASE);

  /* 1. APPS SMMU 4 KiB Stage-1 for 128 MiB DMA arena (SIDs 0x1400 & 0x1401) */
  uint32_t err = hwWifiSetupSmmu();
  if (err) return err;
  hwWifiSetStage(HOUJI_WIFI_STAGE_SMMU_READY);

  if (!hwWifiDynArenaInit(hwWifiMhi.dmaVa, HOUJI_WIFI_DMA_IOVA_BASE, HOUJI_WIFI_DMA_ARENA_BYTES)) {
    return 150u;
  }
  if (!hwWifiFindEpCaps()) return 151u;

  /* 2. Configure DWC MSI receiver + EP ASPM-off / MRRS=128B / BME */
  hwWifiSetupMsiAndBusMaster();

  /* 3. Start Ath12kWifi stack (performs chipPowerUp, MHI boot, QRTR/QMI wlfw, ath12k + mac80211) */
  static const struct lx_platform plat = {
    hwWifiNwNowMs,
    hwWifiNwSleepMs,
    hwWifiNwPoll,
    hwWifiNwLog,
    hwWifiNwHalt,
    hwWifiNwAlloc,
    hwWifiNwFree,
    hwWifiNwDmaAlloc,
    hwWifiNwDmaFree,
    hwWifiNwDmaMap,
    hwWifiNwDmaSync,
    hwWifiNwFwGet,
    hwWifiNwNowNs,
    hwWifiNwBootNs,
    hwWifiNwBusyDelayUs,
    _disable_preemption,
    _enable_preemption,
  };
  static const struct nw_wifi_events ev = {
    hwWifiOnScanDone,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
  };
  static struct nw_board board = {};
  board.bar        = reinterpret_cast<void *>(hwWifi.bar0);
  board.bar_len    = barSize;
  board.device_id  = (uint16_t)HOUJI_WCN7850_DEVICE_ID;
  board.msi_cap    = (uint16_t)hwWifiStack.msiCap;
  board.irq_base   = 1000;
  board.cfg_read   = hwWifiNwCfgRead;
  board.cfg_write  = hwWifiNwCfgWrite;
  board.msi_target = hwWifiNwMsiTarget;
  board.map_phys   = nullptr;
  board.diagnostics = 0u;

  __atomic_store_n(&hwWifiStack.active, 1u, __ATOMIC_RELEASE);
  nw_wifi_set_platform(&plat);
  nw_wifi_set_events(&ev);
  static const struct nw_control_transport ctrlTransport = {
    nullptr, hwWifiCtrlSend, hwWifiCtrlWake
  };
  (void)nw_wifi_control_transport_set(&ctrlTransport);

  int rc = nw_wifi_start(&plat, &board);
  __atomic_store_n(&hwWifiStack.startErr, rc, __ATOMIC_RELEASE);
  hwWifiSampleSmmuFaults();
  if (rc != 0) {
    IOLog("HOUJI WIFI STACK: nw_wifi_start failed rc=%d nw_stage=%u last_err=%d\n",
          rc, nw_wifi_stats.stage, nw_wifi_stats.last_err);
    return 160u;
  }

  /* 4. Attach GICv3 SPI 141 (INTID 173) for DWC iMSI; fall back to 1 ms polling if unavailable */
  uint32_t spiRb = 0;
  uint64_t spiRouter = 0;
  int spiRc = houji_spi_attach(kHwWifiPcie0MsiIntid, 0, hwWifiMsiIrq, nullptr, &spiRb, &spiRouter);
  __atomic_store_n(&hwWifiStack.msiAttached, (spiRc == HoujiSpiOk) ? 1u : 0u, __ATOMIC_RELEASE);
  nw_wifi_irq_mode(spiRc == HoujiSpiOk ? 1 : 0);
  IOLog("HOUJI WIFI STACK: started rc=0 nw_stage=%u spi141=%d\n", nw_wifi_stats.stage, spiRc);

  /* 5. Main wireless worker loop: drive ath12k/mac80211 and trigger Stage 3 verification scan */
  uint64_t sliceStart = hwWifiNwNowNs();
  for (;;) {
    int busy = nw_wifi_step();

    if (nw_wifi_stats.stage >= 4u && !hwWifiStack.scanRequested) {
      hwWifiStack.scanRequested = 1u;
      hwWifiSetStage(HOUJI_WIFI_STAGE_STACK_UP);
      int scanRc = nw_wifi_scan(nullptr, 0);
      IOLog("HOUJI WIFI STACK: radio ready (nw_stage=%u), triggered Stage 3 scan rc=%d\n",
            nw_wifi_stats.stage, scanRc);
    }

    if (!busy) {
      if (__atomic_load_n(&hwWifiStack.msiAttached, __ATOMIC_ACQUIRE)) {
        unsigned wait = nw_wifi_wait_ms(500);
        if (wait) hwWifiMsiWait(wait);
      } else {
        hwWifiSleepMs(1);
      }
      sliceStart = hwWifiNwNowNs();
    } else if (hwWifiNwNowNs() - sliceStart >= 2000000ULL) {
      thread_yield_to_preemption();
      sliceStart = hwWifiNwNowNs();
    }
  }
  return 0u;
}

static void hwWifiStackSnapshot(void) {
  if (!__atomic_load_n(&hwWifiStack.active, __ATOMIC_ACQUIRE)) return;
  IOLog("HOUJI WIFI STACK: start=%d nw_stage=%u last_err=%d scans=%u bss=%u beacons=%u frames=%u spi=%u msi=%08x/%u dma=%uK/%uK(fail=%u)\n",
        __atomic_load_n(&hwWifiStack.startErr, __ATOMIC_RELAXED),
        nw_wifi_stats.stage,
        nw_wifi_stats.last_err,
        nw_wifi_stats.scans,
        nw_wifi_stats.bss_seen,
        nw_wifi_stats.beacons,
        nw_wifi_stats.frames,
        __atomic_load_n(&hwWifiStack.msiAttached, __ATOMIC_RELAXED),
        __atomic_load_n(&hwWifiStack.msiSeenBits, __ATOMIC_RELAXED),
        __atomic_load_n(&hwWifiStack.msiIrqCount, __ATOMIC_RELAXED),
        hwWifiStack.usedBytes / 1024u,
        hwWifiStack.peakBytes / 1024u,
        hwWifiStack.failures);
  uint32_t notes = __atomic_load_n(&hwWifiStack.noteIdx, __ATOMIC_RELAXED);
  if (notes > 0u) {
    uint32_t last = (notes - 1u) & 3u;
    IOLog("HOUJI WIFI NOTE: %s\n", hwWifiStack.lastNote[last]);
  }
  uint32_t ec = __atomic_load_n(&hwWifiStack.errCount, __ATOMIC_RELAXED);
  uint32_t show = (ec < 4u) ? ec : 4u;
  for (uint32_t i = 0; i < show; ++i) {
    IOLog("HOUJI WIFI ERR[%u]: %s\n", i, hwWifiStack.firstErr[i]);
  }
}
