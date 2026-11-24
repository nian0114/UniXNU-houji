/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Pure C/C++ hardware policy, safe SM8650 APPS SMMUv2 Stage-1 planner/programmer,
 * power-of-two 32-bit IOVA arena allocator, and MHI BHI/BHIe firmware boot state
 * machine for Xiaomi 14 (houji / SM8650) WCN7850 (17cb:1107) Stage 2 bring-up.
 * Zero IOKit/XNU dependencies so host tests compile and verify every helper.
 */
#ifndef HOUJI_WIFI_MHI_POLICY_H
#define HOUJI_WIFI_MHI_POLICY_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "HoujiWifiPciePolicy.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Verified houji.dtb (/soc/qcom,pcie@1c00000 & /soc/apps-smmu@15000000) SMMU parameters */
#define HOUJI_APPS_SMMU_BASE        0x15000000ULL
#define HOUJI_APPS_SMMU_MAP_BYTES   0x000d0000u
#define HOUJI_WIFI_SID_RC0          0x1400u
#define HOUJI_WIFI_SID_WCN7850      0x1401u
#define HOUJI_WIFI_SMMU_ASID        0x1401u

/* Dedicated 32-bit IOVA window (128 MiB for ath12k QMI host regions + rings; disjoint from 0x60000000..0x63ffffff) */
#define HOUJI_WIFI_DMA_IOVA_BASE    0x10000000ULL
#define HOUJI_WIFI_DMA_ARENA_BYTES  (128u * 1024u * 1024u)
#define HOUJI_WIFI_MSI_SINK_BYTES   4096u

/* WCN7850 MHI / BHI / BHIe offsets and constants */
#define HOUJI_MHI_CCABAP_LO         0x0058u
#define HOUJI_MHI_ECABAP_LO         0x0060u
#define HOUJI_MHI_CRCBAP_LO         0x0068u
#define HOUJI_MHI_MHICTRLBASE_LO    0x0080u
#define HOUJI_MHI_MHICTRLLIMIT_LO   0x0088u
#define HOUJI_MHI_MHIDATABASE_LO    0x0098u
#define HOUJI_MHI_MHIDATALIMIT_LO   0x00a0u
#define HOUJI_MHI_CTRL_RESET        (1u << 1)
#define HOUJI_MHI_STATUS_READY      (1u << 0)
#define HOUJI_MHI_STATUS_SYSERR     (1u << 2)
#define HOUJI_MHI_STATE_SHIFT       8u

#define HOUJI_BHI_IMGADDR_LOW       0x0008u
#define HOUJI_BHI_IMGADDR_HIGH      0x000cu
#define HOUJI_BHI_IMGSIZE           0x0010u
#define HOUJI_BHI_IMGTXDB           0x0018u
#define HOUJI_BHI_INTVEC            0x0020u
#define HOUJI_BHI_EXECENV           0x0028u
#define HOUJI_BHI_STATUS            0x002cu
#define HOUJI_BHI_ERRCODE           0x0030u

#define HOUJI_BHIE_TXVECADDR_LOW    0x002cu
#define HOUJI_BHIE_TXVECADDR_HIGH   0x0030u
#define HOUJI_BHIE_TXVECSIZE        0x0034u
#define HOUJI_BHIE_TXVECDB          0x003cu
#define HOUJI_BHIE_TXVECSTATUS      0x0044u

#define HOUJI_MHI_SEQ_MASK          0x3fffffffu
#define HOUJI_MHI_XFER_SUCCESS      2u
#define HOUJI_MHI_XFER_ERROR        3u
#define HOUJI_WCN7850_SBL_BYTES     (512u * 1024u)
#define HOUJI_WCN7850_SEG_BYTES     (512u * 1024u)
#define HOUJI_WCN7850_MAX_SEGMENTS  32u

enum {
  HoujiMhiStateReset  = 0u,
  HoujiMhiStateReady  = 1u,
  HoujiMhiStateM0     = 2u,
  HoujiMhiStateBhi    = 7u,
  HoujiMhiStateSysErr = 0xffu,
};

enum {
  HoujiMhiEePbl   = 0u,
  HoujiMhiEeSbl   = 1u,
  HoujiMhiEeAmss  = 2u,
  HoujiMhiEeRddm  = 3u,
  HoujiMhiEeWfw   = 4u,
  HoujiMhiEePthru = 5u,
  HoujiMhiEeEdl   = 6u,
};

enum {
  HoujiMhiIdle = 0u,
  HoujiMhiResetting,
  HoujiMhiSblLoading,
  HoujiMhiWaitReady,
  HoujiMhiNeedContexts,
  HoujiMhiWaitSbl,
  HoujiMhiImageLoading,
  HoujiMhiWaitMission,
  HoujiMhiDone,
  HoujiMhiFailed,
};

enum {
  HoujiMhiErrNone = 0u,
  HoujiMhiErrLayout,
  HoujiMhiErrNotPbl,
  HoujiMhiErrBhi,
  HoujiMhiErrBhie,
  HoujiMhiErrSysErr,
  HoujiMhiErrTimeout,
  HoujiMhiErrState,
  HoujiMhiErrRddm,
};

/* --- 1. SM8650 PARF BDF-to-SID CRC-8 (poly 0x07, MSB-first over big-endian BDF) --- */
static inline uint8_t houji_wifi_bdf_crc8(uint16_t bdf) {
  uint8_t crc = 0u;
  uint8_t bytes[2];
  bytes[0] = (uint8_t)(bdf >> 8);
  bytes[1] = (uint8_t)(bdf & 0xffu);
  for (unsigned i = 0u; i < 2u; ++i) {
    crc ^= bytes[i];
    for (unsigned bit = 0u; bit < 8u; ++bit) {
      crc = (crc & 0x80u) ? (uint8_t)((crc << 1) ^ 0x07u) : (uint8_t)(crc << 1);
    }
  }
  return crc;
}

static inline uint32_t houji_wifi_bdf_sid_entry(uint16_t bdf, uint8_t sid_offset, uint8_t next) {
  return ((uint32_t)bdf << 16) | ((uint32_t)sid_offset << 8) | (uint32_t)next;
}

/* --- 2. Safe APPS SMMUv2 (0x15000000) Stage-1 Planner & Programmer ---
 * Obeys houji hardware rules:
 * - Caps stream-match groups to 128 and total MMIO window to 0xd0000.
 * - NEVER reads S2CR (0xc00 + 4*i) when SMR bit 31 (VALID) is 0.
 * - Never touches bank (banks - 1), which belongs to UFS bypass.
 */
typedef struct {
  void *ctx;
  uint32_t (*rd32)(void *ctx, uint32_t off);
  void (*wr32)(void *ctx, uint32_t off, uint32_t val);
  uint64_t (*rd64)(void *ctx, uint32_t off);
  void (*wr64)(void *ctx, uint32_t off, uint64_t val);
} HoujiWifiSmmuIo;

typedef struct {
  unsigned slot_rc;
  unsigned slot_ep;
  unsigned bank;
  unsigned pages;
  unsigned pa_code;
  unsigned pa_bits;
  unsigned reuse_rc;
  unsigned reuse_ep;
  unsigned reuse_bank;
  uint32_t idr0, idr1, idr2;
  const char *error;
} HoujiWifiSmmuPlan;

static inline unsigned houji_wifi_smmu_pa_bits(unsigned code) {
  switch (code) {
    case 0u: return 32u;
    case 1u: return 36u;
    case 2u: return 40u;
    case 3u: return 42u;
    case 4u: return 44u;
    case 5u: return 48u;
    default: return 0u;
  }
}

static inline HoujiWifiSmmuPlan houji_wifi_plan_smmu_s1(const HoujiWifiSmmuIo *io,
                                                        uint16_t sid_rc,
                                                        uint16_t sid_ep) {
  HoujiWifiSmmuPlan p;
  memset(&p, 0, sizeof(p));
  p.slot_rc = 0xffffffffu;
  p.slot_ep = 0xffffffffu;
  p.bank    = 0xffffffffu;
  if (!io || !io->rd32 || sid_rc == sid_ep) {
    p.error = "invalid SMMU arguments";
    return p;
  }
  p.idr0 = io->rd32(io->ctx, 0x20u);
  p.idr1 = io->rd32(io->ctx, 0x24u);
  p.idr2 = io->rd32(io->ctx, 0x28u);
  if (!(p.idr0 & (1u << 30)) || !(p.idr2 & (1u << 12))) {
    p.error = "SMMU AArch64 4K stage-1 unsupported";
    return p;
  }
  p.pa_code = (p.idr2 >> 4) & 0xfu;
  p.pa_bits = houji_wifi_smmu_pa_bits(p.pa_code);
  unsigned va_bits = houji_wifi_smmu_pa_bits((p.idr2 >> 8) & 0xfu);
  if (!p.pa_bits || va_bits < 32u) {
    p.error = "unsupported SMMU address width";
    return p;
  }
  unsigned count = p.idr0 & 0xffu;
  unsigned banks = p.idr1 & 0xffu;
  unsigned s2    = (p.idr1 >> 16) & 0xffu;
  p.pages = 1u << (((p.idr1 >> 28) & 7u) + 1u);
  if ((p.idr1 >> 31) || !count || p.pages > 128u || banks < 3u || banks > 128u ||
      s2 >= banks - 1u || (p.pages + banks) * 4096u > HOUJI_APPS_SMMU_MAP_BYTES) {
    p.error = "unsupported SMMU geometry";
    return p;
  }
  if (count > 128u) count = 128u;

  uint64_t other_banks_lo = 0ULL, other_banks_hi = 0ULL;
  unsigned rc_matches = 0u, ep_matches = 0u;
  unsigned existing_bank = 0xffffffffu;

  for (unsigned i = 0u; i < count; ++i) {
    uint32_t smr = io->rd32(io->ctx, 0x800u + 4u * i);
    if (!(smr & 0x80000000u)) {
      if (p.slot_rc == 0xffffffffu) p.slot_rc = i;
      else if (p.slot_ep == 0xffffffffu) p.slot_ep = i;
      continue;
    }
    /* SMR is VALID: safe to read S2CR on houji */
    uint32_t s2cr = io->rd32(io->ctx, 0xc00u + 4u * i);
    uint32_t mask = (smr >> 16) & 0x7fffu;
    unsigned match_rc = (((smr ^ sid_rc) & 0xffffu & ~mask) == 0u);
    unsigned match_ep = (((smr ^ sid_ep) & 0xffffu & ~mask) == 0u);
    unsigned b = s2cr & 0xffu;
    if (match_rc || match_ep) {
      if (mask || ((s2cr >> 16) & 3u) != 0u || b >= banks - 1u || b < s2) {
        p.error = "conflicting Wi-Fi SMR/S2CR";
        return p;
      }
      if (existing_bank != 0xffffffffu && existing_bank != b) {
        p.error = "mismatched existing Wi-Fi banks";
        return p;
      }
      existing_bank = b;
      if (match_rc) {
        if (++rc_matches > 1u) { p.error = "duplicate RC0 SMR"; return p; }
        p.reuse_rc = 1u;
        p.slot_rc = i;
      }
      if (match_ep) {
        if (++ep_matches > 1u) { p.error = "duplicate EP SMR"; return p; }
        p.reuse_ep = 1u;
        p.slot_ep = i;
      }
    } else if (((s2cr >> 16) & 3u) == 0u && b < 128u) {
      if (b < 64u) other_banks_lo |= (1ULL << b);
      else other_banks_hi |= (1ULL << (b - 64u));
    }
  }

  /* Ensure slot_rc and slot_ep are distinct when one was reused and one came from free scan */
  if (p.slot_rc == p.slot_ep) {
    p.slot_ep = 0xffffffffu;
    for (unsigned i = 0u; i < count; ++i) {
      if (i == p.slot_rc) continue;
      if (!(io->rd32(io->ctx, 0x800u + 4u * i) & 0x80000000u)) {
        p.slot_ep = i;
        break;
      }
    }
  }
  if (p.slot_rc == 0xffffffffu || p.slot_ep == 0xffffffffu) {
    p.error = "no free SMMU stream-match slots";
    return p;
  }

  if (existing_bank != 0xffffffffu) {
    unsigned used_by_other = (existing_bank < 64u)
      ? ((other_banks_lo >> existing_bank) & 1u)
      : ((other_banks_hi >> (existing_bank - 64u)) & 1u);
    if (used_by_other) {
      p.error = "existing Wi-Fi bank shared with unrelated stream";
      return p;
    }
    p.bank = existing_bank;
    p.reuse_bank = 1u;
    return p;
  }

  /* Pick highest clean disabled bank below (banks - 1), leaving (banks - 1) for UFS bypass */
  for (unsigned b = banks - 1u; b-- > s2;) {
    unsigned used = (b < 64u) ? ((other_banks_lo >> b) & 1u) : ((other_banks_hi >> (b - 64u)) & 1u);
    if (used) continue;
    uint32_t cb_off = (p.pages + b) * 4096u;
    uint32_t sctlr  = io->rd32(io->ctx, cb_off);
    uint32_t cbar   = io->rd32(io->ctx, 0x1000u + 4u * b);
    if ((sctlr & 1u) == 0u && cbar != 0x10000u) {
      p.bank = b;
      return p;
    }
  }
  p.error = "no free disabled SMMU context bank";
  return p;
}

static inline const char *houji_wifi_program_smmu_s1(const HoujiWifiSmmuIo *io,
                                                     const HoujiWifiSmmuPlan *p,
                                                     uint16_t sid_rc,
                                                     uint16_t sid_ep,
                                                     uint64_t root_table_pa,
                                                     uint16_t asid) {
  if (!io || !p) return "null SMMU plan";
  if (p->error) return p->error;
  if ((root_table_pa & 0xfffULL) != 0ULL || root_table_pa == 0ULL) return "unaligned root table PA";

  uint32_t cb = (p->pages + p->bank) * 4096u;
  /* If reusing an earlier Wi-Fi bank, disable SCTLR and sync TLB before updating TTBR0 */
  io->wr32(io->ctx, cb + 0x000u, 0u);
  if (io->rd32(io->ctx, cb + 0x000u) & 1u) return "SMMU CB disable failed";

  uint32_t tcr2  = (1u << 4) | (p->pa_code & 7u);
  uint32_t tcr   = (2u << 30) | (1u << 23) | 0x3500u | 32u; /* TG1=4K, EPD1=1, Inner WBWA, T0SZ=32 */
  uint64_t ttbr0 = ((uint64_t)asid << 48) | root_table_pa;
  uint64_t ttbr1 = (uint64_t)asid << 48;

  io->wr32(io->ctx, 0x1800u + 4u * p->bank, 1u);       /* CBA2R: VA64=1 */
  io->wr32(io->ctx, 0x1000u + 4u * p->bank, 0x10000u); /* CBAR: S1_TRANS_S2_BYPASS */
  io->wr32(io->ctx, cb + 0x010u, tcr2);
  io->wr32(io->ctx, cb + 0x030u, tcr);
  io->wr64(io->ctx, cb + 0x020u, ttbr0);
  io->wr64(io->ctx, cb + 0x028u, ttbr1);
  io->wr32(io->ctx, cb + 0x038u, 0x0000ff44u);         /* MAIR0: Attr0=NC, Attr1=WBWA */
  io->wr32(io->ctx, cb + 0x03cu, 0u);
  io->wr32(io->ctx, cb + 0x058u, 0xffffffffu);         /* Clear CB_FSR */

  /* Bank-local TLBIALL + TLBSYNC */
  io->wr32(io->ctx, cb + 0x618u, 0u);
  io->wr32(io->ctx, cb + 0x7f0u, 0u);
  unsigned synced = 0u;
  for (unsigned i = 0u; i < 2000u; ++i) {
    if ((io->rd32(io->ctx, cb + 0x7f4u) & 1u) == 0u) {
      synced = 1u;
      break;
    }
  }
  if (!synced) return "SMMU CB TLBSYNC timeout";

  if (io->rd32(io->ctx, 0x1800u + 4u * p->bank) != 1u ||
      io->rd32(io->ctx, 0x1000u + 4u * p->bank) != 0x10000u ||
      io->rd64(io->ctx, cb + 0x020u) != ttbr0) {
    return "SMMU CB register readback mismatch";
  }

  /* Enable Stage-1 translation: M=1, TRE=1, AFE=1, CFRE=1, CFIE=0 (polled faults) */
  io->wr32(io->ctx, cb + 0x000u, 0x00000027u);
  if ((io->rd32(io->ctx, cb + 0x000u) & 0x27u) != 0x27u) return "SMMU SCTLR enable failed";
  if (io->rd32(io->ctx, cb + 0x058u) & 0xc00001feu) return "SMMU CB fault on enable";

  /* Publish S2CR BEFORE SMR for RC0 (0x1400) and WCN7850 EP (0x1401), and only
   * read back S2CR AFTER SMR bit 31 (VALID) is set (houji APPS SMMU rule). */
  if (!p->reuse_rc) {
    io->wr32(io->ctx, 0xc00u + 4u * p->slot_rc, p->bank);
    io->wr32(io->ctx, 0x800u + 4u * p->slot_rc, 0x80000000u | sid_rc);
  }
  if (!p->reuse_ep) {
    io->wr32(io->ctx, 0xc00u + 4u * p->slot_ep, p->bank);
    io->wr32(io->ctx, 0x800u + 4u * p->slot_ep, 0x80000000u | sid_ep);
  }
  if (io->rd32(io->ctx, 0x800u + 4u * p->slot_rc) != (0x80000000u | sid_rc) ||
      io->rd32(io->ctx, 0x800u + 4u * p->slot_ep) != (0x80000000u | sid_ep) ||
      io->rd32(io->ctx, 0xc00u + 4u * p->slot_rc) != p->bank ||
      io->rd32(io->ctx, 0xc00u + 4u * p->slot_ep) != p->bank) {
    return "SMMU SMR/S2CR readback mismatch";
  }
  return NULL;
}

/* --- 3. Power-of-Two Aligned 32-bit IOVA Arena Allocator --- */
#define HOUJI_WIFI_ARENA_MAX_BLOCKS 512u

typedef struct {
  uint32_t off;
  uint32_t size;
  uint8_t  used;
} HoujiWifiArenaBlock;

typedef struct {
  uint8_t *va;
  uint64_t iova;
  uint32_t total_bytes;
  uint32_t used_bytes;
  uint32_t peak_bytes;
  unsigned count;
  unsigned failures;
  HoujiWifiArenaBlock blocks[HOUJI_WIFI_ARENA_MAX_BLOCKS];
} HoujiWifiArena;

static inline int houji_wifi_arena_init(HoujiWifiArena *a, uint8_t *va,
                                        uint64_t iova, uint32_t bytes) {
  if (!a || !va || bytes <= HOUJI_WIFI_MSI_SINK_BYTES || (iova & 0xfffULL) != 0ULL) return 0;
  if (iova > 0xffffffffULL - bytes + 1ULL) return 0;
  memset(a, 0, sizeof(*a));
  memset(va, 0, bytes);
  a->va          = va;
  a->iova        = iova;
  a->total_bytes = bytes;
  /* Reserve page 0 (0x10000000..0x10000fff) as the DWC MSI target sink */
  a->blocks[0].off  = HOUJI_WIFI_MSI_SINK_BYTES;
  a->blocks[0].size = bytes - HOUJI_WIFI_MSI_SINK_BYTES;
  a->blocks[0].used = 0u;
  a->count      = 1u;
  a->used_bytes = HOUJI_WIFI_MSI_SINK_BYTES;
  a->peak_bytes = HOUJI_WIFI_MSI_SINK_BYTES;
  return 1;
}

static inline void *houji_wifi_arena_alloc(HoujiWifiArena *a, uint32_t bytes, uint64_t *out_iova) {
  if (!a || !bytes || bytes > a->total_bytes) return NULL;
  uint32_t n = (bytes + 63u) & ~63u;
  if (n >= 4096u) n = (n + 4095u) & ~4095u;
  uint32_t align = 64u;
  if (n >= 4096u) {
    align = 4096u;
    while (align < n && align < 0x80000000u) align <<= 1;
  }
  for (unsigned i = 0u; i < a->count; ++i) {
    if (a->blocks[i].used) continue;
    uint32_t b_off  = a->blocks[i].off;
    uint32_t b_size = a->blocks[i].size;
    /* Align absolute IOVA (a->iova + start) to power-of-two `align` */
    uint64_t abs_start = ((a->iova + b_off) + (uint64_t)align - 1ULL) & ~((uint64_t)align - 1ULL);
    uint32_t start = (uint32_t)(abs_start - a->iova);
    uint32_t pad   = start - b_off;
    if (b_size < pad || b_size - pad < n) continue;
    unsigned has_tail = (b_size > pad + n) ? 1u : 0u;
    unsigned extra    = (pad ? 1u : 0u) + has_tail;
    if (a->count + extra > HOUJI_WIFI_ARENA_MAX_BLOCKS) continue;

    memmove(&a->blocks[i + extra], &a->blocks[i],
            (a->count - i) * sizeof(HoujiWifiArenaBlock));
    a->count += extra;
    unsigned at = i;
    if (pad) {
      a->blocks[at].off  = b_off;
      a->blocks[at].size = pad;
      a->blocks[at].used = 0u;
      ++at;
    }
    a->blocks[at].off  = start;
    a->blocks[at].size = n;
    a->blocks[at].used = 1u;
    if (has_tail) {
      a->blocks[at + 1u].off  = start + n;
      a->blocks[at + 1u].size = b_size - pad - n;
      a->blocks[at + 1u].used = 0u;
    }
    a->used_bytes += n;
    if (a->used_bytes > a->peak_bytes) a->peak_bytes = a->used_bytes;
    uint8_t *ptr = a->va + start;
    memset(ptr, 0, n);
    if (out_iova) *out_iova = a->iova + start;
    return ptr;
  }
  ++a->failures;
  return NULL;
}

static inline void houji_wifi_arena_free(HoujiWifiArena *a, void *ptr) {
  if (!a || !ptr) return;
  uint8_t *p = (uint8_t *)ptr;
  if (p < a->va || p >= a->va + a->total_bytes) return;
  uint32_t off = (uint32_t)(p - a->va);
  for (unsigned i = 0u; i < a->count; ++i) {
    if (a->blocks[i].off != off || !a->blocks[i].used) continue;
    a->used_bytes -= a->blocks[i].size;
    a->blocks[i].used = 0u;
    if (i + 1u < a->count && !a->blocks[i + 1u].used) {
      a->blocks[i].size += a->blocks[i + 1u].size;
      memmove(&a->blocks[i + 1u], &a->blocks[i + 2u],
              (a->count - i - 2u) * sizeof(HoujiWifiArenaBlock));
      --a->count;
    }
    if (i > 0u && !a->blocks[i - 1u].used) {
      a->blocks[i - 1u].size += a->blocks[i].size;
      memmove(&a->blocks[i], &a->blocks[i + 1u],
              (a->count - i - 1u) * sizeof(HoujiWifiArenaBlock));
      --a->count;
    }
    return;
  }
}

/* --- 4. WCN7850 BAR0 Static Window Address Helper --- */
static inline uint32_t houji_wcn7850_bar_offset(uint32_t chip_addr, uint32_t *out_window_reg) {
  if (chip_addr < 0x80000u) {
    if (out_window_reg) *out_window_reg = 0xffffffffu;
    return chip_addr;
  }
  if (out_window_reg) *out_window_reg = 0x40000000u | ((chip_addr >> 19) & 0x3fu);
  if (chip_addr >= 0x01e0e100u && chip_addr <= 0x01e0effcu) {
    return (chip_addr - 0x01e0e100u) & 0x7ffffu;
  }
  return 0x80000u + (chip_addr & 0x7ffffu);
}

/* --- 5. MHI Context Builder, Event Ring Ack, & BHI/BHIe Boot State Machine --- */
typedef struct {
  uint64_t address;
  uint64_t size;
} HoujiBhieEntry;

typedef struct {
  void *ctx;
  uint32_t (*rd)(void *ctx, uint32_t reg);
  void (*wr)(void *ctx, uint32_t reg, uint32_t val);
  uint32_t space;
} HoujiMhiIo;

typedef struct {
  HoujiMhiIo io;
  uint32_t bhi, bhie, reglen;
  uint32_t phase, error, failed_phase, ee, state;
  uint32_t seq, errcode, last_status;
  uint64_t sbl_addr, table_addr;
  uint32_t sbl_size, table_size, msi_vector;
} HoujiMhiBoot;

static inline uint32_t houji_mhi_bhie_table(HoujiBhieEntry *table, uint32_t max_entries,
                                            uint64_t base_iova, uint32_t image_size,
                                            uint32_t seg_size) {
  if (!table || !image_size || !seg_size) return 0u;
  uint32_t needed = (image_size + seg_size - 1u) / seg_size;
  if (needed > max_entries) return 0u;
  for (uint32_t i = 0u; i < needed; ++i) {
    uint32_t rem = image_size - i * seg_size;
    table[i].address = base_iova + (uint64_t)i * seg_size;
    table[i].size    = rem < seg_size ? rem : seg_size;
  }
  return needed;
}

static inline void houji_mhi_program_contexts(const HoujiMhiIo *io,
                                              uint8_t *ctx_va, uint64_t ctx_iova,
                                              uint32_t ctx_bytes,
                                              uint64_t out_ev_wp[2]) {
  const uint32_t kCtx = 44u, kChannels = 128u, kEvents = 2u, kCmdEl = 8u, kEl = 16u;
  const uint32_t evLen[2] = {32u * kEl, 256u * kEl};
  const uint32_t chOff = 0u;
  const uint32_t evOff = kChannels * kCtx;
  const uint32_t cmdOff = evOff + kEvents * kCtx;
  const uint32_t ringOff = (cmdOff + kCtx + 4095u) & ~4095u;
  if (!io || !ctx_va || ctx_bytes < ringOff + evLen[0] + evLen[1] + kCmdEl * kEl) return;

  memset(ctx_va, 0, ctx_bytes);
  uint32_t cur = ringOff;
  uint64_t evBase[2];
  for (uint32_t i = 0u; i < kEvents; ++i) {
    evBase[i] = ctx_iova + cur;
    uint32_t at = evOff + i * kCtx;
    uint32_t v0 = (i == 0u) ? 0u : (1u << 16);
    uint32_t v1 = 1u;
    uint32_t v2 = i + 1u;
    uint64_t rbase = evBase[i];
    uint64_t rlen  = evLen[i];
    uint64_t rp    = evBase[i];
    uint64_t wp    = evBase[i] + evLen[i] - kEl;
    memcpy(ctx_va + at + 0u, &v0, 4u);
    memcpy(ctx_va + at + 4u, &v1, 4u);
    memcpy(ctx_va + at + 8u, &v2, 4u);
    memcpy(ctx_va + at + 12u, &rbase, 8u);
    memcpy(ctx_va + at + 20u, &rlen, 8u);
    memcpy(ctx_va + at + 28u, &rp, 8u);
    memcpy(ctx_va + at + 36u, &wp, 8u);
    if (out_ev_wp) out_ev_wp[i] = wp;
    cur += evLen[i];
  }
  uint64_t cmdBase = ctx_iova + cur;
  uint64_t cmdLen  = kCmdEl * kEl;
  memcpy(ctx_va + cmdOff + 12u, &cmdBase, 8u);
  memcpy(ctx_va + cmdOff + 20u, &cmdLen, 8u);
  memcpy(ctx_va + cmdOff + 28u, &cmdBase, 8u);
  memcpy(ctx_va + cmdOff + 36u, &cmdBase, 8u);

  io->wr(io->ctx, HOUJI_MHI_CCABAP_LO, (uint32_t)(ctx_iova + chOff));
  io->wr(io->ctx, HOUJI_MHI_CCABAP_LO + 4u, (uint32_t)((ctx_iova + chOff) >> 32));
  io->wr(io->ctx, HOUJI_MHI_ECABAP_LO, (uint32_t)(ctx_iova + evOff));
  io->wr(io->ctx, HOUJI_MHI_ECABAP_LO + 4u, (uint32_t)((ctx_iova + evOff) >> 32));
  io->wr(io->ctx, HOUJI_MHI_CRCBAP_LO, (uint32_t)(ctx_iova + cmdOff));
  io->wr(io->ctx, HOUJI_MHI_CRCBAP_LO + 4u, (uint32_t)((ctx_iova + cmdOff) >> 32));
  io->wr(io->ctx, HOUJI_MHI_MHICTRLBASE_LO, 0u);
  io->wr(io->ctx, HOUJI_MHI_MHICTRLBASE_LO + 4u, 0u);
  io->wr(io->ctx, HOUJI_MHI_MHICTRLLIMIT_LO, 0xffffffffu);
  io->wr(io->ctx, HOUJI_MHI_MHICTRLLIMIT_LO + 4u, 0u);
  io->wr(io->ctx, HOUJI_MHI_MHIDATABASE_LO, 0u);
  io->wr(io->ctx, HOUJI_MHI_MHIDATABASE_LO + 4u, 0u);
  io->wr(io->ctx, HOUJI_MHI_MHIDATALIMIT_LO, 0xffffffffu);
  io->wr(io->ctx, HOUJI_MHI_MHIDATALIMIT_LO + 4u, 0u);

  uint32_t cfg = io->rd(io->ctx, HOUJI_MHI_CFG_OFF);
  cfg = (cfg & ~0xffff0000u) | (kEvents << 16);
  io->wr(io->ctx, HOUJI_MHI_CFG_OFF, cfg);

  uint32_t erdb = io->rd(io->ctx, HOUJI_MHI_ERDB_OFF);
  if (erdb >= 0x100u && erdb + 8u * kEvents <= io->space) {
    for (uint32_t i = 0u; i < kEvents; ++i) {
      uint64_t wp = evBase[i] + evLen[i] - kEl;
      io->wr(io->ctx, erdb + 8u * i, (uint32_t)wp);
      io->wr(io->ctx, erdb + 8u * i + 4u, (uint32_t)(wp >> 32));
    }
  }
}

static inline unsigned houji_mhi_ack_events(const HoujiMhiIo *io, uint8_t *ctx_va,
                                            uint64_t acked_rp[2]) {
  const uint32_t kCtx = 44u, kChannels = 128u;
  unsigned moved = 0u;
  uint32_t erdb = io->rd(io->ctx, HOUJI_MHI_ERDB_OFF);
  if (erdb == 0xffffffffu || erdb < 0x100u || erdb + 16u > io->space) return 0u;
  for (unsigned r = 0u; r < 2u; ++r) {
    uint8_t *ctx = ctx_va + kChannels * kCtx + r * kCtx;
    uint64_t base = 0ULL, len = 0ULL, rp = 0ULL;
    memcpy(&base, ctx + 12u, 8u);
    memcpy(&len, ctx + 20u, 8u);
    memcpy(&rp, ctx + 28u, 8u);
    if (rp == acked_rp[r] || rp < base || rp >= base + len) continue;
    acked_rp[r] = rp;
    uint64_t wp = (rp == base) ? (base + len - 16ULL) : (rp - 16ULL);
    memcpy(ctx + 36u, &wp, 8u);
    io->wr(io->ctx, erdb + 8u * r, (uint32_t)wp);
    io->wr(io->ctx, erdb + 8u * r + 4u, (uint32_t)(wp >> 32));
    ++moved;
  }
  return moved;
}

static inline int houji_mhi_boot_open(HoujiMhiBoot *m, const HoujiMhiIo *io) {
  if (!m || !io || !io->rd || !io->wr) return -1;
  memset(m, 0, sizeof(*m));
  m->io     = *io;
  m->reglen = io->space ? io->space : io->rd(io->ctx, HOUJI_MHI_REGLEN_OFF);
  m->bhi    = io->rd(io->ctx, HOUJI_MHI_BHI_OFF);
  m->bhie   = io->rd(io->ctx, HOUJI_MHI_BHIE_OFF);
  int ok = m->reglen >= 0x100u && m->reglen <= 0x200000u &&
           m->bhi >= 0x100u && m->bhi + HOUJI_BHI_ERRCODE + 4u <= m->reglen &&
           m->bhie >= 0x100u && m->bhie + HOUJI_BHIE_TXVECSTATUS + 4u <= m->reglen &&
           (m->bhi & 3u) == 0u && (m->bhie & 3u) == 0u;
  if (!ok) {
    m->phase = HoujiMhiFailed;
    m->error = HoujiMhiErrLayout;
    return -1;
  }
  m->phase = HoujiMhiIdle;
  return 0;
}

static inline uint32_t houji_mhi_boot_ee(HoujiMhiBoot *m) {
  return m->ee = m->io.rd(m->io.ctx, m->bhi + HOUJI_BHI_EXECENV);
}

static inline uint32_t houji_mhi_boot_state(HoujiMhiBoot *m) {
  return m->state = (m->io.rd(m->io.ctx, HOUJI_MHI_STATUS_OFF) >> HOUJI_MHI_STATE_SHIFT) & 0xffu;
}

static inline uint32_t houji_mhi_fail(HoujiMhiBoot *m, uint32_t err) {
  m->failed_phase = m->phase;
  m->error        = err;
  m->phase        = HoujiMhiFailed;
  return m->phase;
}

static inline uint32_t houji_mhi_start_sbl(HoujiMhiBoot *m) {
  m->io.wr(m->io.ctx, m->bhi + HOUJI_BHI_INTVEC, m->msi_vector);
  m->io.wr(m->io.ctx, m->bhi + HOUJI_BHI_IMGADDR_HIGH, (uint32_t)(m->sbl_addr >> 32));
  m->io.wr(m->io.ctx, m->bhi + HOUJI_BHI_IMGADDR_LOW, (uint32_t)m->sbl_addr);
  m->io.wr(m->io.ctx, m->bhi + HOUJI_BHI_IMGSIZE, m->sbl_size);
  m->io.wr(m->io.ctx, m->bhi + HOUJI_BHI_IMGTXDB, m->seq);
  m->phase = HoujiMhiSblLoading;
  return m->phase;
}

static inline uint32_t houji_mhi_boot_begin(HoujiMhiBoot *m, uint32_t msi_vector,
                                            uint64_t sbl_addr, uint32_t sbl_size,
                                            uint64_t table_addr, uint32_t table_size,
                                            uint32_t seq) {
  if (m->phase != HoujiMhiIdle) return houji_mhi_fail(m, HoujiMhiErrState);
  m->msi_vector = msi_vector;
  m->sbl_addr   = sbl_addr;
  m->sbl_size   = sbl_size;
  m->table_addr = table_addr;
  m->table_size = table_size;
  m->seq        = seq & HOUJI_MHI_SEQ_MASK;
  if (!m->seq) m->seq = 1u;
  uint32_t ee = houji_mhi_boot_ee(m);
  if (ee != HoujiMhiEePbl && ee != HoujiMhiEeEdl) return houji_mhi_fail(m, HoujiMhiErrNotPbl);
  uint32_t st = m->io.rd(m->io.ctx, HOUJI_MHI_STATUS_OFF);
  m->state = (st >> HOUJI_MHI_STATE_SHIFT) & 0xffu;
  m->io.wr(m->io.ctx, m->bhi + HOUJI_BHI_INTVEC, msi_vector);
  if ((st & HOUJI_MHI_STATUS_SYSERR) || m->state == HoujiMhiStateSysErr) {
    m->io.wr(m->io.ctx, HOUJI_MHI_CTRL_OFF, HOUJI_MHI_CTRL_RESET);
    m->phase = HoujiMhiResetting;
    return m->phase;
  }
  return houji_mhi_start_sbl(m);
}

static inline uint32_t houji_mhi_start_image(HoujiMhiBoot *m) {
  m->seq = (m->seq + 1u) & HOUJI_MHI_SEQ_MASK;
  if (!m->seq) m->seq = 1u;
  m->io.wr(m->io.ctx, m->bhie + HOUJI_BHIE_TXVECADDR_HIGH, (uint32_t)(m->table_addr >> 32));
  m->io.wr(m->io.ctx, m->bhie + HOUJI_BHIE_TXVECADDR_LOW, (uint32_t)m->table_addr);
  m->io.wr(m->io.ctx, m->bhie + HOUJI_BHIE_TXVECSIZE, m->table_size);
  m->io.wr(m->io.ctx, m->bhie + HOUJI_BHIE_TXVECDB, m->seq);
  m->phase = HoujiMhiImageLoading;
  return m->phase;
}

static inline uint32_t houji_mhi_boot_step(HoujiMhiBoot *m) {
  if (m->phase == HoujiMhiIdle || m->phase == HoujiMhiDone ||
      m->phase == HoujiMhiFailed || m->phase == HoujiMhiNeedContexts) {
    return m->phase;
  }
  uint32_t st = m->io.rd(m->io.ctx, HOUJI_MHI_STATUS_OFF);
  if (st == 0xffffffffu) return m->phase;
  m->state = (st >> HOUJI_MHI_STATE_SHIFT) & 0xffu;
  if (m->phase == HoujiMhiResetting) {
    if (m->io.rd(m->io.ctx, HOUJI_MHI_CTRL_OFF) & HOUJI_MHI_CTRL_RESET) return m->phase;
    return houji_mhi_start_sbl(m);
  }
  uint32_t ee = houji_mhi_boot_ee(m);
  if (ee == HoujiMhiEeRddm) return houji_mhi_fail(m, HoujiMhiErrRddm);
  if ((st & HOUJI_MHI_STATUS_SYSERR) || m->state == HoujiMhiStateSysErr) {
    return houji_mhi_fail(m, HoujiMhiErrSysErr);
  }
  switch (m->phase) {
    case HoujiMhiSblLoading: {
      uint32_t bhi = m->io.rd(m->io.ctx, m->bhi + HOUJI_BHI_STATUS);
      m->last_status = bhi;
      if (bhi == 0xffffffffu) return m->phase;
      if ((bhi >> 30) == HOUJI_MHI_XFER_ERROR) {
        m->errcode = m->io.rd(m->io.ctx, m->bhi + HOUJI_BHI_ERRCODE);
        return houji_mhi_fail(m, HoujiMhiErrBhi);
      }
      if ((bhi >> 30) != HOUJI_MHI_XFER_SUCCESS) return m->phase;
      m->phase = HoujiMhiWaitReady;
      return houji_mhi_boot_step(m);
    }
    case HoujiMhiWaitReady:
      if ((m->io.rd(m->io.ctx, HOUJI_MHI_CTRL_OFF) & HOUJI_MHI_CTRL_RESET) ||
          !(st & HOUJI_MHI_STATUS_READY)) {
        return m->phase;
      }
      m->phase = HoujiMhiNeedContexts;
      return m->phase;
    case HoujiMhiWaitSbl:
      if (ee == HoujiMhiEeAmss || ee == HoujiMhiEeWfw) {
        m->phase = HoujiMhiDone;
        return m->phase;
      }
      if (ee != HoujiMhiEeSbl) return m->phase;
      return houji_mhi_start_image(m);
    case HoujiMhiImageLoading: {
      uint32_t tx = m->io.rd(m->io.ctx, m->bhie + HOUJI_BHIE_TXVECSTATUS);
      m->last_status = tx;
      if ((tx & HOUJI_MHI_SEQ_MASK) != m->seq) return m->phase;
      if ((tx >> 30) == HOUJI_MHI_XFER_ERROR) return houji_mhi_fail(m, HoujiMhiErrBhie);
      if ((tx >> 30) != HOUJI_MHI_XFER_SUCCESS) return m->phase;
      m->phase = HoujiMhiWaitMission;
      return houji_mhi_boot_step(m);
    }
    case HoujiMhiWaitMission:
      if (ee == HoujiMhiEeAmss || ee == HoujiMhiEeWfw) m->phase = HoujiMhiDone;
      return m->phase;
    default:
      return m->phase;
  }
}

static inline uint32_t houji_mhi_boot_contexts_done(HoujiMhiBoot *m) {
  if (m->phase != HoujiMhiNeedContexts) return houji_mhi_fail(m, HoujiMhiErrState);
  uint32_t ctrl = m->io.rd(m->io.ctx, HOUJI_MHI_CTRL_OFF);
  ctrl = (ctrl & ~(0xffu << HOUJI_MHI_STATE_SHIFT) & ~HOUJI_MHI_CTRL_RESET) |
         ((uint32_t)HoujiMhiStateM0 << HOUJI_MHI_STATE_SHIFT);
  m->io.wr(m->io.ctx, HOUJI_MHI_CTRL_OFF, ctrl);
  m->phase = HoujiMhiWaitSbl;
  return houji_mhi_boot_step(m);
}

static inline uint32_t houji_mhi_boot_timeout(HoujiMhiBoot *m) {
  if (m->phase == HoujiMhiIdle || m->phase == HoujiMhiDone || m->phase == HoujiMhiFailed) {
    return m->phase;
  }
  if (m->phase == HoujiMhiSblLoading) {
    m->errcode = m->io.rd(m->io.ctx, m->bhi + HOUJI_BHI_ERRCODE);
  }
  return houji_mhi_fail(m, HoujiMhiErrTimeout);
}

#ifdef __cplusplus
}
#endif

#endif /* HOUJI_WIFI_MHI_POLICY_H */
