#!/usr/bin/env python3
"""Host policy check for Houji Stage 2 Wi-Fi SMMU, DMA arena, and MHI BHI/BHIe boot (no hardware)."""
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
MHI_POLICY = ROOT / 'kernel/overlay/iokit/Kernel/houji-ufs-root/wifi/HoujiWifiMhiPolicy.h'
MHI_RUNTIME = ROOT / 'kernel/overlay/iokit/Kernel/houji-ufs-root/wifi/HoujiWifiMhi.inc'
PCIE_RUNTIME = ROOT / 'kernel/overlay/iokit/Kernel/houji-ufs-root/wifi/HoujiWifiPcie.inc'


def main():
    mhi_text = MHI_RUNTIME.read_text()
    pcie_text = PCIE_RUNTIME.read_text()

    # Static safety invariants
    assert 'HoujiWifiMhiPolicy.h' in mhi_text
    assert 'ArmSmmu4KBuild(' in mhi_text
    assert 'ArmSmmu4KAuditTables(' in mhi_text
    assert 'ArmSmmu4KCheckFaultedStreams' not in mhi_text, 'Must never scan invalid S2CRs on houji APPS SMMU'
    assert 'image/kiwi/amss20.bin' in mhi_text
    assert 'panic(' not in mhi_text, 'Stage 2 Wi-Fi runtime must never panic'
    assert 'HOUJI_PARF_BDF_TO_SID_TABLE' in pcie_text
    assert 'HOUJI_PARF_BDF_TO_SID_CFG' in pcie_text
    assert 'hwWifiRunStage2(' in pcie_text

    unit = '#include <assert.h>\n#include <stdint.h>\n#include <stdio.h>\n#include <stdlib.h>\n'
    unit += '#include ' + json.dumps(str(MHI_POLICY)) + '\n'
    unit += r'''
/* --- Fake APPS SMMU 0x15000000 model that traps invalid-SMR S2CR reads --- */
typedef struct {
  uint32_t regs[HOUJI_APPS_SMMU_MAP_BYTES / 4u];
  unsigned invalid_s2cr_reads;
} FakeSmmu;

static uint32_t smmu_rd32(void *ctx, uint32_t off) {
  FakeSmmu *s = (FakeSmmu *)ctx;
  assert((off & 3u) == 0u && off < HOUJI_APPS_SMMU_MAP_BYTES);
  if (off >= 0xc00u && off < 0xe00u) {
    unsigned idx = (off - 0xc00u) / 4u;
    if ((s->regs[(0x800u + 4u * idx) / 4u] & 0x80000000u) == 0u) {
      ++s->invalid_s2cr_reads;
    }
  }
  return s->regs[off / 4u];
}

static void smmu_wr32(void *ctx, uint32_t off, uint32_t val) {
  FakeSmmu *s = (FakeSmmu *)ctx;
  assert((off & 3u) == 0u && off < HOUJI_APPS_SMMU_MAP_BYTES);
  /* CB_FSR (offset 0x58 within any context bank page >= 0x80000) is W1C */
  if (off >= 0x80000u && (off & 0xfffu) == 0x58u) {
    s->regs[off / 4u] &= ~val;
    return;
  }
  s->regs[off / 4u] = val;
}

static uint64_t smmu_rd64(void *ctx, uint32_t off) {
  return (uint64_t)smmu_rd32(ctx, off) | ((uint64_t)smmu_rd32(ctx, off + 4u) << 32);
}

static void smmu_wr64(void *ctx, uint32_t off, uint64_t val) {
  smmu_wr32(ctx, off, (uint32_t)val);
  smmu_wr32(ctx, off + 4u, (uint32_t)(val >> 32));
}

/* --- Fake WCN7850 MHI/BHI/BHIe register model --- */
typedef struct {
  uint32_t mhi[0x2000u / 4u];
  unsigned sbl_db_writes;
  unsigned bhie_db_writes;
  unsigned m0_writes;
  uint32_t last_sbl_seq;
  uint32_t last_bhie_seq;
} FakeWcn;

static uint32_t wcn_rd(void *ctx, uint32_t reg) {
  FakeWcn *w = (FakeWcn *)ctx;
  assert((reg & 3u) == 0u && reg < sizeof(w->mhi));
  return w->mhi[reg / 4u];
}

static void wcn_wr(void *ctx, uint32_t reg, uint32_t val) {
  FakeWcn *w = (FakeWcn *)ctx;
  assert((reg & 3u) == 0u && reg < sizeof(w->mhi));
  w->mhi[reg / 4u] = val;
  if (reg == 0x100u + HOUJI_BHI_IMGTXDB) {
    ++w->sbl_db_writes;
    w->last_sbl_seq = val;
    /* Simulate PBL completing SBL DMA and setting READY=1 */
    w->mhi[(0x100u + HOUJI_BHI_STATUS) / 4u] = (HOUJI_MHI_XFER_SUCCESS << 30) | val;
    w->mhi[HOUJI_MHI_STATUS_OFF / 4u] = HOUJI_MHI_STATUS_READY;
  } else if (reg == HOUJI_MHI_CTRL_OFF && ((val >> HOUJI_MHI_STATE_SHIFT) & 0xffu) == HoujiMhiStateM0) {
    ++w->m0_writes;
    /* Simulate transition to SBL EE=1 & M0 state */
    w->mhi[(0x100u + HOUJI_BHI_EXECENV) / 4u] = HoujiMhiEeSbl;
    w->mhi[HOUJI_MHI_STATUS_OFF / 4u] = HOUJI_MHI_STATUS_READY | (HoujiMhiStateM0 << HOUJI_MHI_STATE_SHIFT);
  } else if (reg == 0x300u + HOUJI_BHIE_TXVECDB) {
    ++w->bhie_db_writes;
    w->last_bhie_seq = val;
    /* Simulate SBL completing BHIe full image and entering MISSION_MODE (EE=2) */
    w->mhi[(0x300u + HOUJI_BHIE_TXVECSTATUS) / 4u] = (HOUJI_MHI_XFER_SUCCESS << 30) | val;
    w->mhi[(0x100u + HOUJI_BHI_EXECENV) / 4u] = HoujiMhiEeAmss;
  }
}

int main(void) {
  /* 1. SM8650 BDF-to-SID CRC-8 (poly 0x07) */
  assert(houji_wifi_bdf_crc8(0x0000u) == 0x00u);
  uint8_t h0100 = houji_wifi_bdf_crc8(0x0100u);
  assert(h0100 == 0x15u); /* CRC8(0x01, 0x00; poly=0x07) == 0x15 */
  assert(houji_wifi_bdf_sid_entry(0x0100u, 1u, 0u) == 0x01000100u);

  /* 2. Safe APPS SMMU Stage-1 planner & programmer (never reads S2CR on invalid SMR) */
  FakeSmmu *smmu = (FakeSmmu *)calloc(1u, sizeof(FakeSmmu));
  assert(smmu != NULL);
  /* Match houji APPS SMMU geometry: count=128, banks=64, pages=128 (NUMPAGENDXB=6 -> 2^7=128), pa_bits=40 (code=2) */
  smmu->regs[0x20u / 4u] = (1u << 30) | 128u;
  smmu->regs[0x24u / 4u] = (6u << 28) | (0u << 16) | 64u;
  smmu->regs[0x28u / 4u] = (1u << 12) | (5u << 8) | (2u << 4);
  /* Pretend UFS owns slot 0 -> bank 63 (banks - 1) */
  smmu->regs[0x800u / 4u] = 0x80000000u | 0x0100u;
  smmu->regs[0xc00u / 4u] = 63u;

  HoujiWifiSmmuIo sio = { smmu, smmu_rd32, smmu_wr32, smmu_rd64, smmu_wr64 };
  HoujiWifiSmmuPlan plan = houji_wifi_plan_smmu_s1(&sio, HOUJI_WIFI_SID_RC0, HOUJI_WIFI_SID_WCN7850);
  assert(plan.error == NULL);
  assert(smmu->invalid_s2cr_reads == 0u);
  assert(plan.slot_rc == 1u && plan.slot_ep == 2u);
  assert(plan.bank == 62u); /* Leaves bank 63 untouched for UFS */
  assert(plan.pa_bits == 40u);

  const char *perr = houji_wifi_program_smmu_s1(
    &sio, &plan, HOUJI_WIFI_SID_RC0, HOUJI_WIFI_SID_WCN7850, 0x880000000ULL, HOUJI_WIFI_SMMU_ASID);
  assert(perr == NULL);
  assert(smmu->regs[(0x1000u + 4u * 62u) / 4u] == 0x10000u);
  assert(smmu->regs[(0x1800u + 4u * 62u) / 4u] == 1u);
  assert(smmu->regs[(0x800u + 4u * 1u) / 4u] == (0x80000000u | HOUJI_WIFI_SID_RC0));
  assert(smmu->regs[(0x800u + 4u * 2u) / 4u] == (0x80000000u | HOUJI_WIFI_SID_WCN7850));
  assert(smmu->regs[(0xc00u + 4u * 1u) / 4u] == 62u);
  assert(smmu->regs[(0xc00u + 4u * 2u) / 4u] == 62u);

  /* Re-planning reuses both slots and bank 62 without touching UFS bank 63 */
  HoujiWifiSmmuPlan plan2 = houji_wifi_plan_smmu_s1(&sio, HOUJI_WIFI_SID_RC0, HOUJI_WIFI_SID_WCN7850);
  assert(plan2.error == NULL && plan2.reuse_rc == 1u && plan2.reuse_ep == 1u && plan2.reuse_bank == 1u);
  assert(plan2.bank == 62u && smmu->invalid_s2cr_reads == 0u);
  free(smmu);

  /* 3. Power-of-two aligned 32-bit IOVA arena allocator */
  uint8_t *backing = (uint8_t *)calloc(1u, HOUJI_WIFI_DMA_ARENA_BYTES);
  assert(backing != NULL);
  HoujiWifiArena arena;
  assert(houji_wifi_arena_init(&arena, backing, HOUJI_WIFI_DMA_IOVA_BASE, HOUJI_WIFI_DMA_ARENA_BYTES) == 1);
  uint64_t amss_iova = 0, ctx_iova = 0, tbl_iova = 0;
  void *amss = houji_wifi_arena_alloc(&arena, 6365248u, &amss_iova);
  assert(amss != NULL && (amss_iova & ((8u * 1024u * 1024u) - 1u)) == 0ULL);
  assert(amss_iova == 0x10800000ULL);
  void *ctx = houji_wifi_arena_alloc(&arena, 16384u, &ctx_iova);
  assert(ctx != NULL && (ctx_iova & 0x3fffULL) == 0ULL && ctx_iova >= 0x10004000ULL);
  void *tbl = houji_wifi_arena_alloc(&arena, 512u, &tbl_iova);
  assert(tbl != NULL && (tbl_iova & 63ULL) == 0ULL && tbl_iova >= 0x10001000ULL);
  houji_wifi_arena_free(&arena, tbl);
  houji_wifi_arena_free(&arena, ctx);
  houji_wifi_arena_free(&arena, amss);
  assert(arena.used_bytes == HOUJI_WIFI_MSI_SINK_BYTES && arena.count == 1u);

  /* 4. WCN7850 BAR0 static window helper */
  uint32_t win = 0;
  assert(houji_wcn7850_bar_offset(0x3008u, &win) == 0x3008u && win == 0xffffffffu);
  assert(houji_wcn7850_bar_offset(0x1e081b0u, &win) == 0x881b0u && win == (0x40000000u | ((0x1e081b0u >> 19) & 0x3fu)));
  assert(houji_wcn7850_bar_offset(0x1e0e148u, &win) == 0x48u);

  /* 5. BHIe segment table & full simulated PBL -> SBL -> MISSION_MODE MHI boot */
  HoujiBhieEntry segs[HOUJI_WCN7850_MAX_SEGMENTS];
  uint32_t nsegs = houji_mhi_bhie_table(segs, HOUJI_WCN7850_MAX_SEGMENTS, 0x10800000ULL, 6365248u, HOUJI_WCN7850_SEG_BYTES);
  assert(nsegs == 13u);
  assert(segs[0].address == 0x10800000ULL && segs[0].size == 524288u);
  assert(segs[12].address == 0x10800000ULL + 12ULL * 524288ULL && segs[12].size == 6365248u - 12u * 524288u);

  FakeWcn *wcn = (FakeWcn *)calloc(1u, sizeof(FakeWcn));
  assert(wcn != NULL);
  wcn->mhi[HOUJI_MHI_REGLEN_OFF / 4u] = 0x1000u;
  wcn->mhi[HOUJI_MHI_VER_OFF / 4u]    = 0x01000000u;
  wcn->mhi[HOUJI_MHI_ERDB_OFF / 4u]   = 0x0800u;
  wcn->mhi[HOUJI_MHI_BHI_OFF / 4u]    = 0x0100u;
  wcn->mhi[HOUJI_MHI_BHIE_OFF / 4u]   = 0x0300u;
  wcn->mhi[(0x100u + HOUJI_BHI_EXECENV) / 4u] = HoujiMhiEePbl;

  HoujiMhiIo mio = { wcn, wcn_rd, wcn_wr, 0x2000u };
  HoujiMhiBoot boot;
  assert(houji_mhi_boot_open(&boot, &mio) == 0);
  houji_mhi_program_contexts(&mio, backing + 0x4000u, 0x10004000ULL, 16384u, NULL);
  uint32_t phase = houji_mhi_boot_begin(&boot, 0u, 0x10800000ULL, HOUJI_WCN7850_SBL_BYTES,
                                        0x10001000ULL, nsegs * (uint32_t)sizeof(HoujiBhieEntry), 1u);
  assert(phase == HoujiMhiSblLoading && wcn->sbl_db_writes == 1u);
  phase = houji_mhi_boot_step(&boot);
  assert(phase == HoujiMhiNeedContexts);
  houji_mhi_program_contexts(&mio, backing + 0x4000u, 0x10004000ULL, 16384u, NULL);
  phase = houji_mhi_boot_contexts_done(&boot);
  assert(wcn->m0_writes == 1u && wcn->bhie_db_writes == 1u);
  assert(phase == HoujiMhiImageLoading);
  phase = houji_mhi_boot_step(&boot);
  assert(phase == HoujiMhiDone && boot.ee == HoujiMhiEeAmss && boot.error == HoujiMhiErrNone);

  free(wcn);
  free(backing);
  puts("PASS: Stage 2 Wi-Fi SMMU, BDF-to-SID CRC8, DMA arena, and MHI BHI/BHIe checks verified; no hardware");
  return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix='houji-wifi-mhi-') as temporary:
        src = Path(temporary) / 'wifi_mhi.c'
        exe = Path(temporary) / 'wifi_mhi'
        src.write_text(unit)
        subprocess.run(['clang', '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', str(src), '-o', str(exe)], check=True)
        subprocess.run([str(exe)], check=True, timeout=10)


if __name__ == '__main__':
    main()
