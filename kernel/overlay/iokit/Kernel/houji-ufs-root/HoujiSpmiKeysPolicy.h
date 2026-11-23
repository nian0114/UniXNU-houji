// SPDX-License-Identifier: MIT
// Pure SPMI v7 observer poller policy/decoding helpers for Xiaomi 14
// (SM8650 / PMK8550 / PM8550). Host-testable with no IOKit dependencies.
#ifndef HOUJI_SPMI_KEYS_POLICY_H
#define HOUJI_SPMI_KEYS_POLICY_H

#include <stdint.h>

// SM8650 SPMI v7 PMIC arbiter limits (bus 0 has 0x380=896 APIDs, bus 1 has
// 0x80=128 APIDs; core 0x2000..0x2fff, cnfg 0x0..0xfff, obs EE0 0x0..0x7fff
// all span 1024 APIDs).
#define HOUJI_SPMI_MAX_APIDS      1024u
#define HOUJI_SPMI_OWNER_MASK     0x0fu
#define HOUJI_SPMI_OBS_STRIDE     0x20u
#define HOUJI_SPMI_PPID_PON       0x013u
#define HOUJI_SPMI_PPID_VOL_UP    0x18du
#define HOUJI_SPMI_REG_RT_STS     0x10u
#define HOUJI_SPMI_STATUS_DONE    0x01u
#define HOUJI_SPMI_STATUS_ERR     0x0eu
#define HOUJI_SPMI_APID_NONE      0xffffu

static inline int houji_spmi_v7_valid(uint32_t ver, uint32_t features, unsigned *out_count) {
  unsigned count = features & 0x7ffu;
  if ((ver >> 28) != 7u || count == 0u) return 0;
  if (count > HOUJI_SPMI_MAX_APIDS) count = HOUJI_SPMI_MAX_APIDS;
  if (out_count) *out_count = count;
  return 1;
}

static inline uint16_t houji_spmi_ppid_from_map(uint32_t map_word) {
  if (!map_word) return HOUJI_SPMI_APID_NONE;
  return (uint16_t)((map_word >> 8) & 0xfffu);
}

static inline uint8_t houji_spmi_owner_from_cnfg(uint32_t cnfg_word) {
  return (uint8_t)(cnfg_word & HOUJI_SPMI_OWNER_MASK);
}

static inline int houji_spmi_should_pick_apid(uint16_t current_apid, uint8_t owner) {
  return current_apid == HOUJI_SPMI_APID_NONE || owner == 0u;
}

static inline uint32_t houji_spmi_obs_offset(uint16_t apid) {
  return HOUJI_SPMI_OBS_STRIDE * (uint32_t)apid;
}

static inline uint32_t houji_spmi_ext_readl_cmd(uint8_t reg) {
  return (1u << 27) | ((uint32_t)reg << 4);
}

// Returns 0 while pending (st == 0), 1 on clean DONE, -1 on any error status.
static inline int houji_spmi_obs_status(uint32_t st) {
  if (st == 0u) return 0;
  if ((st & HOUJI_SPMI_STATUS_ERR) || !(st & HOUJI_SPMI_STATUS_DONE)) return -1;
  return 1;
}

static inline void houji_spmi_decode_buttons(uint8_t pon_rt, uint8_t vol_up_rt, int out[3]) {
  out[0] = (pon_rt & 0x80u) ? 1 : 0;    // Power (pon_hlos INT_RT_STS bit 7)
  out[1] = (vol_up_rt & 0x01u) ? 0 : 1; // Volume Up (pm8550 gpio6, active-low)
  out[2] = (pon_rt & 0x40u) ? 1 : 0;    // Volume Down (pon_hlos INT_RT_STS bit 6)
}

#endif
