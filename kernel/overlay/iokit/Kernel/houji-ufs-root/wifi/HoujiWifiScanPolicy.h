// SPDX-License-Identifier: BSD-2-Clause-Patent
// Held-BSS staleness and settled-link scan throttling policy for Houji en0/IO80211Interface.
#ifndef HOUJI_WIFI_SCAN_POLICY_H
#define HOUJI_WIFI_SCAN_POLICY_H
#include <stddef.h>
#include <stdint.h>
#ifndef __cplusplus
#include <stdbool.h>
#endif

#define HOUJI_WIFI_HELD_MS 60000u
#define HOUJI_WIFI_LINK_SETTLE_MS 15000u
#define HOUJI_WIFI_RESCAN_MS 20000u
#define HOUJI_WIFI_AIR_CHANNELS 64u

struct houji_wifi_air {
  uint64_t every_ms;
  uint32_t mhz[HOUJI_WIFI_AIR_CHANNELS];
  uint64_t at_ms[HOUJI_WIFI_AIR_CHANNELS];
};
enum houji_wifi_link { HoujiWifiLinkNone, HoujiWifiLinkJoining, HoujiWifiLinkUp };

static inline bool houji_wifi_held_stale(uint32_t age_ms) { return age_ms > HOUJI_WIFI_HELD_MS; }

static inline void houji_wifi_air_mark(struct houji_wifi_air *air, const uint32_t *mhz,
                                       size_t count, uint64_t now_ms) {
  if (!count) { air->every_ms = now_ms; return; }
  for (size_t i = 0; i < count; ++i) {
    size_t place = 0;
    for (size_t slot = 0; slot < HOUJI_WIFI_AIR_CHANNELS; ++slot) {
      if (air->mhz[slot] == mhz[i]) { place = slot; break; }
      if (air->at_ms[slot] < air->at_ms[place]) place = slot;
    }
    air->mhz[place] = mhz[i];
    air->at_ms[place] = now_ms;
  }
}

static inline bool houji_wifi_air_recent(uint64_t at_ms, uint64_t now_ms) {
  return at_ms && now_ms >= at_ms && now_ms - at_ms < HOUJI_WIFI_RESCAN_MS;
}

static inline bool houji_wifi_scan_on_air(const struct houji_wifi_air *air,
                                          enum houji_wifi_link link, uint64_t link_ms,
                                          bool held, const uint32_t *mhz, size_t count,
                                          uint64_t now_ms) {
  if (link == HoujiWifiLinkNone || !held) return true;
  if (link == HoujiWifiLinkJoining || link_ms < HOUJI_WIFI_LINK_SETTLE_MS) return false;
  if (houji_wifi_air_recent(air->every_ms, now_ms)) return false;
  if (!count) return true;
  for (size_t i = 0; i < count; ++i) {
    size_t slot = 0;
    while (slot < HOUJI_WIFI_AIR_CHANNELS && air->mhz[slot] != mhz[i]) ++slot;
    if (slot == HOUJI_WIFI_AIR_CHANNELS || !houji_wifi_air_recent(air->at_ms[slot], now_ms)) return true;
  }
  return false;
}

#endif /* HOUJI_WIFI_SCAN_POLICY_H */
