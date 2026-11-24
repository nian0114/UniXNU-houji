// SPDX-License-Identifier: BSD-2-Clause-Patent
// Apple80211 scan request parsing and card capability bitmap helpers for Houji en0/IO80211Interface.
#ifndef HOUJI_WIFI_SCAN_H
#define HOUJI_WIFI_SCAN_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define HOUJI_WIFI_CAPS_BYTES 12u
#define HOUJI_WIFI_CAP_NAMED_SCAN 22u
#define HOUJI_WIFI_CAP_SCAN_DONE_EVENT 46u

static inline void houji_wifi_caps_fill(uint8_t caps[HOUJI_WIFI_CAPS_BYTES]) {
  static const uint8_t has[] = {2, 3, 6, 9, 10, 14, 17, 19, HOUJI_WIFI_CAP_NAMED_SCAN, HOUJI_WIFI_CAP_SCAN_DONE_EVENT};
  memset(caps, 0, HOUJI_WIFI_CAPS_BYTES);
  for (size_t i = 0; i < sizeof(has); ++i) caps[has[i] / 8] |= (uint8_t)(1u << (has[i] % 8));
}

#define HOUJI_WIFI_SCAN_MULTIPLE_BYTES 0x14e8u
#define HOUJI_WIFI_SCAN_SSID_COUNT 0x8u
#define HOUJI_WIFI_SCAN_SSIDS 0xcu
#define HOUJI_WIFI_SCAN_SSID_ENTRY 40u
#define HOUJI_WIFI_SCAN_SSID_MAX 10u
#define HOUJI_WIFI_SCAN_TYPE 0x200u
#define HOUJI_WIFI_SCAN_TYPE_CACHED 3u

struct houji_wifi_scan_multiple {
  uint32_t named;
  uint32_t wildcard;
  uint32_t scan_type;
  uint8_t length[HOUJI_WIFI_SCAN_SSID_MAX];
  uint8_t ssid[HOUJI_WIFI_SCAN_SSID_MAX][32];
};

static inline uint32_t houji_wifi_scan_u32(const uint8_t *at) {
  uint32_t v;
  memcpy(&v, at, 4);
  return v;
}

static inline int houji_wifi_scan_multiple_parse(const uint8_t *req, size_t size,
                                                 struct houji_wifi_scan_multiple *out) {
  memset(out, 0, sizeof(*out));
  if (!req || size < HOUJI_WIFI_SCAN_TYPE + 4u) return -1;
  const uint32_t count = houji_wifi_scan_u32(req + HOUJI_WIFI_SCAN_SSID_COUNT);
  if (count > HOUJI_WIFI_SCAN_SSID_MAX) return -1;
  for (uint32_t i = 0; i < count; ++i) {
    const uint8_t *entry = req + HOUJI_WIFI_SCAN_SSIDS + i * HOUJI_WIFI_SCAN_SSID_ENTRY;
    const uint32_t length = houji_wifi_scan_u32(entry + 4);
    if (length > 32) return -1;
    if (!length) { out->wildcard = 1; continue; }
    out->length[out->named] = (uint8_t)length;
    memcpy(out->ssid[out->named], entry + 8, length);
    ++out->named;
  }
  out->scan_type = houji_wifi_scan_u32(req + HOUJI_WIFI_SCAN_TYPE);
  return 0;
}

static inline void houji_wifi_scan_multiple_target(const struct houji_wifi_scan_multiple *s,
                                                   const uint8_t **ssid, uint32_t *length) {
  if (s->named == 1 && !s->wildcard) { *ssid = s->ssid[0]; *length = s->length[0]; return; }
  *ssid = NULL;
  *length = 0;
}

#define HOUJI_WIFI_SCAN_ONE_CHANNEL_COUNT 0x44u
#define HOUJI_WIFI_SCAN_ONE_CHANNELS 0x48u
#define HOUJI_WIFI_SCAN_MULTIPLE_CHANNEL_COUNT 0x210u
#define HOUJI_WIFI_SCAN_MULTIPLE_CHANNELS 0x214u
#define HOUJI_WIFI_SCAN_CHANNEL_ENTRY 12u
#define HOUJI_WIFI_SCAN_CHANNELS_READ 64u
#define HOUJI_WIFI_SCAN_FREQUENCIES 32u
#define HOUJI_WIFI_CHANNEL_2GHZ 0x8u
#define HOUJI_WIFI_CHANNEL_5GHZ 0x10u

static inline uint32_t houji_wifi_channel_mhz(uint32_t channel, uint32_t flags) {
  if (flags & HOUJI_WIFI_CHANNEL_2GHZ) return channel == 14 ? 2484 : (channel >= 1 && channel <= 13 ? 2407 + 5 * channel : 0);
  if (flags & HOUJI_WIFI_CHANNEL_5GHZ) return (channel >= 1 && channel <= 196) ? 5000 + 5 * channel : 0;
  return 0;
}

static inline uint32_t houji_wifi_scan_frequencies(const uint8_t *req, size_t size,
                                                   uint32_t count_at, uint32_t list_at,
                                                   uint32_t mhz[HOUJI_WIFI_SCAN_FREQUENCIES]) {
  if (!req || size < (size_t)count_at + 4u) return 0;
  const uint32_t count = houji_wifi_scan_u32(req + count_at);
  if (!count || count > HOUJI_WIFI_SCAN_CHANNELS_READ ||
      size < (size_t)list_at + (size_t)count * HOUJI_WIFI_SCAN_CHANNEL_ENTRY) return 0;
  uint32_t n = 0;
  for (uint32_t i = 0; i < count; ++i) {
    const uint8_t *entry = req + list_at + i * HOUJI_WIFI_SCAN_CHANNEL_ENTRY;
    const uint32_t f = houji_wifi_channel_mhz(houji_wifi_scan_u32(entry + 4), houji_wifi_scan_u32(entry + 8));
    if (!f) continue;
    uint32_t seen = 0;
    for (uint32_t k = 0; k < n; ++k) seen |= (mhz[k] == f);
    if (seen) continue;
    if (n == HOUJI_WIFI_SCAN_FREQUENCIES) return 0;
    mhz[n++] = f;
  }
  return n;
}

#endif /* HOUJI_WIFI_SCAN_H */
