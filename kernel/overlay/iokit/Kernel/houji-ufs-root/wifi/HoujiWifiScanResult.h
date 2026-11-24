// SPDX-License-Identifier: BSD-2-Clause-Patent
// Apple80211 scan result record (0x8e8 bytes) and continuous-clock timestamp helper.
#ifndef HOUJI_WIFI_SCAN_RESULT_H
#define HOUJI_WIFI_SCAN_RESULT_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define HOUJI_WIFI_SCAN_RESULT_BYTES 0x8e8u
#define HOUJI_WIFI_SCAN_ELEMENTS 0x8cu
#define HOUJI_WIFI_SCAN_ELEMENTS_BYTES 2048u
#define HOUJI_WIFI_SCAN_TIMESTAMP 0x8d0u

struct houji_wifi_channel { uint32_t version, channel, flags; };
struct houji_wifi_scan_result {
  uint32_t version;
  struct houji_wifi_channel ch;
  uint16_t noise_known;
  int16_t noise, snr, rssi;
  uint16_t beacon_interval, capability;
  uint8_t bssid[6];
  uint8_t rate_count, unused0;
  uint32_t rates[15];
  uint8_t ssid_length, ssid[32], unused1[3];
  uint32_t age_ms;
  uint8_t flags, unused2;
  uint16_t elements_length;
  uint8_t elements[HOUJI_WIFI_SCAN_ELEMENTS_BYTES];
  uint8_t unused3[68];
  uint64_t timestamp;
  uint8_t unused4[16];
};

static inline uint64_t houji_wifi_scan_timestamp(uint64_t now_ns, uint32_t age_ms) {
  const uint64_t age_ns = (uint64_t)age_ms * 1000000ULL;
  return now_ns > age_ns ? now_ns - age_ns : 0ULL;
}

static inline uint16_t houji_wifi_scan_elements_room(uint32_t request_bytes) {
  if (request_bytes <= HOUJI_WIFI_SCAN_ELEMENTS) return 0u;
  const uint32_t room = request_bytes - HOUJI_WIFI_SCAN_ELEMENTS;
  return (uint16_t)(room < HOUJI_WIFI_SCAN_ELEMENTS_BYTES ? room : HOUJI_WIFI_SCAN_ELEMENTS_BYTES);
}

static inline void houji_wifi_scan_result_stamp(struct houji_wifi_scan_result *r,
                                                const uint8_t *elements, size_t length,
                                                uint32_t age_ms, uint64_t now_ns,
                                                uint32_t request_bytes) {
  const uint16_t room = houji_wifi_scan_elements_room(request_bytes);
  r->age_ms = age_ms;
  r->timestamp = houji_wifi_scan_timestamp(now_ns, age_ms);
  r->elements_length = (uint16_t)(length < room ? length : room);
  if (r->elements_length && elements) {
    memcpy(r->elements, elements, r->elements_length);
  }
}

#endif /* HOUJI_WIFI_SCAN_RESULT_H */
