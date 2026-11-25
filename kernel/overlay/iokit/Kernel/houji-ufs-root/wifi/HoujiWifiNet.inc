// SPDX-License-Identifier: BSD-2-Clause-Patent
// Stage 4 Xiaomi 14 (houji / iOS 16) network interface (en0 / IO80211Interface)
// bridging Apple80211 ioctls, BSD Ethernet/BPF/DHCP frames, and KEV events to Ath12kWifi (nw_abi.h).
// Note: IONetworkStack & IONetworkStackUserClient are already provided by HoujiNetworkStack.cpp.
#include <sys/kern_event.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_media.h>
#include <net/if_ether.h>
#include <net/kpi_interface.h>
extern "C" {
#include <net/bpf.h>
}
#include <net/if_types.h>
#include <netinet/in.h>
#include <sys/kpi_mbuf.h>
#include <kern/thread_call.h>
#include <sys/systm.h>
#include "HoujiWifiScan.h"
#include "HoujiWifiScanResult.h"
#include "HoujiWifiScanPolicy.h"

static_assert(HOUJI_WIFI_SCAN_FREQUENCIES == NW_WIFI_SCAN_FREQUENCIES_MAX, "scan frequency count");

#define HOUJI_SIOCSA80211 0x802869c8UL
#define HOUJI_SIOCGA80211 0xc02869c9UL

extern "C" int houji_kev_post(struct kev_msg *) __asm__("_kev_post_msg");
static void hwWifiWakeWorker(void);

class IO80211Controller : public IOService { OSDeclareDefaultStructors(IO80211Controller); };
OSDefineMetaClassAndStructors(IO80211Controller, IOService);
class IONetworkInterface : public IOService { OSDeclareDefaultStructors(IONetworkInterface); };
OSDefineMetaClassAndStructors(IONetworkInterface, IOService);
class IO80211Interface : public IONetworkInterface {
  OSDeclareDefaultStructors(IO80211Interface);
 public:
  IOReturn newUserClient(task_t, void *, UInt32 type, OSDictionary *, IOUserClient **) APPLE_KEXT_OVERRIDE {
    static unsigned said;
    if (said++ < 4) IOLog("HOUJI WIFI NET: user client type %u -> unsupported (ioctl path)\n", (unsigned)type);
    return kIOReturnUnsupported;
  }
};
OSDefineMetaClassAndStructors(IO80211Interface, IONetworkInterface);

namespace {

struct houji_a80211req {
  char req_if_name[16];
  int32_t req_type;
  int32_t req_val;
  uint32_t req_len;
  uint32_t req_kernel;
  user_addr_t req_data;
};
static_assert(sizeof(houji_a80211req) == 40 && __builtin_offsetof(houji_a80211req, req_data) == 32, "a80211req layout");

enum {
  kHwSsid = 1, kHwAuthType = 2, kHwCipherKey = 3, kHwChannel = 4, kHwPowerSave = 5,
  kHwTxPower = 7, kHwRate = 8, kHwBssid = 9, kHwScanReq = 10, kHwScanResult = 11,
  kHwCardCaps = 12, kHwState = 13, kHwPhyMode = 14, kHwOpMode = 15, kHwRssi = 16,
  kHwNoise = 17, kHwPower = 19, kHwAssociate = 20, kHwAssociateResult = 21,
  kHwDisassociate = 22, kHwSupportedChannels = 27, kHwLocale = 28, kHwDeauth = 29,
  kHwDriverVersion = 43, kHwHardwareVersion = 44, kHwCountryCode = 51,
  kHwScanReqMultiple = 86, kHwScanCacheClear = 90, kHwCurrentNetwork = 103,
  kHwHwSupportedChannels = 254, kHwAbortScan = 382,
};
enum { kHwEvPower = 1, kHwEvSsid = 2, kHwEvBssid = 3, kHwEvLink = 4, kHwEvAssocDone = 9, kHwEvScanDone = 10 };
enum { kHwAssocPending = 0, kHwAssocOk = 1, kHwAssocFailed = 2, kHwAssocTimeout = 9, kHwAssocBadKey = 21 };

// iOS 16 IO80211 reads this after the 16-byte interface name in the KEV payload.
struct hw_assoc_event16 {
  uint8_t attempts[3][44];
  uint32_t status;
};
static_assert(sizeof(hw_assoc_event16) == 136 && __builtin_offsetof(hw_assoc_event16, status) == 0x84,
              "iOS 16 association event layout");

struct hw_assoc_event27 {
  uint8_t attempts[10][52];
  uint32_t reserved[2], reason, result, has_result;
};
struct hw_channels_list { uint32_t version, count; houji_wifi_channel list[401]; uint32_t unused; };
struct hw_assoc_params {
  uint32_t ssid_length; uint8_t ssid[32]; uint8_t bssid[6], unused[2];
  uint32_t key_version, key_length, key_cipher; uint16_t key_flags, key_index; uint8_t key[64];
};
struct hw_assoc_req { uint32_t version; uint16_t mode, auth_lower, auth_upper, unused; hw_assoc_params network; uint8_t rest[0x250 - 0x88]; };
struct hw_assoc_req27 { uint32_t version; uint16_t mode, unused; uint32_t auth_lower, auth_upper; hw_assoc_params network; uint8_t rest[0x290 - 0x8c]; };
struct hw_link_event { uint8_t down, unused0[3]; int32_t rssi; uint16_t snr, noise; uint8_t unused1[4]; uint8_t involuntary, unused2[3]; uint32_t reason, subreason; uint8_t unused3[4]; };

static ifnet_t gHwIf;
static uint8_t gHwMac[6];
static bool gHwPower = true;
static bool gHwLinkSuppressed;
static bool gHwKeyed;
static bool gHwAssocModern;
static bool gHwJoinPending;
static int gHwAssocResult = kHwAssocPending;
static unsigned gHwScanCursor, gHwScanning;
static houji_wifi_air gHwAir;
static uint64_t gHwLinkUpMs;
static thread_call_t gHwCachedScan;
static mbuf_t gHwRxHead, gHwRxTail, gHwRxSpare;
static uint32_t gHwRxPendingPkts, gHwRxPendingBytes, gHwRxFrames, gHwRxErrors, gHwTxFrames, gHwTxRefused;
static uint32_t gHwIoctlCount;
struct HwIoctlLog { int32_t type; uint8_t isSet; uint16_t len; int16_t ret; };
static HwIoctlLog gHwIoctlHist[16];
static uint32_t gHwIoctlHistN;
struct HwWifiActionLog {
  uint32_t requests;
  uint64_t lastIoctl;
};
static HwWifiActionLog gHwScanAction, gHwJoinAction;
static uint64_t gHwJoinAuth;
static uint32_t gHwJoinKeyInfo;
static uint32_t gHwJoinBssMatch;
static uint32_t gHwJoinCompletions;
static int gHwLastJoinResult;
static uint32_t gHwLastScanArgs;
static uint8_t gHwScanFilterSsid[32];
static uint8_t gHwScanFilterLen;

static bool hwNetSsidBlank(const uint8_t *ssid, size_t len) {
  if (!len || !ssid) return true;
  for (size_t i = 0; i < len; ++i) {
    if (ssid[i] != 0u) return false;
  }
  return true;
}

static bool hwNetShadowedHiddenBeacon(const nw_bss_info &b, int count) {
  if (!hwNetSsidBlank(b.ssid, b.ssid_len)) return false;
  nw_bss_info other = {};
  for (int i = 0; i < count; ++i) {
    if (nw_wifi_bss_get(i, &other) || houji_wifi_held_stale(other.age_ms)) continue;
    if (!hwNetSsidBlank(other.ssid, other.ssid_len) && !memcmp(other.bssid, b.bssid, 6)) {
      return true;
    }
  }
  return false;
}

static uint64_t hwNetContMs(void) {
  uint64_t ns = 0;
  absolutetime_to_nanoseconds(mach_continuous_time(), &ns);
  return ns / 1000000ULL;
}

static void hwNetPostEv(uint32_t code, const void *payload, size_t length) {
  char name[16] = "en0";
  struct kev_msg msg;
  memset(&msg, 0, sizeof(msg));
  msg.vendor_code = KEV_VENDOR_APPLE;
  msg.kev_class = 6;
  msg.kev_subclass = 1;
  msg.event_code = code;
  msg.dv[0].data_length = sizeof(name);
  msg.dv[0].data_ptr = name;
  msg.dv[1].data_length = (uint32_t)length;
  msg.dv[1].data_ptr = const_cast<void *>(payload);
  (void)houji_kev_post(&msg);
}

static void hwNetPostLink(bool up) {
  gHwLinkUpMs = up ? hwNetContMs() : 0ULL;
  if (!gHwIf) return;
  ifnet_set_flags(gHwIf, up ? IFF_RUNNING : 0, IFF_RUNNING);
  struct { struct net_event_data data; } payload;
  memset(&payload, 0, sizeof(payload));
  payload.data.if_family = IFNET_FAMILY_ETHERNET;
  payload.data.if_unit = 0;
  snprintf(payload.data.if_name, sizeof(payload.data.if_name), "en");
  struct kev_msg msg;
  memset(&msg, 0, sizeof(msg));
  msg.vendor_code = KEV_VENDOR_APPLE;
  msg.kev_class = KEV_NETWORK_CLASS;
  msg.kev_subclass = KEV_DL_SUBCLASS;
  msg.event_code = up ? KEV_DL_LINK_ON : KEV_DL_LINK_OFF;
  msg.dv[0].data_length = sizeof(payload);
  msg.dv[0].data_ptr = &payload;
  (void)houji_kev_post(&msg);
}

static void hwNetPostLinkDown(bool involuntary, int reason) {
  hwNetPostLink(false);
  hw_link_event ev = {};
  ev.down = 1;
  ev.involuntary = involuntary ? 1 : 0;
  ev.reason = (uint32_t)reason;
  hwNetPostEv(kHwEvLink, &ev, sizeof(ev));
  hwNetPostEv(kHwEvSsid, nullptr, 0);
  hwNetPostEv(kHwEvBssid, nullptr, 0);
}

static void hwNetPostAssocResult(void) {
  const uint32_t result = (uint32_t)__atomic_load_n(&gHwAssocResult, __ATOMIC_ACQUIRE);
  nw_wifi_status cur = {};
  nw_wifi_status_get(&cur);
  if (__atomic_load_n(&gHwAssocModern, __ATOMIC_RELAXED)) {
    hw_assoc_event27 ev = {};
    ev.result = result;
    ev.has_result = 1u;
    memcpy(ev.attempts[0], cur.bssid, 6);
    hwNetPostEv(kHwEvAssocDone, &ev, sizeof(ev));
  } else {
    hw_assoc_event16 ev = {};
    // Status 1000 through 1010 carries result 1 through 11. The result
    // ioctl supplies the full code when this event field cannot carry it.
    if (result >= 1u && result <= 11u) ev.status = 999u + result;
    memcpy(ev.attempts[0], cur.bssid, 6);
    hwNetPostEv(kHwEvAssocDone, &ev, sizeof(ev));
  }
}

static void hwNetDisconnectUser(void) {
  bool pending = __atomic_exchange_n(&gHwJoinPending, false, __ATOMIC_ACQ_REL);
  gHwLinkSuppressed = true;
  __atomic_store_n(&gHwAssocResult, kHwAssocFailed, __ATOMIC_RELEASE);
  nw_wifi_disconnect();
  hwWifiWakeWorker();
  hwNetPostLinkDown(false, 0);
  if (pending) hwNetPostAssocResult();
}

static int hwNetDrainDisconnect(void) {
  hwNetDisconnectUser();
  for (unsigned w = 0; w < 2000u; w += 10u) {
    nw_wifi_status cur = {};
    nw_wifi_status_get(&cur);
    if (cur.state < NW_STA_AUTH) return 0;
    hwWifiSleepMs(10);
  }
  return ETIMEDOUT;
}

static void hwNetVisibleStatus(nw_wifi_status &st) {
  nw_wifi_status_get(&st);
  if (!gHwPower || gHwLinkSuppressed) {
    st.state = NW_STA_IDLE;
    st.ssid_len = 0;
    memset(st.ssid, 0, sizeof(st.ssid));
    memset(st.bssid, 0, sizeof(st.bssid));
    st.freq_mhz = 0;
    st.signal_dbm = 0;
  }
}

static void hwNetOnScanDone(void) {
  __atomic_store_n(&gHwScanning, 0u, __ATOMIC_RELEASE);
  gHwScanCursor = 0;
  hwWifiSetStage(HOUJI_WIFI_STAGE_SCAN_DONE);
  hwNetPostEv(kHwEvScanDone, nullptr, 0);
  IOLog("HOUJI WIFI NET: scan done bss=%d\n", nw_wifi_bss_count());
}

static void hwNetCachedScanDone(thread_call_param_t, thread_call_param_t) {
  hwNetOnScanDone();
}

static void hwNetOnConnectDone(int result) {
  if (!gHwPower || gHwLinkSuppressed) return;
  nw_wifi_status snap = {};
  nw_wifi_status_get(&snap);
  if (result == NW_RES_OK && snap.state != NW_STA_UP) return;
  __atomic_store_n(&gHwLastJoinResult, result, __ATOMIC_RELAXED);
  __atomic_fetch_add(&gHwJoinCompletions, 1u, __ATOMIC_RELEASE);
  const int assocResult = (result == NW_RES_OK) ? kHwAssocOk :
                          (result == NW_RES_BAD_KEY) ? kHwAssocBadKey :
                          (result == NW_RES_TIMEOUT) ? kHwAssocTimeout : kHwAssocFailed;
  __atomic_store_n(&gHwAssocResult, assocResult, __ATOMIC_RELEASE);
  bool pending = __atomic_exchange_n(&gHwJoinPending, false, __ATOMIC_ACQ_REL);
  IOLog("HOUJI WIFI NET: connect done res=%d state=%u rssi=%d\n", result, snap.state, (int)snap.signal_dbm);
  hwNetPostLink(result == NW_RES_OK);
  if (pending) hwNetPostAssocResult();
  if (result == NW_RES_OK) {
    hwNetPostEv(kHwEvSsid, nullptr, 0);
    hwNetPostEv(kHwEvBssid, nullptr, 0);
    hw_link_event ev = {};
    ev.rssi = snap.signal_dbm;
    ev.noise = (uint16_t)-95;
    ev.snr = (snap.signal_dbm > -95) ? (uint16_t)(snap.signal_dbm + 95) : 0u;
    hwNetPostEv(kHwEvLink, &ev, sizeof(ev));
  }
}

static void hwNetOnLinkLost(int reason) {
  IOLog("HOUJI WIFI NET: link lost reason=%d\n", reason);
  __atomic_store_n(&gHwAssocResult, kHwAssocFailed, __ATOMIC_RELEASE);
  hwNetPostLinkDown(true, reason);
}

static void hwNetOnLinkUpdate(const nw_wifi_status *st) {
  if (!gHwPower || gHwLinkSuppressed || st->state != NW_STA_UP || st->signal_dbm >= 0) return;
  hw_link_event ev = {};
  ev.rssi = st->signal_dbm;
  ev.noise = (uint16_t)-95;
  ev.snr = (st->signal_dbm > -95) ? (uint16_t)(st->signal_dbm + 95) : 0u;
  hwNetPostEv(kHwEvLink, &ev, sizeof(ev));
}

static void hwNetFlushRx(void) {
  if (!gHwRxHead || !gHwIf) return;
  mbuf_t pkts = gHwRxHead;
  uint32_t count = gHwRxPendingPkts, bytes = gHwRxPendingBytes;
  gHwRxHead = gHwRxTail = nullptr;
  gHwRxPendingPkts = gHwRxPendingBytes = 0;
  struct ifnet_stat_increment_param inc = {};
  inc.packets_in = count;
  inc.bytes_in = bytes;
  errno_t err = ifnet_input(gHwIf, pkts, &inc);
  if (err) gHwRxErrors += count;
  else gHwRxFrames += count;
}

static mbuf_t hwNetAllocRx(size_t len) {
  if (len <= 2048u) {
    if (!gHwRxSpare) {
      unsigned chunks = 1;
      (void)mbuf_allocpacket_list(16, MBUF_DONTWAIT, 2048, &chunks, &gHwRxSpare);
    }
    if (gHwRxSpare) {
      mbuf_t p = gHwRxSpare;
      gHwRxSpare = mbuf_nextpkt(p);
      mbuf_setnextpkt(p, nullptr);
      return p;
    }
  }
  mbuf_t p = nullptr;
  if (mbuf_allocpacket(MBUF_DONTWAIT, len, nullptr, &p)) return nullptr;
  return p;
}

static void hwNetOnRxPacket(void *ctx, size_t len, nw_packet_reader reader) {
  if (!gHwIf || len < 14u) return;
  constexpr size_t kAlign = 2u;
  mbuf_t m = hwNetAllocRx(len + kAlign);
  if (!m && gHwRxHead) { hwNetFlushRx(); m = hwNetAllocRx(len + kAlign); }
  if (!m) return;
  size_t done = 0;
  bool first = true;
  for (mbuf_t n = m; n; n = mbuf_next(n)) {
    size_t room = mbuf_maxlen(n) - mbuf_leadingspace(n);
    if (first) {
      if (room < kAlign + 14u) break;
      mbuf_setdata(n, static_cast<uint8_t *>(mbuf_datastart(n)) + mbuf_leadingspace(n) + kAlign, 0);
      room -= kAlign;
    }
    size_t take = (len - done < room) ? (len - done) : room;
    if (reader(ctx, done, mbuf_data(n), take)) { done = 0; break; }
    mbuf_setlen(n, take);
    done += take;
    first = false;
  }
  if (done != len) { mbuf_freem(m); return; }
  mbuf_pkthdr_setlen(m, len);
  mbuf_pkthdr_setrcvif(m, gHwIf);
  mbuf_pkthdr_setheader(m, mbuf_data(m));
  mbuf_adj(m, 14);
  mbuf_setnextpkt(m, nullptr);
  if (gHwRxTail) mbuf_setnextpkt(gHwRxTail, m);
  else gHwRxHead = m;
  gHwRxTail = m;
  ++gHwRxPendingPkts;
  gHwRxPendingBytes += (uint32_t)len;
  if (gHwRxPendingPkts >= 64u) hwNetFlushRx();
}

static int hwNetFlatRead(void *ctx, size_t off, void *dst, size_t len) {
  memcpy(dst, static_cast<const uint8_t *>(ctx) + off, len);
  return 0;
}

static void hwNetOnRx(const uint8_t *eth, size_t len) {
  hwNetOnRxPacket(const_cast<uint8_t *>(eth), len, hwNetFlatRead);
}

static const struct nw_wifi_events gHwWifiNetEvents = {
  hwNetOnScanDone,
  hwNetOnConnectDone,
  hwNetOnLinkLost,
  hwNetOnRx,
  hwNetFlushRx,
  hwNetOnRxPacket,
  hwNetOnLinkUpdate,
};

static int hwNetMbufRead(void *ctx, size_t off, void *dst, size_t len) {
  return mbuf_copydata(static_cast<mbuf_t>(ctx), off, len, dst);
}

static void hwNetMbufRelease(void *ctx) {
  mbuf_freem(static_cast<mbuf_t>(ctx));
}

static errno_t hwNetIfOutput(ifnet_t, mbuf_t m) {
  size_t len = mbuf_pkthdr_len(m);
  if (len >= 14u && len <= 2000u) {
    if (nw_wifi_tx_packet(m, len, hwNetMbufRead, hwNetMbufRelease) == 0) {
      ifnet_stat_increment_out(gHwIf, 1, (uint32_t)len, 0);
      __atomic_fetch_add(&gHwTxFrames, 1u, __ATOMIC_RELAXED);
      hwWifiWakeWorker();
      return 0;
    }
    __atomic_fetch_add(&gHwTxRefused, 1u, __ATOMIC_RELAXED);
  }
  mbuf_freem(m);
  return 0;
}

static void hwNetIfEventStub(ifnet_t, const struct kev_msg *) {}

static void hwNetFillChannel(houji_wifi_channel &c, uint32_t mhz) {
  c.version = 1;
  if (mhz >= 4900u) { c.channel = (mhz - 5000u) / 5u; c.flags = 0x2u | 0x10u; }
  else { c.channel = (mhz == 2484u) ? 14u : (mhz - 2407u) / 5u; c.flags = 0x2u | 0x8u; }
}

static void hwNetFillResult(houji_wifi_scan_result &r, const nw_bss_info &b, uint32_t reqBytes) {
  memset(&r, 0, sizeof(r));
  r.version = 1;
  hwNetFillChannel(r.ch, b.freq_mhz);
  r.noise_known = 1;
  r.noise = -95;
  r.rssi = b.signal_dbm;
  r.snr = (int16_t)(b.signal_dbm + 95);
  r.beacon_interval = b.beacon_int;
  r.capability = b.caps;
  memcpy(r.bssid, b.bssid, 6);
  r.ssid_length = b.ssid_len;
  memcpy(r.ssid, b.ssid, 32);
  uint64_t now = 0;
  absolutetime_to_nanoseconds(mach_continuous_time(), &now);
  houji_wifi_scan_result_stamp(&r, b.ie, b.ie_len, b.age_ms, now, reqBytes);
  r.rate_count = 0;
}

static int hwNetCopyOut(const houji_a80211req &rq, const void *src, size_t size) {
  if (!rq.req_len || !rq.req_data) return EINVAL;
  size_t n = (rq.req_len < size) ? rq.req_len : size;
  if (rq.req_kernel) { memcpy(reinterpret_cast<void *>(rq.req_data), src, n); return 0; }
  return copyout(src, rq.req_data, n);
}

static int hwNetAnswerVal(houji_a80211req &rq, uint32_t val) {
  if (!rq.req_len || !rq.req_data) { rq.req_val = (int32_t)val; return 0; }
  const uint32_t w[2] = { 1u, val };
  return hwNetCopyOut(rq, w, sizeof(w));
}

static int hwNetAnswerBytes(houji_a80211req &rq, const void *src, uint32_t size) {
  if (!rq.req_data) return EINVAL;
  uint32_t n = (rq.req_len < size) ? rq.req_len : size;
  rq.req_len = size;
  if (rq.req_kernel) { memcpy(reinterpret_cast<void *>(rq.req_data), src, n); return 0; }
  return copyout(src, rq.req_data, n);
}

static int hwNetCopyIn(const houji_a80211req &rq, void *dst, size_t size) {
  if (!rq.req_data) return EINVAL;
  memset(dst, 0, size);
  size_t n = (rq.req_len < size) ? rq.req_len : size;
  if (rq.req_kernel) { memcpy(dst, reinterpret_cast<const void *>(rq.req_data), n); return 0; }
  return copyin(rq.req_data, dst, n);
}

static int hwNetCopyAssoc(const houji_a80211req &rq, hw_assoc_params &out) {
  if (rq.req_len != sizeof(hw_assoc_req) && rq.req_len != sizeof(hw_assoc_req27)) return EINVAL;
  union { hw_assoc_req legacy; hw_assoc_req27 modern; } wire;
  int err = hwNetCopyIn(rq, &wire, sizeof(wire));
  if (!err) {
    const bool modern = rq.req_len == sizeof(hw_assoc_req27);
    const uint32_t version = modern ? wire.modern.version : wire.legacy.version;
    if (version != 1) {
      err = EINVAL;
    } else {
      out = modern ? wire.modern.network : wire.legacy.network;
      const uint32_t lower = modern ? wire.modern.auth_lower : wire.legacy.auth_lower;
      const uint32_t upper = modern ? wire.modern.auth_upper : wire.legacy.auth_upper;
      __atomic_store_n(&gHwJoinAuth, ((uint64_t)upper << 32) | lower, __ATOMIC_RELAXED);
      __atomic_store_n(&gHwJoinKeyInfo, (MIN(out.key_cipher, 65535u) << 16) | MIN(out.key_length, 65535u),
                       __ATOMIC_RELAXED);
    }
  }
  memset(&wire, 0, sizeof(wire));
  return err;
}

static void hwNetCountry(char cc[3]) {
  cc[0] = 'C'; cc[1] = 'N'; cc[2] = 0;
  int best = -200;
  nw_bss_info b = {};
  for (int i = 0, n = nw_wifi_bss_count(); i < n; ++i) {
    if (nw_wifi_bss_get(i, &b) || b.signal_dbm <= best) continue;
    for (unsigned o = 0; o + 2u <= b.ie_len && o + 2u + b.ie[o + 1] <= b.ie_len; o += 2u + b.ie[o + 1]) {
      if (b.ie[o] == 7 && b.ie[o + 1] >= 2 &&
          b.ie[o + 2] >= 'A' && b.ie[o + 2] <= 'Z' &&
          b.ie[o + 3] >= 'A' && b.ie[o + 3] <= 'Z') {
        cc[0] = (char)b.ie[o + 2];
        cc[1] = (char)b.ie[o + 3];
        best = b.signal_dbm;
        break;
      }
    }
  }
}

static int hwNetMapState(unsigned s) {
  switch (s) {
    case NW_STA_SCANNING: return 1;
    case NW_STA_AUTH: return 2;
    case NW_STA_ASSOC: case NW_STA_KEYS: return 3;
    case NW_STA_UP: return 4;
    default: return 0;
  }
}

static int hwNetApple80211(bool set, houji_a80211req &rq) {
  nw_wifi_status st = {};
  hwNetVisibleStatus(st);
  const int type = rq.req_type;
  union Out { uint8_t raw[5120]; hw_channels_list chans; houji_wifi_scan_result res; };
  Out *outp = static_cast<Out *>(IOMallocData(sizeof(Out)));
  if (!outp) return ENOMEM;
  memset(outp, 0, sizeof(Out));
  struct Free { Out *p; ~Free() { IOFreeData(p, sizeof(Out)); } } guard{outp};
  Out &out = *outp;
  uint32_t *w = reinterpret_cast<uint32_t *>(out.raw);

  if (set) {
    switch (type) {
      case kHwPower: {
        uint32_t in[6] = {};
        if (hwNetCopyIn(rq, in, sizeof(in))) return EFAULT;
        gHwPower = (in[2] != 0);
        if (!gHwPower) hwNetDisconnectUser();
        nw_wifi_power(gHwPower ? 1 : 0);
        hwWifiWakeWorker();
        hwNetPostEv(kHwEvPower, nullptr, 0);
        return 0;
      }
      case kHwScanReq: case kHwScanReqMultiple: {
        if (!gHwPower) return ENETDOWN;
        if (gHwLinkSuppressed) {
          nw_wifi_status cur = {};
          nw_wifi_status_get(&cur);
          if (cur.state >= NW_STA_AUTH) return EBUSY;
        }
        uint32_t ssidLen = 0, scanType = 0, freqs = 0, mhz[HOUJI_WIFI_SCAN_FREQUENCIES];
        const uint8_t *ssid = nullptr;
        if (type == kHwScanReq) {
          const uint32_t copied = HOUJI_WIFI_SCAN_ONE_CHANNELS + HOUJI_WIFI_SCAN_CHANNELS_READ * HOUJI_WIFI_SCAN_CHANNEL_ENTRY;
          if (hwNetCopyIn(rq, out.raw, copied)) return EFAULT;
          memcpy(&ssidLen, out.raw + 16, 4);
          ssid = out.raw + 20;
          memcpy(&scanType, out.raw + 0x34, 4);
          freqs = houji_wifi_scan_frequencies(out.raw, rq.req_len < copied ? rq.req_len : copied,
                                              HOUJI_WIFI_SCAN_ONE_CHANNEL_COUNT, HOUJI_WIFI_SCAN_ONE_CHANNELS, mhz);
        } else {
          const uint32_t copied = HOUJI_WIFI_SCAN_MULTIPLE_CHANNELS + HOUJI_WIFI_SCAN_CHANNELS_READ * HOUJI_WIFI_SCAN_CHANNEL_ENTRY;
          if (hwNetCopyIn(rq, out.raw, copied)) return EFAULT;
          houji_wifi_scan_multiple *names = reinterpret_cast<houji_wifi_scan_multiple *>(out.raw + 0x600);
          const uint32_t held = rq.req_len < copied ? rq.req_len : copied;
          if (houji_wifi_scan_multiple_parse(out.raw, held, names)) return EINVAL;
          freqs = houji_wifi_scan_frequencies(out.raw, held, HOUJI_WIFI_SCAN_MULTIPLE_CHANNEL_COUNT,
                                              HOUJI_WIFI_SCAN_MULTIPLE_CHANNELS, mhz);
          scanType = names->scan_type;
          houji_wifi_scan_multiple_target(names, &ssid, &ssidLen);
        }
        __atomic_store_n(&gHwLastScanArgs, (MIN(scanType, 65535u) << 16) | (freqs << 1) |
                         (ssidLen > 0u && ssidLen <= 32u), __ATOMIC_RELAXED);
        if (ssid && ssidLen > 0u && ssidLen <= 32u) {
          memcpy(gHwScanFilterSsid, ssid, ssidLen);
          gHwScanFilterLen = (uint8_t)ssidLen;
        } else {
          gHwScanFilterLen = 0u;
        }
        if (scanType == HOUJI_WIFI_SCAN_TYPE_CACHED && nw_wifi_bss_count() > 0) {
          if (!gHwCachedScan) gHwCachedScan = thread_call_allocate(hwNetCachedScanDone, nullptr);
          __atomic_store_n(&gHwScanning, 1u, __ATOMIC_RELEASE);
          gHwScanCursor = 0;
          uint64_t at;
          clock_interval_to_deadline(10, kMillisecondScale, &at);
          thread_call_enter_delayed(gHwCachedScan, at);
          return 0;
        }
        const uint64_t now = hwNetContMs();
        if (st.state != NW_STA_UP) gHwLinkUpMs = 0;
        else if (!gHwLinkUpMs) gHwLinkUpMs = now;
        const houji_wifi_link link = (st.state == NW_STA_UP) ? HoujiWifiLinkUp :
                                     (st.state >= NW_STA_AUTH) ? HoujiWifiLinkJoining : HoujiWifiLinkNone;
        if (!houji_wifi_scan_on_air(&gHwAir, link, now - gHwLinkUpMs, nw_wifi_bss_count() > 0, mhz, freqs, now)) {
          if (!gHwCachedScan) gHwCachedScan = thread_call_allocate(hwNetCachedScanDone, nullptr);
          gHwScanning = 1;
          gHwScanCursor = 0;
          uint64_t at;
          clock_interval_to_deadline(2000, kMillisecondScale, &at);
          thread_call_enter_delayed(gHwCachedScan, at);
          return 0;
        }
        const bool merged = __atomic_load_n(&gHwScanning, __ATOMIC_ACQUIRE) != 0;
        gHwScanning = 1;
        gHwScanCursor = 0;
        int res = nw_wifi_scan_frequencies((ssid && ssidLen && ssidLen <= 32u) ? ssid : nullptr,
                                           (ssid && ssidLen <= 32u) ? ssidLen : 0u,
                                           freqs ? mhz : nullptr, freqs);
        if (res) {
          if (!merged) __atomic_store_n(&gHwScanning, 0u, __ATOMIC_RELEASE);
          return res == -EBUSY ? EBUSY : ENETDOWN;
        }
        if (!merged) houji_wifi_air_mark(&gHwAir, mhz, freqs, now);
        hwWifiWakeWorker();
        return 0;
      }
      case kHwAssociate: {
        hw_assoc_params a = {};
        int err = hwNetCopyAssoc(rq, a);
        if (err) return err;
        if (!a.ssid_length || a.ssid_length > 32u || a.key_length > 64u) return EINVAL;
        if (a.key_length && !((a.key_cipher == 6 && a.key_length == 32) ||
                              (a.key_cipher == 10 && a.key_length >= 8 && a.key_length <= 63))) {
          memset(&a, 0, sizeof(a));
          return EINVAL;
        }
        unsigned matches = 0, frequency = 0;
        int bestSignal = -200;
        for (int i = 0, count = nw_wifi_bss_count(); i < count; ++i) {
          nw_bss_info b = {};
          if (nw_wifi_bss_get(i, &b) || houji_wifi_held_stale(b.age_ms) ||
              b.ssid_len != a.ssid_length || memcmp(b.ssid, a.ssid, a.ssid_length)) continue;
          ++matches;
          if (b.signal_dbm > bestSignal) {
            frequency = b.freq_mhz;
            bestSignal = b.signal_dbm;
          }
        }
        __atomic_store_n(&gHwJoinBssMatch, (matches << 16) | (frequency & 65535u), __ATOMIC_RELAXED);
        const bool hasBssid = (a.bssid[0] | a.bssid[1] | a.bssid[2] | a.bssid[3] | a.bssid[4] | a.bssid[5]) != 0;
        const bool hasKey = (a.key_length != 0);
        if (!gHwPower) { memset(&a, 0, sizeof(a)); return ENETDOWN; }
        nw_wifi_status cur = {};
        nw_wifi_status_get(&cur);
        if (cur.state >= NW_STA_AUTH) {
          int derr = hwNetDrainDisconnect();
          if (derr) { memset(&a, 0, sizeof(a)); return derr; }
          if (!gHwPower) { memset(&a, 0, sizeof(a)); return ENETDOWN; }
        }
        char pass[65];
        memset(pass, 0, sizeof(pass));
        if (hasKey) memcpy(pass, a.key, a.key_length);
        unsigned keyLen = a.key_length;
        if (hasKey && a.key_cipher == 6 && a.key_length == 32) {
          static const char hex[] = "0123456789abcdef";
          for (int i = 0; i < 32; ++i) {
            pass[2 * i] = hex[a.key[i] >> 4];
            pass[2 * i + 1] = hex[a.key[i] & 15];
          }
          keyLen = 64u;
        }
        __atomic_store_n(&gHwAssocModern, rq.req_len == sizeof(hw_assoc_req27), __ATOMIC_RELAXED);
        __atomic_store_n(&gHwAssocResult, kHwAssocPending, __ATOMIC_RELEASE);
        gHwLinkSuppressed = false;
        __atomic_store_n(&gHwJoinPending, true, __ATOMIC_RELEASE);
        gHwKeyed = hasKey;
        int r = nw_wifi_connect(a.ssid, a.ssid_length, hasBssid ? a.bssid : nullptr,
                                hasKey ? pass : nullptr, hasKey ? keyLen : 0u);
        if (!r) hwWifiWakeWorker();
        else {
          __atomic_store_n(&gHwAssocResult, kHwAssocFailed, __ATOMIC_RELEASE);
          __atomic_store_n(&gHwJoinPending, false, __ATOMIC_RELEASE);
        }
        memset(pass, 0, sizeof(pass));
        memset(&a, 0, sizeof(a));
        return r ? EINVAL : 0;
      }
      case kHwDisassociate: case kHwDeauth:
        hwNetDisconnectUser();
        return 0;
      case kHwAbortScan:
        if (gHwCachedScan) thread_call_cancel(gHwCachedScan);
        if (__atomic_exchange_n(&gHwScanning, 0u, __ATOMIC_ACQ_REL)) {
          gHwScanCursor = 0;
          gHwScanFilterLen = 0u;
          hwNetPostEv(kHwEvScanDone, nullptr, 0);
        }
        return 0;
      case kHwScanCacheClear: case kHwLocale: case kHwCountryCode: case kHwPowerSave:
      case kHwAuthType: case kHwCipherKey:
        return 0;
      default:
        return EOPNOTSUPP;
    }
  }

  switch (type) {
    case kHwPower: w[0] = 1; w[1] = 1; w[2] = (gHwPower && st.state != NW_STA_OFF) ? 1u : 0u; return hwNetCopyOut(rq, w, 24);
    case kHwState: return hwNetAnswerVal(rq, (uint32_t)(gHwPower ? hwNetMapState(st.state) : 0));
    case kHwOpMode: return hwNetAnswerVal(rq, 1u);
    case kHwAuthType: w[0] = 1; w[1] = 1; w[2] = gHwKeyed ? 0x10u : 0u; w[3] = 0; return hwNetCopyOut(rq, w, 16);
    case kHwPowerSave: return hwNetAnswerVal(rq, 0u);
    case kHwCardCaps: houji_wifi_caps_fill(out.raw); return hwNetAnswerBytes(rq, out.raw, HOUJI_WIFI_CAPS_BYTES);
    case kHwPhyMode: w[0] = 1; w[1] = 0x7fu; w[2] = (st.state == NW_STA_UP) ? 0x8u : 0u; return hwNetCopyOut(rq, w, 12);
    case kHwSsid: if (st.state < NW_STA_ASSOC) return ENOENT; return hwNetAnswerBytes(rq, st.ssid, st.ssid_len);
    case kHwBssid: if (st.state < NW_STA_ASSOC) return ENOENT; return hwNetAnswerBytes(rq, st.bssid, 6u);
    case kHwChannel: if (st.state < NW_STA_AUTH) return ENOENT; w[0] = 1; hwNetFillChannel(*reinterpret_cast<houji_wifi_channel *>(out.raw + 4), st.freq_mhz); return hwNetCopyOut(rq, w, 16);
    case kHwRssi: case kHwNoise: {
      if (type == kHwRssi && st.state != NW_STA_UP) return ENOENT;
      uint32_t v = (uint32_t)((type == kHwRssi) ? (int32_t)st.signal_dbm : -95);
      w[0] = 1; w[1] = 1; w[2] = 0;
      for (int i = 3; i < 13; ++i) w[i] = v;
      return hwNetCopyOut(rq, w, 13 * 4);
    }
    case kHwRate: return hwNetAnswerVal(rq, (st.state == NW_STA_UP) ? (st.tx_rate_100kbps / 10u) : 0u);
    case kHwTxPower: return hwNetAnswerVal(rq, 15u);
    case kHwDriverVersion: case kHwHardwareVersion: {
      const char *v = (type == kHwDriverVersion) ? "nativewifi 1" : "WCN7850";
      strlcpy(reinterpret_cast<char *>(out.raw), v, 256);
      return hwNetCopyOut(rq, out.raw, 256);
    }
    case kHwCountryCode: { char cc[3]; hwNetCountry(cc); return hwNetAnswerBytes(rq, cc, 3u); }
    case kHwAssociateResult: {
      uint32_t result = (uint32_t)__atomic_load_n(&gHwAssocResult, __ATOMIC_ACQUIRE);
      if (result == kHwAssocPending && !__atomic_load_n(&gHwAssocModern, __ATOMIC_RELAXED)) result = 0xffffu;
      return hwNetAnswerVal(rq, result);
    }
    case kHwSupportedChannels: case kHwHwSupportedChannels: {
      out.chans.version = 1;
      static const uint16_t kFreqs[] = {
        2412, 2417, 2422, 2427, 2432, 2437, 2442, 2447, 2452, 2457, 2462, 2467, 2472,
        5180, 5200, 5220, 5240, 5745, 5765, 5785, 5805, 5825
      };
      unsigned n = 0;
      for (uint16_t f : kFreqs) {
        hwNetFillChannel(out.chans.list[n], f);
        out.chans.list[n].flags |= 0x80u;
        ++n;
      }
      out.chans.count = n;
      return hwNetCopyOut(rq, &out.chans, sizeof(out.chans));
    }
    case kHwScanResult: {
      nw_bss_info b = {};
      const int count = nw_wifi_bss_count();
      do {
        if (gHwScanCursor >= (unsigned)count || nw_wifi_bss_get((int)gHwScanCursor, &b)) {
          gHwScanCursor = 0;
          gHwScanFilterLen = 0u;
          return EIO;
        }
        ++gHwScanCursor;
        if (!houji_wifi_held_stale(b.age_ms)) {
          if (gHwScanFilterLen > 0u &&
              (b.ssid_len != gHwScanFilterLen || memcmp(b.ssid, gHwScanFilterSsid, gHwScanFilterLen) != 0)) {
            b.age_ms = 0xffffffffu;
          } else if (hwNetShadowedHiddenBeacon(b, count)) {
            b.age_ms = 0xffffffffu;
          }
        }
      } while (houji_wifi_held_stale(b.age_ms));
      hwNetFillResult(out.res, b, rq.req_len);
      return hwNetCopyOut(rq, &out.res, sizeof(out.res));
    }
    case kHwCurrentNetwork: {
      if (st.state < NW_STA_ASSOC) return ENOENT;
      nw_bss_info b = {}, fallback = {};
      bool found = false, hasFallback = false;
      const int count = nw_wifi_bss_count();
      for (int i = 0; i < count; ++i) {
        if (nw_wifi_bss_get(i, &b) || memcmp(b.bssid, st.bssid, 6)) continue;
        if (st.ssid_len && b.ssid_len == st.ssid_len && !memcmp(b.ssid, st.ssid, st.ssid_len)) {
          found = true;
          break;
        }
        if (!hasFallback || (!hwNetSsidBlank(b.ssid, b.ssid_len) && hwNetSsidBlank(fallback.ssid, fallback.ssid_len))) {
          fallback = b;
          hasFallback = true;
        }
      }
      if (!found) {
        if (!hasFallback) return ENOENT;
        b = fallback;
      }
      hwNetFillResult(out.res, b, rq.req_len);
      if (hwNetSsidBlank(out.res.ssid, out.res.ssid_length) && st.ssid_len && st.ssid_len <= 32u) {
        out.res.ssid_length = st.ssid_len;
        memcpy(out.res.ssid, st.ssid, st.ssid_len);
      }
      out.res.rssi = st.signal_dbm;
      out.res.snr = (st.signal_dbm > -95 && st.signal_dbm < 0) ? (int16_t)(st.signal_dbm + 95) : 0;
      return hwNetCopyOut(rq, &out.res, sizeof(out.res));
    }
    default:
      return EOPNOTSUPP;
  }
}

static errno_t hwNetIfIoctl(ifnet_t, unsigned long cmd, void *data) {
  switch (cmd) {
    case HOUJI_SIOCGA80211: case HOUJI_SIOCSA80211: {
      houji_a80211req *rq = static_cast<houji_a80211req *>(data);
      rq->req_kernel = 0;
      uint32_t origLen = rq->req_len;
      const bool set = cmd == HOUJI_SIOCSA80211;
      HwWifiActionLog *action = nullptr;
      if (set) {
        switch (rq->req_type) {
          case kHwScanReq: case kHwScanReqMultiple:
            action = &gHwScanAction;
            __atomic_store_n(&gHwLastScanArgs, 0, __ATOMIC_RELAXED);
            break;
          case kHwAssociate:
            action = &gHwJoinAction;
            __atomic_store_n(&gHwJoinAuth, 0, __ATOMIC_RELAXED);
            __atomic_store_n(&gHwJoinKeyInfo, 0, __ATOMIC_RELAXED);
            __atomic_store_n(&gHwJoinBssMatch, 0, __ATOMIC_RELAXED);
            break;
          default: break;
        }
      }
      int ret = hwNetApple80211(set, *rq);
      if (action) {
        const uint64_t entry = ((uint64_t)origLen << 32) | ((uint32_t)rq->req_type << 16) | (uint16_t)ret;
        __atomic_store_n(&action->lastIoctl, entry, __ATOMIC_RELAXED);
        __atomic_fetch_add(&action->requests, 1u, __ATOMIC_RELEASE);
      }
      __atomic_fetch_add(&gHwIoctlCount, 1u, __ATOMIC_RELAXED);
      uint32_t idx = __atomic_fetch_add(&gHwIoctlHistN, 1u, __ATOMIC_RELAXED);
      if (idx < 16u) {
        gHwIoctlHist[idx] = { rq->req_type, (uint8_t)set,
                              (uint16_t)(origLen > 65535u ? 65535u : origLen), (int16_t)ret };
      }
      return ret;
    }
    case SIOCGIFMEDIA: {
      struct ifmediareq *m = static_cast<struct ifmediareq *>(data);
      nw_wifi_status st = {};
      hwNetVisibleStatus(st);
      m->ifm_current = IFM_IEEE80211 | IFM_AUTO;
      m->ifm_mask = 0;
      m->ifm_status = IFM_AVALID | ((st.state == NW_STA_UP) ? IFM_ACTIVE : 0);
      m->ifm_active = IFM_IEEE80211 | IFM_AUTO;
      m->ifm_count = 1;
      return 0;
    }
    case SIOCSIFFLAGS: case SIOCSIFMTU: case SIOCADDMULTI: case SIOCDELMULTI: case SIOCSIFADDR: case SIOCSIFMEDIA:
      return 0;
    default:
      return EOPNOTSUPP;
  }
}

static IOService *hwNetPublish(IOService *svc, IOService *provider, const char *name) {
  if (!svc || !svc->attach(provider)) { OSSafeReleaseNULL(svc); return nullptr; }
  svc->setName(name);
  if (!svc->start(provider)) { svc->detach(provider); svc->release(); return nullptr; }
  svc->registerService();
  return svc;
}

static void hwNetPublishRegistry(const char *ifname) {
  IOService *platform = IOService::getPlatform();
  IO80211Controller *ctrl = OSTypeAlloc(IO80211Controller);
  IO80211Interface *wlan = OSTypeAlloc(IO80211Interface);
  if (!platform || !ctrl || !wlan || !ctrl->init() || !wlan->init()) {
    OSSafeReleaseNULL(ctrl);
    OSSafeReleaseNULL(wlan);
    return;
  }
  if (OSData *mac = OSData::withBytes(gHwMac, 6)) { ctrl->setProperty("IOMACAddress", mac); mac->release(); }
  ctrl->setProperty("IOBuiltin", true);
  ctrl = static_cast<IO80211Controller *>(hwNetPublish(ctrl, platform, "HoujiWLANController"));
  if (!ctrl) { wlan->release(); return; }
  wlan->setProperty("IOInterfaceName", ifname);
  wlan->setProperty("BSD Name", ifname);
  wlan->setProperty("IOInterfaceNamePrefix", "en");
  if (OSNumber *n = OSNumber::withNumber((unsigned long long)IFT_ETHER, 32)) { wlan->setProperty("IOInterfaceType", n); n->release(); }
  if (OSNumber *n = OSNumber::withNumber(0ULL, 32)) { wlan->setProperty("IOInterfaceUnit", n); n->release(); }
  wlan->setProperty("IOBuiltin", true);
  wlan->setProperty("IOPrimaryInterface", true);
  wlan->setProperty("IO80211InterfaceRole", "Infrastructure");
  if (hwNetPublish(wlan, ctrl, "HoujiWLAN")) wlan->release();
  ctrl->release();
}

}  // namespace

static void houjiWifiNetStart(const uint8_t mac[6]) {
  if (gHwIf) return;
  memcpy(gHwMac, mac, 6);
  struct ifnet_init_eparams p;
  memset(&p, 0, sizeof(p));
  p.ver = IFNET_INIT_CURRENT_VERSION;
  p.len = sizeof(p);
  p.flags = IFNET_INIT_LEGACY | IFNET_INIT_NX_NOAUTO;
  p.name = "en";
  p.unit = 0;
  p.family = IFNET_FAMILY_ETHERNET;
  p.subfamily = IFNET_SUBFAMILY_WIFI;
  p.type = IFT_ETHER;
  p.output = hwNetIfOutput;
  p.demux = ether_demux;
  p.add_proto = ether_add_proto;
  p.del_proto = ether_del_proto;
  p.check_multi = ether_check_multi;
  p.framer = ether_frameout;
  p.ioctl = hwNetIfIoctl;
  p.event = hwNetIfEventStub;
  static const uint8_t bcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  p.broadcast_addr = bcast;
  p.broadcast_len = 6;

  ifnet_t ifp = nullptr;
  errno_t e = ifnet_allocate_extended(&p, &ifp);
  if (e || !ifp) { IOLog("HOUJI WIFI NET: ifnet_allocate_extended failed %d\n", e); return; }
  ifnet_set_mtu(ifp, 1500);
  ifnet_set_flags(ifp, IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST, 0xffff);
  ifnet_set_baudrate(ifp, 54000000ULL);
  ifnet_set_hdrlen(ifp, 14);
  ifnet_set_addrlen(ifp, 6);
  ifnet_set_eflags(ifp, IFEF_ENQUEUE_MULTI, IFEF_ENQUEUE_MULTI);
  e = ifnet_attach(ifp, nullptr);
  if (e) { IOLog("HOUJI WIFI NET: ifnet_attach failed %d\n", e); ifnet_release(ifp); return; }
  ifnet_set_lladdr(ifp, mac, 6);
  (void)bpf_attach(ifp, DLT_EN10MB, 14, nullptr, nullptr);
  gHwIf = ifp;
  ifnet_set_flags(ifp, IFF_UP, IFF_UP);
  nw_wifi_set_events(&gHwWifiNetEvents);
  hwNetPublishRegistry("en0");
  IOLog("HOUJI WIFI NET: en0 up mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void hwWifiNetSnapshot(void) {
  if (!gHwIf) return;
  char ip[32] = "none";
  ifaddr_t *list = nullptr;
  if (!ifnet_get_address_list_family(gHwIf, &list, AF_INET) && list) {
    if (list[0]) {
      struct sockaddr_in a = {};
      if (!ifaddr_address(list[0], reinterpret_cast<struct sockaddr *>(&a), sizeof(a))) {
        const uint8_t *b = reinterpret_cast<const uint8_t *>(&a.sin_addr);
        snprintf(ip, sizeof(ip), "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
      }
    }
    ifnet_free_address_list(list);
  }
  nw_wifi_status st = {};
  nw_wifi_status_get(&st);
  nw_control_stats cs = {};
  nw_wifi_control_stats_get(&cs);
  IOLog("HOUJI WIFI NET: en0 ip=%s sta=%u rssi=%d ioctls=%u rx=%u/%u tx=%u/%u ctl=s%llu(c%llu/d%llu/op%u)\n",
        ip, st.state, (int)st.signal_dbm,
        __atomic_load_n(&gHwIoctlCount, __ATOMIC_RELAXED),
        gHwRxFrames, gHwRxErrors,
        __atomic_load_n(&gHwTxFrames, __ATOMIC_RELAXED),
        __atomic_load_n(&gHwTxRefused, __ATOMIC_RELAXED),
        (unsigned long long)cs.active_session,
        (unsigned long long)cs.connections,
        (unsigned long long)cs.disconnections,
        cs.last_operation);
  const uint32_t scans = __atomic_load_n(&gHwScanAction.requests, __ATOMIC_ACQUIRE);
  const uint32_t joins = __atomic_load_n(&gHwJoinAction.requests, __ATOMIC_ACQUIRE);
  const uint64_t scan = __atomic_load_n(&gHwScanAction.lastIoctl, __ATOMIC_RELAXED);
  const uint64_t join = __atomic_load_n(&gHwJoinAction.lastIoctl, __ATOMIC_RELAXED);
  const uint64_t auth = __atomic_load_n(&gHwJoinAuth, __ATOMIC_RELAXED);
  const uint32_t key = __atomic_load_n(&gHwJoinKeyInfo, __ATOMIC_RELAXED);
  const uint32_t match = __atomic_load_n(&gHwJoinBssMatch, __ATOMIC_RELAXED);
  const uint32_t completions = __atomic_load_n(&gHwJoinCompletions, __ATOMIC_ACQUIRE);
  const uint32_t scanArgs = __atomic_load_n(&gHwLastScanArgs, __ATOMIC_RELAXED);
  IOLog("HOUJI WIFI REQUESTS: scan=%u last=%uS(%u)->%u mode=%u named=%u freqs=%u join=%u last=%uS(%u)->%u auth=%x/%x cipher=%u key-bytes=%u match=%u/%uMHz done=%u result=%d\n",
        scans, (unsigned)(uint16_t)(scan >> 16), (unsigned)(scan >> 32), (unsigned)(uint16_t)scan,
        scanArgs >> 16, scanArgs & 1u, (scanArgs & 65535u) >> 1,
        joins, (unsigned)(uint16_t)(join >> 16), (unsigned)(join >> 32), (unsigned)(uint16_t)join,
        (unsigned)auth, (unsigned)(auth >> 32), key >> 16, key & 65535u, match >> 16, match & 65535u,
        completions, __atomic_load_n(&gHwLastJoinResult, __ATOMIC_RELAXED));
  uint32_t hn = __atomic_load_n(&gHwIoctlHistN, __ATOMIC_RELAXED);
  if (hn > 16u) hn = 16u;
  if (hn > 0u) {
    char line[220];
    int at = snprintf(line, sizeof(line), "HOUJI WIFI IOCTL:");
    for (uint32_t i = 0; i < hn && at < (int)sizeof(line) - 24; ++i) {
      at += snprintf(line + at, sizeof(line) - (size_t)at, " %d%c(%u)->%d",
                     gHwIoctlHist[i].type, gHwIoctlHist[i].isSet ? 'S' : 'G',
                     (unsigned)gHwIoctlHist[i].len, (int)gHwIoctlHist[i].ret);
    }
    IOLog("%s\n", line);
  }
}
