// SPDX-License-Identifier: MIT
// Read-only SPMI v7 observer poller for Xiaomi 14 (SM8650 / PMK8550 / PM8550)
// hardware buttons: Power (pon_hlos 0x013 bit 7), Volume Down (pon_hlos 0x013
// bit 6), and Volume Up (pm8550 gpio6 0x18d bit 0, active-low).
// Only EXT_READL commands on observer channels are issued; no PMIC writes.
#include "HoujiSpmiKeysPolicy.h"
extern "C" void sweet_hid_key(int, int);
extern "C" void sweet_hid_buttons_status(unsigned *registered, unsigned *clients, unsigned *dispatched);
extern "C" void houji_dvfs_touch(void);

static struct {
  uintptr_t core, cnfg, obs;
  OSSharedPtr<IOMemoryMap> coreMap, cnfgMap, obsMap;
  uint32_t ver, rawCount, scanCount;
  uint16_t ponApid, volUpApid;
  uint8_t ponOwner, volUpOwner;
  bool started;
  unsigned stage, polls, ponOk, gpioOk, events, errors;
  uint32_t lastPonSt, lastGpioSt;
  uint8_t lastPon, lastGpio, stateMask;
} hk;
static int hkWaitChannel;

static void hkWait(unsigned ms) {
  uint64_t deadline;
  clock_interval_to_deadline(ms, NSEC_PER_MSEC, &deadline);
  (void)assert_wait_deadline(&hkWaitChannel, THREAD_UNINT, deadline);
  thread_block(THREAD_CONTINUE_NULL);
}

static uint16_t hkFindApid(uint16_t targetPpid, unsigned count, uint8_t *ownerOut) {
  uint16_t found = HOUJI_SPMI_APID_NONE;
  uint8_t foundOwner = 0xffu;
  for (unsigned i = 0; i < count; i++) {
    uint32_t map = htRead(hk.core, 0x2000u + 4u * i);
    if (houji_spmi_ppid_from_map(map) != targetPpid) continue;
    uint8_t owner = houji_spmi_owner_from_cnfg(htRead(hk.cnfg, 4u * i));
    if (houji_spmi_should_pick_apid(found, owner)) {
      found = (uint16_t)i;
      foundOwner = owner;
    }
  }
  if (ownerOut) *ownerOut = foundOwner;
  return found;
}

static bool hkReadObserver(uint16_t apid, uint8_t reg, uint8_t *out, uint32_t *stOut) {
  if (apid == HOUJI_SPMI_APID_NONE) return false;
  uint32_t off = houji_spmi_obs_offset(apid);
  uint32_t cmd = houji_spmi_ext_readl_cmd(reg);
  __asm__ volatile("dmb oshst" ::: "memory");
  *(volatile uint32_t *)(hk.obs + off) = cmd;
  __asm__ volatile("dsb osh" ::: "memory");
  uint32_t st = 0;
  for (unsigned i = 0; i < 1000; i++) {
    IODelay(1);
    st = htRead(hk.obs, off + 0x08u);
    int res = houji_spmi_obs_status(st);
    if (res != 0) {
      if (stOut) *stOut = st;
      if (res < 0) return false;
      *out = (uint8_t)htRead(hk.obs, off + 0x18u);
      return true;
    }
  }
  if (stOut) *stOut = st;
  return false;
}

static void hkThread(void *, wait_result_t) {
  hkWait(1200);
  hk.ponApid = HOUJI_SPMI_APID_NONE;
  hk.volUpApid = HOUJI_SPMI_APID_NONE;
  hk.ponOwner = 0xffu;
  hk.volUpOwner = 0xffu;
  hk.core = mapPhys(0x0c400000, 0x3000, hk.coreMap);
  hk.cnfg = mapPhys(0x0c42d000, 0x4000, hk.cnfgMap);
  hk.obs = mapPhys(0x0c440000, 0x80000, hk.obsMap);
  if (!hk.core || !hk.cnfg || !hk.obs) {
    __atomic_store_n(&hk.stage, 1u, __ATOMIC_RELEASE);
    IOLog("HOUJI KEYS: SPMI MMIO map failed\n");
    thread_terminate(current_thread());
    return;
  }
  uint32_t ver = htRead(hk.core, 0x0000u);
  uint32_t features = htRead(hk.core, 0x0004u);
  unsigned count = 0;
  __atomic_store_n(&hk.ver, ver, __ATOMIC_RELAXED);
  __atomic_store_n(&hk.rawCount, features & 0x7ffu, __ATOMIC_RELAXED);
  if (!houji_spmi_v7_valid(ver, features, &count)) {
    __atomic_store_n(&hk.stage, 2u, __ATOMIC_RELEASE);
    IOLog("HOUJI KEYS: unexpected SPMI ver=%x count=%u\n", ver, features & 0x7ffu);
    thread_terminate(current_thread());
    return;
  }
  __atomic_store_n(&hk.scanCount, count, __ATOMIC_RELAXED);
  hk.ponApid = hkFindApid(HOUJI_SPMI_PPID_PON, count, &hk.ponOwner);
  hk.volUpApid = hkFindApid(HOUJI_SPMI_PPID_VOL_UP, count, &hk.volUpOwner);
  IOLog("HOUJI KEYS: SPMI v7 ver=%x count=%u/%u ponApid=%u(ee=%u) volUpApid=%u(ee=%u)\n",
        ver, features & 0x7ffu, count, hk.ponApid, hk.ponOwner, hk.volUpApid, hk.volUpOwner);
  if (hk.ponApid == HOUJI_SPMI_APID_NONE && hk.volUpApid == HOUJI_SPMI_APID_NONE) {
    __atomic_store_n(&hk.stage, 3u, __ATOMIC_RELEASE);
    thread_terminate(current_thread());
    return;
  }
  __atomic_store_n(&hk.stage, 4u, __ATOMIC_RELEASE);

  int state[3] = {0, 0, 0};
  for (;;) {
    uint8_t pon = 0, gpio = 1;
    uint32_t ponSt = 0, gpioSt = 0;
    bool pok = hkReadObserver(hk.ponApid, HOUJI_SPMI_REG_RT_STS, &pon, &ponSt);
    bool gok = hkReadObserver(hk.volUpApid, HOUJI_SPMI_REG_RT_STS, &gpio, &gpioSt);
    __atomic_add_fetch(&hk.polls, 1u, __ATOMIC_RELAXED);
    if (pok) {
      __atomic_add_fetch(&hk.ponOk, 1u, __ATOMIC_RELAXED);
      __atomic_store_n(&hk.lastPon, pon, __ATOMIC_RELAXED);
    }
    if (gok) {
      __atomic_add_fetch(&hk.gpioOk, 1u, __ATOMIC_RELAXED);
      __atomic_store_n(&hk.lastGpio, gpio, __ATOMIC_RELAXED);
    }
    __atomic_store_n(&hk.lastPonSt, ponSt, __ATOMIC_RELAXED);
    __atomic_store_n(&hk.lastGpioSt, gpioSt, __ATOMIC_RELAXED);
    if (!pok && !gok) __atomic_add_fetch(&hk.errors, 1u, __ATOMIC_RELAXED);

    int now[3];
    houji_spmi_decode_buttons(pon, gpio, now);
    for (int k = 0; k < 3; k++) {
      bool valid = (k == 1) ? gok : pok;
      if (valid && now[k] != state[k]) {
        state[k] = now[k];
        if (state[k]) houji_dvfs_touch();
        sweet_hid_key(k, state[k]);
        __atomic_add_fetch(&hk.events, 1u, __ATOMIC_RELAXED);
      }
    }
    uint8_t mask = (uint8_t)((state[0] ? 1u : 0u) | (state[1] ? 2u : 0u) | (state[2] ? 4u : 0u));
    __atomic_store_n(&hk.stateMask, mask, __ATOMIC_RELAXED);
    hkWait(20);
  }
}

static void houjiKeysStart(void) {
  if (hk.started) return;
  hk.started = true;
  thread_t thread;
  if (kernel_thread_start(hkThread, nullptr, &thread) == KERN_SUCCESS) {
    thread_deallocate(thread);
  }
}

// Cached state only: never touches SPMI MMIO during checkpoint or recovery.
static void houjiKeysReport(void) {
  unsigned hidReg = 0, hidClients = 0, hidDispatched = 0;
  sweet_hid_buttons_status(&hidReg, &hidClients, &hidDispatched);
  IOLog("HOUJI KEYS: stage=%u ver=%x count=%u/%u pon-apid=%u(ee=%u) volup-apid=%u(ee=%u) polls=%u ok=%u/%u pon=%02x(st=%x) gpio=%02x(st=%x) state=%x events=%u errors=%u hid=%u/%u/%u; stages 0=init 1=map 2=ver 3=no-apid 4=poll\n",
        __atomic_load_n(&hk.stage, __ATOMIC_ACQUIRE),
        __atomic_load_n(&hk.ver, __ATOMIC_RELAXED),
        __atomic_load_n(&hk.rawCount, __ATOMIC_RELAXED),
        __atomic_load_n(&hk.scanCount, __ATOMIC_RELAXED),
        (unsigned)hk.ponApid, (unsigned)hk.ponOwner,
        (unsigned)hk.volUpApid, (unsigned)hk.volUpOwner,
        __atomic_load_n(&hk.polls, __ATOMIC_RELAXED),
        __atomic_load_n(&hk.ponOk, __ATOMIC_RELAXED),
        __atomic_load_n(&hk.gpioOk, __ATOMIC_RELAXED),
        (unsigned)__atomic_load_n(&hk.lastPon, __ATOMIC_RELAXED),
        __atomic_load_n(&hk.lastPonSt, __ATOMIC_RELAXED),
        (unsigned)__atomic_load_n(&hk.lastGpio, __ATOMIC_RELAXED),
        __atomic_load_n(&hk.lastGpioSt, __ATOMIC_RELAXED),
        (unsigned)__atomic_load_n(&hk.stateMask, __ATOMIC_RELAXED),
        __atomic_load_n(&hk.events, __ATOMIC_RELAXED),
        __atomic_load_n(&hk.errors, __ATOMIC_RELAXED),
        hidReg, hidClients, hidDispatched);
}
