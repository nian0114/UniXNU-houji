// SPDX-License-Identifier: MIT
// Read-only SPMI v7 observer poller for Xiaomi 14 (SM8650 / PMK8550 / PM8550)
// hardware buttons: Power (pon_hlos 0x013 bit 7), Volume Down (pon_hlos 0x013
// bit 6), and Volume Up (pm8550 gpio6 0x18d bit 0, active-low).
// Only EXT_READL commands on observer channels are issued; no PMIC writes.
extern "C" void sweet_hid_key(int, int);
extern "C" void houji_dvfs_touch(void);

static struct {
  uintptr_t core, cnfg, obs;
  OSSharedPtr<IOMemoryMap> coreMap, cnfgMap, obsMap;
  uint16_t ponApid, volUpApid;
  bool started;
  unsigned events, errors;
} hk;
static int hkWaitChannel;

static void hkWait(unsigned ms) {
  uint64_t deadline;
  clock_interval_to_deadline(ms, NSEC_PER_MSEC, &deadline);
  (void)assert_wait_deadline(&hkWaitChannel, THREAD_UNINT, deadline);
  thread_block(THREAD_CONTINUE_NULL);
}

static uint16_t hkFindApid(uint16_t targetPpid, unsigned count) {
  uint16_t found = 0xffffu;
  for (unsigned i = 0; i < count; i++) {
    uint32_t map = htRead(hk.core, 0x2000u + 4u * i);
    if (!map || ((map >> 8) & 0xfffu) != targetPpid) continue;
    uint32_t owner = htRead(hk.cnfg, 4u * i) & 7u;
    if (found == 0xffffu || owner == 0) found = (uint16_t)i;
  }
  return found;
}

static bool hkReadObserver(uint16_t apid, uint8_t reg, uint8_t *out) {
  if (apid == 0xffffu) return false;
  uint32_t off = 0x20u * apid;
  uint32_t cmd = (1u << 27) | ((uint32_t)reg << 4);
  __asm__ volatile("dmb oshst" ::: "memory");
  *(volatile uint32_t *)(hk.obs + off) = cmd;
  __asm__ volatile("dsb osh" ::: "memory");
  for (unsigned i = 0; i < 1000; i++) {
    uint32_t st = htRead(hk.obs, off + 0x08u);
    if (st & 1u) {
      if (st & 0x0eu) return false;
      *out = (uint8_t)htRead(hk.obs, off + 0x18u);
      return true;
    }
    IODelay(1);
  }
  return false;
}

static void hkThread(void *, wait_result_t) {
  hkWait(1200);
  hk.core = mapPhys(0x0c400000, 0x4000, hk.coreMap);
  hk.cnfg = mapPhys(0x0c42d000, 0x4000, hk.cnfgMap);
  hk.obs = mapPhys(0x0c440000, 0x80000, hk.obsMap);
  if (!hk.core || !hk.cnfg || !hk.obs) {
    IOLog("HOUJI KEYS: SPMI MMIO map failed\n");
    thread_terminate(current_thread());
    return;
  }
  uint32_t ver = htRead(hk.core, 0x0000u);
  uint32_t count = htRead(hk.core, 0x0004u) & 0x7ffu;
  if ((ver >> 28) != 7u || count == 0) {
    IOLog("HOUJI KEYS: unexpected SPMI ver=%x count=%u\n", ver, count);
    thread_terminate(current_thread());
    return;
  }
  if (count > 512u) count = 512u;
  hk.ponApid = hkFindApid(0x013u, count);
  hk.volUpApid = hkFindApid(0x18du, count);
  IOLog("HOUJI KEYS: SPMI v7 ver=%x count=%u ponApid=%u volUpApid=%u\n",
        ver, count, hk.ponApid, hk.volUpApid);
  if (hk.ponApid == 0xffffu && hk.volUpApid == 0xffffu) {
    thread_terminate(current_thread());
    return;
  }

  int state[3] = {0, 0, 0};
  for (;;) {
    uint8_t pon = 0, gpio = 1;
    bool pok = hkReadObserver(hk.ponApid, 0x10u, &pon);
    bool gok = hkReadObserver(hk.volUpApid, 0x10u, &gpio);
    int now[3] = {
      (pon & 0x80u) ? 1 : 0,
      (gpio & 0x01u) ? 0 : 1,
      (pon & 0x40u) ? 1 : 0,
    };
    if (!pok && !gok) __atomic_add_fetch(&hk.errors, 1u, __ATOMIC_RELAXED);
    for (int k = 0; k < 3; k++) {
      bool valid = (k == 1) ? gok : pok;
      if (valid && now[k] != state[k]) {
        state[k] = now[k];
        if (state[k]) houji_dvfs_touch();
        sweet_hid_key(k, state[k]);
        __atomic_add_fetch(&hk.events, 1u, __ATOMIC_RELAXED);
      }
    }
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
