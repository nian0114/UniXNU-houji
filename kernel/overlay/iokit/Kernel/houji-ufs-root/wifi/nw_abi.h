/* The boundary between the board code and the WiFi module: what the board provides, and the calls into the module. Plain C types only. */
#ifndef NW_ABI_H
#define NW_ABI_H
#include <stdint.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
struct lx_platform {
  uint64_t (*now_ms)(void);
  void (*sleep_ms)(unsigned int ms);
  void (*poll)(void);
  void (*log)(int level, const char *line);
  void (*halt)(void);
  void *(*alloc)(size_t n);
  void (*free)(void *p);
  void *(*dma_alloc)(size_t n, uint64_t *bus);
  void (*dma_free)(size_t n, void *p, uint64_t bus);
  uint64_t (*dma_map)(void *p, size_t n, int dir);
  void (*dma_sync)(uint64_t bus, size_t n, int dir);
  int (*fw_get)(const char *name, const uint8_t **data, size_t *size);
  uint64_t (*now_ns)(void);
  uint64_t (*boottime_ns)(void);
  void (*busy_delay_us)(unsigned int us);
  void (*preempt_disable)(void);
  void (*preempt_enable)(void);
};
struct nw_board {
  void *bar; size_t bar_len;
  uint16_t device_id, msi_cap; int irq_base;
  int (*cfg_read)(int off, int size, uint32_t *v);
  int (*cfg_write)(int off, int size, uint32_t v);
  int (*msi_target)(uint32_t *lo, uint32_t *hi, uint32_t *data);
  void *(*map_phys)(uint64_t pa, size_t n);
  unsigned diagnostics;
};
struct nw_wifi_stats { uint32_t stage, scans, frames, beacons, bss_seen; int last_err; };
struct nw_buffer_stats {
  uint64_t skb_allocations, skb_frees, dma_allocations, dma_frees;
  uint64_t live_dma, peak_dma, clones, cow, expansions, copied_bytes, allocation_failures;
  uint64_t pool_hits, pool_misses, pool_cached_bytes, pool_cached_blocks;
};
void nw_wifi_buffer_stats_get(struct nw_buffer_stats *out);
void nw_wifi_buffer_pool_configure(size_t maximum_bytes);
void nw_wifi_buffer_pool_trim(void);
struct nw_bss_info {
  uint8_t bssid[6]; uint8_t ssid_len; uint8_t ssid[32];
  uint32_t freq_mhz; int8_t signal_dbm; uint16_t caps, beacon_int; uint32_t age_ms;
  uint16_t ie_len; uint8_t ie[384];
};
enum { NW_STA_OFF, NW_STA_IDLE, NW_STA_SCANNING, NW_STA_AUTH, NW_STA_ASSOC, NW_STA_KEYS, NW_STA_UP };
enum { NW_RES_OK = 0, NW_RES_NOT_FOUND = 1, NW_RES_TIMEOUT = 2, NW_RES_REJECTED = 3, NW_RES_BAD_KEY = 4, NW_RES_UNSUPPORTED = 5, NW_RES_FAILED = 6 };
struct nw_wifi_status { uint32_t state; int32_t result; uint8_t bssid[6]; uint8_t ssid_len; uint8_t ssid[32]; uint32_t freq_mhz; int8_t signal_dbm; uint8_t mac[6]; uint32_t channels, tx_rate_100kbps; };
typedef int (*nw_packet_reader)(void *context, size_t offset, void *destination, size_t length);
struct nw_wifi_events {
  void (*scan_done)(void);
  void (*connect_done)(int result);
  void (*link_lost)(int reason);
  void (*rx)(const uint8_t *eth, size_t len);
  void (*rx_flush)(void);
  void (*rx_packet)(void *context, size_t length, nw_packet_reader reader);
  void (*link_update)(const struct nw_wifi_status *status);
};
void nw_wifi_set_events(const struct nw_wifi_events *ev);
int nw_wifi_scan(const uint8_t *ssid, size_t len);
#define NW_WIFI_SCAN_FREQUENCIES_MAX 32
int nw_wifi_scan_frequencies(const uint8_t *ssid, size_t len, const uint32_t *mhz, size_t count);
int nw_wifi_bss_count(void);
int nw_wifi_bss_get(int i, struct nw_bss_info *out);
int nw_wifi_connect(const uint8_t *ssid, size_t len, const uint8_t *bssid, const char *pass, size_t plen);
void nw_wifi_disconnect(void);
void nw_wifi_power(int enabled);
int nw_wifi_tx(const uint8_t *eth, size_t len);
int nw_wifi_tx_packet(void *context, size_t length, nw_packet_reader reader, void (*release)(void *));
void nw_wifi_status_get(struct nw_wifi_status *st);
void nw_wifi_tx_reasons(char *text, int size);
void nw_wifi_link_state(char *text, int size);
int nw_wifi_start(const struct lx_platform *p, const struct nw_board *b);
void nw_wifi_set_platform(const struct lx_platform *p);
int nw_wifi_step(void);
void nw_wifi_irq_mode(int delivered);
void nw_wifi_irq_pending(uint32_t vectors);
void nw_wifi_poll(void);
unsigned nw_wifi_wait_ms(unsigned maximum);
void nw_wifi_stop(void);
extern struct nw_wifi_stats nw_wifi_stats;
extern volatile uint64_t nw_wifi_where[4];
#define NW_CONTROL_NAME "org.unixnu.wifi.control"
#define NW_CONTROL_GET_SESSION 1
enum nw_control_status {
  NW_CONTROL_OK, NW_CONTROL_INVALID, NW_CONTROL_BUSY, NW_CONTROL_NOT_READY,
  NW_CONTROL_AUTH_FAILED, NW_CONTROL_TIMED_OUT, NW_CONTROL_UNSUPPORTED,
  NW_CONTROL_NO_MEMORY, NW_CONTROL_NOT_FOUND, NW_CONTROL_DRIVER_FAILED,
  NW_CONTROL_STALE, NW_CONTROL_STATUS_MAX
};
enum nw_control_send_result { NW_CONTROL_SEND_OK, NW_CONTROL_SEND_AGAIN, NW_CONTROL_SEND_CLOSED };
struct nw_control_transport {
  void *context;
  int (*send)(void *context, uint64_t session, const void *bytes, size_t length);
  void (*wake)(void *context);
};
struct nw_control_stats {
  uint64_t accepted, dispatched, replies, events, malformed, stale_sessions, rx_full, tx_full, send_retries;
  size_t rx_bytes, tx_bytes; unsigned rx_items, tx_items;
  uint64_t connections, disconnections, active_session;
  unsigned last_operation, last_status;
};
int nw_wifi_control_transport_set(const struct nw_control_transport *transport);
int nw_wifi_control_attach(uint64_t *session);
void nw_wifi_control_detach(uint64_t session);
int nw_wifi_control_receive(uint64_t session, size_t length, int (*reader)(void *, void *, size_t), void *context);
void nw_wifi_control_writable(uint64_t session);
void nw_wifi_control_stats_get(struct nw_control_stats *stats);
#ifdef __cplusplus
}
#endif
#endif
