/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Pure C/C++ hardware constants and policy helpers for Xiaomi 14 (houji /
 * SM8650) PCIe RC0 and WCN7850 (qcom,cnss-kiwi, 17cb:1107) Stage 1 bring-up.
 * Zero IOKit/XNU dependencies so host tests compile and verify every helper.
 */
#ifndef HOUJI_WIFI_PCIE_POLICY_H
#define HOUJI_WIFI_PCIE_POLICY_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Verified device houji.dtb (/soc/qcom,pcie@1c00000) MMIO windows */
#define HOUJI_PCIE0_PARF_BASE       0x01c00000u
#define HOUJI_PCIE0_PARF_SIZE       0x00003000u
#define HOUJI_PCIE0_PHY_BASE        0x01c06000u
#define HOUJI_PCIE0_PHY_SIZE        0x00002000u
#define HOUJI_PCIE0_DBI_BASE        0x60000000u
#define HOUJI_PCIE0_DBI_SIZE        0x00001000u
#define HOUJI_PCIE0_ELBI_OFFSET     0x00000f20u
#define HOUJI_PCIE0_IATU_BASE       0x60001000u
#define HOUJI_PCIE0_IATU_SIZE       0x00001000u
#define HOUJI_PCIE0_ECAM_BASE       0x60100000u
#define HOUJI_PCIE0_ECAM_SIZE       0x00010000u
#define HOUJI_PCIE0_MMIO_BASE       0x60300000u
#define HOUJI_PCIE0_MMIO_SIZE       0x03d00000u
#define HOUJI_PCIE0_MMIO_LIMIT      0x63ffffffu
#define HOUJI_PCIE0_SLV_SPACE_SIZE  0x04000000u

/* Verified device TLMM GPIOs (base 0x0f100000, stride 0x1000) */
#define HOUJI_TLMM_BASE             0x0f100000u
#define HOUJI_TLMM_STRIDE           0x00001000u
#define HOUJI_TLMM_GPIO_WLAN_EN     16u
#define HOUJI_TLMM_GPIO_SW_CTRL     18u
#define HOUJI_TLMM_GPIO_WLAN_SW     19u
#define HOUJI_TLMM_GPIO_PERST       94u
#define HOUJI_TLMM_GPIO_CLKREQ      95u
#define HOUJI_TLMM_GPIO_WAKE        96u

/* Read-only TCSR PCIe0 100 MHz RefClk enable register (verified in ClockDxe.efi) */
#define HOUJI_TCSR_PCIE0_CLKREF_PA  0x01ff1000u
#define HOUJI_TCSR_PCIE0_CLKREF_OFF 0x00000100u

/* WCN7850 (qcom,cnss-kiwi, dtbo_a.img fragment 91) PCI identity */
#define HOUJI_WCN7850_VENDOR_ID     0x17cbu
#define HOUJI_WCN7850_DEVICE_ID     0x1107u
#define HOUJI_WCN7850_ID_WORD       ((HOUJI_WCN7850_DEVICE_ID << 16) | HOUJI_WCN7850_VENDOR_ID)

/* Qualcomm PCIe 2.7.0 / 1.9.0 (SM8650) PARF offsets */
#define HOUJI_PARF_SYS_CTRL             0x0000u
#define HOUJI_PARF_PM_CTRL              0x0020u
#define HOUJI_PARF_PM_STTS              0x0024u
#define HOUJI_PARF_PHY_CTRL             0x0040u
#define HOUJI_PARF_PHY_REFCLK           0x004cu
#define HOUJI_PARF_DBI_BASE_ADDR_V1     0x0168u
#define HOUJI_PARF_SLV_ADDR_SPACE_V1    0x016cu
#define HOUJI_PARF_MHI_CLK_RST_CTRL     0x0174u
#define HOUJI_PARF_Q2A_FLUSH            0x01acu
#define HOUJI_PARF_LTSSM                0x01b0u
#define HOUJI_PARF_DBI_BASE_ADDR_V2     0x0350u
#define HOUJI_PARF_DBI_BASE_ADDR_V2_HI  0x0354u
#define HOUJI_PARF_SLV_ADDR_SPACE_V2    0x0358u
#define HOUJI_PARF_SLV_ADDR_SPACE_V2_HI 0x035cu
#define HOUJI_PARF_ATU_BASE_ADDR        0x0634u
#define HOUJI_PARF_ATU_BASE_ADDR_HI     0x0638u
#define HOUJI_PARF_DEVICE_TYPE          0x1000u

/* Read-only GCC PCIe0 diagnostic base (0x16b000, verified in ClockDxe.efi) */
#define HOUJI_GCC_PCIE0_BASE            0x0016b000u

/* PARF bits */
#define HOUJI_PARF_SYS_CTRL_L1_CLK_RMV_DIS      (1u << 1)
#define HOUJI_PARF_SYS_CTRL_L23_CLK_RMV_DIS     (1u << 2)
#define HOUJI_PARF_SYS_CTRL_AUX_PWR_DET         (1u << 4)
#define HOUJI_PARF_SYS_CTRL_CORE_CLK_CGC_DIS    (1u << 6)
#define HOUJI_PARF_SYS_CTRL_MSTR_ACLK_CGC_DIS   (1u << 10)
#define HOUJI_PARF_SYS_CTRL_SLV_ACLK_CGC_DIS    (1u << 11)
#define HOUJI_PARF_SYS_CTRL_MST_WAKEUP_EN       (1u << 13)
#define HOUJI_PARF_SYS_CTRL_SLV_WAKEUP_EN       (1u << 14)
#define HOUJI_PARF_SYS_CTRL_MAC_PHY_PD_MUX_EN   (1u << 29)
#define HOUJI_PARF_PM_CTRL_REQ_NOT_ENTR_L1      (1u << 5)
#define HOUJI_PARF_PHY_CTRL_TEST_PWR_DOWN       (1u << 0)
#define HOUJI_PARF_PHY_REFCLK_USE_PAD           (1u << 12)
#define HOUJI_PARF_PHY_REFCLK_SSP_EN            (1u << 16)
#define HOUJI_PARF_MHI_A7_AXI_CLK_EN            (1u << 0)
#define HOUJI_PARF_MHI_MSTR_AXI_CLK_EN          (1u << 1)
#define HOUJI_PARF_MHI_BYPASS                   (1u << 4)
#define HOUJI_PARF_LTSSM_EN                     (1u << 8)
#define HOUJI_PARF_LTSSM_STATE_MASK             0x3fu
#define HOUJI_PARF_LTSSM_L0                     0x11u
#define HOUJI_PARF_DEVICE_TYPE_RC               0x4u

/* ELBI / DWC DBI offsets */
#define HOUJI_ELBI_SYS_CTRL         0x0000u
#define HOUJI_ELBI_LT_ENABLE        (1u << 0)
#define HOUJI_ELBI_SYS_STTS         0x0008u
#define HOUJI_ELBI_XMLH_LINK_UP     (1u << 10)
#define HOUJI_DBI_VENDOR_DEVICE     0x0000u
#define HOUJI_DBI_COMMAND           0x0004u
#define HOUJI_DBI_CLASS_REV         0x0008u
#define HOUJI_DBI_BUS_NUMBERS       0x0018u
#define HOUJI_DBI_MEM_BASE_LIMIT    0x0020u
#define HOUJI_DBI_PREF_BASE_LIMIT   0x0024u
#define HOUJI_DBI_EXP_LINK_CAP      0x007cu
#define HOUJI_DBI_EXP_LINK_CTRL_STS 0x0080u
#define HOUJI_DBI_LNKSTA_DLLLA      (1u << 29)
#define HOUJI_DBI_PORT_LINK_CTRL    0x0710u
#define HOUJI_DBI_PORT_DEBUG0       0x0728u
#define HOUJI_DBI_PORT_DEBUG1       0x072cu
#define HOUJI_DBI_DEBUG1_LINK_UP    (1u << 4)
#define HOUJI_DBI_DEBUG1_TRAINING   (1u << 29)
#define HOUJI_DBI_LINK_WIDTH_SPEED  0x080cu
#define HOUJI_DBI_MISC_CONTROL_1    0x08bcu
#define HOUJI_DBI_RO_WR_EN          (1u << 0)
#define HOUJI_DBI_AUX_CLK_FREQ      0x0b40u

/* Unrolled iATU outbound region layout (stride 0x200) */
#define HOUJI_IATU_OUTBOUND_STRIDE  0x0200u
#define HOUJI_IATU_REGION_CTRL1     0x0000u
#define HOUJI_IATU_REGION_CTRL2     0x0004u
#define HOUJI_IATU_LOWER_BASE       0x0008u
#define HOUJI_IATU_UPPER_BASE       0x000cu
#define HOUJI_IATU_LIMIT            0x0010u
#define HOUJI_IATU_LOWER_TARGET     0x0014u
#define HOUJI_IATU_UPPER_TARGET     0x0018u
#define HOUJI_IATU_TYPE_MEM         0x0000u
#define HOUJI_IATU_TYPE_CFG0        0x0004u
#define HOUJI_IATU_ENABLE           0x80000000u

/* QMP v6.20 PHY status / reset / power-down offsets from houji.dtb */
#define HOUJI_PHY_COM_C_READY_STTS  0x01f8u
#define HOUJI_PHY_SW_RESET          0x0200u
#define HOUJI_PHY_PCS_STATUS        0x0214u
#define HOUJI_PHY_PCS_STATUS2       0x0218u
#define HOUJI_PHY_STATUS_BIT        (1u << 6)
#define HOUJI_PHY_POWER_DOWN_CTRL   0x0240u
#define HOUJI_PHY_START_CTRL        0x0244u

/* Verified ClockDxe.efi GCC PCIe0 read-only diagnostic offsets (base 0x0016b000) */
#define HOUJI_GCC_PCIE0_PIPE_CBCR_OFF   0x0048u
#define HOUJI_GCC_PCIE0_PIPE_MUXR_OFF   0x0070u

/* Read-only MHI register offsets inside WCN7850 BAR0 */
#define HOUJI_MHI_REGLEN_OFF        0x0100u
#define HOUJI_MHI_VER_OFF           0x0108u
#define HOUJI_MHI_CFG_OFF           0x0110u
#define HOUJI_MHI_STATUS_OFF        0x0148u

/* Stage 1 probe progress stages */
enum {
  HOUJI_WIFI_STAGE_IDLE       = 0u,
  HOUJI_WIFI_STAGE_GPIO       = 1u,
  HOUJI_WIFI_STAGE_PHY        = 2u,
  HOUJI_WIFI_STAGE_LINK       = 3u,
  HOUJI_WIFI_STAGE_ENUM       = 4u,
  HOUJI_WIFI_STAGE_BAR0_READY = 5u,
};

typedef struct {
  uint32_t offset;
  uint32_t ctrl1;
  uint32_t ctrl2;
  uint32_t lower_base;
  uint32_t upper_base;
  uint32_t limit;
  uint32_t lower_target;
  uint32_t upper_target;
} houji_iatu_window;

typedef struct {
  uint32_t ltssm_state;
  unsigned xmlh_link_up;
  unsigned in_l0;
  unsigned link_speed;
  unsigned link_width;
} houji_pcie_link_info;

static inline uint32_t houji_wifi_tlmm_phys(uint32_t gpio) {
  return HOUJI_TLMM_BASE + gpio * HOUJI_TLMM_STRIDE;
}

/* Build TLMM GPIO_CFG word preserving upper owner bits while setting pull/func/drive/OE. */
static inline uint32_t houji_wifi_tlmm_cfg(uint32_t orig_cfg, uint32_t pull,
                                           uint32_t func, uint32_t drive,
                                           unsigned output_enable) {
  uint32_t cleared = orig_cfg & ~0x3ffu;
  return cleared | (pull & 3u) | ((func & 0xfu) << 2) |
         ((drive & 7u) << 6) | (output_enable ? (1u << 9) : 0u);
}

/* Encode an unrolled outbound iATU window. Returns 1 on valid input, 0 otherwise. */
static inline int houji_wifi_encode_iatu(unsigned region, uint32_t type,
                                         uint32_t cpu_base, uint32_t size,
                                         uint32_t pci_target,
                                         houji_iatu_window *out) {
  if (!out || region >= 8u || size == 0u) return 0;
  if (type != HOUJI_IATU_TYPE_MEM && type != HOUJI_IATU_TYPE_CFG0) return 0;
  if ((cpu_base & 0xfffu) != 0u || (size & 0xfffu) != 0u) return 0;
  if (cpu_base > 0xffffffffu - (size - 1u)) return 0;
  out->offset       = region * HOUJI_IATU_OUTBOUND_STRIDE;
  out->ctrl1        = type;
  out->ctrl2        = HOUJI_IATU_ENABLE;
  out->lower_base   = cpu_base;
  out->upper_base   = 0u;
  out->limit        = cpu_base + (size - 1u);
  out->lower_target = pci_target;
  out->upper_target = 0u;
  return 1;
}

/* Encode PCI CFG0 target address for bus/dev/fn in DWC iATU LOWER_TARGET. */
static inline uint32_t houji_wifi_cfg0_target(uint32_t bus, uint32_t dev, uint32_t fn) {
  return ((bus & 0xffu) << 24) | ((dev & 0x1fu) << 19) | ((fn & 0x7u) << 16);
}

/* Decode PCIe link state from DWC DEBUG0/DEBUG1/LNKSTA, PARF_LTSSM, and ELBI_SYS_STTS. */
static inline houji_pcie_link_info houji_wifi_decode_link_dwc(uint32_t parf_ltssm,
                                                              uint32_t elbi_stts,
                                                              uint32_t dbi_link_ctrl_sts,
                                                              uint32_t dbg0,
                                                              uint32_t dbg1) {
  houji_pcie_link_info info;
  uint32_t link_sts = (dbi_link_ctrl_sts >> 16) & 0xffffu;
  uint32_t dwc_ltssm = dbg0 & HOUJI_PARF_LTSSM_STATE_MASK;
  unsigned dwc_up = ((dbg1 & HOUJI_DBI_DEBUG1_LINK_UP) != 0u &&
                     (dbg1 & HOUJI_DBI_DEBUG1_TRAINING) == 0u) ? 1u : 0u;
  unsigned dllla = (dbi_link_ctrl_sts & HOUJI_DBI_LNKSTA_DLLLA) != 0u ? 1u : 0u;
  unsigned legacy_up = ((elbi_stts & HOUJI_ELBI_XMLH_LINK_UP) != 0u &&
                        (parf_ltssm & HOUJI_PARF_LTSSM_STATE_MASK) == HOUJI_PARF_LTSSM_L0) ? 1u : 0u;
  info.ltssm_state  = (dbg0 != 0u) ? dwc_ltssm : (parf_ltssm & HOUJI_PARF_LTSSM_STATE_MASK);
  info.xmlh_link_up = (dwc_up || dllla || (elbi_stts & HOUJI_ELBI_XMLH_LINK_UP) != 0u) ? 1u : 0u;
  info.in_l0        = (dwc_up || dllla || legacy_up) ? 1u : 0u;
  info.link_speed   = link_sts & 0xfu;
  info.link_width   = (link_sts >> 4) & 0x3fu;
  return info;
}

static inline houji_pcie_link_info houji_wifi_decode_link(uint32_t parf_ltssm,
                                                          uint32_t elbi_stts,
                                                          uint32_t dbi_link_ctrl_sts) {
  return houji_wifi_decode_link_dwc(parf_ltssm, elbi_stts, dbi_link_ctrl_sts, 0u, 0u);
}

/* Validate EP Vendor/Device ID word read from ECAM offset 0x00. */
static inline int houji_wifi_is_wcn7850_id(uint32_t id_word) {
  uint32_t vid = id_word & 0xffffu;
  uint32_t did = (id_word >> 16) & 0xffffu;
  if (vid == 0x0000u || vid == 0xffffu || did == 0x0000u || did == 0xffffu) return 0;
  return (vid == HOUJI_WCN7850_VENDOR_ID && did == HOUJI_WCN7850_DEVICE_ID) ? 1 : 0;
}

/* Decode and validate a 32/64-bit memory BAR0 size mask against houji PCIe0 MMIO window. */
static inline int houji_wifi_validate_bar0(uint32_t bar_mask_raw,
                                           uint32_t assigned_base,
                                           uint32_t *out_size,
                                           unsigned *out_is_64bit) {
  if (!out_size || !out_is_64bit) return 0;
  if (bar_mask_raw == 0u || bar_mask_raw == 0xffffffffu) return 0;
  if ((bar_mask_raw & 1u) != 0u) return 0; /* Reject IO BAR */
  uint32_t mem_type = (bar_mask_raw >> 1) & 3u;
  if (mem_type != 0u && mem_type != 2u) return 0; /* Only 32-bit (0) or 64-bit (2) */
  uint32_t addr_mask = bar_mask_raw & ~0xfu;
  if (addr_mask == 0u) return 0;
  uint32_t size = (~addr_mask) + 1u;
  /* Size must be a power of two between 4 KiB and 32 MiB and fit inside MMIO window */
  if (size < 0x1000u || size > 0x02000000u || (size & (size - 1u)) != 0u) return 0;
  if (assigned_base < HOUJI_PCIE0_MMIO_BASE ||
      (assigned_base & (size - 1u)) != 0u ||
      assigned_base > HOUJI_PCIE0_MMIO_LIMIT - (size - 1u)) {
    return 0;
  }
  *out_size = size;
  *out_is_64bit = (mem_type == 2u) ? 1u : 0u;
  return 1;
}

/* Compute naturally aligned BAR0 base inside 0x60300000..0x63ffffff (e.g. 0x60400000 for 2 MiB). */
static inline int houji_wifi_assign_bar0(uint32_t bar_mask_raw,
                                         uint32_t *out_base,
                                         uint32_t *out_size,
                                         unsigned *out_is_64bit) {
  if (!out_base || !out_size || !out_is_64bit) return 0;
  if (bar_mask_raw == 0u || bar_mask_raw == 0xffffffffu || (bar_mask_raw & 1u) != 0u) return 0;
  uint32_t addr_mask = bar_mask_raw & ~0xfu;
  if (addr_mask == 0u) return 0;
  uint32_t size = (~addr_mask) + 1u;
  if (size < 0x1000u || size > 0x02000000u || (size & (size - 1u)) != 0u) return 0;
  uint32_t aligned = (HOUJI_PCIE0_MMIO_BASE + (size - 1u)) & ~(size - 1u);
  if (!houji_wifi_validate_bar0(bar_mask_raw, aligned, out_size, out_is_64bit)) return 0;
  *out_base = aligned;
  return 1;
}

/* Encode Type 1 RC Memory Base/Limit register (DBI offset 0x20). */
static inline uint32_t houji_wifi_rc_mem_base_limit(uint32_t base, uint32_t limit) {
  return ((base >> 16) & 0xfff0u) | (limit & 0xfff00000u);
}

#ifdef __cplusplus
}
#endif

#endif /* HOUJI_WIFI_PCIE_POLICY_H */
