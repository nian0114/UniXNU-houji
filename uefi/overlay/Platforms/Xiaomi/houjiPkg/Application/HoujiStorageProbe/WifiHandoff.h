/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Native UEFI firmware handoff for Xiaomi 14 (houji / SM8650) WCN7850 Wi-Fi
 * and PCIe RC0. Uses OEM CmdDbDxe, RpmhDxe, and ClockDxe exclusively; no
 * direct PMIC, GCC, or RSC register writes.
 *
 * Verified against device houji.dtb, dtbo_a.img fragment 91 (qcom,cnss-kiwi),
 * and OEM ClockDxe.efi:
 * - WCN7850 rails: ldob15 1800 mV, ldoc3 1200 mV, ldok6 1800 mV, smpc1 1316 mV,
 *                  smpc2 976 mV, smpc3 916 mV, smpc6 1864 mV, smpi4 940 mV.
 * - PCIe0 PHY analog rails: ldoi1 880 mV, ldoe3 880 mV, ldoi3 1200 mV.
 * - Optional RPMh RF clock: rfclka1 / rfclk1 (RPMH_RF_CLK1).
 * - PCIe0 power domains & clocks via ClockDxe.
 */
#ifndef HOUJI_WIFI_HANDOFF_H
#define HOUJI_WIFI_HANDOFF_H

typedef struct {
  CONST CHAR8 *Name;
  UINT32       Millivolts;
  BOOLEAN      SetMode;
} HJ_WIFI_RAIL;

STATIC BOOLEAN mWifiHandoffReady;
STATIC VOID   *mWifiPowerClient;

STATIC EFI_STATUS
PrepareWifiHandoff (VOID)
{
  EFI_CLOCK_PROTOCOL *Clock = NULL;
  HJ_RPMH            *Rpmh  = NULL;
  HJ_CMDDB           *Db    = NULL;

  CONST HJ_WIFI_RAIL Rails[11] = {
    // WCN7850 (qcom,cnss-kiwi, dtbo_a.img fragment 91)
    {"ldob15", 1800, TRUE }, // vdd-wlan-io        (L15B, pmic5-ldo)
    {"ldoc3",  1200, TRUE }, // vdd-wlan-io12      (L3C,  pmic5-ldo)
    {"ldok6",  1800, TRUE }, // vdd-wlan-ant-share (L6K,  pmic5-ldo)
    {"smpc1",  1316, TRUE }, // vdd-wlan-rfa2      (S1C,  pmic5-ftsmps)
    {"smpc2",   976, FALSE}, // vdd-wlan-aon       (S2C,  SMPS)
    {"smpc3",   916, FALSE}, // vdd-wlan-dig       (S3C,  SMPS)
    {"smpc6",  1864, FALSE}, // vdd-wlan-rfa1      (S6C,  SMPS)
    {"smpi4",   940, FALSE}, // vdd-wlan           (S4I,  SMPS)
    // PCIe0 QMP PHY analog supplies (SM8650 houji.dtb)
    {"ldoi1",   880, TRUE }, // vreg-qref / vdda-phy (pmic5-ldo)
    {"ldoe3",   880, TRUE }, // vreg-0p9             (pmic5-ldo)
    {"ldoi3",  1200, TRUE }, // vreg-1p2 / vdda-pll  (pmic5-ldo)
  };

  CONST CHAR8 *Domains[2] = {
    "gcc_pcie_0_gdsc",
    "gcc_pcie_0_phy_gdsc",
  };

  CONST CHAR8 *Clocks[12] = {
    "gcc_cnoc_pcie_sf_axi_clk",
    "gcc_ddrss_pcie_sf_qtb_clk",
    "gcc_hlos1_vote_aggre_noc_mmu_pcie_qtb_clk",
    "gcc_aggre_noc_pcie_axi_clk",
    "gcc_cfg_noc_pcie_anoc_ahb_clk",
    "gcc_pcie_0_cfg_ahb_clk",
    "gcc_pcie_0_mstr_axi_clk",
    "gcc_pcie_0_slv_axi_clk",
    "gcc_pcie_0_slv_q2a_axi_clk",
    "gcc_pcie_0_aux_clk",
    "gcc_pcie_0_phy_rchng_clk",
    "tcsr_pcie_0_clkref_en",
  };

  CONST CHAR8 *RfClkCandidates[2] = {
    "rfclka1",
    "rfclk1",
  };

  UINT32 Address[ARRAY_SIZE (Rails)];
  UINT32 Slave[ARRAY_SIZE (Rails)];
  UINTN  DomainIds[ARRAY_SIZE (Domains)];
  UINTN  ClockIds[ARRAY_SIZE (Clocks)];
  UINTN  PipeClockId   = 0;
  BOOLEAN HasPipeClock = FALSE;
  UINT32 RfClkAddr     = 0;
  CONST CHAR8 *RfClkName = NULL;

  mWifiHandoffReady = FALSE;

  EFI_STATUS Status = gBS->LocateProtocol (&gEfiClockProtocolGuid, NULL, (VOID **)&Clock);
  Print (L"HOUJI WIFI UEFI: Clock locate=%r\n", Status);
  if (EFI_ERROR (Status) || !Clock || !Clock->GetClockID || !Clock->EnableClock ||
      !Clock->IsClockOn || !Clock->GetClockPowerDomainID || !Clock->EnableClockPowerDomain) {
    return EFI_NOT_READY;
  }

  Status = gBS->LocateProtocol (&mProvidesRpmhDxe, NULL, (VOID **)&Rpmh);
  if (EFI_ERROR (Status)) {
    Print (L"HOUJI WIFI UEFI: RPMh locate=%r\n", Status);
    return Status;
  }
  Status = gBS->LocateProtocol (&mCmdDb, NULL, (VOID **)&Db);
  if (EFI_ERROR (Status)) {
    Print (L"HOUJI WIFI UEFI: CmdDb locate=%r\n", Status);
    return Status;
  }
  Print (L"HOUJI WIFI UEFI: Clock=%lx RPMh=%lx CmdDb=%lx\n", Clock->Version, Rpmh->Version, Db->Version);
  if (Rpmh->Version != 0x10001 || Db->Version != 0x10000 ||
      !Rpmh->Methods[1] || !Rpmh->Methods[5] || !Rpmh->Methods[18] || !Rpmh->Methods[11] ||
      !Db->Methods[1] || !Db->Methods[7]) {
    return EFI_UNSUPPORTED;
  }

  // Phase 1: Resolve every CmdDb resource, power domain, and clock before issuing any vote.
  for (UINTN I = 0; I < ARRAY_SIZE (Rails); I++) {
    Address[I] = 0;
    Slave[I]   = 0;
    Status = ((HJ_QUERY)Db->Methods[1]) (Db, Rails[I].Name, &Address[I]);
    if (!EFI_ERROR (Status)) {
      Status = ((HJ_QUERY)Db->Methods[7]) (Db, Rails[I].Name, &Slave[I]);
    }
    Print (L"HOUJI WIFI UEFI: rail %a address=%x slave=%u query=%r\n",
           Rails[I].Name, Address[I], Slave[I], Status);
    if (EFI_ERROR (Status) || Slave[I] != 4 || (Address[I] >> 16) != 4 ||
        (Address[I] & 15) != 0 || Address[I] == 0) {
      return EFI_UNSUPPORTED;
    }
    for (UINTN K = 0; K < I; K++) {
      if (Address[K] == Address[I]) {
        Print (L"HOUJI WIFI UEFI: duplicate CmdDb address %x for %a\n", Address[I], Rails[I].Name);
        return EFI_UNSUPPORTED;
      }
    }
  }

  for (UINTN I = 0; I < ARRAY_SIZE (RfClkCandidates); I++) {
    UINT32 Addr = 0, Slv = 0;
    EFI_STATUS Qs = ((HJ_QUERY)Db->Methods[1]) (Db, RfClkCandidates[I], &Addr);
    if (!EFI_ERROR (Qs)) {
      Qs = ((HJ_QUERY)Db->Methods[7]) (Db, RfClkCandidates[I], &Slv);
    }
    Print (L"HOUJI WIFI UEFI: rfclk %a address=%x slave=%u query=%r\n",
           RfClkCandidates[I], Addr, Slv, Qs);
    if (!EFI_ERROR (Qs) && Slv == 4 && (Addr >> 16) == 4 && (Addr & 15) == 0 && Addr != 0) {
      RfClkAddr = Addr;
      RfClkName = RfClkCandidates[I];
      break;
    }
  }

  for (UINTN I = 0; I < ARRAY_SIZE (Domains); I++) {
    DomainIds[I] = 0;
    Status = Clock->GetClockPowerDomainID (Clock, Domains[I], &DomainIds[I]);
    Print (L"HOUJI WIFI UEFI: domain %a id=%lx lookup=%r\n", Domains[I], DomainIds[I], Status);
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }

  EFI_STATUS ClockLookupStatus = EFI_SUCCESS;
  for (UINTN I = 0; I < ARRAY_SIZE (Clocks); I++) {
    ClockIds[I] = 0;
    Status = Clock->GetClockID (Clock, Clocks[I], &ClockIds[I]);
    Print (L"HOUJI WIFI UEFI: clock %a id=%lx lookup=%r\n", Clocks[I], ClockIds[I], Status);
    if (EFI_ERROR (Status) && !EFI_ERROR (ClockLookupStatus)) {
      ClockLookupStatus = Status;
    }
  }
  if (EFI_ERROR (ClockLookupStatus)) {
    return ClockLookupStatus;
  }

  Status = Clock->GetClockID (Clock, "gcc_pcie_0_pipe_clk", &PipeClockId);
  Print (L"HOUJI WIFI UEFI: clock gcc_pcie_0_pipe_clk id=%lx lookup=%r\n", PipeClockId, Status);
  if (!EFI_ERROR (Status)) {
    HasPipeClock = TRUE;
  }

  // Phase 2: Create RPMh DRV 2 client and vote all 11 rails (+ optional RF clock).
  BOOLEAN Valid = FALSE;
  Status = ((HJ_DRV_VALID)Rpmh->Methods[1]) (2, &Valid);
  if (EFI_ERROR (Status) || !Valid) {
    return EFI_UNSUPPORTED;
  }
  Status = ((HJ_CREATE)Rpmh->Methods[5]) (2, "houji-wifi-vdd", &mWifiPowerClient);
  if (EFI_ERROR (Status) || !mWifiPowerClient) {
    return EFI_NOT_READY;
  }

  for (UINTN I = 0; I < ARRAY_SIZE (Rails); I++) {
    CONST UINT32 Offsets[3] = {0, 8, 4};
    CONST UINT32 Values[3]  = {Rails[I].Millivolts, 7, 1}; // voltage(mV), HPM=7, enable=1
    for (UINTN J = 0; J < 3; J++) {
      if (J == 1 && !Rails[I].SetMode) {
        continue;
      }
      UINT32 Request = 0;
      Status = ((HJ_ISSUE)Rpmh->Methods[18]) (
        mWifiPowerClient, 0, TRUE, Address[I] + Offsets[J], Values[J], &Request
      );
      if (!EFI_ERROR (Status) && Request) {
        Status = ((HJ_WAIT)Rpmh->Methods[11]) (mWifiPowerClient, Request);
      }
      Print (L"HOUJI WIFI UEFI: %a+%u=%u request=%u result=%r\n",
             Rails[I].Name, Offsets[J], Values[J], Request, Status);
      if (EFI_ERROR (Status)) {
        return Status;
      }
    }
  }

  if (RfClkAddr != 0 && RfClkName != NULL) {
    UINT32 Request = 0;
    EFI_STATUS RfStatus = ((HJ_ISSUE)Rpmh->Methods[18]) (
      mWifiPowerClient, 0, TRUE, RfClkAddr + 4, 1, &Request
    );
    if (!EFI_ERROR (RfStatus) && Request) {
      RfStatus = ((HJ_WAIT)Rpmh->Methods[11]) (mWifiPowerClient, Request);
    }
    Print (L"HOUJI WIFI UEFI: %a+4=1 request=%u result=%r\n", RfClkName, Request, RfStatus);
  }

  // Phase 3: Enable PCIe0 GDSCs and clocks through OEM ClockDxe.
  for (UINTN I = 0; I < ARRAY_SIZE (Domains); I++) {
    Status = Clock->EnableClockPowerDomain (Clock, DomainIds[I]);
    Print (L"HOUJI WIFI UEFI: domain %a enable=%r\n", Domains[I], Status);
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }

  for (UINTN I = 0; I < ARRAY_SIZE (Clocks); I++) {
    BOOLEAN On = FALSE;
    UINT32 TargetHz = 0;
    if (AsciiStrCmp (Clocks[I], "gcc_pcie_0_aux_clk") == 0) {
      TargetHz = 19200000;
    } else if (AsciiStrCmp (Clocks[I], "gcc_pcie_0_phy_rchng_clk") == 0) {
      TargetHz = 100000000;
    }
    if (TargetHz != 0 && Clock->SetClockFreqHz != NULL) {
      UINT32 ActualHz = 0;
      EFI_STATUS FreqStatus = Clock->SetClockFreqHz (
        Clock, ClockIds[I], TargetHz, EFI_CLOCK_FREQUENCY_HZ_EXACT, &ActualHz
      );
      Print (L"HOUJI WIFI UEFI: clock %a rate=%u/%u result=%r\n",
             Clocks[I], ActualHz, TargetHz, FreqStatus);
    }
    Status = Clock->EnableClock (Clock, ClockIds[I]);
    if (!EFI_ERROR (Status)) {
      (VOID)Clock->IsClockOn (Clock, ClockIds[I], &On);
    }
    Print (L"HOUJI WIFI UEFI: clock %a on=%u result=%r\n", Clocks[I], On, Status);
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }

  // Pipe clock is externally sourced from QMP PHY (BRANCH_HALT_SKIP): enable branch
  // without requiring IsClockOn==TRUE before XNU runs the QMP PHY init sequence.
  if (HasPipeClock) {
    BOOLEAN PipeOn = FALSE;
    EFI_STATUS PipeStatus = Clock->EnableClock (Clock, PipeClockId);
    if (!EFI_ERROR (PipeStatus)) {
      (VOID)Clock->IsClockOn (Clock, PipeClockId, &PipeOn);
    }
    Print (L"HOUJI WIFI UEFI: clock gcc_pcie_0_pipe_clk on=%u result=%r\n", PipeOn, PipeStatus);
  }

  mWifiHandoffReady = TRUE;
  Print (L"HOUJI WIFI UEFI: firmware handoff ready; native votes retained\n");
  return EFI_SUCCESS;
}

#endif /* HOUJI_WIFI_HANDOFF_H */
