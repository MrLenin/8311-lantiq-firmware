# Shipping omcid (v7.5.1) vs SDK Source (v4.5.0): Divergence Analysis

Systematic comparison of functions in the shipping G-010S-P omcid binary against
the Lantiq GPON SDK v4.5.0 source we're building from. Identifies what the vendor
build added or changed, and what we need to replicate.

## Status Legend

| Symbol | Meaning |
|--------|---------|
| FIXED  | Already implemented in our custom source build |
| TODO   | Needs implementation |
| N/A    | Not needed for our use case |
| EXISTS | Already present in v4.5.0 (no action needed) |

---

## 1. Already Fixed (Phase 3 + ME 171)

These were binary patches in the shipping firmware that we've replaced with
clean source-level modifications.

| Feature | Source File | Status |
|---------|-----------|--------|
| SW Image version override (0x84CE) | `omci_api_sw_image_falcon.c` | **FIXED** |
| SW Image reboot NOP (0x417B6) | `omci_api_sw_image.c` | **FIXED** |
| fw_update_guard (shell wrappers → source) | `omci_api_sw_image_falcon.c` | **FIXED** |
| PPTP admin_state force-unlock | `omci_pptp_ethernet_uni.c` | **FIXED** |
| Sync Time → settimeofday() | `omci_onu_g.c` | **FIXED** |
| ME 171 association_type=1 (mapper) | `omci_api_extended_vlan_config_data.c` | **FIXED** |
| ME 171 3-way dispatch (LAN/GEM/pMapper) | `omci_api_extended_vlan_config_data.c` | **FIXED** |
| ME 290 802.1x enforcement ioctl | `omci_api_dot1x_port_ext_pkg.c` | **FIXED** |

---

## 2. Vendor Additions — HIGH Priority

Functions in the shipping binary that v4.5.0 lacks. These are queried by real
OLTs and affect operational functionality.

### 2a. ANI-G Optical Monitoring Getters (ME 263, attrs 3-7)

| Function | Status |
|----------|--------|
| `omci_api_ani_g_laser_bias_current_get` | **FIXED** — `omci_api_ani_g.c:248` |
| `omci_api_ani_g_laser_temperature_get` | **FIXED** — `omci_api_ani_g.c:277` |
| `omci_api_ani_g_supply_voltage_get` | **FIXED** — `omci_api_ani_g.c:305` |
| `omci_api_ani_g_gem_block_len_get` | **FIXED** — `omci_api_ani_g.c` |

Implemented in Phase 4. Self-test handler also added to `omci_ani_g.c`.

### 2b. PPTP Ethernet UNI State Getters (ME 11, attrs 5-6)

| Function | Status |
|----------|--------|
| `omci_api_pptp_ethernet_uni_oper_state_get` | **FIXED** — `omci_api_pptp_ethernet_uni.c:604` |
| `omci_api_pptp_ethernet_uni_sensed_type_get` | **FIXED** — `omci_api_pptp_ethernet_uni.c:641` |
| `omci_api_pptp_ethernet_uni_lan_is_available` | **FIXED** — `omci_api_pptp_ethernet_uni.c` |
| `omci_api_pptp_ethernet_uni_lan_port_enable` | **FIXED** — `omci_api_pptp_ethernet_uni.c` |

Implemented in Phase 4. Getter callbacks wired in `omci_pptp_ethernet_uni.c`.

---

## 3. Vendor Additions — MEDIUM Priority

Features that some ISPs or OLTs may use, but not critical for basic operation.

### 3a. ONU Loop Detection (vendor-specific ME ~65528)

4 API functions + full ME handler with timers, state machine, and alarms.

| Function | Status |
|----------|--------|
| `omci_api_onu_loop_detection_create` | **FIXED** — Phase A |
| `omci_api_onu_loop_detection_destroy` | **FIXED** — Phase A |
| `omci_api_onu_loop_detection_update` | **FIXED** — Phase A |
| `omci_api_onu_loop_detection_packet_send` | **FIXED** — Phase A |
| ME handler (init/shutdown/update/timers) | **FIXED** — Phase B |

### 3b. Performance Monitoring Extensions

| Category | Functions | Status |
|----------|-----------|--------|
| PMHD total_cnt_get | 8 functions | **FIXED** — Phase D |
| PMHD cnt_reset | 3 functions | **FIXED** — Phase D |
| MTU exceeded discard | 2 functions | **FIXED** — Phase D |

### 3c. MAC Bridge Port Filter Extensions

| Function | Status |
|----------|--------|
| `omci_api_mac_bridge_port_filter_assign` | **FIXED** — Phase C |
| GPE exception table writes (was `#if 0`) | **FIXED** — Phase C |
| `omci_api_mac_bridge_port_filter_table_entry_add` | **FIXED** — Phase C |
| `omci_api_mac_bridge_port_filter_table_entry_remove` | **FIXED** — Phase C |

---

## 4. Vendor Additions — LOW Priority

### 4a. Energy Consumption PMHD (ME 343)

| Function | v8.6.3 source |
|----------|---------------|
| `omci_api_energy_consumption_pmhd_cnt_get` | `omci_energy_consumption_pmhd.c` |
| `omci_api_energy_consumption_pmhd_total_cnt_get` | same |

**Priority:** LOW — power monitoring, not critical for operation.

### 4b. PPTP LCT UNI (ME 12)

Line Card Test UNI management — 3 functions. Not used in typical GPON deployments.

### 4c. IEEE 802.1ag CFM (MEs 299-306)

Ethernet OAM connectivity fault management. 8 ME classes in v8.6.3.
Not in v4.5.0. Unlikely to be in shipping binary (no strings found).

---

## 5. Functions Present in BOTH (No Action Needed)

These were initially suspected as missing but confirmed present in v4.5.0:

| Function | v4.5.0 Location |
|----------|-----------------|
| `omci_api_bridge_flooding_modify` | `omci_api_table_access.c:158` |
| `omci_api_onu_event_link_state_change` | `omci_api_event.c:90` |
| ext_vlan_action_add / ext_vlan_filter | Different naming: `tag_oper_table_entry_add()` |
| VEIP (ME 329) | `omci_virtual_ethernet_interface_point.c` |
| MAC Bridge Port Extension (ME 208/240) | `omci_mac_bridge_port_extension.c` |

---

## 6. Behavioral Divergences (Same Function, Different Implementation)

These functions exist in v4.5.0 but the shipping binary may implement them
differently due to vendor modifications.

### 6a. ME 171 Extended VLAN — FIXED

The major behavioral difference was:
- v4.5.0: 2-way dispatch (LAN vs GEM), no mapper support
- Shipping: 3-way dispatch (LAN/GEM/pMapper), full mapper fanout
- **Status: FIXED** in our source

### 6b. ME 171 association types 4, 7-10

| Type | Entity | Status |
|------|--------|--------|
| 4 | IPv6 host config data | **FIXED** — Phase F |
| 7 | MoCA | N/A (no MoCA) |
| 8 | 802.11 | N/A (no WiFi) |
| 9 | Ethernet Flow TP | LOW (rarely used) |
| 10 | VEIP (ME 329) | **FIXED** — Phase F |

ME 78 also updated: association types 3 (IP host), 4 (IPv6 host), 10/11 added.

### 6c. SW Image — CONFIRMED DIFFERENT

Shipping binary has hardcoded behaviors. Our source replaces all of them:
- Version override → UCI/fwenv read
- Reboot on activate → NOP
- fw_update_guard → shadow + capture in source

### 6d. Behavioral Differences — Audited and Fixed

All functions decompiled from stock v7.5.1 and compared (Phases 8-13, E, I):

- `omci_api_mac_bridge_port_config_data_update` — **FIXED** Phase E (11→9 params, umc_flood, tp_type 7/0xFF)
- `omci_api_gem_port_network_ctp_update` — **FIXED** Phase I (traffic mgmt opt, dual-dir meter cleanup)
- `omci_api_tcont_create` — **FIXED** (audited, matches stock)
- `omci_api_priority_queue_update` — **FIXED** Phase I (sbin_enable, avg_weight, >>9 shift)
- `omci_api_traffic_scheduler_update` — **FIXED** Phase I (TBS for scheduler_index 0x43)
- `omci_api_vlan_tagging_filter_data_update` — **FIXED** (audited, matches stock)

---

## 7. Recommended Implementation Order

1. **ANI-G optical getters** — High impact, straightforward (extract from existing BOSA ioctl data)
2. **PPTP Ethernet UNI state getters** — High impact, straightforward (extend existing ioctl calls)
3. **ME 171 association_type=10 (VEIP)** — Medium impact, follows existing pattern
4. **Loop detection** — Medium impact, backport from v8.6.3
5. **PMHD total counters** — Medium impact, extend existing PM framework
6. **MAC bridge port filter extensions** — Medium impact, extend existing ME 80 handler

---

## 8. ME Count Gap Analysis

| | Shipping | Our Build | Status |
|---|---|---|---|
| Total MEs | ~100 | ~120 | **Exceeds stock** (extra stubs for OLT compat) |
| VoIP | 17 MEs | 17 MEs | **FIXED** — K1-K4 data-only stubs |
| PM | 14 MEs | 14+4 MEs | **FIXED** — INCLUDE_PM enabled + 4 VoIP PM stubs |
| Extra in ours | — | ME 332 + stubs | Enhanced Security Control, Dot1ag, ZTE, etc. |

### PM MEs — ALL FIXED

All 14 shipping PM MEs now registered (INCLUDE_PM enabled):
321, 24, 89, 296, 322, 312, 276, 267, 51, 52, 273, 274, 341, 135

Plus 4 VoIP PM stubs (K3): 140, 144, 151, 152

### VoIP MEs — ALL FIXED (data-only stubs, no telephony HW)

K1: 58, 138, 139, 141, 142 (core VoIP data MEs)
K2: 143, 145, 150, 153 (SIP/RTP config MEs + ME 53 audit)
K3: 140, 144, 151, 152 (VoIP PM MEs)
K4: 146, 147, 149, 283 (new v7.5.1 MEs from G.988 spec)

### Remaining Non-Functional Gaps

- ME 332 (Enhanced Security Control): Present in ours, absent from shipping. Harmless extra.
- xDSL/WiFi/MoCA MEs: Intentionally out of scope (no hardware).
- ME 9 (Ethernet Flow TP) association type: Rarely used, low priority.

---

## 9. Kernel MIB Mirror (TODO)

**Status**: Not implemented. Identified via omci_logger trace comparison.

### What Stock Does

The stock v7.5.1 binary pushes MIB template entries to the kernel driver during
`me_init()` via a dedicated ioctl. These appear in the omci_logger trace as:

```
[...] ? TBL 31 sz=0 len=0                    ← kernel MIB reset (clear previous entries)
[...] B ??? 01 sz=644 len=644 [00 04 02 14 41 4c 43 4c ...]   ← ME 4 (ONU-G), vendor "ALCL"
[...] B ??? 01 sz=644 len=644 [00 14 02 00 42 56 4c 33 ...]   ← ME 257 (ONU2-G), equip ID
[...] B ??? 01 sz=644 len=644 [00 04 02 14 41 4c 43 4c ...]   ← ME 4 updated with equip string
[...] B ??? 01 sz=644 len=644 [00 04 02 14 41 4c 43 4c ...]   ← ME 4 after port init complete
```

The ioctl magic is unknown to our `omci_logger` (appears as `???`). Each entry is
exactly 644 bytes. The payload starts with `class_id(2) + flags(2)` followed by the
full ME attribute data (padded to 640 bytes).

### Key Observations

1. **`TBL 31` reset happens before any MIB entries** — the kernel MIB table is cleared
   first, then populated incrementally during init.

2. **Entries are interleaved with port init** — they're not a bulk copy. MIB entries appear
   at specific points during initialization:
   - First two entries immediately after SCE constants read (before port setup)
   - Third entry after GPE config update (between GTC config and optic calibration)
   - Fourth entry after LAN port 0 initialization completes

   This interleaving means the kernel receives ME data as each ME is created, not as
   a post-init dump. The `me_init()` handler for each ME likely calls the push ioctl.

3. **Identity MEs are pushed** — ME 4 (ONU-G: vendor "ALCL") and ME 257 (ONU2-G:
   equipment ID "BVL3A5HNAAG010SP") are the observed entries. These are exactly the
   MEs needed for PLOAM fast-path identity responses during ranging.

### What Our Build Does

Nothing. Our v4.5.0 code loads MIBs entirely in userspace via `mib_create()` →
`me_create()`. There is no kernel MIB mirror. The kernel driver has no copy of ME data.

### Why This Matters

The kernel MIB mirror likely serves multiple purposes:

- **PLOAM fast-path**: During ONU ranging, the OLT queries identity attributes (serial
  number, equipment ID) with tight timing constraints. If the kernel can respond directly
  from its MIB mirror without round-tripping to userspace omcid, it eliminates latency
  that could cause ranging timeouts.

- **MIB upload acceleration**: When the OLT requests a full MIB upload (which can be
  hundreds of MEs), the kernel can serve the data directly, reducing the number of
  userspace/kernel transitions.

- **Crash resilience**: If omcid crashes or is restarted, the kernel retains the last
  known MIB state and can continue responding to OLT queries during the restart window.

### Investigation Needed

1. **Identify the ioctl**: The magic number for `B ??? 01` and `? TBL 31` is unknown.
   Need to check v7.5.1 kernel module symbols or decompile the stock `omcid` MIB push
   call sites to find the ioctl definitions.

2. **Determine if essential**: Test on a real OLT to see if the absence of kernel MIB
   mirror causes ranging failures or MIB upload issues. Bench test cannot evaluate this
   since there's no OLT.

3. **Struct layout**: The 644-byte entry format needs reverse engineering. First 4 bytes
   are `class_id(2) + flags(2)`, remaining 640 bytes contain attribute data.

---

## 10. Ioctl Trace Comparison: Stock vs Custom Init

**Source**: `omci_trace-stock.log` (637 lines) vs `omci_trace-custom.log` (553 lines)

Both traces captured via `omci_logger` on the same hardware (G-010S-P) with no fiber/OLT
connected. Stock = shipping v7.5.1 binary. Custom = our v4.5.0-based build (commit 091617f).

### 10a. Init Sequence Order

| Step | Stock | Custom | Difference |
|------|-------|--------|------------|
| 1 | `R GPE 61` (config read) | `R GPE 61` (config read) | **Same** |
| 2 | `R ONU 11` (portmap) | `R ONU 11` (portmap) | **Same** |
| 3 | **`R GTC 02`** (GTC config read) | `W EVT c9` (event setup) | **Different order** |
| 4 | `W EVT c9` (event setup) | `W GPE 78` (flush) | Stock reads GTC before EVT |
| 5 | `W GPE 78` (flush) | `W ??? 01` (download enable) | |
| 6 | `W ??? 01` (download enable) | `W ONU 0b` (ONU write) | |
| 7 | `W ONU 0b` (ONU write) | `W GTC 0b sz=40` | Custom writes GTC here |
| 8 | **`? TBL 31`** (kernel MIB reset) | — | **Missing from custom** |
| 9 | **`R TBL 24`** (SCE constants) | — | Stock reads SCE early |
| 10 | **`B ??? 01`** x2 (MIB push) | — | **Missing from custom** |
| 11 | `R GPE 02 / W GPE 01` | `W GPE 26` (GPE write) | |
| 12 | **`W ??? 00 sz=40`** | — | **Unknown 40B write, missing** |
| 13 | `R GPE 28 / W GPE 26` | `R GTC 02 / W GTC 01` | Stock reads GPE 28 first |
| 14 | **`B ??? 01`** (MIB push #3) | `R GPE 02 / W GPE 01` | |
| 15 | `R GTC 02 / W GTC 01` | GPE port setup | |
| 16 | `R GPE 02 / W GPE 01` | LAN port 0 init | |
| 17 | **Optic calibration** (5 ops) | — | **Missing from custom init** |
| 18 | GPE port setup | Queue init (0x80-0x87) | |
| 19 | LAN port 0 init | Scheduler init (0-7) | |
| 20 | **`B ??? 01`** (MIB push #4) | Traffic schedulers | |
| 21 | **LAN ports 1-3 init** | ANI queues | |
| 22 | Queue init (0x80-0x87) | Exception config table | |
| 23 | Scheduler init (0-7) | mib_copy (incl. optic reads) | |
| 24 | Traffic schedulers | Error probes, alarms | |
| 25 | ANI queues | | |
| 26 | SCE constants write | | |
| 27 | mib_copy | | |
| 28 | Error probes, alarms | | |

### 10b. Optic Calibration Timing

**Stock** performs optic driver calibration during early init (before any port setup):
```
R ??? 03 sz=34   ← Read optic calibration data
R ??? 01 sz=22   ← Read optic RSSI calibration
W ??? 00 sz=22   ← Write adjusted calibration (byte 16-17 changed: 00 00 → a1 e8)
R ??? 0d sz=24   ← Read BOSA TX data
W ??? 02 sz=34   ← Write back calibration (last 4 bytes changed: 08 e2 → 2a b9 01 e8)
```

**Custom** reads optic data only during `mib_copy` (ANI-G attribute getters):
```
R ??? 0c sz=32   ← BOSA RX read (v7.5.1 struct, 32 bytes)
R ??? 0d sz=24   ← BOSA TX read
```

**Impact**: Stock's early calibration write-back (`W ??? 00` and `W ??? 02`) adjusts the
optic driver's internal calibration constants before any data path operations. This
ensures accurate power readings from the first measurement. Our code reads raw values
during mib_copy but never performs the calibration write-back — the optic driver uses
whatever defaults the kernel module loaded at insmod time.

This is `FIO_MM_CALIBRATION_CFG_SET` (cmd 0/2) and `FIO_MM_CALIBRATION_CFG_GET` (cmd 1/3).
v4.5.0 `omci_api_ani_g.c` has `_calibration_init()` but it may not match stock behavior.
**Needs decompilation to verify.**

### 10c. Repeated Port 0 Init Passes (CORRECTED)

**Original analysis was wrong.** Stock does NOT initialize 4 different LAN ports.
ALL LAN ioctl operations in the stock trace have `index = 0` (port 0). What appeared
to be 4-port init was actually 3 passes of `_config()` + `_enabled()` on the same port.

**Stock** performs 3 passes of `_config()` + `_enabled()` on port 0 (lines 37-93):
- Pass 1 (L37-56): Full init — `_config()` + `_enabled()` with PORT_ENABLE, table valid/auth, 802.1x
- Pass 2 (L58-74): Redundant — same `_config()` + `_enabled()`, but PORT_ENABLE skipped
  (already enabled), table data unchanged. Preceded by kernel MIB push (L57).
- Pass 3 (L75-93): Redundant — same pattern, preceded by 3× GTC TOD reads (L85-87).

**Custom** performs 1 pass on port 0 (lines 23-39), plus 3× diagnostic STATUS_GET reads.

**Why stock has multiple passes:** Other MEs (UNI-G ME 264, MAC Bridge Port Config ME 47)
cascade back into the PPTP UNI `_config()` + `_enabled()` functions during their own
`me_init()`. This is an artifact of the stock ME framework's interconnected init — NOT
intentional multi-port init.

**Impact: NONE.** The functional table state is established entirely in pass 1 (valid bit,
PORT_ENABLE, auth bit). Passes 2-3 read the table and write it back unchanged. Our single
pass produces the same final hardware state. Verified by comparing GPE table data across
all stock table writes — data words are identical after pass 1.

### 10d. LAN Port State Polling Method

**Stock** uses `B LAN 04 sz=52` (FIO_LAN_PORT_CFG_GET — full 52-byte config struct):
```
B LAN 04 sz=52 [...00 00 00 01 ff ff ff ff 00 00 00 04 00 00 00 0f...]
```

**Custom** uses `B LAN 09 sz=20` (FIO_LAN_PORT_STATE_GET — 20-byte state-only struct):
```
B LAN 09 sz=20 [...00 00 00 0f 00 00 00 01 00 00 00 01...]
```

**Impact**: Both retrieve link state information for alarm evaluation. The stock approach
reads the full config (52 bytes) which includes PHY configuration, speed, duplex — more
data than needed for state polling but ensures config consistency. Our approach reads
only the state struct (20 bytes), which is more efficient but retrieves less data. The
key field (link state bits) is present in both responses.

Both produce the same alarm behavior: LAN-LOS alarm raised on ME 11.257, cleared ~5s later.

### 10e. TCONT Create Logger Artifact (CORRECTED)

**Original analysis was wrong.** GPE cmd 0x1b is `FIO_GPE_TCONT_CREATE` (char[8]),
NOT `FIO_GPE_SCHEDULER_CFG_SET` (cmd 0x0E, struct gpe_scheduler_cfg = 12 bytes).

**Stock**: `W GPE 1b sz=8 len=8 [id(4) + policy(4)]`
**Custom**: `W GPE 1b sz=8 len=16 [id(4) + policy(4) + 8 extra bytes]`

Both use the same 8-byte TCONT create ioctl (`FIO_GPE_TCONT_CREATE`). The `sz=8` field
is the kernel ioctl size (correct in both). The `len=16` in custom is an omci_logger
artifact — the logger reads 16 bytes from the ioctl buffer, but the kernel only copies
`sz=8` bytes via `copy_from_user`. The extra 8 bytes (`77 7c 53 a0 00 ff 00 01`) are
uninitialized stack data beyond the buffer boundary.

**Impact: NONE.** Both stock and custom pass identical 8-byte data to the same ioctl.
The kernel ignores bytes beyond `sz=8`. No code change needed.

### 10f. SCE Constants Timing

**Stock**: Reads SCE constants (`R TBL 24 sz=176`) early during init (line 15), before
port setup. Writes them back (`W TBL 25 sz=176`) much later, after mib_copy (lines 614-617).

**Custom**: Does not read SCE constants during early init. Writes them during the
scheduler/traffic descriptor init phase (not shown in first 100 lines, occurs later).

**Impact**: The early SCE read in stock may be checking for pre-existing GPE state or
validating the constants before port initialization begins.

### 10g. Timing Summary

| Phase | Stock (s) | Custom (s) | Notes |
|-------|-----------|------------|-------|
| Init → port 0 complete | 0.13 | 0.07 | Custom faster (1 pass vs 3) |
| Port 0 → queues done | 0.03 | 0.12 | Custom slower (fewer redundant passes) |
| Queues → mib_copy | 0.12 | 0.45 | Custom slower (more scheduler ops) |
| mib_copy → alarm | 0.4 | 0.5 | Comparable |
| Alarm → clear | 4.8 | 4.6 | Comparable (~5s timeout) |
| **Total init** | **1.9** | **~1.6*** | *Excludes logger reattach gap |

Both traces show a ~5-second gap between LAN-LOS alarm assertion and clearance, matching
the expected alarm debounce/holdoff timer in the event handler.

---

## 11. IOP (Interoperability Option) Mask

### 11a. `omci_iop_mask_isset` — Semantic Mismatch

**Shipping (FUN_00408cec) vs v4.5.0 `omci_interface.c:1646`**

The IOP mask is a 32-bit bitmask at context offset `0x154c` (shipping) / `iop_mask`
field (v4.5.0), set via `--iop-mask` CLI argument and queryable via `iop_mask_get` /
`iop_mask_set` commands.

| | Implementation | `omci_iop_mask_isset(ctx, 8)` tests... |
|---|---|---|
| **Shipping** | `(param & ctx->iop_mask) != 0` | bit 3 (mask 0x08) |
| **v4.5.0** | `((1u << param) & ctx->iop_mask) != 0` | bit 8 (mask 0x100) |

The shipping binary treats the parameter as a **direct mask value**. The v4.5.0
source treats it as a **bit position** and shifts `1 << param`. This causes:

- **IOP 0x20 (bit 5)**: Shipping tests bit 5. Our code does `1 << 0x20` = `1 << 32`
  = **undefined behavior** on 32-bit `uint32_t`.
- **IOP 0x08 (bit 3)**: Shipping tests bit 3. Our code tests bit 8.
- **IOP 0x02 (bit 1)**: Shipping tests bit 1. Our code tests bit 2.

**Fix**: Change `omci_iop_mask_isset` to use direct mask comparison, and rename
option defines from bit positions to mask values.

### 11b. Stock IOP Bits — Complete Inventory

Only **5 calls** to `omci_iop_mask_isset` exist in the shipping binary, using
**3 distinct mask values**:

| Mask | Bit | Call Sites | Function | Purpose |
|---|---|---|---|---|
| `0x02` | 1 | T-CONT `me_update` x1 | `FUN_00423a70` | Skip Alloc-ID termination on deactivation |
| `0x08` | 3 | `rx_vlan_oper_table_entry_set` x4 | ExtVLAN table | Zero DS treatment inner_prio/vid |
| `0x20` | 5 | `me171_init` x1 | ExtVLAN init | Enable common IGMP SCE meter |

Our code defines `OMCI_IOP_OPTION_0` (MCC multicast), `OMCI_IOP_OPTION_4` (US
pre-scan), and `OMCI_IOP_OPTION_8` (DS zeroing). The stock binary does not use
options 0 or 4 at all — MCC was rewritten in v7.5.1 and the US pre-scan logic
changed.

### 11c. IOP Bit 1 (0x02) — T-CONT Alloc-ID Termination Skip

**Shipping `me_update` for ME 262 (T-CONT) — FUN_00423a70:**

```
FUN_00423a70(ctx, me, data):
    if (!me->is_initialized):
        omci_api_tcont_create(ctx->api, me->instance_id, data->policy)
    else if (data->alloc_id == 0xFF || data->alloc_id == 0xFFFF):
        if (omci_iop_mask_isset(ctx, 0x02)):      ← IOP bit 1
            log("IOP option to skip Alloc-IDs termination upon T-CONT deactivation")
            return SUCCESS                         ← skip termination
        omci_api_tcont_delete(ctx->api, me->instance_id)
    else:
        omci_api_tcont_set(ctx->api, me->instance_id)
```

**v4.5.0 `me_update` dispatches to `omci_api_tcont_update()` which internally
checks for 0xFF/0xFFFF** — same deactivation detection but no IOP gate:

```
v4.5.0:  me_update → tcont_update() → { tcont_delete | tcont_set }
v7.5.1:  me_update → iop_check → { tcont_delete | tcont_set }
```

The stock moved the 0xFF/0xFFFF check from the API layer into the ME handler and
inserted the IOP gate between detection and action. The API-layer function
`omci_api_tcont_update()` was eliminated.

**Status: TODO** — Need to restructure `me_update` to 3-way dispatch with IOP gate.

### 11d. IOP Bit 3 (0x08) — DS Treatment Zeroing

Used in `rx_vlan_oper_table_entry_set` (all three vendor paths: HWTC, ALCL,
generic). When set, zeros the downstream treatment's `inner_prio` and `inner_vid`
fields before programming the GPE table.

**Status: IMPLEMENTED** — Our code checks this via `OMCI_IOP_OPTION_8` in
`omci_extended_vlan_config_data.c:632`. Functionally correct but uses wrong
mask semantics (tests bit 8 instead of bit 3 due to `1 << 8`).

### 11e. IOP Bit 5 (0x20) — Common IGMP SCE Meter

**Shipping `me171_init` (ME 171 ExtVLAN init) — FUN_00415810:**

After `me_data_write`, the stock checks:
```
if (omci_iop_mask_isset(ctx, 0x20)):     ← IOP bit 5
    ret = omci_api_sce_meter_helper(ctx->api, 1)
    if (ret != 0):
        error("DRV ERR(%d) Can't enable common IGMP meter")
        return -13
```

`omci_api_sce_meter_helper` (FUN_00446ba0) reads/writes the GPE SCE constants
table to enable a common IP handling meter across all IGMP sessions.

**Status: TODO** — Our `me_init` in `omci_extended_vlan_config_data.c:1229`
has no such check. Requires implementing `omci_api_sce_meter_helper` (SCE
constants GET/SET ioctls).

---

## 12. OLT Vendor Dispatch

### 12a. Vendor ID Match Function

**Shipping FUN_00408bf8 — OLT vendor comparison:**

```c
bool olt_vendor_match(int ctx, void *vendor_str) {
    lock();
    result = memcmp(ctx + 8, vendor_str, 4) == 0;
    unlock();
    return result;
}
```

Called from `rx_vlan_oper_table_entry_set` to dispatch between HWTC (Huawei),
ALCL (Nokia/Alcatel), and generic vendor paths. The vendor ID is stored at
context offset +8 in the shipping binary.

**Our implementation**: `get_olt_vendor_type()` in
`omci_extended_vlan_config_data.c:37` uses `memcmp(ctx->olt_vendor_id, ...)`.
Functionally equivalent but without locking.

### 12b. OLT Type Detection and Persistence

**Shipping OLT-G `me_update` (FUN_0041f6f0, MIPS16e) — additional logic
not in v4.5.0:**

After caching the vendor ID (only when attr 1 bit is set in mask, with locking),
the stock classifies the OLT type:

```
if vendor == "ALCL":
    if version == "              " (blank): skip
    olt_type = *(uint16_t *)(data->olt_version + 4)   // bytes 4-5 of version
    if olt_type > 2: force to 0, log "Wrong ALU OLT type"
    fw_setenv("olt_type", type_table[olt_type])        // "0", "1", or "2"
else:
    if vendor == "    " (blank): skip
    fw_setenv("olt_type", "0")                         // default for non-ALCL
```

The ALU OLT type is a uint16 from bytes 4-5 of the OLT version string (attr 3).
Valid values: 0, 1, 2 — mapping to different Nokia/ALU OLT hardware generations.
Saved to U-Boot env for consumption by external shell scripts.

**Status: TODO (low priority)** — Only affects external scripts, not omcid logic.
Our vendor dispatch works via `olt_vendor_id` comparison directly.

### 12c. Nokia Version Gate — SW Image Flash Compatibility

**Shipping FUN_00440fb8 (470 bytes) — called from ImageStoreThread
(FUN_00441678):**

A flash compatibility check during OLT-initiated firmware updates:

1. Reads `/proc/flashinfo` to get device flash type ID
2. Compares incoming image's equipment ID against known Nokia products:
   - `6BA1896SPLQA17` — standard, logged as "Standard support version"
   - `3FE56853AOPD95` — Nokia AOPD, logged as "Nokia support version"
   - `3FE47113AOPE01` — Nokia AOPE, requires minimum version
3. Checks OLT version string prefixes (`1620-00801`, `1620-00802`,
   `1620-00802-01`) with byte-level minimum version comparisons
4. Returns -1 if image is too old for the flash → blocks update with
   "image_version:%s don't support new flash"

**Call chain:**
```
ImageStoreThread → FUN_00440cc0 (download) → FUN_00440fb8 (version gate)
                                            → FUN_004412a4 (flash write)
```

**Status: N/A** — OLT-initiated firmware updates are blocked by our reboot NOP
patch (0x417B6) and `fw_update_guard`. We control firmware via our own update
mechanism.

---

## 13. ME Handler Divergences Not Yet Audited

The IOP analysis revealed that the stock v7.5.1 binary restructured several ME
handlers beyond what the earlier phase audits covered. Known examples:

| ME | Handler | Stock Change | Our Status |
|---|---|---|---|
| ME 262 (T-CONT) | `me_update` | 3-way dispatch + IOP gate (was 2-way) | TODO |
| ME 131 (OLT-G) | `me_update` | Added OLT type classification + env persistence | TODO (low) |
| ME 171 (ExtVLAN) | `me_init` | Added IOP bit 5 SCE meter enable | TODO |

**A systematic audit of all ME handlers against stock decompilation is
recommended.** The phase 8-13 audits focused on API-layer functions and ME
attribute definitions. The ME handler layer (`me_init`, `me_update`,
`me_shutdown`, `me_validate`) may contain additional vendor additions not yet
cataloged — particularly in handlers for MEs that interact with the GTC/GPE
subsystems (T-CONTs, GEM ports, bridges, schedulers).

---

## 14. Methodology for Future Comparisons

For systematic binary-vs-source comparison at scale:

1. **String extraction**: `strings omcid | grep -E 'omci_api_|FIO_|__FUNCTION__'`
   recovers ~90% of function names from debug prints
2. **Ghidra headless decompilation**: Export all functions → match against v4.5.0
   source by string references and call patterns
3. **Ioctl enumeration**: Extract all `_IOW`/`_IOR`/`_IOWR` constants from binary
   and cross-reference with v4.5.0 `drv_onu_*_interface.h` headers
4. **v8.6.3 as Rosetta Stone**: When shipping binary has a function not in v4.5.0,
   check v8.6.3 first — it often has the implementation we need

Tools that would accelerate this:
- Ghidra headless analyzer with v4.5.0 type imports (structs, enums, FIO macros)
- ghidra-bridge Python library for scripted decompilation queries
- MCP server wrapping Ghidra's AnalyzeHeadless for Claude integration
