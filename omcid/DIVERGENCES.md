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

## 9. Methodology for Future Comparisons

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
