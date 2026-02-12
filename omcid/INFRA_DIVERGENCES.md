# Infrastructure Function Divergences: v4.5.0 Source vs v7.5.1 Shipping Binary

Beyond Managed Entity definitions (covered in DIVERGENCES.md), the non-ME infrastructure
code changed significantly between the v4.5.0 SDK and the shipping v7.5.1 binary. This
document catalogs those differences, determined by Ghidra decompilation of the shipping
binary and comparison against v4.5.0 and v8.6.3 source.

---

## 1. `omci_init()` — Core Initialization

**Shipping (FUN_00408370, 740 bytes) vs v4.5.0 `omci_interface.c:268`**

### 1a. Context struct size

| | Size | Notes |
|---|---|---|
| Shipping | 0x1554 (5460 bytes) | `IFXOS_MemAlloc(0x1554)` |
| v4.5.0 | ~2200 bytes (est.) | Without PM, without MCC |

The shipping context is larger because it includes:
- PM context (`struct pm_context`) — enabled in shipping
- MCC context — MCC (multicast) is enabled in shipping
- Action Handled Event (third IFXOS_event_t)
- Additional callback pointers (uboot_set, uboot_get, uboot_save)

### 1b. Three events instead of two

| Event | v4.5.0 | Shipping |
|-------|--------|----------|
| `msg_event` | YES | YES |
| `action_event` | YES | YES |
| `action_handled_event` | **NO** | YES |

The shipping binary initializes a third event at context + 0x6A4 (byte offset 0x35E*2).
Error string: "Action Handled Event init failed". This is likely used for synchronization
between the core thread and action handler — the action thread signals this event when
it finishes processing a message, allowing the core thread to wait for completion.

**Impact**: MEDIUM. Without this, the core thread may poll `action.ready` instead of
blocking on an event. The v4.5.0 code uses `action.ready` volatile flag checks, which
still works but is less efficient.

**Action**: Add `IFXOS_event_t action_handled_event` to `struct omci_context` after
`action_event`. Initialize in `omci_init()`, use in action handler completion path.

### 1c. PM and MCC initialization

Shipping `omci_init()` calls (in order):
1. `alarm_copy_init` → `mib_copy_init` → `tbl_copy_init` → `msg_fifo_init` → `timeout_init`
2. `omci_api_init` → `mib_create` → `omci_api_start`
3. `core_thread_start` → `action_thread_start` → **`pm_init`**
4. `omci_processing_enable(true)`
5. **`mcc_init`** — LAST, after everything else

Our v4.5.0 has `pm_init` behind `#ifdef INCLUDE_PM` (disabled) and MCC behind
`--enable-mcc` configure flag.

**Impact**: HIGH for PM (14 MEs depend on it). MEDIUM for MCC (multicast ISPs).

**Action**: Enable `INCLUDE_PM` in build. Verify MCC compiles with `--enable-mcc`.

### 1d. Config callback struct

Shipping `omci_init` takes `(context**, config_struct*)` where config_struct has:
```
[0] mib_on_reset    — callback
[1] cli_on_exec     — callback (or event_cb)
[2] uboot_set       — firmware env setter
[3] uboot_get       — firmware env getter
[4] uboot_save      — firmware env saver
[5] lct_port        — uint8
[6] iop_mask        — uint32
[7] omcc_version    — uint8 (in first byte)
```

v4.5.0 passes these as individual function parameters. The uboot_set/get/save callbacks
are how the shipping binary reads/writes firmware environment variables without shell
wrappers. Our source uses `popen("fw_printenv")` and `popen("fw_setenv")` directly in
`omci_api_sw_image_falcon.c`.

**Impact**: LOW — our approach (source-level fw_guard) is architecturally better than
the shipping binary's callback approach. The callbacks were a way to inject behavior
without modifying the OMCI stack; we modify the stack directly.

**Action**: No change needed. Our parameter-based approach works fine.

### 1e. `OMCI_DEFAUL_MAX_ACTION_TIMEOUT`

| | Value |
|---|---|
| v4.5.0 | 200 (ms) |
| Shipping | 900 (ms) — `*(uint32_t*)(context + 0x1134) = 900` |

**Impact**: MEDIUM — affects how long omcid waits for ME action handlers before
returning BUSY. 200ms may be too aggressive for slow operations.

**Action**: Change `OMCI_DEFAUL_MAX_ACTION_TIMEOUT` from 200 to 900 in `omci_core.h`.

---

## 2. `omci_config_api.c` — Config API Module (NEW)

Two functions found referencing "omci_config_api.c":

### 2a. `omci_cfg_logical_onu_id_get` (FUN_0040a4ac)

Reads "omci_loid" from firmware environment via `context->uboot_get` callback.
Asserts data_size == 24 (0x18). Returns LOID string for Chinese ISP authentication.

### 2b. `omci_cfg_logical_password_get` (FUN_0040a504)

Reads "omci_lpwd" from firmware environment via `context->uboot_get` callback.
Asserts data_size == 12 (0xc). Returns LPWD string.

**Impact**: MEDIUM — only needed for Chinese ISPs using LOID authentication.
v8.6.3 has this in `src/omci_config_api.c`.

**Action**: Implement `omci_config_api.c` with direct UCI reads (no callback needed).
Read from `fwenv_get 8311_loid` / `fwenv_get 8311_lpwd` or UCI equivalent.

---

## 3. `omci_net_iface_state_cb` — Network Interface State (NEW)

**FUN_00408714, 358 bytes**

Called when a network interface changes state (via ubus/uloop events). Updates
IP Host Config Data (ME 134, class_id = 0x86) attributes:
1. Looks up interface name → ME instance_id
2. Locks MIB, finds ME 134
3. Reads admin_state (attr 1), checks bit 0
4. If enabled, reads/refreshes attrs 9-15 (IP address, subnet, gateway, DNS, etc.)
5. Unlocks MIB

**Dependencies**: ubus, uloop — event infrastructure for monitoring OpenWRT network state.

Shipping binary strings confirm: `ubus_connect`, `ubus_register_event_handler`,
`uloop_init`, `uloop_fd_add`, `uloop_run_events`, "Ubus init failed!", "Ubus start failed!"

**Impact**: MEDIUM — without this, ME 134 IP attributes won't auto-update when
interface comes up/down. OLTs that query ME 134 may see stale data.

**Action**: Implement ubus event monitoring for network interface state changes.
The v8.6.3 `omci_net.c` is likely the reference for this. Can use existing ubus
infrastructure (device has libubus already).

---

## 4. SW Update Functions

Shipping strings show a refactored SW update subsystem:

| Function | Purpose |
|----------|---------|
| `omci_sw_updt_start` | Start SW download session |
| `omci_sw_updt_window_download` | Download window/section |
| `omci_sw_updt_end` | End SW download |
| `omci_sw_updt_activate` | Activate downloaded image |
| `omci_sw_updt_commit` | Commit active image |
| `omci_sw_updt_image_upgrade` | Full image upgrade flow |
| `omci_sw_updt_action_handler` | Action dispatch for SW image ME |
| `omci_store_image_version` | Persist image version string |

Our v4.5.0 has these as functions within `omci_sw_image.c` and `omci_api_sw_image.c`
with our `omci_api_sw_image_falcon.c` overlay. The naming difference suggests v7.5.1
factored them into a separate namespace.

**Impact**: LOW — our source-level implementation already handles all these operations.
The `omci_store_image_version` function is covered by our fw_update_guard version capture.

**Action**: No change needed. Verify functional parity via testing.

---

## 5. MAC Bridge Port Filter Extensions

New API functions in shipping:

| Function | Purpose |
|----------|---------|
| `omci_api_mac_bridge_port_filter_assign` | Assign filter rules to bridge port |
| `omci_api_mac_bridge_port_filter_table_entry_add` | Add dynamic filter entry |
| `omci_api_mac_bridge_port_filter_table_entry_remove` | Remove dynamic filter entry |

These extend the MAC Bridge Port Filter Table Data (ME 49/80) with dynamic entry
management. v4.5.0 has the ME handlers but may not have these dynamic APIs.

**Impact**: MEDIUM — affects ME 80 (MAC Bridge Port Filter Table Data). Some OLTs
use dynamic filter entries for MAC-based filtering.

**Action**: Check v4.5.0 `omci_api_table_access.c` for existing filter functions.
If missing, implement using v8.6.3 as reference. These likely call existing GPE
table ioctls.

---

## 6. MAC Learning Depth Refresh

```
omci_api_refresh_mbp_mac_learning_depth
  bridge_idx_get: failed
  omci_api_mac_bridge_data_get: failed
```

A new function that refreshes the MAC learning depth setting on bridge ports. Called
when bridge configuration changes.

**Impact**: LOW — affects MAC learning table size per bridge port. Default values
typically work for home gateway scenarios.

**Action**: Investigate in v8.6.3 source. Low priority.

---

## 7. PM (Performance Monitoring) Total Counter & Reset Functions

These are API functions for PM MEs that go beyond basic interval counters:

| Category | Functions | Count |
|----------|-----------|-------|
| `*_total_cnt_get` | Cumulative counters across intervals | 8 |
| `*_cnt_reset` | Reset counter capability | 3 |
| `*_mtu_exceeded_discard_*` | Frame size violation counting | 2 |

Present in shipping binary strings. Absent from v4.5.0 unless `INCLUDE_PM` is enabled.

**Impact**: HIGH (collectively with PM enablement) — OLTs that collect PM data
query these counters.

**Action**: Enable `INCLUDE_PM` to get the framework, then add `_total_cnt_get`
functions. The v8.6.3 source has the implementation patterns.

---

## 8. ubus/uloop Event Infrastructure

Shipping binary uses OpenWRT's ubus and uloop for:
- Network interface state monitoring (`omci_net_iface_state_cb`)
- Possibly PLOAM state notifications
- Integration with netifd

Confirmed strings: `libubus.so`, `ubus_connect`, `ubus_register_event_handler`,
`ubus_free`, `uloop_init`, `uloop_fd_add`, `uloop_done`, `uloop_run_events`

v4.5.0 does NOT use ubus/uloop. It relies on direct kernel driver events
via ioctl/callback.

**Impact**: MEDIUM — adds network state awareness. Device has libubus.so available.

**Action**: Add ubus event handling in the daemon or a new `omci_net.c` module.
Reference v8.6.3 `omci_net.c` for the implementation pattern.

---

## 9. ONU Loop Detection

| Function | Purpose |
|----------|---------|
| `omci_api_onu_loop_detection_create` | Create loop detection instance |
| `omci_api_onu_loop_detection_destroy` | Destroy instance |
| `omci_api_onu_loop_detection_update` | Update config |
| `omci_api_onu_loop_detection_packet_send` | Send loop detection packet |
| `omci_onu_loop_detect_action` | Trigger loop detection action |

These are the API functions behind ME 65528 (ONU Loop Detection). We already have
the ME stub registered; these API functions provide the actual hardware interface.

**Impact**: MEDIUM — some Asian ISPs enable loop detection. Without the API
functions, the ME accepts OMCI commands but doesn't actually detect loops.

**Action**: Implement API functions. The kernel driver (`mod_onu.ko`) likely has
the `FIO_ONU_LOOP_*` ioctl interface. Check v8.6.3 `omci_api_onu_loop_detection.c`.

---

## 10. Summary: Implementation Priority

### P0 — High Impact, Required for Parity

| Item | Section | Effort |
|------|---------|--------|
| Enable INCLUDE_PM | §1c, §7 | MEDIUM — enable flag, reconcile class_id 333→341 |
| Action timeout 200→900 | §1e | TRIVIAL — one constant change |
| Action Handled Event | §1b | LOW — add event to struct, init, use in handler |

### P1 — Medium Impact, Common ISP Needs

| Item | Section | Effort |
|------|---------|--------|
| MCC init verification | §1c | LOW — verify `--enable-mcc` works |
| LOID/LPWD config API | §2 | LOW — simple UCI/fwenv getter |
| ubus/uloop + net state cb | §3, §8 | MEDIUM — new module, link libubus |
| MAC bridge port filter APIs | §5 | MEDIUM — implement 3 API functions |

### P2 — Low Impact, Nice to Have

| Item | Section | Effort |
|------|---------|--------|
| Loop detection API | §9 | MEDIUM — need ioctl investigation |
| MAC learning depth refresh | §6 | LOW — single API function |
| PM total_cnt / cnt_reset | §7 | LOW (after PM enabled) |

---

## 11. Files Changed Between v4.5.0 and v8.6.3 (Non-ME)

Files present in BOTH versions but likely modified:

| File | v4.5.0 | v8.6.3 | Key Differences |
|------|--------|--------|-----------------|
| `omci_core.c` | YES | YES | msg_fifo refactored out, action_handled_event |
| `omci_interface.c` | YES | YES | IOP mask, OMCC version, net_iface_state_cb |
| `omci_mib.c` | YES | YES | ME count assertion may differ |
| `omci_me_handlers.c` | YES | YES | Possibly IOP-mask-gated behavior |
| `omci_alarm.c` | YES | YES | Minor changes |
| `omci_daemon.c` | YES | YES | Config struct, ubus init |
| `omci_daemon_mib.c` | YES | YES | MIB field count changes |
| `omci_cli_access.c` | YES | YES | New commands (already added) |
| `omci_cli_autogen.c` | YES | YES | Renames (already done) |
| `omci_pm.c` | YES | YES | total_cnt, cnt_reset additions |

Files NEW in v8.6.3 (may also be in v7.5.1):

| File | Purpose | In Shipping? |
|------|---------|-------------|
| `omci_config_api.c` | LOID/LPWD config getters | YES (confirmed) |
| `omci_net.c` | ubus/uloop net interface monitoring | YES (confirmed) |
| `omci_msg_fifo.c` | Refactored FIFO from omci_core.c | MAYBE |
| `omci_mic_check.c` | Message Integrity Check | UNKNOWN |
| `omci_secure.c` | Security/encryption | UNKNOWN |
| `omci_pa.c` | PON Adapter (v8.x only) | NO (not in v7.5.1) |
| `mcc/omci_mcc*.c` | Multicast Control Classifier (7 files) | YES (partial) |
| `omci_daemon_dsl.c` | DSL extensions | NO (no xDSL hardware) |

---

## 12. Methodology

1. **Ghidra ListFunctions**: Generated complete function list (1289 non-PLT functions)
2. **String extraction**: `strings omcid | grep '^omci_'` recovered ~150 function names
3. **FindByString decompilation**: Decompiled key functions by their debug string refs
4. **Cross-reference**: Compared shipping strings against v4.5.0 source to find gaps
5. **v8.6.3 file catalog**: Identified new modules by comparing directory listings
6. **ubus/uloop detection**: Confirmed via PLT imports and error strings

### Ghidra Quick Reference

```bash
# List all functions
./ghidra-decompile.sh --list > functions.txt

# Decompile by debug string reference (for stripped binary)
cat > /mnt/c/temp/run_ghidra_query.bat << 'BATEOF'
@echo off
set JAVA_HOME=C:\Users\johne\.jdk\jdk-21.0.8+9
cd /d C:\devel\ghidra_12.0.3_PUBLIC\support
call analyzeHeadless.bat C:\Users\johne 8311 -process omcid -noanalysis ^
  -scriptPath C:\temp\ghidra_scripts ^
  -postScript G8311_FindByString.java "<search_string>" "C:\temp\ghidra_out.c" ^
  > C:\temp\ghidra_log.txt 2>&1
BATEOF
cmd.exe /c "C:\temp\run_ghidra_query.bat" && cat /mnt/c/temp/ghidra_out.c

# Decompile by address
./ghidra-decompile.sh 0x00408370
```
