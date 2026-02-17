# Ioctl Compatibility: v4.5.0 SDK Headers → v7.5.1 Shipping Kernel

## Background

The shipping G-010S-P firmware runs v7.5.1 kernel modules (`mod_onu.ko`,
`mod_optic.ko`) but we build a custom omcid from v4.5.0 SDK source. The
kernel validates the **full 32-bit ioctl number** — direction, struct size,
magic, and command must all match or the call returns `EINVAL`. A single
mismatched byte in any field causes failure.

Rather than maintaining a separate compat layer (`drv_onu_compat.h`), we
updated the original v4.5.0 SDK headers in-place to produce correct v7.5.1
ioctl values. The v4.5.0 source code accesses struct members by **name**,
so using wider structs (with padding) is transparent to the calling code.

## MIPS Linux Ioctl Encoding

```
Bits 31-29: direction (3 bits)
  _IOC_NONE  = 1 (0x20000000)
  _IOC_READ  = 2 (0x40000000)  ← IOR
  _IOC_WRITE = 4 (0x80000000)  ← IOW
  _IOC_RW    = 6 (0xC0000000)  ← IOWR

Bits 28-16: size (13 bits, max 8191)
Bits 15-8:  magic number (8 bits)
Bits 7-0:   command number (8 bits)
```

Magic numbers: ONU=1, ~~ONU_EVENT=2~~(removed), GTC=6, GPE=4, GPE_TABLE=5, LAN=7, OPTIC=9

**Note:** v4.5.0 used PLOAM_MAGIC=3 and GTC_MAGIC=6. In v7.5.1, all PLOAM
ioctls merged under GTC_MAGIC=6 and PLOAM_MAGIC=3 is unused. Some GPE ioctls
(magic 4) moved to GPE_TABLE (magic 5). ONU_EVENT_MAGIC=2 was removed entirely.

---

## Changes by Subsystem

### 1. ONU Common (magic=1) — `drv_onu_common_interface.h`

**Struct field widenings** (type change, same field semantics):

| Struct | Field(s) | v4.5.0 | v7.5.1 | Impact |
|--------|----------|--------|--------|--------|
| `onu_dbg_level` | `level` | `uint8_t` | `uint32_t` | Size 1→4 |
| `onu_reg_addr` | `form` | `uint8_t` | `uint32_t` | Size grows |
| `onu_reg_val` | `form` | `uint8_t` | `uint32_t` | Size grows |
| `onu_reg_addr_val` | `form` | `uint8_t` | `uint32_t` | Size grows |
| `onu_version_string` | *(appended)* | 400B (5×80) | 480B (6×80) | `device_type[80]` added |

All FIO_ cmd numbers **unchanged** — the ioctl values change only due to size.

---

### 2. GTC (magic=6) — `drv_onu_gtc_interface.h`

**All 16 surviving ioctls shifted by -1** due to removal of `FIO_GTC_PLOAM_RECEIVE`
(was cmd 0x02). The PLOAM receive mechanism moved to the event subsystem.

| Ioctl | v4.5.0 cmd | v7.5.1 cmd |
|-------|-----------|-----------|
| PLOAM_SEND_CTRL_SET | 0x01 | 0x01 *(unchanged)* |
| ~~PLOAM_RECEIVE~~ | 0x02 | **removed** |
| PLOAM_COUNTER_GET | 0x03 | 0x02 |
| GTC_COUNTER_GET | 0x04 | 0x03 |
| GTC_COUNTER_RESET | 0x05 | 0x04 |
| GTC_COUNTER_THRESHOLD_SET | 0x06 | 0x05 |
| GTC_COUNTER_THRESHOLD_GET | 0x07 | 0x06 |
| GTC_TCA_GET | 0x08 | 0x07 |
| GTC_STATE_GET | 0x09 | 0x08 |
| GTC_BER_INTERVAL_SET | 0x0A | 0x09 |
| GTC_BER_INTERVAL_GET | 0x0B | 0x0A |
| GTC_IDLE_SET | 0x0C | 0x0B |
| GTC_IDLE_GET | 0x0D | 0x0C |
| GTC_ROGUE_DETECT_SET | 0x0E | 0x0D |
| GTC_ROGUE_DETECT_GET | 0x0F | 0x0E |
| GTC_ROGUE_MODE_SET | 0x10 | 0x0F |
| GTC_ROGUE_MODE_GET | 0x11 | 0x10 |

**Struct padding** added:

| Struct | Padding | v4.5.0 → v7.5.1 |
|--------|---------|------------------|
| `gtc_ploam_cnt` | `uint32_t _v751_reserved[2]` | 12B → 20B |
| `gtc_cnt_val` | `uint64_t _v751_reserved[6]` | 104B → 152B |
| `gtc_cnt_threshold` | `uint64_t _v751_reserved[6]` | 112B → 160B |

---

### 3. GPE (magic=4) — `drv_onu_gpe_interface.h`

The largest set of changes. ~65 FIO_ macros updated.

**Category 1: Magic changes (GPE→GPE_TABLE)**

Several ioctls that were under GPE_MAGIC=4 in v4.5.0 moved to GPE_TABLE_MAGIC=5
in v7.5.1:

| Ioctl | v4.5.0 magic | v7.5.1 magic |
|-------|-------------|-------------|
| TABLE_ENTRY_WRITE/READ/SET | 4 | 5 |
| TABLE_ENTRY_ADD/GET/DELETE | 4 | 5 |

**Category 2: Struct size changes**

| Struct | Padding | v4.5.0 → v7.5.1 |
|--------|---------|------------------|
| `gpe_parser_cfg` | `uint32_t _v751_reserved[2]` | 20B → 28B |
| `gpe_tod_sync` | `int32_t` fields appended | 16B → 24B |
| `gpe_tcont_cfg` | `uint32_t _v751_reserved[2]` | 8B → 16B |

**Category 3: Direction changes**

| Ioctl | v4.5.0 | v7.5.1 |
|-------|--------|--------|
| TOD_SYNC_SET | `_IOW` | `_IOWR` |
| TCONT_SET | `_IOW` | `_IOWR` |
| PARSER_CFG_GET | `_IOR` | `_IOWR` |

**Category 4: Removed ioctls (11)**

These are not in the v7.5.1 dispatch table at all. Ioctls still referenced
by v4.5.0 source are defined with dead magic `0xFF` (guaranteed ENOTTY):

| Removed Ioctl | v4.5.0 cmd | Still referenced? |
|--------------|-----------|-------------------|
| PLOAM_RECEIVE | 0x03 | No |
| EGRESS_QUEUE_COUNTER_CFG_SET | 0x1A | No |
| EGRESS_QUEUE_COUNTER_CFG_GET | 0x1B | No |
| TMU_COUNTER_RESET | 0x25 | No |
| SCE_COUNTER_GET | 0x26 | **Yes** → `_IOWR(0xFF, 0x01, ...)` |
| SCE_COUNTER_RESET | 0x27 | No |
| BRIDGE_PORT_COUNTER_GET | 0x72 | **Yes** → `_IOWR(0xFF, 0x02, ...)` |
| BRIDGE_PORT_COUNTER_THRESHOLD_SET | 0x73 | No |
| BRIDGE_PORT_COUNTER_THRESHOLD_GET | 0x74 | No |
| BRIDGE_PORT_TCA_GET | 0x75 | No |
| BRIDGE_PORT_COUNTER_RESET | 0x76 | No |

**Category 5: Cmd number shifts**

Many surviving ioctls shifted cmd numbers. Too numerous to list individually;
see the header file for each FIO_ macro's v7.5.1 value.

---

### 4. GPE Tables (magic=5) — `drv_onu_gpe_tables_interface.h`

**Core data type change:**

The `gpe_table_data` union (in `drv_onu_gpe_tables.h`) grew from 32 to 34
bytes via a `uint8_t _v751_pad[34]` member. This cascades to:

| Type | v4.5.0 | v7.5.1 |
|------|--------|--------|
| `gpe_table_data` (union) | 32B | 34B |
| `gpe_table_entry` | 80B | 84B |
| `gpe_table` | 44B | 46B |

**Struct padding additions:**

| Struct | Padding | v4.5.0 → v7.5.1 | Significance |
|--------|---------|------------------|--------------|
| `gpe_sce_constants` | `uint8_t _v751_reserved[102]` | 74B → 176B | **CRITICAL** — prevented 102B stack overflow |
| `gpe_mac_mc_port_modify` | `uint32_t _v751_reserved` | 22B → 26B | MCC multicast |
| `gpe_ipv4_mc_port` | `uint32_t _v751_reserved` | 16B → 20B | MCC multicast |
| `gpe_ipv4_mc_port_modify` | `uint32_t _v751_reserved[2]` | 20B → 28B | MCC multicast |

**Size overrides** (v7.5.1 struct shrank or restructured):

| Ioctl | FIO_ type override | v4.5.0 struct | v7.5.1 size |
|-------|-------------------|--------------|-------------|
| LONG_FWD_ADD | `char[48]` | `gpe_table_entry` (84B) | 48B |
| LONG_FWD_DELETE | `char[48]` | `gpe_table_entry` (84B) | 48B |
| LONG_FWD_FORWARD | `char[48]` | `gpe_table_entry` (84B) | 48B |
| VLAN_FID_ADD | `char[4]` | `union gpe_vlan_fid_u` | 4B |
| VLAN_FID_GET | `char[4]` | `union gpe_vlan_fid_u` | 4B |
| VLAN_FID_DELETE | `char[4]` | `struct gpe_vlan_fid_in` | 4B |

**Direction change:**

| Ioctl | v4.5.0 | v7.5.1 |
|-------|--------|--------|
| SCE_CONSTANTS_GET | `_IOWR` | `_IOR` |

**Removed ioctls (8):**

| Removed Ioctl | v4.5.0 cmd | Replacement | Still referenced? |
|--------------|-----------|-------------|-------------------|
| TAGGING_FILTER_GET | 0x0F | — | No |
| TAGGING_FILTER_SET | 0x10 | — | **Yes** → `_IOW(0xFF, 0x03, ...)` |
| TAGGING_FILTER_DO | 0x1A | — | No |
| ACL_TABLE_ENTRY_SET | 0x23 | ACL_RULE_ADD | No |
| ACL_TABLE_ENTRY_GET | 0x24 | ACL_FILTER_CFG_GET | No |
| ACL_TABLE_ENTRY_DELETE | 0x25 | ACL_INIT | No |
| SCE_MAC_GET | 0x28 | folded into SCE_CONSTANTS | No |
| SCE_MAC_SET | 0x29 | folded into SCE_CONSTANTS | No |

**Cmd number shifts** (29 ioctls shifted due to removals compacting the table):

| Ioctl | v4.5.0 cmd | v7.5.1 cmd |
|-------|-----------|-----------|
| LONG_FWD_ADD | 0x0F | 0x0D |
| LONG_FWD_DELETE | 0x10 | 0x0E |
| COP_TABLE0_READ | 0x11 | 0x0F |
| SHORT_FWD_ADD | 0x12 | 0x10 |
| SHORT_FWD_DELETE | 0x13 | 0x11 |
| COP_DEBUG_SET | 0x14 | 0x12 |
| SHORT_FWD_RELEARN | 0x15 | 0x13 |
| EXT_VLAN_CUSTOM_SET | 0x16 | 0x14 |
| COP_DEBUG_SERVER | 0x17 | 0x15 |
| SHORT_FWD_FORWARD | 0x18 | 0x16 |
| TABLE_ENTRY_SEARCH | 0x19 | 0x17 |
| TABLE_REINIT | 0x1B | 0x18 |
| LONG_FWD_FORWARD | 0x1C | 0x19 |
| EXT_VLAN_CUSTOM_GET | 0x1D | 0x1A |
| AGING_TIME_SET | 0x1E | 0x1B |
| AGING_TIME_GET | 0x1F | 0x1C |
| AGE_GET | 0x20 | 0x1D |
| AGE | 0x21 | 0x1E |
| AGING_TIME_SET_DEBUG | 0x22 | 0x1F |
| SCE_CONSTANTS_GET | 0x26 | 0x24 |
| SCE_CONSTANTS_SET | 0x27 | 0x25 |
| SHORT_FWD_MAC_MC_PORT_ADD | 0x2A | 0x26 |
| SHORT_FWD_MAC_MC_PORT_DELETE | 0x2B | 0x27 |
| SHORT_FWD_MAC_MC_PORT_MODIFY | 0x2C | 0x28 |
| VLAN_FID_ADD | 0x2D | 0x29 |
| VLAN_FID_GET | 0x2E | 0x2A |
| VLAN_FID_DELETE | 0x2F | 0x2B |
| SHORT_FWD_IPV4_MC_PORT_ADD | 0x30 | 0x2C |
| SHORT_FWD_IPV4_MC_PORT_DELETE | 0x31 | 0x2D |
| SHORT_FWD_IPV4_MC_PORT_MODIFY | 0x32 | 0x2E |

---

### 5. LAN (magic=7) — `drv_onu_lan_interface.h`

**Struct changes (already in headers from prior compat work):**

| Struct | Change | v4.5.0 → v7.5.1 |
|--------|--------|------------------|
| `lan_port_cfg` | 2 fields INSERTED + 2 appended | 36B → 52B |
| `lan_loop_cfg` | 2 fields appended | 24B → 32B |
| `lan_port_capability_cfg` | `bool` → `uint32_t` for 8 fields | 12B → 36B |
| `lan_cnt_val` (in `drv_onu_types.h`) | `uint64_t _v751_reserved[2]` | 352B → 368B |

`lan_port_cfg` is SEVERE — fields were **inserted** (not appended), shifting
all subsequent field offsets by 8 bytes. New fields: `mdio_dev_addr` (int32),
`gmux_mode` (enum lan_mode_gmux), `invtx`, `invrx`.

`lan_port_capability_cfg` is SEVERE — every `bool` (1B) became `uint32_t` (4B),
completely changing the struct layout.

**FIO_ size overrides** (struct shrank):

| Ioctl | Override | Reason |
|-------|----------|--------|
| FIO_LAN_CFG_SET | `char[16]` (was 20) | One field removed in v7.5.1 |
| FIO_LAN_CFG_GET | `char[16]` (was 20) | Same |
| FIO_LAN_TCA_GET | `char[372]` | v7.5.1 includes port index prefix |

All other LAN cmd numbers unchanged.

---

### 6. Event Subsystem (magic=2) — `drv_onu_event_interface.h`

**Entirely removed in v7.5.1.** ONU_EVENT_MAGIC=2 has no dispatch table in
the shipping kernel. All event ioctls return EINVAL.

| Removed Ioctl | Impact |
|--------------|--------|
| FIO_ONU_EVENT_ENABLE_SET | Used by omci_api_event.c — returns EINVAL, handled |
| FIO_ONU_EVENT_ENABLE_GET | Same |
| FIO_ONU_EVENT_FIFO | Same |

The event header was left unmodified since the failure is non-fatal — the code
handles EINVAL gracefully. The crash we were fixing occurs in `omci_api_start()`
which runs before event polling begins.

---

## Dead Ioctl Pattern

For ioctls that were removed in v7.5.1 but are still called by v4.5.0 source
code, we define them with magic `0xFF`:

```c
/* Not in v7.5.1 kernel — dead ioctl, will return ENOTTY at runtime */
#define FIO_GPE_SCE_COUNTER_GET _IOWR(0xFF, 0x01, union gpe_sce_cnt_get_u)
```

Magic 0xFF is not used by any kernel subsystem, so these will always return
`ENOTTY` (no matching dispatch). The calling code in `dev_ctl()` handles
ioctl errors and continues operation.

Three dead ioctls are currently defined:
- `FIO_GPE_SCE_COUNTER_GET` — Ethernet DS PM counters (magic 0xFF, nr 0x01)
- `FIO_GPE_BRIDGE_PORT_COUNTER_GET` — MAC bridge port PM counters (magic 0xFF, nr 0x02)
- `FIO_GPE_TAGGING_FILTER_SET` — VLAN tagging filter config (magic 0xFF, nr 0x03)

---

## The SCE Constants Stack Overflow (Root Cause of omci_api_start Crash)

The most critical fix was `gpe_sce_constants`:

| | v4.5.0 | v7.5.1 |
|---|--------|--------|
| Struct size | 74 bytes | 176 bytes |
| FIO_GPE_SCE_CONSTANTS_GET direction | `_IOWR` | `_IOR` |

When omcid called `ioctl(fd, FIO_GPE_SCE_CONSTANTS_GET, &buf)` with a 74-byte
`buf` on the stack, the v7.5.1 kernel wrote 176 bytes — **102 bytes of stack
corruption**. This was the root cause of the crash loop during `omci_api_start()`.

Fixed by adding `uint8_t _v751_reserved[102]` to `struct gpe_sce_constants`.

---

## Reference: v7.5.1 Dispatch Table

The complete v7.5.1 ioctl dispatch table (318 entries) was extracted from
the shipping `mod_onu.ko` binary and saved as `mod_onu_ioctls.txt`. Each
entry shows the full 32-bit ioctl value, which was cross-referenced against
every FIO_ macro to verify correctness.

## Source of Truth for Field Names

CLI help text baked into `mod_onu.ko` (`onu help <cmd>`) provides the v7.5.1
field names and types. Search the binary for `"<cmd_name>\nShort Form"` to
extract individual struct layouts.
