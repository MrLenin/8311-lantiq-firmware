# Firmware Internals — Reverse Engineering Reference

Reverse engineering findings for the Lantiq Falcon GPON SFP ONU firmware.
Covers the omcid daemon, kernel modules, GPE packet engine, and OMCI stack
internals. Organized by component, not by problem domain.

Hardware: Source Photonics SPS-34-24T-HP-TDFO reference design (Falcon SoC).
Firmware: ~v7.5.1 era, proprietary build by Nokia/Alcatel-Lucent. Modified
by @拾麦穗-sam (sean) from right.com.cn forums, Sep 2023.

For binary patch details, see [PATCHES.md](8311-mods/lib/modules/3.10.49/PATCHES.md).
For 802.1x enforcement analysis, see [eager-conjuring-dewdrop.md](.claude/plans/eager-conjuring-dewdrop.md).

---

## Platform: Lantiq Falcon SoC

- **CPU:** MIPS 34Kc (big-endian), single-core
- **Packet engine:** GPE (GPON Processing Engine) — proprietary VLIW microcode
- **Ethernet:** EIM (Ethernet Interface Module) — simple L2 switch, NO PCE/GSWIP
- **Kernel:** Linux 3.10.49 (OpenWRT-derived)
- **Shell:** busybox ash
- **OMCI daemon:** omcid (proprietary, MIPS16e)
- **Device nodes:** `/dev/onu0` (ONU driver), `/dev/optic` (optic driver)

**No GSWIP/PCE on Falcon.** The GSWIP with programmable PCE rules is on
later xRX/PRX SoCs (xRX200, xRX300, PRX300). On Falcon, all packet
classification and VLAN processing is in the GPE firmware. The kernel-level
`vlanctl` and GPE are separate datapaths — GPE programs hardware tables
directly via ioctls, not through vlanctl.

---

## omcid — OMCI Daemon

**Binary:** `8311-mods/opt/lantiq/bin/omcid`
**Architecture:** MIPS16e (compact instruction encoding), big-endian
**VA base offset:** File offset + 0x400000 = virtual address (Ghidra)
**Stock version:** `6BA1896SPE2C05, internal_version =1620-00802-05-00-000D-01`
**Stock MD5:** `0da3eb0b76af1df5f4df414e3fc09dbb` (with baked-in patches)

### Decompiled Function Reference

#### OMCI Core

| VA | Name / Purpose | Notes |
|----|----------------|-------|
| `0x00408bf8` | Vendor detection | 4-byte `memcmp` at ctx+2: "HWTC" / "ALCL" |
| `0x00432244` | ioctl wrapper | `(flag_byte, fd, ioctl_code, buf, size)` |
| `0x00434ac0` | Resource mapping register | Stores (type, ME_instance) → key |
| `0x00434de0` | Resource mapping lookup | (type, ME_instance) → key or error |

- `flag_byte = *(byte*)(ctx + 0x144c)`
- `fd = *(int*)(ctx + 8)` — file descriptor to `/dev/onu0`
- Vendor strings: `DAT_0045cc38` = "HWTC", `DAT_0045cd04` = "ALCL"

#### ME 171 (Extended VLAN Tagging Operation)

| VA | Name / Purpose | Notes |
|----|----------------|-------|
| `0x00415311` | qsort comparator (MIPS16e) | Sorts entries by filter bytes (8-byte memcmp) |
| `0x00415548` | `me_tbl_copy` | Table copy handler |
| `0x004155e0` | `me_validate` | assoc_type switch (0-10), validates assoc ME exists |
| `0x00415740` | `me_shutdown` | ME deletion/cleanup |
| `0x00415810` | `me_init` | Allocates internal_data (0x28 bytes), inits linked list |
| `0x00415944` | filter entry comparator | Compares ME 171 filter fields for override detection |
| `0x00415a44` | `rx_vlan_oper_table_entry_set` | Main table entry handler — all 3 vendor paths |
| `0x00416768` | `me_set` | Attribute set → dispatches to `rx_vlan_oper_table_entry_set` |

**ME 171 handler vtable** at `0x0045d484`:

| Offset | VA | Handler |
|--------|-----|---------|
| +0x00 | `0x0042a380` | `set_table_action_handle` (generic) |
| +0x04 | `0x00415810` | `me_init` |
| +0x08 | `0x00415740` | `me_shutdown` |
| +0x0C | `0x004155e0` | `me_validate` |
| +0x10 | `0x00416768` | `me_set` |
| +0x14 | `0x00415548` | `me_tbl_copy` |

**ME 171 processing pipeline:**
```
OLT writes ME 171 table entry (16 bytes)
  → rx_vlan_oper_table_entry_set (0x415a44)
    ├── Parses 14 fields from 16-byte entry
    ├── Manages linked list, sorts by filter bytes via qsort
    ├── Vendor-specific paths: HWTC → hwtc_rule_add, ALCL → alcl_rule_add, else → comm_rule_add
    └── All paths call:
        omci_api_ext_vlan_filter2action (0x4390a0)
          ├── Rule finder (0x4394f4) — scans 68-entry template table at DAT_0048a910
          ├── US action generator (0x439a94) — 42-byte US action
          └── DS action generator (0x439c98) — 42-byte DS action (skipped if mode==1)
              → omci_api_ext_vlan_action_add (0x43a130) — programs GPE via ioctls
```

**ALCL (Nokia OLT) interop:** The `alcl_rule_add` path adds an extra "IOP DS"
passthrough entry (from `DAT_0045d514`, 42 bytes) before each real DS entry.
US/DS indices tracked independently. XREFs at `0x00416182` and `0x00416758`
(two sites within `rx_vlan_oper_table_entry_set`, both in the ALCL vendor path).

**`DAT_0045d514` decode** (42-byte v7.5.1 action format, single-tag VID=0 passthrough):

Verified by decompiling `omci_api_ext_vlan_action_add` (VA `0x0043a130`) and tracing
each `param_5[N]` access to its GPE `gpe_vlan_rule_table` bitfield position.

```
Byte  Hex   42-byte field          GPE rule/treatment field         Value
────  ────  ─────────────────────  ───────────────────────────────  ─────
 0    0x01  valid                  rule word 1 bit 31               1
 1    0x00  (unused)
 2    0x00  def                    rule word 1 bit 29               0
 3    0x00  two_enable             rule word 0 bit 2                0
 4    0x01  one_enable             rule word 0 bit 1                1
 5    0x00  zero_enable            rule word 0 bit 0                0
 6    0x00  outer_de_filter        rule word 0 bit 28               0
 7    0x00  outer_de_enable        rule word 0 bit 27               0
 8    0x00  outer_reg_tpid_en      rule word 0 bit 26               0
 9    0x00  outer_input_tpid_en    rule word 0 bit 25               0
10-11 0x0000 outer_vid_filter      rule word 0 bits 24-13           0
12    0x01  outer_vid_enable       rule word 0 bit 12               1
13    0x00  outer_pri_filter       rule word 0 bits 11-9            0
14    0x00  outer_pri_enable       rule word 0 bit 8                0
15-29 0x00  (all inner filter, ethertype = 0)                       0
30    0x00  tagb_tpid              treatment word 0 bits 30-28      0
32-33 0x0000 tagb_vid              treatment word 0 bits 27-15      0
34    0x0F  tagb_treatment         treatment word 0 bits 14-11      15 (don't modify)
35    0x00  taga_tpid              treatment word 0 bits 9-7        0
36-37 0x0000 taga_vid              treatment word 1/0 split         0
38    0x0F  taga_treatment         treatment word 1 bits 25-22      15 (don't modify)
39    0x01  inner_not_generate     treatment word 0 bit 10          1
40    0x01  outer_not_generate     treatment word 1 bit 21          1
41    0x00  discard_enable         treatment word 0 bit 31          0
```

GPE words: rule `0x00001002 0x80000000`, treatment `0x00007C00 0x03E00000`

**Interpretation:** Single-tag passthrough for priority-tagged frames (VID=0).
`one_enable=1` matches single-tagged frames; `outer_vid_enable=1, vid=0` filters
to VID 0 (priority-tagged). Treatment 15 = don't modify either tag. Inserted before
each real DS rule in the ALCL path as a Nokia OLT interop safety net — catches
priority-tagged DS frames that shouldn't be translated by the VID-specific rules.

This format does NOT exist in v4.5.0 — v4.5.0 uses separate `gpe_vlan_rule_table` +
`gpe_vlan_treatment_table` structs via `omci_api_rule_ds_map`. The 42-byte unified
action format is a v7.5.1 addition that produces identical GPE table entries (same
`FIO_GPE_EXT_VLAN_GET/SET` ioctls, same 1044-byte buffer layout). Unrelated to the
dual-VLAN collision problem.

**42-byte action format field map** (decompiled from `omci_api_ext_vlan_action_add`):
```
FILTER (bytes 0-29):                                GPE rule bitfield:
  byte 0:      valid                                rule word 1 bit 31
  byte 1:      (unused)
  byte 2:      def                                  rule word 1 bit 29
  byte 3:      two_enable                           rule word 0 bit 2
  byte 4:      one_enable                           rule word 0 bit 1
  byte 5:      zero_enable                          rule word 0 bit 0
  byte 6:      outer_de_filter                      rule word 0 bit 28
  byte 7:      outer_de_enable                      rule word 0 bit 27
  byte 8:      outer_reg_tpid_en                    rule word 0 bit 26
  byte 9:      outer_input_tpid_en                  rule word 0 bit 25
  bytes 10-11: outer_vid_filter (BE u16 & 0xFFF)    rule word 0 bits 24-13
  byte 12:     outer_vid_enable                     rule word 0 bit 12
  byte 13:     outer_pri_filter (& 7)               rule word 0 bits 11-9
  byte 14:     outer_pri_enable                     rule word 0 bit 8
  byte 15:     inner_de_filter                      rule word 1 bit 20
  byte 16:     inner_de_enable                      rule word 1 bit 19
  byte 17:     inner_reg_tpid_en                    rule word 1 bit 18
  byte 18:     inner_input_tpid_en                  rule word 1 bit 17
  byte 19:     (unused)
  bytes 20-21: inner_vid_filter (BE u16 & 0xFFF)    rule word 1 bits 16-5
  byte 22:     inner_vid_enable                     rule word 1 bit 4
  byte 23:     inner_pri_filter (& 7)               rule word 1 bits 3-1
  byte 24:     inner_pri_enable                     rule word 1 bit 0
  byte 25:     ethtype_filter1_en (IPv4 0x0800)     rule word 1 bit 21
  byte 26:     ethtype_filter2_en (PPPoE 0x8863)    rule word 1 bit 22
  byte 27:     ethtype_filter3_en (ARP 0x0806)      rule word 1 bit 23
  byte 28:     ethtype_filter4_en (IPv6 0x86DD)     rule word 1 bit 24
  byte 29:     ethtype_filter5_en                   rule word 1 bit 25

TREATMENT (bytes 30-41):                             GPE treatment bitfield:
  byte 30:     tagb_tpid (& 7)                      treatment word 0 bits 30-28
  byte 31:     (unused)
  bytes 32-33: tagb_vid (BE u16 & 0x1FFF)            treatment word 0 bits 27-15
  byte 34:     tagb_treatment (& 0xF, 15=no modify)  treatment word 0 bits 14-11
  byte 35:     taga_tpid (& 7)                      treatment word 0 bits 9-7
  bytes 36-37: taga_vid (BE u16 & 0x1FFF)            treatment word 1:0 split
  byte 38:     taga_treatment (& 0xF, 15=no modify)  treatment word 1 bits 25-22
  byte 39:     inner_not_generate (& 1)              treatment word 0 bit 10
  byte 40:     outer_not_generate (& 1)              treatment word 1 bit 21
  byte 41:     discard_enable (& 1)                  treatment word 0 bit 31
```
NOTE: "outer"/"inner" in the 42-byte format map to GPE `outer`/`inner` respectively.
The naming is consistent with the GPE `gpe_vlan_rule_table` struct, NOT with OMCI
ME 171 conventions (which swap inner/outer depending on direction).

**Template system:** Matcher table at `DAT_0048a910` (68 entries × 128 bytes)
classifies rules by pattern. Action template table at `UNK_00486158` (272-byte
stride) provides selectors for building 42-byte US/DS actions. Negative
selectors resolved by `FUN_004394a0` (-23 = filter_inner_vid, -18 =
treatment_inner_vid, etc.).

**Auto-default:** On first table write to an ME 171 instance (`internal_data->0x20 == 0`),
omcid auto-programs one default entry from `DAT_0045d540`:
`F8 00 00 00 F8 00 00 00 00 0F 00 00 00 0F 00 00` = untagged passthrough.

#### ME 171 Association / ExtVLAN Linker

| VA | Name / Purpose | Notes |
|----|----------------|-------|
| `0x00438b4c` | `omci_api_ext_vlan_cfg_data_update` | Association linker: creates ExtVLAN tables, links bridge ports |
| `0x00439364` | GPE entry delete | By sort_index and direction |
| `0x00439408` | GPE table clear | Before reprogramming (called before sort loop) |
| `0x00439e90` | GPE table allocator | Allocates new ExtVLAN table, returns key |
| `0x00439ee4` | GPE table initializer | Initializes newly allocated table |
| `0x0043a058` | ExtVLAN table TPID config | Configures TPIDs on ExtVLAN table |
| `0x0043a0e4` | Table key resolver | Maps (ME instance, direction) → GPE table key |
| `0x0043a130` | `omci_api_ext_vlan_action_add` | Programs GPE hardware via ioctls |
| `0x00445734` | Bridge port ExtVLAN US linker | Links bridge port to US ExtVLAN table |
| `0x00445878` | Bridge port ExtVLAN DS linker | Links bridge port to DS table (table type 0x19) |
| `0x00446a20` | Mapper port list getter | Gets bridge ports for a mapper (assoc_type=1) |

**assoc_type → ME class mapping** (from `me_validate` at `0x4155e0`):

| assoc_type | ME class | Association target |
|-----------|----------|-------------------|
| 0 | 47 | MAC bridge port config data |
| 1 | 130 | IEEE 802.1p mapper service profile |
| 2 | 11 | PPTP Ethernet UNI |
| 3 | 134 | IP host config data |
| 4 | 98 | PPTP xDSL UNI |
| 5 | 266 | GEM interworking TP |
| 6 | 281 | Multicast operations profile |
| 7 | 162 | Physical path TP MoCA UNI |
| 8 | 91 | Physical path TP CES UNI |
| 9 | 286 | (unknown) |
| 10 | 329 | VEIP |

**Table keys** are dynamically allocated sequential integers (0, 1, 2...).
Each ME 171 instance gets its own US+DS table pair via composite key
`0xAB0000 | instance_id` (0xAB = 171 = ME class).

#### ME 266 (GEM Interworking TP)

| VA | Name / Purpose | Notes |
|----|----------------|-------|
| `0x0043b0b0` | `omci_api_gem_interworking_tp_update` | GEM port → GPIX mapping, LAN/bridge port tables |
| `0x00444fcc` | DS GEM port table programmer | Programs DS_GEM_PORT_TABLE entries |
| `0x00446234` | LAN port table programmer | Programs LAN_PORT_TABLE entries |
| `0x004172bc` | ME 266 `me_update` handler | GEM IW TP create/set → calls `0x0043b0b0` |
| `0x0041740c` | ME 266 `me_validate` handler | Validation |
| `0x0041747c` | ME 266 `me_shutdown` handler | Delete/shutdown |

GEM IW TP handler does NOT touch ExtVLAN tables — it manages GEM port → GPIX
mapping and LAN/bridge port table wiring via `FIO_GPE_GEM_PORT_GET` (ioctl
`0xc01c0406`, 28 bytes).

#### ME 290 (Dot1x Port Extension Package) — 802.1x

| VA | Name / Purpose | Notes |
|----|----------------|-------|
| `0x004432f0` | `omci_api_dotx_port_ext_pkg_pptp_eth_uni_update` | ME 290 API: resource lookup → decision tree → single ioctl |
| `0x00443570` | Decision tree | MIPS16, evaluates dot1x_enable/action_register |

Decision tree: if `dot1x_enable == 0` OR `action_register == 3` → OPEN (0);
if `action_register` in {1, 2} → BLOCK (1). Single ioctl `0x80080725`
(`FIO_LAN_PORT_802_1X_AUTH_CFG_SET`), 8-byte payload: {port_info, auth_state}.

#### ME 84 (VLAN Tagging Filter Data)

- ME 84 class structure at VA `0x472280`, class_id=0x54, data_size=26 bytes
- `me_update` handler at VA `0x424ad5`
- API function `omci_api_vlan_tagging_filter_data_update` at VA `0x44293c`
- Includes ALCL OLT interop code (VID=0 injection for TP type 3/5/6)
- `forwarding_oper` (fwdop) passed straight through — no conditioning on
  802.1x or any other ME state

#### GPE Table I/O

| VA | Name / Purpose | Notes |
|----|----------------|-------|
| `0x004440c0` | GPE table read | `(ctx, table_type, index, attr_count, buffer)` |
| `0x00444174` | GPE table write | `(ctx, write_type, buffer)` |

### Key Data Addresses

| Address | Content |
|---------|---------|
| `DAT_0045cc38` | `"HWTC"` (Huawei vendor string) |
| `DAT_0045cd04` | `"ALCL"` (Alcatel vendor string) |
| `DAT_0045d484` | ME 171 handler vtable |
| `DAT_0045d514` | Hardcoded IOP DS action (42 bytes, single-tag VID=0 passthrough). XREF 2× in ALCL path. See decode above |
| `DAT_0045d540` | ME 171 auto-default entry (16 bytes, untagged passthrough) |
| `UNK_00486158` | Action template table (272-byte stride) |
| `DAT_0048a910` | Rule matcher table (128-byte stride, 68 entries) |

#### Synchronize Time Handler (sync_time_action_handle)

| VA | Name / Purpose | Notes |
|----|----------------|-------|
| `0x00420924` | `sync_time_action_handle` | OMCI Synchronize Time (ME 256 ONU-G action) |
| `0x004203b0` | `sync_time_walker` | PM TCA cleanup callback (passed to mib_walk) |
| `0x00420564` | Error log function | `(format_string, error_code, ...)` |
| `0x0040c520` | mib_walk | `(ctx, callback, arg)` → walks PM MEs |
| `0x00433494` | ioctl wrapper | `FIO_ONU_SYNC_TIME_SET` — PM counter intervals only |

**Function layout (156 bytes code + 20 bytes literal pool):**
```
VA 0x420924–0x4209BF: code (MIPS16e)
VA 0x4209C0–0x4209D3: literal pool (5 × 32-bit entries)
```

**Literal pool entries:**

| # | File offset | VA | Value | Content |
|---|-------------|-----|-------|---------|
| 0 | `0x0209C0` | `0x4209C0` | `0x47F2B0` | `"%p, %p, %p, %p"` (debug entry format) |
| 1 | `0x0209C4` | `0x4209C4` | `0x46AC30` | `"sync_time_action_handle"` |
| 2 | `0x0209C8` | `0x4209C8` | `0x4203C1` | sync_time_walker (+1 = MIPS16e ISA bit) |
| 3 | `0x0209CC` | `0x4209CC` | `0x452D34` | Script path (patched from error string) |
| 4 | `0x0209D0` | `0x4209D0` | `0x46ABAC` | `"DRV ERR(%d) can't sync time!"` |

**Decompiled flow (from Ghidra):**
```c
int sync_time_action_handle(ctx, msg, arg3, response) {
    FUN_00420654(ctx, msg, ...);          // debug entry
    FUN_004092c4(ctx, ...);               // setup
    *(ctx + 0x78c) = 0;                   // clear flag
    *(ctx + 0x788) = 0;                   // clear flag
    FUN_004092f8(ctx, ...);               // setup

    iVar1 = FUN_0040c520(ctx, sync_time_walker+1, 0);  // mib_walk: PM reset
    if (iVar1 != 0) error_log("ERROR...", iVar1);

    iVar2 = FUN_00433494(*(ctx + 0x780));  // ioctl: PM interval mgmt
    if (iVar2 != 0) error_log("DRV ERR...", iVar2);

    // Response formatting: sets success/failure byte at response+8 or +10
    FUN_00420390("sync_time_action_handle", iVar1);  // debug exit
    return iVar1;
}
```

**Key finding:** The function NEVER reads OMCI message time fields (msg+8:
year, month, day, hour, minute, second). The ioctl
`FIO_ONU_SYNC_TIME_SET` (`_IOW(ONU_MAGIC, 9, struct onu_sync_time)`)
only manages PM 15-minute interval boundaries — confirmed from v4.5.0
SDK source (`drv_onu_common.c:884`):
```c
struct onu_sync_time {
    uint32_t interval_enable;           // 15-min PM interval on/off
    uint32_t interval_supervision_ext;  // external supervision flag
};
```
Clock setting was a TODO that was never implemented in any SDK version.

**PLT stubs used by the patch:**

| PLT VA | Function | JALX encoding |
|--------|----------|---------------|
| `0x402BA0` | `system()` | `1e 00 0a e8` |
| `0x403280` | `sprintf()` | `1e 00 0c a0` |
| `0x402AD0` | `memset()` | `1e 00 0a b4` (209 call sites) |

### Patch Sites

| File Offset | VA | Size | Purpose |
|-------------|-----|------|---------|
| `0x84CE`-`0x84D1` | `0x484CE` | 3B | Image version override disable (baked-in) |
| `0x20962`-`0x20981` | `0x420962` | 32B | sync_time system() call (baked-in) |
| `0x52D34`-`0x52D54` | `0x452D34` | 33B | sync_time script path string (baked-in) |
| `0x43589` (275849) | `0x443589` | 1B | 802.1x enforcement flag (runtime) |
| `0x4D2E5` (316133) | `0x44D2E5` | 58B | Version string override (runtime) |
| `0x4B1E8` (307944) | `0x44B1E8` | 58B | Earlier version offset (commented out) |

---

## mod_onu.ko — ONU Kernel Module

**File:** `8311-mods/lib/modules/3.10.49/mod_onu.ko`
**Size:** 1,022,908 bytes
**Architecture:** MIPS32 big-endian ELF

### Key Functions

| Offset | Name / Purpose | Size |
|--------|----------------|------|
| `0x4594c` | `lan_port_802_1x_auth_cfg_set` | 396B |
| `0x47880` | `lan_port_802_1x_auth_cfg_get` | — |
| `0x20ab4` | `onu_sync_time_set` | 184B |
| `0x1ea64` | `onu_sync_time_get` | 44B |

`lan_port_802_1x_auth_cfg_set` does two GPE operations:
1. Reads LAN Port Table (0x43) entry via `gpe_table_entry_intresp` (sub=0x3f)
2. XORs state with 1, inserts into bit 28 of data word 5 (`ins v1,v0,0x1c,0x1`)
3. Writes back via `gpe_table_entry_intcmd`
4. Reads Constants[1] via `gpe_sce_constant_get(ctrl, 1, &value)`
5. BLOCK: `value |= 0x1`; OPEN: `value &= 0xFFFFFFFE`
6. Writes back via `gpe_sce_constant_set(ctrl, 1, value)`

### Key Symbols (from `readelf -s`)

| Symbol | Address | Size | Purpose |
|--------|---------|------|---------|
| `gpe_sce_constants_set` | `0x3c264` | — | Write GPE constants table |
| `gpe_sce_constants_get` | `0x3bf34` | — | Read GPE constants table |
| `gpe_table_lanport_acc_ctrl` | `0x3d34c` | — | LAN Port Table access control sub-table view |
| `gpe_lan_port_table_init` | `0x3af98` | — | LAN Port Table init (memset to 0) |
| `gpe_vlan_tagging_filter_create` | — | — | ME 84 → GPE Tagging Filter Table (0x11) |
| `gpe_vlan_tagging_filter_set` | — | — | fwdop → bits 17-19 of header word |
| `gpe_ethertype_filter_cfg_set` | `0x34994` | — | Also touches LAN Port Table (0x43), bits 21-28 |

### SBS2.TOD — Hardware Time of Day Subsystem

The Falcon SoC has a hardware Time of Day clock in the SBS2 (System Bus
Slave 2) register block. It counts TAI seconds since epoch (1970-01-01,
no leap seconds) and is populated by the GTC layer during PLOAM ranging.

**Hardware registers:**

| Register | Access | Purpose |
|----------|--------|---------|
| `SBS2.TOD.PPSSEC` | RO | Seconds counter (TAI epoch) — `tod_pps_get()` |
| `SBS2.TOD.SFCC` | RW | Superframe counter — `tod_sfcc_set/get()` |
| `SBS2.TOD.RLDS` | RW | Reload seconds — `tod_rlds_set/get()` |
| `SBS2.TOD.RLDNS` | RW | Reload nanoseconds (14-bit hi + 15-bit lo) — `tod_rldns_set/get()` |

**Key functions in mod_onu.ko:**

| Offset | Name | Size | Purpose |
|--------|------|------|---------|
| `0x67248` | `tod_pps_get` | 16B | Read PPSSEC register (TAI seconds) |
| `0x672b0` | `tod_init` | 60B | PPS interrupt setup, ASC1 init |
| `0x66dbc` | `tod_sync_get` | 128B | Read reload register values |
| `0x66e3c` | `tod_reload_update` | 864B | Full reload: compute corrections, write SFCC/RLDS/RLDNS |
| `0x4dcf8` | `onu_time_to_tm` | 112B | TAI seconds → broken-down time (wraps kernel `time_to_tm`) |
| `0x24b5c` | `gpe_tod_get` | 160B | `tod_pps_get()` → `onu_time_to_tm()` → fill `struct gpe_tod` |
| `0x27c84` | `gpe_tod_sync_set` | 156B | Write SBS2.TOD registers (explicit ToD set) |
| `0x24bfc` | `gpe_tod_sync_get` | 100B | Read back reload register values |
| `0x24c60` | `gpe_tod_sync_status_get` | 116B | Read ToD sync status + nanoseconds |

**GTC ranging auto-populates ToD.** Cross-reference analysis of `tod_reload_update`
callers (3 sites):

| .text offset | Containing function | Context |
|---|---|---|
| `0x27d08` | `gpe_tod_sync_set` | Explicit set from CLI/ioctl |
| `0x688d0` | (unnamed, GTC ranging) | Surrounded by `gtc_ranged_delay_set/adjust/enable` |
| `0x695cc` | (unnamed, GTC ranging) | Surrounded by `gtc_ranged_delay_get/set` |

The two GTC ranging callers run during PLOAM O4→O5 registration. After
ranging completes, `tod_reload_update` loads the current time into the
SBS2.TOD registers. The PPSSEC counter then counts up from the loaded
value, providing a valid TAI timestamp for `tod_pps_get()`.

**CLI commands:**

| Command | Handler | Output format |
|---------|---------|---------------|
| `onu gpe_tod_get` | `cli_gpe_tod_get` | `errorcode=N sec=N min=N hour=N mday=N mon=N year=N wday=N yday=N sec_tai=N` |
| `onu gpetsg` | `cli_gpe_tod_sync_get` | `errorcode=N multiframe_count=N tod_seconds=N tod_extended_seconds=N tod_nano_seconds=N` |
| `onu gpetss` | `cli_gpe_tod_sync_set` | Takes: multiframe_count, tod_seconds, tod_extended_seconds, tod_nano_seconds |

**Live test (offline stick, no OLT):**
```
errorcode=0 sec=0 min=0 hour=0 mday=1 mon=1 year=1970 wday=4 yday=0 sec_tai=0
```
`sec_tai=0` is expected without OLT registration — GTC ranging hasn't run.

**TAI → UTC conversion:** TAI = UTC + leap_seconds. Current offset is 37
seconds (since 2017-01-01). The `omci_sync_time.sh` helper script reads
`sec_tai`, subtracts the leap second offset (configurable via
`8311.config.tai_utc_offset`), and sets the Linux system clock with `date -s`.

**Ghidra note:** `gpe_tod_get` decompiles poorly because the first JAL
targets `tod_pps_get` via an unresolved R_MIPS_26 relocation (shows as
`jal SUB_00000000`). Ghidra treats this as CALL_TERMINATOR and marks
everything after as undefined bytes. The function is structurally identical
to the v4.5.0 SDK source — two JAL calls (`tod_pps_get`, `onu_time_to_tm`)
followed by SWL/SWR pairs filling the output struct.

**Kernel symbol imports (time-related):** mod_onu imports `time_to_tm`
(epoch → broken-down time) and `jiffies` but does NOT import
`do_settimeofday`, `call_usermodehelper`, or any other clock-setting or
usermode-helper API. Setting the Linux system clock from mod_onu.ko would
require ELF section surgery to add new symbol imports.

### Proprietary ioctls

| ioctl | Name | Size | Purpose |
|-------|------|------|---------|
| `0x80080725` | `FIO_LAN_PORT_802_1X_AUTH_CFG_SET` | 8B | 802.1x port auth |
| `0x80080726` | `FIO_LAN_PORT_802_1X_AUTH_CFG_GET` | 8B | 802.1x port auth read |
| `0xc01c0406` | `FIO_GPE_GEM_PORT_GET` | 28B | GEM port lookup |
| `0xc4140508` | ExtVLAN table read | 1044B | Read GPE ExtVLAN table |
| `0x84120509` | ExtVLAN table write | 1044B | Write GPE ExtVLAN table |
| `0x4020051a` | Custom EtherType config | — | TPID configuration |
| `0x80200514` | Custom EtherType config | — | TPID configuration |

**None of the 802.1x ioctls exist in the v4.5.0 SDK.**

---

## mod_optic.ko — Optic Kernel Module

**File:** `8311-mods/lib/modules/3.10.49/mod_optic.ko`
**Size:** 344,332 bytes
**Architecture:** MIPS32 big-endian ELF

### Key Symbols (from `readelf -s`)

| Symbol | Address | Size | Purpose |
|--------|---------|------|---------|
| `optic_gpio_init` | `0x14c00` | 260B | GPIO pin init (NOP'd in patch) |
| `optic_gpio_set` | `0x14d70` | 32B | Direct GPIO write (bypassed) |
| `optic_gpio_get` | `0x14d0c` | 32B | Read GPIO value |
| `optic_gpio_set_input` | `0x14d2c` | 68B | Set GPIO as input |
| `optic_gpio_free` | `0x14d04` | 8B | GPIO cleanup |
| `optic_isr_gpio_sd` | `0x1a79c` | 56B | Signal detect ISR |
| `optic_register_los_pin_update` | `0x12dac` | 12B | Stores callback at `optic_ctrl+0x904` |
| `optic_register_laser_age_update` | `0x12da0` | 12B | Stores callback at nearby offset |

### Callback Mechanism

`optic_register_los_pin_update()` stores a function pointer at offset
`0x904` in the `optic_ctrl` structure. `mod_onu` registers
`onu_rssi_los_handle` here during its init. In stock firmware, `mod_optic`
never invokes this callback — the patches wire it in.

---

## GPE (GPON Processing Engine)

The GPE is a programmable VLIW packet processor that handles all packet
classification, VLAN translation, forwarding, and 802.1x enforcement on
the Falcon SoC. It runs proprietary microcode and is configured via
kernel-space table operations (ioctls to `/dev/onu0`).

### GPE Table Map (from mod_onu.ko string analysis)

| Table ID | Name | Purpose |
|----------|------|---------|
| `0x11` (17) | `ONU_GPE_TAGGING_FILTER_TABLE` | ME 84 fwdop → bits 17-19 |
| `0x12` (18) | `ONU_GPE_VLAN_TABLE` | VLAN assignment |
| `0x19` (25) | Bridge port DS config | DS ExtVLAN linker (16 attrs) |
| `0x21` (33) | `gpe_bridge_port_table` | US ExtVLAN linker (8 attrs) |
| `0x29` (41) | `ONU_GPE_EXTENDED_VLAN_TABLE` | ME 171 extended VLAN rules |
| `0x2A` (42) | `ONU_GPE_VLAN_RULE_TABLE` | VLAN match/action rules |
| `0x2B` (43) | `ONU_GPE_VLAN_TREATMENT_TABLE` | VLAN tag treatment |
| `0x40` (64) | `ONU_GPE_CONSTANTS_TABLE` | SCE constants (51 fields) |
| `0x41` (65) | `ONU_GPE_BRIDGE_PORT_TABLE` | Bridge port config |
| `0x42` (66) | `ONU_GPE_PMAPPER_TABLE` | P-bit mapper (8 bridge port indices per mapper) |
| `0x43` (67) | `ONU_GPE_LAN_PORT_TABLE` | Per-port config + auth bit |
| `0x44` (68) | `ONU_GPE_ENQUEUE_TABLE` | Queue assignment |
| `0x49` (73) | `ONU_GPE_REDIRECTION_TABLE` | Traffic redirection |
| `0x4A` (74) | `ONU_GPE_VLAN_START_ID_TABLE` | VLAN ID range start |
| `0x4C` (76) | `ONU_GPE_BRIDGE_TABLE` | Bridge config |
| `0x4D` (77) | `ONU_GPE_STATUS_TABLE` | Runtime status |
| `0x4E` (78) | `ONU_GPE_EXCEPTION_TABLE` | Exception handling |
| `0x4F` (79) | `ONU_GPE_ETHERTYPE_EXCEPTION_TABLE` | EtherType-based exceptions |

**LAN Port Table (0x43)** has five sub-table views (all same table ID,
different config data): `general`, `vlan`, `acc_ctrl`, `tfc_mgmt`, `oam`.

### GPE SCE Constants Field Map (51 entries)

| Index | Field | Notes |
|-------|-------|-------|
| 0 | `packet_processing_enable` | Master enable |
| **1** | **`eapol_transparent_enable`** | **802.1x EAPoL passthrough gate** |
| 2 | `default_outer_vid` | |
| 3 | `default_inner_vid` | |
| 4 | `default_dscp` | |
| 5 | `vlan_unaware_l3_mc` | |
| 6 | `fwd_table_size` | |
| 7-10 | `tpid_a` through `tpid_d` | Tag Protocol IDs |
| 11 | `global_timer` | |
| 12 | `added_latency` | |
| 13-14 | `pcp_max_prio` / `_enable` | Priority code point |
| 16 | `tci_disable` | |
| 17 | `dual_if_enable` | |
| 18-19 | `ani_exception_meter_id` / `_enable` | |
| **20** | **`drop_mask`** | Per-exception drop bitmask |
| **21** | **`transparent_mask`** | Per-exception passthrough bitmask |
| **22** | **`extraction_mask`** | Per-exception CPU extraction bitmask |
| 23 | `meter_l2_only_enable` | |
| 28 | `lrn_full_fwd` | Learning table full action |
| 35-38 | Trunking config | |
| 39-46 | `traffic_class_map_0..7` | TC mapping |

In v4.5.0 SDK, index 1 was `ONU_GPE_CONST_DEFAULT_FID` (init to 0). The
expanded struct (51 vs 18 entries) is proprietary to the post-v4.5.0 build.

### GPE Exception Types (32 types, from v4.5.0 `drv_onu_resource_gpe.h`)

Constants[20-22] (`drop_mask`, `transparent_mask`, `extraction_mask`) are
bitmasks over these 32 exception types. Exception profiles (8 total: UNI0-3,
GEM_US, GEM_DS, MC_GEM, BC_GEM) have per-profile ingress/egress masks.

| Bit | Type | Notes |
|-----|------|-------|
| 0-2 | ETH / ETH_BC / ETH_MC | Raw Ethernet |
| 3-4 | TCP / UDP | Transport |
| 5-6 | IPv4 / IPv6 | Network |
| 7-8 | PPPoE_8864 / LEN | PPPoE Discovery / Length |
| 9-12 | MPLS / IPv4_BC / IPv4_MC / IPv6_MC | |
| 13-15 | PPPoE_8863_BC / AppleTalk / IPX | |
| 16-18 | ARP / RARP / NetBEUI | |
| 19 | BPDU | STP |
| 20 | DHCP | |
| **21** | **SPECTAG** | **Special EtherType (matched via table 0x4F)** |
| 22-23 | ICMP / IGMP_MLD | |
| 24-25 | CFM / MAC_CTRL | 802.1ag / MAC Control |
| 26-27 | PPPoE_8863 / OMCI | |
| 28-29 | LOCAL_MAC / DoS | |
| 30-31 | DoS_LEARN / PARSER | |

**EtherType Exception Table (0x4F):** Stores up to 8 special EtherType values.
A match triggers the SPECTAG exception (bit 21). Whether this check occurs
before or after VLAN tag stripping is unknown. 0x888E is not registered by
default. Structure from `drv_onu_gpe_tables.h`:
`gpe_ethertype_exception_table` — 8 × uint16 EtherType entries.

### GPE Resource Type Map (omcid internal, managed via `0x434de0` / `0x434ac0`)

| Type | Hex | Purpose |
|------|-----|---------|
| 1 | `0x01` | Bridge port |
| 10 | `0x0A` | MAC bridge service profile |
| 16 | `0x10` | Mapper → bridge index |
| 19 | `0x13` | Multicast chain lookup |
| 22 | `0x16` | Multicast operations profile |
| 27 | `0x1B` | LAN port (PPTP path) |
| 30 | `0x1E` | VEIP |
| 31 | `0x1F` | LAN port (VEIP/xDSL path) |
| 39 | `0x27` | ExtVLAN US table key |
| 40 | `0x28` | ExtVLAN DS table key |
| 41 | `0x29` | ExtVLAN ↔ bridge port association |
| 42 | `0x2A` | GEM port index (GPIX) |

### Bridge Port ExtVLAN Linkage Bit Layout

**US linkage** (table type 0x21):
- Enable flag: bit 7 of byte (`(enable & 0xff) << 7`)
- ExtVLAN table key: bits 0-6 (7 bits, `key & 0x7f`)
- Layout: `[E KKK KKKK]`

**DS linkage** (table type 0x19):
- Enable flag: bit 4 of offset +1 byte (`(enable & 1) << 4`)
- ExtVLAN table key: bits 13-19 of word (`(key & 0x7f) << 0xd`)
- Layout: `[... KKKK KKK. .... .E.. ....]`

### ExtVLAN ioctl Buffer Layout (1044 bytes)

```
Offset  Size   Content
0x000   4      table_key (composite: 0xAB0000 | ME_instance, or allocated index)
0x004   12     header (3 × uint32, preserved from read)
0x010   512    64 filter entries × 8 bytes (2 × uint32 each)
0x210   512    64 treatment entries × 8 bytes (2 × uint32 each)
0x410   2      entry_count (uint16, 0-64)
0x412   2      padding
```

- Read: `ioctl(fd, 0xc4140508, buf)` — set buf[0]=table_key, returns 1044B
- Write: `ioctl(fd, 0x84120509, buf)` — full 1044B buffer
- Filter VID packing: `vid << 0xd` (bits 13-24 of filter word 0, 12-bit VID)
- Entry limit: 64 per direction (enforced at entry)

### GPE Firmware Microcode (falcon_gpe_fw.bin)

**File:** `~/dev-orig/lib/firmware/sfu/falcon_gpe_fw.bin`
**Size:** 15,008 bytes (0x3AA0)
**Architecture:** 64-bit VLIW instruction words (8 bytes each), 1876 instructions
**Header magic:** `09 5a 06 01`

**Cross-firmware comparison:** Three distinct GPE versions exist across all Nokia
Falcon SFP ONUs. All share the same post-VLAN EAPoL dispatch bug:

| Version | Header | Size | Firmwares | MD5 |
|---------|--------|------|-----------|-----|
| v6.4 | `09 2f` | 13,872B | G-010S-P AOPD39 (2015) | `7f1f6b642e87d62044a227e292801ed4` |
| v7.5 | `09 5a 06 01` | 15,008B | G-010S-P BOPD09, G-010S-A AFGA95, **this firmware** | `8e44da609dbe4fd183b3b4346f335f20` |
| v7.5+ | `09 5a 07 00` | 15,024B | G-010S-A BFIB36, BGCB22p03 | `b744e2845e8535f9f5a910762eb5accd` |

G-010S-P AOPD39 uses path `a2x/falcon_gpe_fw.bin` (not `sfu/`). All v7.5+
firmwares (G-010S-A only) are +16 bytes with offsets shifted accordingly.

**EtherType references:**

| EtherType | Offset | Opcode | Occurrences |
|-----------|--------|--------|-------------|
| `0x888E` (EAPoL) | `0x33b9` | `0xe0` | 1 |
| `0x887B` (MKA/pre-auth) | `0x3149` | `0xe0` | 1 |
| `0x8100` (802.1Q) | `0x0955` | — | 1 |
| `0x9100` (QinQ legacy) | `0x0eaf` | — | 1 |

Not present: 0x88A8, 0x86DD, 0x0806, 0x88CC, 0x88F7.

**EAPoL handling code block (0x3380-0x3400):**
```
0x3380: c8 66 8e 00 00 00 00 00    # branch into EAPoL handler
0x33b8: e0 88 8e 00 00 00 00 00    # 0xe0: immediate-load 0x888E (EAPoL compare)
0x33c0: d1 d8 02 80 7f 80 08 01    # reads Constants[1] — unique d1 with byte[7]=0x01
0x33c8: d1 dc f2 00 00 01 60 00    # references 0x0160 (Constants Table base)
0x3400: d2 66 8e 00 00 00 00 00    # end of handler / writeback
```

Instruction at 0x33c0 is the **only** `d1`-opcode instruction in the entire
firmware with byte[7] = 0x01. Confirms GPE gates EAPoL handling on
`eapol_transparent_enable` (Constants[1]).

Only 3 instructions in the firmware use opcode `0xe0` (immediate-load):
`0x2a20` (imm=0x1270), `0x3148` (imm=0x887B), `0x33b8` (imm=0x888E).

**0x66-series EtherType dispatch mechanism:**

The GPE uses a three-instruction pattern for EtherType-specific packet handling:

| Opcode prefix | Role | Description |
|---------------|------|-------------|
| `d0 66 XX` | SETUP | Begin EtherType check / comparison |
| `c8 66 XX` | DISPATCH | Route packet to EtherType handler |
| `d2 66 XX` | CLOSE | End operation / writeback / cleanup |

The third byte (`XX`) varies by EtherType context but correlates with the
protocol being handled. VLAN dispatchers use `XX=81` / `XX=c8`; EAPoL uses
`XX=8e`.

Complete 0x66-series instruction map:

```
Offset  Bytes              Role      Context
0x07d8  d2 66 83 ...       CLOSE     (early cleanup)
0x08c0  c8 66 02 ...       DISPATCH  (protocol dispatch)
0x1d90  d0 66 c8 ...       SETUP  ─┐
0x1da0  c8 66 81 ...       DISPATCH │ VLAN tag processing (first stage)
0x2100  d0 66 c8 ...       SETUP  ─┐
0x2108  c8 66 81 ...       DISPATCH │ VLAN tag processing (second stage)
0x2390  d0 66 8e ...       SETUP  ─┐ Post-VLAN EAPoL check
0x2398  d2 66 88 ...       CLOSE   │ ← immediately closed, no dispatch
0x3200  d0 66 ca ...       SETUP  ─┐
0x3238  d2 66 8a ...       CLOSE   │ (other protocol)
0x3380  c8 66 8e ...       DISPATCH ─ Pre-VLAN EAPoL handler entry
  ...(handler code, Constants[1] check)...
0x3400  d2 66 8e ...       CLOSE   ─ EAPoL handler exit
0x3450  c8 66 18 ...       DISPATCH  (protocol dispatch)
0x3848  c8 66 2f ...       DISPATCH  (protocol dispatch)
0x3850  d0 66 c8 ...       SETUP     (late VLAN)
0x38d0  c8 66 2e ...       DISPATCH  (protocol dispatch)
0x38d8  d0 66 c8 ...       SETUP     (late VLAN)
```

Totals: 6× `d0 66` (SETUP), 7× `c8 66` (DISPATCH), 5× `d2 66` (CLOSE).

**Post-VLAN EAPoL path (0x2390-0x2398):**

The pre-VLAN EAPoL handler at 0x3380 works for untagged frames (outer
EtherType = 0x888E). For tagged/priority-tagged frames (outer EtherType =
0x8100), the packet enters the VLAN path at 0x1d90/0x2100 first. After VLAN
tag stripping exposes the inner EtherType, the `d0 66 8e` SETUP at 0x2390
recognizes EAPoL — but immediately closes (`d2 66 88` at 0x2398) without
dispatching. The `c8 66 8e` dispatch instruction is absent.

Compare with the working VLAN path: `d0 66 c8` (SETUP) → `c8 66 81`
(DISPATCH) → handler. The post-VLAN EAPoL path is: `d0 66 8e` (SETUP) →
`d2 66 88` (CLOSE) — dispatch step is missing.

**Firmware statistics:** 630 null instructions (33.6% of 1876 total). NOP
regions are fragmented — no contiguous block ≥ 24 bytes.

### LAN Port Table Auth Bit

- Table 0x43, data word 5 (byte offset 20), **bit 28**
- OPEN (authorized): bit = 1
- BLOCK (unauthorized): bit = 0
- At init (`gpe_lan_port_table_init`, 0x3af98): memset to 0 → bit 28 = 0
- `gpe_ethertype_filter_cfg_set` also modifies bits 21-28 of LAN Port entries
  (ethertype filter pointer/mode/enable)

### VLAN Tagging Filter Structure (Table 0x11)

Header word contains forwarding operation bits:
- **Bit 19**: fwdop flag 1 (output offset +268)
- **Bit 18**: fwdop flag 2 (output offset +272)
- **Bit 17**: fwdop flag 3 (output offset +276)

These 3 bits encode the ME 84 `forwarding_operation` field.

---

## ME 171 Table Entry Format (16 bytes)

From `8311-extvlan-decode.sh` and omcid decompilation:

```
Word 1 (filter outer):  [priority:31-28] [VID:27-15] [TPID/DEI:14-12] [pad:11-0]
Word 2 (filter inner):  [priority:31-28] [VID:27-15] [TPID/DEI:14-12] [ext-criteria:11-4] [ethertype:3-0]
Word 3 (treat outer):   [remove-tags:31-30] [pad:29-20] [priority:19-16] [VID:15-3] [TPID/DEI:2-0]
Word 4 (treat inner):   [pad:31-20] [priority:19-16] [VID:15-3] [TPID/DEI:2-0]
```

**EtherType filter codes** (word 2, bits 3-0):
| Code | EtherType |
|------|-----------|
| 0 | No filter |
| 1 | 0x0800 (IPv4) |
| 2 | 0x8863/0x8864 (PPPoE) |
| 3 | 0x0806 (ARP) |
| 4 | 0x86DD (IPv6) |
| **5** | **0x888E (EAPoL)** |

**Special values:**
- Filter VID 4096 = no filter (0-4094 = literal VID)
- Filter priority 8 = any; 14 = default rule; 15 = no tag (outer: not double-tag)
- Treatment VID 4096 = copy inner; 4097 = copy outer
- Treatment remove_tags: 0=none, 1=outer, 2=both, 3=discard (G.988 delete sentinel)

---

## Diagnostic Interface

### onu CLI (via `/opt/lantiq/bin/onu`)

**GPE 802.1x:**
```sh
onu lanp8021acg <port>                # Read 802.1x auth state
onu lanp8021acs <port> <state>        # Set auth state (0=OPEN, 1=BLOCK)
onu gpecsg <index>                    # Read GPE Constants[index]
onu gpecss <index> <value>            # Set GPE Constants[index]
onu gpe_exception_profile_cfg_get <port>  # Read exception profile
onu gpe_ethertype_filter_cfg_get <port>  # Read EtherType filter config
onu gpe_ethertype_filter_cfg_set <port> <mode> <enable> <ptr>  # Set EtherType filter
```

**GPE Time of Day:**
```sh
onu gpe_tod_get                      # Read hardware ToD (TAI → broken-down time)
onu gpetsg                           # Read raw ToD reload register values
onu gpetss <mfc> <sec> <ext> <nsec>  # Set hardware ToD registers
```

**GPE tables:**
```sh
onu xml_table <table_name> [-1]       # Dump GPE table (XML, -1=all entries)
onu xml_table gpe_bridge_port_table -1
onu xml_table gpe_ds_gem_port_table -1
onu xml_table gpe_us_gem_port_table -1
onu xml_table gpe_pmapper_table -1
onu xml_table gpe_table_extvlan -1
onu xml_table gpe_counter_table -1
```

**GPE bridge port counters:**
```sh
onu gpebpcg <index> <reset_mask> <curr>   # Get counters (ibp/ebp good/discard)
onu gpebpcr <index> <reset_mask> <curr>   # Reset counters
onu gpegtcg <val>                          # GEM total counters (rx/tx frames/bytes)
```

**Note:** `gpetr`/`gpetw`/`gpets`/`gpeta`/`gpetd` operate on GPE table
**descriptors** (metadata), NOT per-entry data. The table name and index
parameters are ignored. Per-entry access requires direct ioctls.

### omci_pipe.sh (via `/opt/lantiq/bin/omci_pipe.sh`)

```sh
omci_pipe.sh md                          # MIB dump (all ME instances)
omci_pipe.sh meg <class> <instance>      # Get ME attributes
omci_pipe.sh meadg <class> <inst> <attr> # Get single attribute
omci_pipe.sh meads <class> <inst> <attr> <value>  # Set single attribute
omci_pipe.sh rmr <bytes...>              # Raw OMCI message (40 bytes baseline)
omci_pipe.sh managed_entity_attr_data_get <class> <inst> <attr>
omci_pipe.sh managed_entity_attr_data_set <class> <inst> <attr> <bytes...>
```

### gtop (via `/opt/lantiq/bin/gtop`)

```sh
gtop -b -g "Bridge port counter"     # IBP/EBP per bridge port
gtop -b -g "GEM port"               # GEM port info
gtop -b -g "GPE DS GEM port"        # Per-direction GEM port view
gtop -b -g "GPE bridge port"        # Bridge port config
gtop -b -g "GPE Counter"            # COP counters
gtop -b -g "GPE VLAN"               # VLAN table
gtop -b -g "GPE FID assignment"     # FID assignment table
gtop -b -g "GTC counters"           # Global tx/rx GEM frames/bytes
```

---

## SDK Version Map

| Version | Era | 802.1x | GPE Constants | Architecture | Source |
|---------|-----|--------|---------------|--------------|--------|
| v4.5.0 | ~2014 | None | 18 entries | Pre-pon_adapter | Osmocom mirror, `/mnt/c/devel/gpon_onu_drv-4.5.0/` |
| ~v7.5.1 | 2017-18 | Added (buggy) | 51 entries | Pre-pon_adapter | Shipping firmware (proprietary, no source) |
| v8.6.3 | ~2020+ | Present | 51+ entries | pon_adapter refactoring | `/mnt/e/Downloads/gpon_omci_onu-8.6.3/` |

- v4.5.0: Zero 802.1x/EAPoL references. `FIO_LAN_PORT_802_1X_AUTH_CFG_SET/GET`
  are proprietary additions. Constants index 1 = `ONU_GPE_CONST_DEFAULT_FID`.
- Shipping firmware: Core OMCI ME handler code closer to v8.6.3 than v4.5.0.
  ME 290 has custom `me_init` (defaults action_register=3, force-authenticated).
- pon_adapter/libponnet introduced after v7.5.1 era (architectural change).

---

## Nokia omciMgr (G-010S-A) — 802.1x Comparison

The G-010S-A uses Nokia's proprietary `omciMgr` C++ OMCI stack instead of
Lantiq `omcid`. Despite different architecture, the 802.1x enforcement path
is functionally equivalent. omciMgr does NOT use MIB files for ME init.

**Source:** G-010S-A BGCB22p03 firmware from
[hwti/G-010S-A](https://github.com/hwti/G-010S-A). Extracted rootfs at
`/tmp/gpe-compare/G010SA_BGCB22p03_2021_root_0/`.

### Call Chain

```
omciMgr: Dot1XPortExtension::set_attributes (VA 0x455a04, 548B)
  → validates dot1x_enable: only 0 or 1
  → validates action_register: only 2 or 3 (rejects 1 with OMCI error)
  → configUniDot1xParams (VA 0x51afac, 132B) → async message
    → configUniDot1xParamsAction (VA 0x51b030, 280B) → card type check
      → sal_config_port_802_1x_action (libsal_qos.so, 0x3b90, 972B)
        → is_802_1x_feature_supported → hal_is_sfu_system → TRUE
        → hal_config_port_to_allow_all_packets (OPEN)
        → hal_config_port_to_only_allow_802_1x_packets (BLOCK)
          → hal_cfg_dot1x_state (libhal_dp.so, 0x2bd20, 248B)
            → ioctl(fd, 0x80080725, ...) ← same ioctl as omcid
```

### SAL Decision Tree (decompiled)

```c
// libsal_qos.so: sal_config_port_802_1x_action
if (dot1x_enable == 0)           → OPEN
else if (action_register == 3)   → OPEN
else if (action_register == 2)   → BLOCK
else                             → return -1 (no ioctl)
```

### Defaults (set_to_default, VA 0x455e64)

```
me->dot1x_enable = 0       // sb zero, 2(a0)
me->action_register = 3    // li v0, 3; sb v0, 3(a0)
```

Calls `configUniDot1xParams(portId, {0, 3})` → SAL → OPEN on init.

### Key Difference: action_register=1 Handling

| | omcid | omciMgr |
|-|-------|---------|
| AR=1 | BLOCK (maps 1&2 → BLOCK) | REJECTED (OMCI error, no ioctl) |
| AR=2 | BLOCK | BLOCK |
| AR=3 | OPEN | OPEN |

omciMgr's validation explicitly rejects AR=1 at the ME layer before it
reaches the SAL function. omcid accepts AR=1 and incorrectly blocks the port.
Per G.988, AR=1 = "force authorized" = should OPEN. Neither implementation
is correct for AR=1, but omciMgr fails less destructively.

**Conclusion:** Both stacks BLOCK identically for AR=2 (what AT&T sends).
Both use the same GPE firmware with the same EAPoL transparent mode bug.
The G-010S-A "working" on AT&T is most likely OLT-side provisioning behavior
(different ONU identity → different OMCI config pushed), not a firmware fix.

---

## Nokia Proprietary Managed Entities

Extracted from the G-010S-P BOPD09 firmware (`omciLibMgr`/`omciLibParser`).
Nokia uses vendor-specific MEs in the 65xxx range (0xFF01+). These are
NOT available in the Lantiq/sean firmware — only documented for reference.

**Class table:** 31 vendor MEs from 65281 (0xFF01) to 65531 (0xFFFB).

### Named entries (22) from omciLibParser string table

| Class ID | Hex | Name | C++ Handler | Purpose |
|----------|-----|------|-------------|---------|
| 65281 | 0xFF01 | ONT AGGR GEM PORT PM HIST DATA | `AggrGemPortPMHistData` | Aggregate GEM port PM |
| 65282 | 0xFF02 | ETHERNET TM HIST DATA | `EtherTMHistData` | Ethernet traffic management PM |
| 65283 | 0xFF03 | STATIC MULTICAST ADDR LIST | `McastSubscriberInfo` | Static multicast addresses |
| 65284 | 0xFF04 | VOIP CALL STATISTICS | `VoipCallStatistics` | VoIP call stats |
| 65285 | 0xFF05 | MOCA_UNI_SUPPLEMENTAL_1 | — | MoCA UNI supplemental |
| 65286 | 0xFF06 | MOCA_PHY_PM_HIST_DATA | — | MoCA PHY PM |
| 65287 | 0xFF07 | VLAN_MAPPER | `VlanMapper` | VLAN mapper (Nokia extension) |
| 65288 | 0xFF08 | NTP_CONFIGURATION | `NtpConfiguration` | NTP client config |
| 65289 | 0xFF09 | ETHERNET_UNI_OAM | — | Ethernet UNI OAM |
| 65291 | 0xFF0B | VOIP_CLIENT_1 | `VoipClient_1` | VoIP client |
| 65292 | 0xFF0C | VOIP_SUPPLEMENT_1 | `VoipSupplement_1` | VoIP supplement |
| 65295 | 0xFF0F | ONT_OPTICAL_SUPERVISION | `OntOpticalSupervision` | Optical monitoring/alarms |
| 65296 | 0xFF10 | ONT_GENERIC_V2 | `OntGenericV2` | ONT-G extended (timers, etc.) |
| 65297 | 0xFF11 | UNI_SUPPLEMENTAL_1V2 | `UniSupp_1V2` | UNI supplemental v2 |
| 65301 | 0xFF15 | IP_MAC_ANTI_SPOOF_LIST | — | IP/MAC anti-spoofing |
| 65304 | 0xFF18 | NTP_CONFIGURATION_V2 | `NtpConfigurationV2` | NTP config v2 (with alarms) |
| 65307 | 0xFF1B | PPTP_HPNA_UNI | `HpnaUniPptp` | PPTP HPNA UNI |
| 65312 | 0xFF20 | ANI_G_SUPP_1 | `AnigSupp_1` | ANI-G supplemental (RSSI alarms) |
| 65313 | 0xFF21 | ONT AGGR ETHERNET PM HIST DATA | `AggrEthernetPMHistData` | Aggregate Ethernet PM |
| 65314 | 0xFF22 | CLOCK_DATA_SET | `ClockDataSet` | IEEE 1588 clock data set |
| 65315 | 0xFF23 | PTP_MASTER_CONFIG_DATA_PROFILE | `PtpMasterConfigDataProfile` | PTP master config |
| 65316 | 0xFF24 | PTP_PORT | `PtpPort` | PTP port config |
| 65319 | 0xFF27 | ONU_CLOCK_ADJUSTMENTS | `OnuClockAdjustments` | ONU clock tuning |

### Unnamed entries (9) from binary class table scan

| Class ID | Hex | Notes |
|----------|-----|-------|
| 65293 | 0xFF0D | Between VOIP_SUPPLEMENT_1 and ONT_OPTICAL_SUPERVISION |
| 65299 | 0xFF13 | Between UNI_SUPPLEMENTAL_1V2 and IP_MAC_ANTI_SPOOF_LIST |
| 65300 | 0xFF14 | Between UNI_SUPPLEMENTAL_1V2 and IP_MAC_ANTI_SPOOF_LIST |
| 65303 | 0xFF17 | Between IP_MAC_ANTI_SPOOF_LIST and NTP_CONFIGURATION_V2 |
| 65305 | 0xFF19 | Between NTP_CONFIGURATION_V2 and PPTP_HPNA_UNI |
| 65306 | 0xFF1A | Between NTP_CONFIGURATION_V2 and PPTP_HPNA_UNI |
| 65529 | 0xFFF9 | CTC ONU Capability (from MIB file) |
| 65530 | 0xFFFA | CTC LOID Password (from MIB file) |
| 65531 | 0xFFFB | CTC-related (highest entry in table) |

### Notes

**Gaps (not in this firmware):** 65290 (0xFF0A), 65294 (0xFF0E),
65298 (0xFF12), 65302 (0xFF16), 65308–65311 (0xFF1C–0xFF1F),
65317–65318 (0xFF25–0xFF26).

**ME 65302 (0xFF16):** Reported by Gemini as a Nokia clock ME, but
confirmed NOT present in the G-010S-P BOPD09 firmware. May exist on other
Nokia ONT platforms (e.g., XS-010X-Q).

**65529–65531 (CTC):** China Telecom Corporation standard MEs, not Nokia
proprietary. Present because the G-010S-P was also deployed on Chinese
GPON networks.

**Clock/timing stack:** 6 MEs — NTP_CONFIGURATION (65288),
NTP_CONFIGURATION_V2 (65304), CLOCK_DATA_SET (65314),
PTP_MASTER_CONFIG_DATA_PROFILE (65315), PTP_PORT (65316),
ONU_CLOCK_ADJUSTMENTS (65319). None of these are in the G-010S-P's
Lantiq/sean firmware — they exist only in Nokia's proprietary `omciLibMgr`.

**ME 350:** Huawei uses ME 350 for ONU clock synchronization on their
Lantiq-based ONTs (confirmed in Huawei SDK). This is a vendor-specific
extension, not part of the standard G.988 OMCI spec.

---

## Calix Vendor Managed Entities

Extracted by up-n-atom from Calix AXOS ONT firmware. Three vendor MEs
registered in `init_omci_fsanontprivate()`:

| ME class | Symbol | Purpose |
|----------|--------|---------|
| 241 (0x00F1) | `fsanOntPrivateInfoTable` | Time/timezone/DST — **clock setting** |
| 65317 (0xFF25) | `fsanOntCalixRgConfigTable` | RG (Residential Gateway) config |
| 65503 (0xFFDF) | `fsanOntCalixOntMgmtTable` | ONT management |

### ME 241 — fsanOntPrivateInfoTable (Clock Setting)

Decompiled from `fsanOntPrivateInfoTableSysSet` (Ghidra). This is how
**Calix OLTs set the clock** on their ONTs — a vendor-specific alternative
to the standard OMCI Synchronize Time action.

**Attribute layout (from struct offsets):**

| Offset | Attribute | Notes |
|--------|-----------|-------|
| +0x14 | Time value | Passed to `lib_omci_sys_set_time()` |
| +0x18 | (unknown) | Set in case 3 |
| +0x2c | Flags bitmap | bit 0: ?, bit 12: DST dirty, bit 15: time offset valid? |
| +0x34 | Timezone offset | Seconds from UTC, passed to `omci_sys_set_time_offset()` |
| +0x38 | DST enable | 0=false, non-zero=true → `omci_sys_set_daylight_savings()` |

**SET handler flow (case 2):**
```c
// 1. Set timezone offset
omci_sys_set_time_offset(*(param_1 + 0x34));

// 2. Set daylight savings
omci_sys_set_daylight_savings(*(param_1 + 0x38));

// 3. Convert offset to timezone string
if (dst_enable == 0)
    lib_omci_sys_get_timezone_by_offset(-offset, tz_name, ...);
else
    lib_omci_sys_get_timezone_by_offset(-0xe10 - offset, tz_name, ...);
    // 0xe10 = 3600 = 1 hour DST shift

// 4. Set system clock
lib_omci_sys_set_time(tz_name, buf1, buf2, *(param_1 + 0x14));
```

**Key difference from our approach:** Calix sends time + timezone + DST via
a vendor ME SET operation. Our firmware uses the standard Synchronize Time
action (ME 256) and reads hardware ToD registers instead. The Calix approach
is richer (timezone-aware) but vendor-specific — only Calix OLTs send ME 241.

### Vendor Clock ME Comparison

| Vendor | ME | Method | Timezone | DST | Hardware Req |
|--------|-----|--------|----------|-----|-------------|
| Standard | 256 action 14 | Synchronize Time | No | No | None |
| Nokia | 65288/65304 | NTP client config | Via NTP | Via NTP | NTP server access |
| Nokia | 65314-65316 | PTP/1588 profiles | N/A | N/A | 1588 hardware (G-010S-B) |
| Huawei | 350 | Direct clock set | Unknown | Unknown | None |
| Calix | 241 | Time + TZ + DST set | Yes (offset) | Yes (flag) | None |

### IEEE 1588v2 vs OMCI Synchronize Time

These are two separate mechanisms that are often confused:

1. **OMCI Synchronize Time** (ME 256 ONU-G, action 14): Standard OMCI action.
   OLT sends year/month/day/hour/minute/second. Mandatory per G.988. Should be
   sent by all OLTs regardless of 1588 capability. This is what our patch hooks.

2. **IEEE 1588v2 / PLOAM ToD**: Precision time sync via GTC layer PLOAM messages.
   Requires hardware support — Nokia made a dedicated G-010S-B (3FE 46955 AA)
   with an additional switching chip for 1588v2 and SyncE. The G-010S-P/A lack
   this hardware. OLT checks capability bits (e.g., on WAS-110: ME 131 attr 4)
   before sending PLOAM ToD.

The SBS2.TOD hardware registers (`tod_pps_get`, `sec_tai`) are populated by GTC
ranging code (`tod_reload_update`), which runs during PLOAM O4→O5 regardless of
1588 capability. Whether `sec_tai` contains a valid absolute timestamp depends on
the OLT putting time data in the PLOAM ranging messages — needs live testing to
confirm. If `sec_tai=0` on a live OLT (OLT doesn't populate ToD during ranging),
the script's validation rejects it and does nothing.
