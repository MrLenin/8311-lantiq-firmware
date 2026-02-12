# Ioctl Compatibility: v4.5.0 SDK vs Shipping v7.5.1 Kernel Modules

## Background

The shipping G-010S-P firmware runs v7.5.1 kernel modules (`mod_onu.ko`, `mod_optic.ko`)
but we're building a custom omcid from v4.5.0 SDK source. The kernel validates the FULL
ioctl number including struct size and direction bits, so mismatches cause `EINVAL` (not
crashes). This document catalogs every difference.

## MIPS Linux Ioctl Encoding

**Critical:** MIPS uses different direction bit encoding than x86.

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

Magic numbers: ONU=1, PLOAM=3, GPE=4, GPE_TABLE=5, GTC=6, LAN=7, OPTIC=9

## Matching Ioctls (24 — no changes needed)

These have identical ioctl numbers in v4.5.0 and shipping. Safe to use as-is.

| Ioctl | Direction | Size | Magic:Cmd | Value |
|-------|-----------|------|-----------|-------|
| GPE_CFG_SET | IOW | 32 | 4:0x01 | 0x80200401 |
| GPE_CFG_GET | IOR | 32 | 4:0x02 | 0x40200402 |
| GPE_GEM_PORT_ADD | IOW | 28 | 4:0x04 | 0x801C0404 |
| GPE_GEM_PORT_DELETE | IOW | 4 | 4:0x05 | 0x80040405 |
| GPE_GEM_PORT_GET | IOWR | 28 | 4:0x06 | 0xC01C0406 |
| GPE_GEM_PORT_SET | IOW | 28 | 4:0x07 | 0x801C0407 |
| GPE_EGRESS_QUEUE_CFG_SET | IOW | 64 | 4:0x17 | 0x80400417 |
| GPE_EGRESS_QUEUE_CFG_GET | IOWR | 64 | 4:0x18 | 0xC0400418 |
| GPE_METER_CREATE | IOW | 4 | 4:0x29 | 0x80040429 |
| GPE_METER_DELETE | IOW | 4 | 4:0x2A | 0x8004042A |
| GPE_METER_CFG_SET | IOW | 28 | 4:0x2B | 0x801C042B |
| GPE_TABLE_ENTRY_WRITE | IOWR | 84 | 5:0x01 | 0xC0540501 |
| GPE_TABLE_ENTRY_READ | IOWR | 84 | 5:0x02 | 0xC0540502 |
| GPE_TABLE_ENTRY_SET | IOWR | 84 | 5:0x03 | 0xC0540503 |
| LAN_PORT_ENABLE | IOW | 4 | 7:0x05 | 0x80040705 |
| LAN_PORT_DISABLE | IOW | 4 | 7:0x06 | 0x80040706 |
| LAN_COUNTER_RESET | IOW | 16 | 7:0x0C | 0x8010070C |
| ONU_SYNC_TIME_SET | IOW | 8 | 1:0x06 | 0x80080106 |
| ONU_REGISTER_SET | IOW | 12 | 1:0x02 | 0x800C0102 |
| ONU_REGISTER_GET | IOWR | 12 | 1:0x03 | 0xC00C0103 |
| PLOAM_LINE_ENABLE_SET | IOW | 4 | 3:0x0F | 0x8004030F |

## Mismatched Ioctls (7 — require compat layer)

### 1. `lan_port_cfg` — 36 → 52 bytes (+16), fields INSERTED

**v4.5.0 struct (36 bytes):**
```c
struct lan_port_cfg {
    uint32_t index;                              // offset 0
    uint32_t uni_port_en;                        // offset 4
    enum lan_mode_interface mode;                // offset 8
    enum lan_mode_duplex duplex_mode;            // offset 12
    enum lan_mode_flow_control flow_control_mode;// offset 16
    enum lan_mode_speed speed_mode;              // offset 20
    uint8_t tx_clk_dly;                          // offset 24
    uint8_t rx_clk_dly;                          // offset 25
    uint16_t max_frame_size;                     // offset 26
    uint32_t lpi_enable;                         // offset 28
    enum sgmii_autoneg_mode autoneg_mode;        // offset 32
} __PACKED__;
```

**Shipping struct (52 bytes) — from kernel CLI help:**
```c
struct lan_port_cfg {
    uint32_t index;                              // offset 0   (=pport)
    uint32_t uni_port_en;                        // offset 4   (=enable)
    int32_t mdio_dev_addr;                       // offset 8   ← NEW (inserted)
    enum lan_mode_gmux gmux_mode;                // offset 12  ← NEW (inserted)
    enum lan_mode_interface mode;                // offset 16  (shifted +8)
    enum lan_mode_duplex duplex_mode;            // offset 20  (shifted +8)
    enum lan_mode_flow_control flow_control_mode;// offset 24  (shifted +8)
    enum lan_mode_speed speed_mode;              // offset 28  (shifted +8)
    uint8_t tx_clk_dly;                          // offset 32  (shifted +8)
    uint8_t rx_clk_dly;                          // offset 33  (shifted +8)
    uint16_t max_frame_size;                     // offset 34  (shifted +8)
    uint32_t lpi_enable;                         // offset 36  (shifted +8)
    enum sgmii_autoneg_mode autoneg_mode;        // offset 40  (shifted +8)
    uint32_t invtx;                              // offset 44  ← NEW (appended)
    uint32_t invrx;                              // offset 48  ← NEW (appended)
} __PACKED__;
```

**Impact:** SEVERE — field offsets shifted by 8 bytes for all fields after `uni_port_en`.
v4.5.0 code writing `mode` at offset 8 would hit `mdio_dev_addr` in shipping kernel.
Must use the new struct definition.

**New enum type:**
```c
enum lan_mode_gmux {
    LAN_MODE_GMUX_GPHY0_GMII = 0,
    LAN_MODE_GMUX_GPHY0_MII2 = 1,
    LAN_MODE_GMUX_GPHY1_GMII = 2,
    LAN_MODE_GMUX_GPHY1_MII2 = 3,
    LAN_MODE_GMUX_SGMII = 4,
    LAN_MODE_GMUX_XMII0 = 5,
    LAN_MODE_GMUX_XMII1 = 6,
};
```

**Ioctl values:**
| | v4.5.0 | Shipping |
|---|--------|----------|
| SET | `_IOW(7,0x03,36)` = 0x80240703 | `_IOW(7,0x03,52)` = 0x80340703 |
| GET | `_IOWR(7,0x04,36)` = 0xC0240704 | `_IOWR(7,0x04,52)` = 0xC0340704 |

---

### 2. `lan_loop_cfg` — 24 → 32 bytes (+8), fields APPENDED

**v4.5.0 struct (24 bytes):**
```c
struct lan_loop_cfg {
    uint32_t index;                    // offset 0
    uint32_t mac_egress_loop_en;       // offset 4
    uint32_t mii_ingress_loop_en;      // offset 8
    uint32_t sgmii_ingress_loop_en;    // offset 12
    uint32_t phy_ingress_loop_en;      // offset 16
    uint32_t phy_egress_loop_en;       // offset 20
} __PACKED__;
```

**Shipping struct (32 bytes) — from kernel CLI help:**
```c
struct lan_loop_cfg {
    uint32_t index;                    // offset 0
    uint32_t mac_egress_loop_en;       // offset 4
    uint32_t mii_ingress_loop_en;      // offset 8
    uint32_t sgmii_ingress_loop_en;    // offset 12
    uint32_t phy_ingress_loop_en;      // offset 16
    uint32_t phy_egress_loop_en;       // offset 20
    uint32_t lan_port_ingress_loop_en; // offset 24  ← NEW (appended)
    uint32_t mac_swap_en;              // offset 28  ← NEW (appended)
} __PACKED__;
```

**Impact:** LOW — append-only, existing field offsets preserved. Zero-padding safe.

**Ioctl values:**
| | v4.5.0 | Shipping |
|---|--------|----------|
| SET | `_IOW(7,0x07,24)` = 0x80180707 | `_IOW(7,0x07,32)` = 0x80200707 |
| GET | `_IOWR(7,0x08,24)` = 0xC0180708 | `_IOWR(7,0x08,32)` = 0xC0200708 |

---

### 3. `lan_port_capability_cfg` — 12 → 36 bytes (+24), TYPE CHANGE bool→uint32_t

**v4.5.0 struct (12 bytes):**
```c
struct lan_port_capability_cfg {
    uint32_t index;        // offset 0  (4 bytes)
    bool full_duplex;      // offset 4  (1 byte)
    bool half_duplex;      // offset 5  (1 byte)
    bool mbit_10;          // offset 6  (1 byte)
    bool mbit_100;         // offset 7  (1 byte)
    bool mbit_1000;        // offset 8  (1 byte)
    bool sym_pause;        // offset 9  (1 byte)
    bool asym_pause;       // offset 10 (1 byte)
    bool eee;              // offset 11 (1 byte)
} __PACKED__;
```

**Shipping struct (36 bytes) — from kernel CLI help:**
```c
struct lan_port_capability_cfg {
    uint32_t index;        // offset 0  (4 bytes)
    uint32_t full_duplex;  // offset 4  (4 bytes) ← TYPE CHANGE
    uint32_t half_duplex;  // offset 8  (4 bytes) ← TYPE CHANGE
    uint32_t mbit_10;      // offset 12 (4 bytes) ← TYPE CHANGE
    uint32_t mbit_100;     // offset 16 (4 bytes) ← TYPE CHANGE
    uint32_t mbit_1000;    // offset 20 (4 bytes) ← TYPE CHANGE
    uint32_t sym_pause;    // offset 24 (4 bytes) ← TYPE CHANGE
    uint32_t asym_pause;   // offset 28 (4 bytes) ← TYPE CHANGE
    uint32_t eee;          // offset 32 (4 bytes) ← TYPE CHANGE
} __PACKED__;
```

**Impact:** SEVERE — all field offsets changed. Every `bool` (1B) → `uint32_t` (4B).
v4.5.0 code writing `full_duplex` at offset 4 as a 1-byte value would corrupt the
shipping struct. Must use the new definition.

**Ioctl values:**
| | v4.5.0 | Shipping |
|---|--------|----------|
| SET | `_IOW(7,0x19,12)` = 0x800C0719 | `_IOW(7,0x19,36)` = 0x80240719 |
| GET | `_IOWR(7,0x1a,12)` = 0xC00C071A | `_IOWR(7,0x1a,36)` = 0xC024071A |

---

### 4. `gpe_parser_cfg` — 20 → 28 bytes (+8), hidden fields

**v4.5.0 struct (20 bytes):**
```c
struct gpe_parser_cfg {
    uint32_t tpid[4];      // offset 0  (16 bytes)
    uint32_t special_tag;  // offset 16 (4 bytes)
} __PACKED__;
```

**Shipping struct (28 bytes) — CLI only shows 5 fields (20 bytes):**
```c
struct gpe_parser_cfg {
    uint32_t tpid[4];      // offset 0  (16 bytes)
    uint32_t special_tag;  // offset 16 (4 bytes)
    uint32_t _reserved[2]; // offset 20 (8 bytes) ← NEW, not in CLI
} __PACKED__;
```

**Impact:** LOW — append-only (CLI-visible fields unchanged). The 2 hidden fields are
likely internal state the kernel sets; zero-padding is safe.

**Ioctl values:**
| | v4.5.0 | Shipping |
|---|--------|----------|
| SET | `_IOW(4,0x22,20)` = 0x80140422 | `_IOW(4,0x22,28)` = 0x801C0422 |
| GET | `_IOR(4,0x23,20)` = 0x40140423 | `_IOWR(4,0x23,28)` = 0xC01C0423 **direction change** |

---

### 5. `gpe_tod_sync` — 16 → 24 bytes (+8), field appended + direction change

**v4.5.0 struct (16 bytes):**
```c
struct gpe_tod_sync {
    uint32_t multiframe_count;     // offset 0
    uint32_t tod_seconds;          // offset 4
    uint32_t tod_extended_seconds; // offset 8
    uint32_t tod_nano_seconds;     // offset 12
} __PACKED__;
```

**Shipping struct (24 bytes) — from CLI help + v8.x source:**
```c
struct gpe_tod_sync {
    uint32_t multiframe_count;      // offset 0
    uint32_t tod_seconds;           // offset 4
    uint32_t tod_extended_seconds;  // offset 8
    uint32_t tod_nano_seconds;      // offset 12
    int32_t tod_offset_pico_seconds;// offset 16 ← NEW (from CLI)
    int32_t tod_quality;            // offset 20 ← NEW (from v8.x source)
} __PACKED__;
```

**Impact:** LOW for SET (append-only, zero-padding safe). **Direction changed for SET.**

**Ioctl values:**
| | v4.5.0 | Shipping |
|---|--------|----------|
| SET | `_IOW(4,0x2C,16)` = 0x8010042C | `_IOWR(4,0x2C,24)` = 0xC018042C **direction change** |
| GET | `_IOR(4,0x2E,16)` = 0x4010042E | (not found — may not be used) |

---

### 6. `gpe_tcont_cfg` (CREATE) — 8 → 16 bytes (+8), hidden fields + direction change for SET

**v4.5.0 struct (8 bytes):**
```c
struct gpe_tcont_cfg {
    uint32_t epn;     // offset 0
    uint32_t policy;  // offset 4
} __PACKED__;
```

**Shipping struct (16 bytes) — CLI only shows 2 fields:**
```c
struct gpe_tcont_cfg {
    uint32_t epn;          // offset 0
    uint32_t policy;       // offset 4
    uint32_t _reserved[2]; // offset 8 ← NEW, not in CLI
} __PACKED__;
```

**Impact:** LOW for CREATE — append-only, zero-padding safe.

**v4.5.0 `gpe_tcont` struct for SET (16 bytes, unchanged):**
```c
struct gpe_tcont {
    uint32_t tcont_idx;       // offset 0
    uint32_t alloc_id;        // offset 4
    uint32_t reg_egress_port; // offset 8
    uint32_t pre_egress_port; // offset 12
} __PACKED__;
```

**Ioctl values:**
| | v4.5.0 | Shipping |
|---|--------|----------|
| CREATE | `_IOW(4,0x1C,8)` = 0x8008041C | `_IOW(4,0x1C,16)` = 0x8010041C |
| SET | `_IOW(4,0x1D,16)` = 0x8010041D | `_IOWR(4,0x1D,16)` = 0xC010041D **direction change** |

---

### 7. `onu_version_string` — 400 → 480 bytes (+80), field APPENDED

**v4.5.0 struct (400 bytes):**
```c
struct onu_version_string {
    char onu_version[80];
    char fw_version[80];
    char cop_version[80];
    char sce_interface_version[80];
    char chip_id[80];
} __PACKED__;
```

**Shipping struct (480 bytes) — from kernel CLI help:**
```c
struct onu_version_string {
    char onu_version[80];
    char fw_version[80];
    char cop_version[80];
    char sce_interface_version[80];
    char chip_id[80];
    char device_type[80];  // ← NEW (appended)
} __PACKED__;
```

**Impact:** LOW — append-only. The new field is an output-only string.

**Ioctl values:**
| | v4.5.0 | Shipping |
|---|--------|----------|
| GET | `_IOR(1,4,400)` = 0x41900104 | `_IOR(1,4,480)` = 0x41E00104 |

---

## Summary of Required Changes

### Struct Redefinitions (must change)

| Struct | Change Type | Severity |
|--------|------------|----------|
| `lan_port_cfg` | Fields inserted + appended | **SEVERE** — offsets shifted |
| `lan_port_capability_cfg` | `bool` → `uint32_t` type change | **SEVERE** — offsets changed |
| `lan_loop_cfg` | Fields appended | Low — zero-pad safe |
| `gpe_parser_cfg` | Hidden fields appended | Low — zero-pad safe |
| `gpe_tod_sync` | Field appended | Low — zero-pad safe |
| `gpe_tcont_cfg` | Hidden fields appended | Low — zero-pad safe |
| `onu_version_string` | Field appended | Low — zero-pad safe |

### Direction Changes (must change FIO_* macros)

| Ioctl | v4.5.0 Direction | Shipping Direction |
|-------|------------------|--------------------|
| `FIO_GPE_TOD_SYNC_SET` | `_IOW` | `_IOWR` |
| `FIO_GPE_TCONT_SET` | `_IOW` | `_IOWR` |
| `FIO_GPE_PARSER_CFG_GET` | `_IOR` | `_IOWR` |

### New Enum Types Required

- `enum lan_mode_gmux` (7 values: GPHY0_GMII, GPHY0_MII2, GPHY1_GMII, GPHY1_MII2, SGMII, XMII0, XMII1)

### New Ioctls in Shipping (not in v4.5.0)

These are registered in `mod_onu.ko` but have no v4.5.0 equivalent:
- `FIO_LAN_PORT_802_1X_AUTH_CFG_SET/GET` — 802.1x authentication control
- `FIO_LAN_PORT_LOOP_DETECTION_CFG_SET/GET` — loop detection
- `FIO_LAN_SYNCE_CFG_SET/GET` — SyncE clock recovery
- `FIO_LAN_PORT_LCT_VLAN_CFG_SET/GET` — LCT VLAN configuration
- `FIO_ONU_ASC0_PIN_CFG_SET/GET` — ASC0 serial pin config
- `FIO_ONU_LOS_PIN_CFG_SET/GET` — LOS pin config
- `FIO_ONU_PORTMAP_SET/GET` — Port mapping
- `FIO_GPE_TOD_NMEA_CFG_SET/GET` — NMEA time config
- `FIO_GPE_NTR_PIN_CFG_SET/GET` — NTR pin config
- `FIO_GPE_ACL_*` — Access control lists

## Implementation Strategy

1. Create `drv_onu_compat.h` that `#include`s the original v4.5.0 headers, then
   redefines the 7 mismatched structs and 3 FIO_* macros
2. The v4.5.0 API code (`gpon_omci_api`) accesses struct members by **name**, not
   offset — so using the new struct definitions will automatically produce correct offsets
3. For `lan_port_cfg`: set new fields `mdio_dev_addr=-1`, `gmux_mode=LAN_MODE_GMUX_SGMII`,
   `invtx=0`, `invrx=0` as sensible defaults
4. For `lan_port_capability_cfg`: changing `bool` → `uint32_t` is source-compatible
   (values 0/1 work in both types)
5. For append-only structs: zero-initialize new fields (safe defaults)
