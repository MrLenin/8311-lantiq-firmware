# Binary Patches

Both `mod_optic.ko` and `mod_onu.ko` are binary-patched on top of builds by
@拾麦穗-sam (sean) from the Chinese mod community (right.com.cn forums).

Base binary: `/home/sean/1620-00802/05/build_dir/...`, built Sep 26 2023.
These are the same binaries shipped in the `dev-orig` image.

## Background

The Lantiq GPON optic driver (`mod_optic.ko`) and ONU driver (`mod_onu.ko`)
have a callback mechanism for LOS (Loss of Signal) pin state changes:

1. `mod_onu` registers `onu_rssi_los_handle` as a callback via
   `optic_register_los_pin_update()` during its init.
2. `optic_register_los_pin_update()` stores the callback pointer at offset
   `0x904` in the `optic_ctrl` structure.
3. In stock firmware, `mod_optic` **never calls this callback**. Instead, it
   just calls `optic_gpio_set(3, 1)` to directly toggle a GPIO pin, bypassing
   the ONU driver's alarm state machine entirely.
4. Even if it did call the callback, `mod_onu`'s `onu_rssi_los_handle` had a
   bug: it only asserted the RXLOS GPIO on alarm, but never deasserted it when
   the alarm cleared.

Additionally, `optic_gpio_init()` in the module's `.init.text` claims GPIO
pins at load time, which conflicts with `pin_cfg.sh` configuring them via
`onu_los_pin_cfg_set` later in the boot sequence.

## mod_optic.ko Patches (25 bytes changed, 3 sites)

File size: 344,332 bytes (unchanged).

### Patch 1: Wire in LOS callback (alarm assertion path)

| Field | Value |
|-------|-------|
| Section | `.text` |
| .text offset | `0x136B0` |
| File offset | `0x136F0` (79,600) |
| Function | Called from `optic_fifo_cloneentry` / `optic_temperature_alarm_check` region |
| Relocation at 0x136B8 | `R_MIPS_26 → optic_gpio_set` (0x14d70) |

**Original (12 bytes):**
```mips
0x136B0: li    $a0, 3             # 24 04 00 03  GPIO pin 3
0x136B4: li    $a1, 1             # 24 05 00 01  value 1 (high)
0x136B8: jal   optic_gpio_set     # 0c 00 00 00  direct GPIO toggle
```

**Patched (12 bytes):**
```mips
0x136B0: li    $a0, 1             # 24 04 00 01  alarm state = asserted
0x136B4: lw    $a1, 0x904($v0)   # 8c 45 09 04  load LOS callback ptr
0x136B8: jalr  $a1               # 00 a0 f8 09  call onu_rssi_los_handle(1)
```

**Effect:** Instead of directly toggling GPIO 3, calls the registered LOS
callback (`onu_rssi_los_handle` from `mod_onu`) with alarm state = 1 (asserted).
This routes the signal through the ONU driver's alarm state machine.

### Patch 2: Wire in LOS callback (second call site)

| Field | Value |
|-------|-------|
| Section | `.text` |
| .text offset | `0x13708` |
| File offset | `0x13748` (79,688) |
| Relocation at 0x13710 | `R_MIPS_26 → optic_gpio_set` (0x14d70) |

Same transformation as Patch 1. Second `optic_gpio_set(3, 1)` call site in
the same function, likely the deassertion or alternate code path.

### Patch 3: Skip GPIO init at module load

| Field | Value |
|-------|-------|
| Section | `.init.text` |
| .init.text offset | `0x15C` |
| File offset | `0x251FC` (152,060) |
| Relocation at 0x15C | `R_MIPS_26 → optic_gpio_init` (0x14c00) |

**Original (8 bytes):**
```mips
0x15C: jal   optic_gpio_init    # 0c 00 00 00
0x160: move  $s2, $v0           # 00 40 90 21  (delay slot, saves return value)
```

**Patched (8 bytes):**
```mips
0x15C: nop                      # 00 00 00 00
0x160: nop                      # 00 00 00 00
```

**Effect:** Prevents `mod_optic` from claiming and configuring GPIO pins during
`insmod`. This avoids conflicts with `pin_cfg.sh`, which configures SFP GPIO
pins later in the boot sequence via `onu_los_pin_cfg_set` and
`optic_pin_cfg_set`.

## mod_onu.ko Patches (8 bytes changed, 4 sites)

File size: 1,022,908 bytes (unchanged).

These patches fix the deassertion asymmetry bug in `onu_rssi_los_handle`. The
stock callback only calls `onu_los_pin_update()` to set the GPIO when an alarm
is **asserted** — it never deasserts the GPIO when the alarm **clears**. This
causes the RXLOS pin to stay high permanently after fiber is restored.

See commit `61b9cf5` for the commit message documenting this fix.

### Patch sites

4 pairs of 2-byte changes at:
- File offsets 927,425–927,435 (`0xE2741`–`0xE274B`)
- File offsets 1,004,793–1,004,803 (`0xF5679`–`0xF5683`)

Each pair changes `0F 43` → `0C 01`. These are in the ELF relocation/data
tables and modify conditional branch targets or immediate values that control
the assertion/deassertion logic.

## Key Symbols

From `readelf -s` of `mod_optic.ko`:

| Symbol | Address | Size | Purpose |
|--------|---------|------|---------|
| `optic_gpio_init` | 0x14c00 | 260B | GPIO pin init (NOP'd out) |
| `optic_gpio_set` | 0x14d70 | 32B | Direct GPIO write (bypassed) |
| `optic_gpio_get` | 0x14d0c | 32B | Read GPIO value |
| `optic_gpio_set_input` | 0x14d2c | 68B | Set GPIO as input |
| `optic_gpio_free` | 0x14d04 | 8B | GPIO cleanup |
| `optic_isr_gpio_sd` | 0x1a79c | 56B | Signal detect ISR |
| `optic_register_los_pin_update` | 0x12dac | 12B | Stores callback at `optic_ctrl+0x904` |
| `optic_register_laser_age_update` | 0x12da0 | 12B | Stores callback at nearby offset |

## Verification

To verify the patches, diff against the unpatched base image:

```sh
cmp -l dev-orig/lib/modules/3.10.49/mod_optic.ko \
       8311-mods/lib/modules/3.10.49/mod_optic.ko

cmp -l dev-orig/lib/modules/3.10.49/mod_onu.ko \
       8311-mods/lib/modules/3.10.49/mod_onu.ko
```

The optic diff should show exactly 25 changed bytes; the onu diff exactly 8.

---

## omcid Baked-in Patch

Unlike the runtime patches below, this patch is applied directly to the `omcid`
binary shipped in the firmware image. The "stock" MD5 checksum used by
`config_onu.sh` refers to the binary **with** this patch already applied.

Base binary: `dev-orig/opt/lantiq/bin/omcid` (sean's unpatched build).

### Patch: Disable hardcoded image version override

| Field | Value |
|-------|-------|
| File offsets | `0x84CE`, `0x84D0`, `0x84D1` (3 bytes) |
| Byte sequence (6 bytes at 0x84CE) | `1A 00 1A CF 65 00` → `65 00 65 00 65 00` |
| Original bytes | `0x1A`, `0x1A`, `0xCF` |
| Patched bytes | `0x65`, `0x65`, `0x00` |

**Effect:** Prevents `omcid` from overwriting the `image0_version` and
`image1_version` U-Boot environment variables with a hardcoded value. Without
this patch, omcid always writes its internal version string to these fw_env
variables, overriding any user-configured values.

With the patch, the firmware environment values set by the user (or by the OLT
via `fw_setenv`) persist. The `fw_setenv` wrapper at `8311-mods/usr/sbin/fw_setenv`
allows `imageX_version` writes through (only `committed_image` is blocked) so
the OLT can see correct version/validity info.

### Patch: Replace sync_time ioctl with system clock set

| Field | Value |
|-------|-------|
| Code patch | File offsets `0x20962`–`0x20981` (32 bytes) |
| String patch | File offset `0x52D34` (33 bytes) |
| Function | `sync_time_action_handle` (VA 0x420924) |
| Encoding | MIPS16e (16/32-bit mixed, big-endian) |

**Problem:** The OMCI Synchronize Time action (ME 256 ONU-G) is sent by the
OLT to set the ONU's clock. The Lantiq SDK handler (`sync_time_action_handle`)
resets PM counters and calls an ioctl (`FIO_ONU_SYNC_TIME_SET`) that only
manages 15-minute PM interval boundaries — it never reads the time fields
from the OMCI message and never sets the system clock. The SDK v4.5.0 source
confirms this was a TODO that was never implemented.

**Solution:** Replace the ioctl call with `system("/opt/lantiq/bin/omci_sync_time.sh")`.
The shell script reads the hardware Time of Day registers (SBS2.TOD, populated
by the GTC/PLOAM layer) via `onu gpe_tod_get`, converts TAI seconds to UTC,
and sets the Linux system clock with `date -s`.

**String replacement at 0x52D34:**
```
Old: "ERROR(%d) while cleaning TCA data\0"  (33+1 bytes)
New: "/opt/lantiq/bin/omci_sync_time.sh\0"   (32+1 bytes, null-padded)
```

Literal pool entry 3 at file offset `0x209CC` already contains VA `0x452D34`
pointing to this string — no literal pool modification needed.

**Code patch at 0x20962–0x20981 (32 bytes):**

| Offset | Old | New | Instruction |
|--------|-----|-----|-------------|
| 0x20962 | `22 04` | `65 00` | NOP (was BEQZ, TCA error check) |
| 0x20964 | `b4 1a` | `65 00` | NOP (was LW, TCA error string) |
| 0x20966 | `1a 00` | `65 00` | NOP (was JAL hi, error_log) |
| 0x20968 | `81 5d` | `65 00` | NOP (was JAL lo, error_log) |
| 0x2096a | `67 a2` | `65 00` | NOP (was MOVR32 $a1,$v0, delay slot) |
| 0x2096c | `f7 80` | `b4 18` | LW $a0, 0x60(pc) → script path from LP3 |
| 0x2096e | `98 84` | `1e 00` | JALX system() @ PLT 0x402BA0 (hi) |
| 0x20970 | `1a 00` | `0a e8` | JALX system() @ PLT 0x402BA0 (lo) |
| 0x20972 | `cd 19` | `65 00` | NOP (JALX delay slot) |
| 0x20974 | `65 00` | `6a 00` | LI $v0, 0 (force success for response) |
| 0x20976 | `67 02` | `67 02` | KEEP: MOVR32 $s0,$v0 (saves iVar2=0) |
| 0x20978 | `22 04` | `65 00` | NOP (was BEQZ, DRV ERR check) |
| 0x2097a | `b4 16` | `65 00` | NOP (was LW, DRV ERR string) |
| 0x2097c | `1a 00` | `65 00` | NOP (was JAL hi, error_log) |
| 0x2097e | `81 5d` | `65 00` | NOP (was JAL lo, error_log) |
| 0x20980 | `67 a2` | `65 00` | NOP (was MOVR32 $a1,$v0, delay slot) |

**What is preserved:** The PM counter reset (mib_walk callback to
`sync_time_walker` at VA 0x4203C0) still executes — it runs before our patch
region. The OMCI response formatting (success/failure byte) still executes
after — our `LI $v0, 0` ensures it reports success.

**JALX encoding verified against:** existing `system()` call at VA 0x40A5FE,
`memset()` JALX (`1e 00 0a b4`) with 209 call sites, `sprintf()` JALX
(`1e 00 0c a0`).

### Verification

```sh
cmp -l dev-orig/opt/lantiq/bin/omcid \
       8311-mods/opt/lantiq/bin/omcid
```

Should show 64 changed bytes total: 3 (image version patch) + 28 (code patch,
4 bytes unchanged) + 33 (string replacement).

---

## omcid Runtime Patches

The `omcid` binary (OMCI daemon) is patched **at runtime** by
`config_onu.sh mod` during boot. Unlike the kernel module patches above,
these are applied to a copy in `/tmp` and written back, not baked into the
firmware image. Patches are checksum-guarded: they only apply if the binary's
MD5 matches either the stock checksum or the last-patched checksum.

Stock omcid MD5: `0da3eb0b76af1df5f4df414e3fc09dbb` (with baked-in patches)
Stock version string: `6BA1896SPE2C05, internal_version =1620-00802-05-00-000D-01`

### Patch: Disable 802.1x enforcement

| Field | Value |
|-------|-------|
| File offset | 275,849 (`0x43589`) |
| Size | 1 byte |
| Original | `0x01` (enforce 802.1x) |
| Patched | `0x00` (disable) |
| UCI toggle | `8311.config.omcid_8021x` = `1` to apply |
| Applied by | `config_onu.sh mod` → `mod_omcid_8021x()` |
| Reversed by | `config_onu.sh restore_8021x` → writes `0x01` back |

**Effect:** Disables 802.1x packet enforcement in omcid. The stock behavior
drops service packets that fail 802.1x authentication; this patch prevents
that filtering. Referenced in the Chinese mod changelog (2023.10.20):
"directly disable the function of 802.1x discarding service packets."

### Patch: Version string override

| Field | Value |
|-------|-------|
| File offset | 316,133 (`0x4D2E5`) |
| Size | 58 bytes (zero-padded) |
| Original | Stock version string (see above) |
| Patched | User-specified string from `8311.config.omcid_version` |
| UCI toggle | `8311.config.omcid_version` = any string (max 58 chars) |
| Applied by | `config_onu.sh mod` → `mod_omcid_version()` |
| Reversed by | `config_onu.sh restore_sw_ver` → writes stock string back |

**Effect:** Changes the software version reported by `omcid -v` and visible to
the OLT via OMCI managed entities. Used for ISP interoperability — some OLTs
reject ONUs that don't report an expected version string. The version string
is written as raw bytes at the offset, zero-padded to 58 bytes.

**Note:** A second version offset at 307,944 (`0x4B1E8`) was used in earlier
versions but is now commented out in `config_onu.sh`.

### Safety mechanism

Both patches share a checksum guard in `mod_omcid()`:

1. On first patch: only proceeds if binary MD5 = stock checksum
2. On subsequent patches: only proceeds if MD5 = stored checksum from last patch
3. After patching: new MD5 stored in `8311.config.omcid_csum`
4. If checksum doesn't match: logs error and aborts (prevents double-patching
   or patching an unknown binary)

---

## Historical / Superseded Patches

These patches are **not** in the current firmware. They document earlier
approaches that were replaced by the current patches.

### Earlier RX_LOS patch (superseded by Patches 1 & 2)

This was the original simpler approach to the RXLOS problem, applied before the
`optic_register_los_pin_update` callback mechanism was understood.

| Field | Value |
|-------|-------|
| Module | `mod_optic.ko` |
| Section | `.text` |
| .text offset | `0x1370C` |
| File offset | `0x1374C` (79,692) |
| Function | Same region as current Patch 2 |

**Original (4 bytes):**
```mips
0x1370C: li    $a1, 1             # 24 05 00 01  value 1 (high)
```

**Earlier patch (4 bytes):**
```mips
0x1370C: li    $a1, 0             # 24 05 00 00  value 0 (low)
```

**Effect:** Changed `optic_gpio_set(3, 1)` to `optic_gpio_set(3, 0)` — instead
of driving GPIO 3 high on LOS alarm, it drove it low. This was a crude
single-byte fix (just the immediate value of `$a1`) that changed the GPIO
assertion polarity at one call site.

**Why superseded:** This approach only modified the GPIO value argument without
routing through the ONU driver's alarm state machine. The current Patches 1 & 2
replace both `optic_gpio_set` call sites entirely with indirect calls through
the LOS callback at `optic_ctrl+0x904`, which properly integrates with
`onu_rssi_los_handle` and the `pin_cfg.sh` pin configuration subsystem.

---

## Related Components

- `8311-mods/etc/uci-defaults/sfp-pins-preconfig`: Sets LOS to GPIO 3 (matching
  the pin that `mod_optic` was internally using but not properly managing)
- `8311-mods/etc/init.d/pin_cfg.sh`: Calls `onu_los_pin_cfg_set` and
  `optic_pin_cfg_set` during boot to configure SFP signal pins
- `onu_rssi_los_handle` (in mod_onu.ko): The callback that patches 1 & 2
  invoke — handles LOS alarm state transitions including GPIO deassertion
- `config_onu.sh`: Applies omcid runtime patches and handles identity/config
