# 8311-lantiq-firmware

**USE AT YOUR OWN RISK!**

Unless it is a tagged release, consider all changes to 'main' as *completely* **UNTESTED**!

Translation and extension of the firmware modification for the Lantiq family of SFP ONTs
created by talented users of the [right.com.cn forums](https://www.right.com.cn/forum/thread-8220173-1-1.html).

This project is for now focusing on the G-010S-P image file, but eventually the additional
source files will be added and the scripts will be updated so that all of the images will
be built.

## Notable Changes

### Identity & Configuration
- UNI type can now be configured via UCI or LuCI, either PPTP or VEIP.
- Improved handling of custom MIB file with respect to VEIP.
- Untethered customization settings from serial number configuration.
- Automatically calculate and insert null padding for custom hw version and equipment id.
- Automatically trim hw version, equipment id, and vendor id to maximum length.
- Default to using the actual device info and not always the Huawei MA5671A.
- Only reset hw version, equipment id, and vendor id once, when custom MIB file is disabled
  and not on every boot, save in LuCI, and shutdown.
- Applies configuration changes on apply instead of on save.

### Custom omcid Build
- Replaced proprietary shipping binary with a custom build from Lantiq SDK v4.5.0 source.
- All binary patches (version override, reboot NOP, 802.1x disable) replaced with
  source-level modifications.
- Full ioctl compatibility with shipping v7.5.1 kernel modules (6 subsystems updated).
- v7.5.1 stock binary parity: vendor-specific ExtVLAN paths (HWTC/ALCL/generic),
  optic event handling, ~125 ME handlers.
- Ability to disable 802.1x enforcement on the ONU to workaround situations where the OLT
  has not properly configured the ONU to not discard supplicant traffic. This cannot bypass
  upstream enforcement of 802.1x by the provider (OLT configuration).

### Dual-VLAN DS Fix
- Fixes downstream VLAN collision when multiple customer VIDs map to the same transport VID
  (e.g., Bell Aliant: VID 34 and VID 35 both mapped to VID 1119).
- Transparent GPE-level shadow DS ExtVLAN tables per mapper — invisible to OLT MIB.
- Configurable via UCI (`8311.config.dual_vlan`).

### Firmware Update Guard
- Prevents accidental flash overwrites via `mtd` and `fw_setenv` wrappers.
- Shadows `committed_image` in tmpfs — cleared on reboot so U-Boot reads the real value.
