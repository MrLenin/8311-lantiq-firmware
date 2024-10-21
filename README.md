# 8311-lantiq-firmware

**USE AT YOUR OWN RISK!**

Unless it is a tagged release, consider all changes to 'main' as *completely* **UNTESTED**!

Translation and extension of the firmware modification for the Lantiq family of SFP ONTs 
created by talented users of the [right.com.cn forums](https://www.right.com.cn/forum/thread-8220173-1-1.html).

This project is for now focusing on the G-010S-P image file, but eventually the additional 
source files will be added and the scripts will be updated so that all of the images will 
be built.

Translates... (WIP)

Notable changes:
- UNI type can now be configured via uci or luci, either PPTP or VEIP.
- Improved handling of custom mib file with respect to VEIP.
- Untethered customization settings from serial number configuration.
- Patched omcid to prevent overwriting of image0_version.
- Added ability to patch omcid to disable enforcement of 802.1x on the ONU to workaround 
  situations where the OLT has not properly configured the ONU to not discard supplicant 
  traffic. This cannot bypass upstream enforcement of 802.1x by the provider (OLT configuration).
- Automatically calculate and insert null padding for custom hw version and equipment id.
- Automatically trim hw version, equipment id, and vendor id to maximum length.
- Default to using the actual device info and not always the Huawei MA5671A.
- Only reset hw version, equipment id, and vendor id once, when custom mib file is disabled
  and not on every boot, save in luci, and shutdown.
- Applies configuration changes on apply instead of on save.z
