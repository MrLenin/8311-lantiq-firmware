# 8311-lantiq-firmware

Translation and extension of the Lantiq SFP ONT firmware modification by Chinese users.

Translates...

Improved handling of custom mib file with respect to VEIP.
UNI type can now be configured via uci or luci, either PPTP or VEIP.
Untethered customization settings from serial number configuration.
Patched omcid to prevent overwriting of image0_version.
Added ability to patch omcid to disable enforcement of 802.1x on the ONU to workaround 
situations where the OLT has not properly configured the ONU to not discard supplicant 
traffic.
Automatically calculate and insert null padding for custom hw version and equipment id.
Automatically trim hw version, equipment id, and vendor id to maximum length.
Default to using the actual device info and not always the Huawei MA5671A.
Only reset hw version, equipment id, and vendor id once, when custom mib file is disabled
and not on every boot, save in luci, and shutdown.
Applies configuration changes on apply instead of on save.
