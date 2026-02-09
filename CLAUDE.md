# 8311 Lantiq Firmware Mod

Firmware modification for Lantiq-based SFP ONUs (primarily the Alcatel G-010S-P).
Derived from OpenWRT. Translates and extends work from the right.com.cn forums.

## Project Structure

```
8311-mods/                 # All modified files injected into the firmware rootfs
  etc/config/              # UCI configuration (gpon, luci, system)
  etc/init.d/              # Init scripts (onu.sh, vlan-svc.sh, omcid.sh, pin_cfg.sh)
  etc/mibs/                # OMCI MIB files for different ONU types
  etc/uci-defaults/        # First-boot UCI defaults
  lib/                     # Shell libraries and kernel modules
    8311.sh                # Main library (getters/setters for ONU params)
    8311_backend.sh        # Backend implementation (UCI/fwenv updates)
    8311-vlans-lib.sh      # VLAN traffic control wrapper (tc flower)
    8311-omci-lib.sh       # OMCI managed entity query functions
    functions/             # Utility libraries (hexbin.sh, int.sh)
    modules/3.10.49/       # Kernel modules (mod_onu.ko, mod_optic.ko)
  opt/lantiq/bin/          # Main scripts and binaries
    config_onu.sh          # Central config script (EEPROM, OMCID patching)
    vlanexec.sh            # VLAN tagging daemon (OLT interoperability)
    monitoptic.sh          # Optic monitoring daemon (RX/TX, factory reset)
    monitomcid.sh          # OMCID health monitoring daemon
    omcid                  # Patched OMCID binary
  usr/lib/lua/luci/        # LuCI web interface
    controller/8311.lua    # Routes, form generation, status pages
    model/cbi/8311-*.lua   # CBI form models (config, network, optic-cal)
    view/8311/             # HTML templates
  www/                     # Static web assets (CSS, JS, images)
source/                    # Original firmware components (kernel, rootfs)
build/                     # Temporary build artifacts (gitignored)
out/                       # Final firmware image output (gitignored)
build.sh                   # Build script
excludes                   # Files to remove from stock rootfs
pseudofile                 # squashfs file metadata (permissions, timestamps)
```

## Reference Files (Do Not Commit)

Some untracked files in the working tree are **reference material** from
[8311-was-110-firmware-builder](https://github.com/djGrrr/8311-was-110-firmware-builder),
which targets newer hardware (WAS-110) running a newer OpenWRT. They exist for comparison
but cannot be used directly. Known reference files include:

- `8311-mods/lib/8311.sh`, `8311_backend.sh`, `8311-vlans-lib.sh`, `8311-omci-lib.sh`
- `8311-mods/usr/lib/lua/luci/cbi.lua`
- `8311-mods/usr/lib/lua/luci/view/alt-footer.htm`, `alt-header.htm`, `nsection.htm`, `tmap.htm`
- `8311-mods/usr/sbin/`

These should not be staged or committed without first adapting them for this project's
hardware and OpenWRT version.

## Build Process

Run `./build.sh` to produce `out/alcatel-g010sp_8311.img`.

**Requirements:** `mkimage`, `unsquashfs`, `mksquashfs` (with xz support), standard coreutils.

**Steps:**
1. Generates version info from git (tag, hash, dirty suffix)
2. Creates uImage kernel from source LZMA
3. Extracts stock rootfs, removes files listed in `excludes`, injects `8311-mods/`
4. Builds xz-compressed squashfs with metadata from `pseudofile`
5. Concatenates kernel + rootfs + padding (0x00 then 0xFF) to target size

**Important:** The `pseudofile` uses `@TIMESTAMP` placeholder, replaced by git epoch at build time for reproducible builds. WSL has a separate code path due to an unsquashfs pipe bug.

## Adding New Files

When adding a new file to the firmware:
1. Place it under `8311-mods/` at the path it should appear in the rootfs
2. If it replaces a stock file, add the stock path to `excludes`
3. Add a line to `pseudofile` with permissions and the `cat` command to inject it

## Shell Script Conventions

- Target shell is **busybox ash** (`#!/bin/sh`), not bash
- Use `local` for function variables (SC3043 is suppressed in shellcheckrc)
- Libraries use include guards: `_lib_name() { return 0; }` at the top
- Logging goes through `logger -t "tag"` and/or `tee -a /dev/console`
- UCI for persistent config, firmware env vars (`fwenv_get`/`fwenv_set`) for EEPROM-backed settings
- The `8311_` prefix is used for firmware environment variables specific to this mod
- Validate inputs carefully; these scripts run on real hardware with real ISP connections

## Lua / LuCI Conventions

- Uses LuCI CBI (Configuration Bind Interface) for config forms
- Controller in `controller/8311.lua`, models in `model/cbi/8311-*.lua`
- LuCI globals (Map, TypedSection, Value, Flag, etc.) are configured in `.vscode/settings.json`
- Custom views in `view/8311/` use Lua template syntax (`<%...%>`)
- A patched `cbi.lua` and `dispatcher.lua` are included for custom UI features

## Key Domain Concepts

- **PLOAM:** Physical Layer OAM - handles ONU registration with OLT
- **OMCI:** ONU Management and Control Interface - OLT manages ONU config
- **O5 state:** Operational PLOAM state (ONU is registered and active)
- **ME:** Managed Entity - OMCI configuration object (identified by class ID + instance)
- **PPTP/VEIP:** UNI port types (Physical vs Virtual Ethernet Interface Point)
- **MIB file:** Defines the initial OMCI managed entity configuration
- **OLT:** Optical Line Terminal (ISP side); **ONU/ONT:** Optical Network Unit (customer side)

## Safety Considerations

- This firmware runs on real networking hardware connected to ISP infrastructure
- Bad VLAN config or OMCI handling can disrupt internet connectivity
- The `config_onu.sh` script patches a binary (`omcid`) - be very careful with offsets
- Factory reset is triggered by unplugging fiber 5 times quickly (monitoptic.sh)
- Auto-reboot features exist for recovery from bad states - respect their logic

## Shellcheck

A `.shellcheckrc` exists with these suppressions:
- SC3043: `local` keyword (ash supports it, not POSIX)
- SC2018/SC2019: Character ranges in `tr` (intentional)

Run `shellcheck` on shell scripts before committing changes.
