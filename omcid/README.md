# Custom omcid Build

Build the OMCI daemon from Lantiq GPON SDK v4.5.0 source code, replacing
the proprietary shipping binary and all binary patches with readable,
maintainable source-level modifications.

## Source Components

| Directory | Description |
|-----------|-------------|
| `gpon_omci_onu-4.5.0/` | OMCI stack + daemon (~125 MEs, ~40K lines in ME handlers) |
| `gpon_omci_api-4.5.0/` | OMCI API library (ioctl bridge to `/dev/onu0`, `/dev/optic0`) |
| `gpon_onu_drv-4.5.0/` | ONU kernel driver headers (ioctl definitions, updated for v7.5.1) |
| `gpon_optic_drv/` | Optic driver headers (from [Osmocom mirror](https://gitea.osmocom.org/gpon/gpon_optic_drv)) |
| `lib_ifxos/` | OS abstraction layer v1.5.19 (from [xdarklight/lib_ifxos](https://github.com/xdarklight/lib_ifxos)) |
| `libcli/` | CLI pipe library headers + static lib (from OpenWRT SDK) |
| `ghidra/` | Pyghidra decompilation scripts for v7.5.1 stock binary analysis |
| `IOCTL_COMPAT.md` | Full ioctl compatibility analysis (6 subsystems) |
| `DIVERGENCES.md` | v4.5.0 vs v7.5.1 ME handler divergence audit |
| `INFRA_DIVERGENCES.md` | Infrastructure-level divergences |

## v7.5.1 Parity

The goal is to bring the v4.5.0 SDK code in line with the stock v7.5.1 binary
behavior. The stock binary represents years of evolution — function signatures
changed, parameters were added or removed, entire subsystems were restructured.

### Current Status

- **API layer**: Full audit complete (ioctl structs, ME APIs, GPE table headers).
- **ME handlers**: ~125 handlers (exceeds stock ~100, includes VoIP/Dot1ag/ZTE/PoE stubs).
- **Vendor-specific ExtVLAN paths**: HWTC (Huawei), ALCL (Nokia), generic — dispatched
  via OLT-G (ME 131) vendor ID.
- **Optic event handler**: Rewritten to match stock v7.5.1 alarm mapping (IRQ-based).
- **Dual-VLAN DS fix**: GPE-level shadow DS ExtVLAN tables for downstream collision
  resolution (transparent to OLT MIB).
- **Ioctl compatibility**: All 6 subsystems updated (ONU, GTC, GPE, GPE_TABLE, LAN, Event).
  Critical fixes include GPE table 16-byte headers, BOSA RX struct 14→32 bytes,
  and SCE constants 74→176 bytes.

See `DIVERGENCES.md` and `INFRA_DIVERGENCES.md` for detailed gap analysis.

## 8311 Source Modifications

All modifications are marked with `/* 8311 mod: */` comments where practical
and visible in git history (vanilla SDK committed first, mods applied on top).

Key modified files (non-exhaustive):

| File | Modification |
|------|-------------|
| `omci_api_sw_image_falcon.c` | Firmware update guard (blocks flash writes, shadows committed_image, version overrides via UCI) |
| `omci_api_sw_image.c` | Remove reboot on SW Image Activate |
| `omci_onu_g.c` | Implement OMCI Synchronize Time (settimeofday) |
| `omci_pptp_ethernet_uni.c` | Force admin_state=0 to prevent SFP management lockout |
| `omci_extended_vlan_config_data.c` | Vendor path dispatch (HWTC/ALCL/generic), dual-VLAN DS collision detection and shadow table split |
| `omci_api_extended_vlan_config_data.c` | Directional rule add, IOP DS passthrough, shadow DS create/destroy/link APIs |
| `omci_api_event.c` | Optic event FIFO rewrite (v7.5.1 alarm mapping, fd fix, struct size fix) |
| `omci_api_onu_dyn_pwr_mngmt_ctrl.c` | Power management ioctl magic fix (ONU_PWR_MAGIC=8) |
| `omci_daemon_mib.c` | TABLE attr type support in `mec` CLI command |
| `drv_onu_gpe_tables_interface.h` | GPE table entry 16-byte header (`_v751_padding`), struct size corrections |

## Toolchain Setup

The build requires the **OpenWRT Barrier Breaker 14.07 xrx200 toolchain**
(GCC 4.8.3 Linaro + uClibc 0.9.33.2). This produces correct soft-float
MIPS32r2 binaries matching the G-010S-P device ABI.

### Archives (in this directory, tracked with git-lfs)

| Archive | Contents |
|---------|----------|
| `OpenWrt-SDK-lantiq-for-linux-x86_64-gcc-4.8-linaro_uClibc-0.9.33.2.tar.bz2` | Full SDK (includes toolchain + sysroot with libuci, libcli, etc.) |
| `OpenWrt-Toolchain-lantiq-for-mips_34kc+dsp-gcc-4.8-linaro_uClibc-0.9.33.2.tar.bz2` | Standalone cross-compiler toolchain |

These are also available from the OpenWRT archive:
https://archive.openwrt.org/barrier_breaker/14.07/lantiq/xrx200/

### Extraction

```sh
# Extract the SDK (contains both the toolchain and a sysroot with target libraries)
tar xf OpenWrt-SDK-lantiq-for-linux-x86_64-gcc-4.8-linaro_uClibc-0.9.33.2.tar.bz2

# The toolchain is at:
#   OpenWrt-SDK-.../staging_dir/toolchain-mips_34kc_gcc-4.8-linaro_uClibc-0.9.33.2/
# Copy or symlink it to the default location:
cp -a OpenWrt-SDK-.../staging_dir/toolchain-mips_34kc_gcc-4.8-linaro_uClibc-0.9.33.2 /tmp/owrt-tc
```

### Important Notes

- Use the `.bin` GCC binary directly (`gcc.bin`), not the wrapper script
  (the wrapper script pollutes PATH and can cause build failures)
- Pass `--sysroot=/tmp/owrt-tc` to GCC for correct header/library paths
- The Falcon SoC has **no FPU** and the kernel has no FP emulator —
  hard-float binaries will cause illegal instruction faults

## Building

```sh
# Set toolchain location (default: /tmp/owrt-tc)
export OWRT_TC=/path/to/toolchain

# Build everything
./build_omcid.sh

# Clean build artifacts
./build_omcid.sh clean
```

Output: `gpon_omci_onu-4.5.0/src/omcid` (~5.3MB unstripped, ~856KB stripped)

### Manual Build (alternative)

```sh
# Build API library (if API source changed)
cd gpon_omci_api-4.5.0 && rm -f src/me/lib_a-<changed>.o && make

# Build omcid (force relink if API changed)
cd gpon_omci_onu-4.5.0 && rm -f src/omcid && make

# Strip and deploy to firmware tree
/tmp/owrt-tc/bin/mips-openwrt-linux-uclibc-strip.bin src/omcid -o ../../8311-mods/opt/lantiq/bin/omcid
```

## Ioctl Compatibility

The shipping kernel modules (v7.5.1) have different ioctl struct sizes,
command numbers, directions, and even magic numbers compared to the v4.5.0
SDK headers. The original v4.5.0 headers have been updated in-place with
`_v751_reserved` padding, corrected FIO_ macros, and shifted command
numbers. See `IOCTL_COMPAT.md` for the full analysis covering all 6
subsystems (ONU, GTC, GPE, GPE_TABLE, LAN, Event).
