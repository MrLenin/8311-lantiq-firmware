# Custom omcid Build

Build the OMCI daemon from Lantiq GPON SDK v4.5.0 source code, replacing
the proprietary shipping binary and all binary patches with readable,
maintainable source-level modifications.

## Source Components

| Directory | Description |
|-----------|-------------|
| `gpon_omci_onu-4.5.0/` | OMCI stack + daemon (103 MEs, ~4000 lines core) |
| `gpon_omci_api-4.5.0/` | OMCI API library (ioctl bridge to `/dev/onu0`, `/dev/optic0`) |
| `gpon_onu_drv-4.5.0/` | ONU kernel driver headers (ioctl definitions) |
| `gpon_optic_drv/` | Optic driver headers (from [Osmocom mirror](https://gitea.osmocom.org/gpon/gpon_optic_drv)) |
| `lib_ifxos/` | OS abstraction layer v1.5.19 (from [xdarklight/lib_ifxos](https://github.com/xdarklight/lib_ifxos)) |
| `drv_onu_compat.h` | Compat header fixing ioctl struct sizes for shipping v7.5.1 kernel |
| `IOCTL_COMPAT.md` | Full ioctl compatibility analysis |

## 8311 Source Modifications

All modifications are marked with `/* 8311 mod: */` comments and visible
in git history (vanilla SDK committed first, mods applied on top).

| File | Modification |
|------|-------------|
| `omci_api_sw_image_falcon.c` | Firmware update guard (blocks flash writes, shadows committed_image, version overrides via UCI) |
| `omci_api_sw_image.c` | Remove reboot on SW Image Activate |
| `omci_onu_g.c` | Implement OMCI Synchronize Time (settimeofday) |
| `omci_pptp_ethernet_uni.c` | Force admin_state=0 to prevent SFP management lockout |

## Toolchain Setup

The build requires the **OpenWRT Barrier Breaker 14.07 xrx200 toolchain**
(GCC 4.8.3 Linaro + uClibc 0.9.33.2). This produces correct soft-float
MIPS32r2 binaries matching the G-010S-P device ABI.

### Download

```sh
# Download and extract the SDK (contains the toolchain)
wget https://archive.openwrt.org/barrier_breaker/14.07/lantiq/xrx200/OpenWrt-SDK-lantiq-xrx200_gcc-4.8-linaro_uClibc-0.9.33.2.Linux-x86_64.tar.bz2
tar xf OpenWrt-SDK-lantiq-xrx200_gcc-4.8-linaro_uClibc-0.9.33.2.Linux-x86_64.tar.bz2

# The toolchain is at:
#   OpenWrt-SDK-.../staging_dir/toolchain-mips_34kc_gcc-4.8-linaro_uClibc-0.9.33.2/
# Copy or symlink it:
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

Output: `gpon_omci_onu-4.5.0/src/omcid` (~3.7MB unstripped, ~1MB stripped)

## Ioctl Compatibility

The shipping kernel modules (v7.5.1) have different ioctl struct sizes
than the v4.5.0 SDK headers. `drv_onu_compat.h` fixes all 7 mismatches
and 3 direction changes. See `IOCTL_COMPAT.md` for the full analysis.

The compat header must be included **after** `drv_onu_interface.h` in any
source file that issues ioctls. It uses `#undef` + redefine with
compile-time size assertions.
