#!/bin/bash
# build_omcid.sh — Build custom omcid from Lantiq GPON SDK v4.5.0 source
#
# Prerequisites: See README.md for toolchain setup.
#
# Usage: ./build_omcid.sh [clean]
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ---- Toolchain ----
# Override with environment variable if your toolchain is elsewhere
TC="${OWRT_TC:-/tmp/owrt-tc}"
CC="${TC}/bin/mips-openwrt-linux-uclibc-gcc.bin"
SYSROOT="${TC}"

if [ ! -x "$CC" ]; then
	echo "ERROR: Toolchain not found at ${TC}"
	echo "Set OWRT_TC=/path/to/toolchain or see README.md for setup."
	exit 1
fi

# ---- Source directories (relative to this script) ----
IFXOS_SRC="${SCRIPT_DIR}/lib_ifxos"
OMCI_API_SRC="${SCRIPT_DIR}/gpon_omci_api-4.5.0"
OMCI_ONU_SRC="${SCRIPT_DIR}/gpon_omci_onu-4.5.0"
ONU_DRV_INC="${SCRIPT_DIR}/gpon_onu_drv-4.5.0/src/include"
OPTIC_DRV_INC="${SCRIPT_DIR}/gpon_optic_drv/src/include"
LIBCLI_INC="${SCRIPT_DIR}/libcli/include/cli"
LIBCLI_LIB="${SCRIPT_DIR}/libcli/lib"
# ---- Install prefixes (temporary, under /tmp) ----
IFXOS_INSTALL="/tmp/lib_ifxos_install"
OMCI_API_INSTALL="/tmp/omci_api_install"
OMCID_INSTALL="/tmp/omcid_install"

HOST="mips-openwrt-linux-uclibc"
BUILD="x86_64-linux-gnu"

export CC="$CC --sysroot=$SYSROOT"
export LDFLAGS="-L${SYSROOT}/usr/lib"

# ---- Handle 'clean' argument ----
if [ "${1:-}" = "clean" ]; then
	echo "=== Cleaning build artifacts ==="
	for dir in "$IFXOS_SRC" "$OMCI_API_SRC" "$OMCI_ONU_SRC"; do
		if [ -f "$dir/Makefile" ]; then
			make -C "$dir" clean 2>/dev/null || true
			make -C "$dir" distclean 2>/dev/null || true
		fi
	done
	rm -rf "$IFXOS_INSTALL" "$OMCI_API_INSTALL" "$OMCID_INSTALL"
	echo "Done."
	exit 0
fi

# ---- Step 1: Build lib_ifxos ----
echo "=== Building lib_ifxos ==="
cd "$IFXOS_SRC"
if [ ! -f configure ]; then
	autoreconf -fi
fi
if [ ! -f Makefile ]; then
	./configure \
		--host="$HOST" \
		--build="$BUILD" \
		--prefix="$IFXOS_INSTALL" \
		--without-kernel-module \
		--enable-linux-26
fi
make -j"$(nproc)"
make install

# ---- Step 2: Build gpon_omci_api ----
echo "=== Building gpon_omci_api ==="
cd "$OMCI_API_SRC"
if [ ! -f Makefile ]; then
	./configure \
		--host="$HOST" \
		--build="$BUILD" \
		--prefix="$OMCI_API_INSTALL" \
		--enable-ifxos-include="-I${IFXOS_SRC}/src/include" \
		--enable-driver-include="-I${ONU_DRV_INC} -I${OPTIC_DRV_INC}" \
		--enable-device=PSB98030 \
		--enable-falcon-sw-image-support \
		--enable-mcc \
		--disable-voip \
		--disable-remote-onu \
		--enable-debug-prints
fi
make -j"$(nproc)"

# ---- Step 3: Build omcid ----
echo "=== Building omcid ==="
cd "$OMCI_ONU_SRC"
if [ ! -f Makefile ]; then
	CPPFLAGS="-I${ONU_DRV_INC}" \
	./configure \
		--host="$HOST" \
		--build="$BUILD" \
		--prefix="$OMCID_INSTALL" \
		--enable-ifxos-include="-I${IFXOS_SRC}/src/include -I${IFXOS_SRC}/src/include/ifxos" \
		--enable-ifxos-library="-L${IFXOS_INSTALL}/lib" \
		--enable-omci-api-include="-I${OMCI_API_SRC}/include -I${OMCI_API_SRC}/include/me -I${OMCI_API_SRC}/include/mcc" \
		--enable-omci-api-library="-L${OMCI_API_SRC}/src" \
		--enable-cli \
		--enable-cli-pipe \
		--enable-cli-include="-I${LIBCLI_INC}" \
		--enable-cli-library="-L${LIBCLI_LIB}" \
		--disable-voip \
		--enable-pm \
		--disable-remote-onu \
		--enable-omci-uci \
		--enable-libucimap \
		--enable-formatted-omci-dump \
		--enable-debug-prints
fi
make -j"$(nproc)"

# ---- Done ----
OMCID_BIN="${OMCI_ONU_SRC}/src/omcid"
if [ -f "$OMCID_BIN" ]; then
	SIZE=$(stat -c%s "$OMCID_BIN")
	STRIPPED_SIZE=$(mips-openwrt-linux-uclibc-strip --strip-unneeded -o /dev/null "$OMCID_BIN" 2>/dev/null && stat -c%s /dev/null || echo "?")
	echo ""
	echo "=== Build successful ==="
	echo "  Binary: ${OMCID_BIN}"
	echo "  Size:   ${SIZE} bytes (unstripped)"
	file "$OMCID_BIN"
else
	echo "ERROR: omcid binary not found"
	exit 1
fi
