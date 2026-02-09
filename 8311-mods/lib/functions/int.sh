#!/bin/sh
# Signed and unsigned integer conversion functions for OMCI attribute parsing.
#
# OMCI MIB attributes store numeric values as raw hex bytes. After
# concatenation into a hex integer, these functions mask to the correct
# bit width and apply two's complement conversion for signed types.
#
# Each intN function checks if the high bit is set (>= 0x80, 0x8000,
# or 0x80000000) to determine whether the value is negative in two's
# complement representation. If so, it subtracts 2^N to produce the
# correct negative decimal value.
#
# Called dynamically by mibattrdata as "${inttype}${size}" (e.g. "uint16").

# Guard function: allows callers to test if this library is already loaded.
_lib_int() {
	return 0
}

# int8 <value>
# Convert to signed 8-bit integer via two's complement.
# Values with bit 7 set (> 0x80) are negative: subtract 0x100 (256).
int8() {
	int=$(($1 & 0xff))
	[ "$int" -gt $((0x80)) ] && echo $((int - 0x100)) || echo $int
}

# uint8 <value>
# Mask to unsigned 8-bit integer (0-255).
uint8() {
	echo $(($1 & 0xff))
}

# int16 <value>
# Convert to signed 16-bit integer via two's complement.
# Values >= 0x8000 are negative: subtract 0x10000 (65536).
int16() {
	int=$(($1 & 0xffff))
	[ "$int" -ge $((0x8000)) ] && echo $((int - 0x10000)) || echo $int
}

# uint16 <value>
# Mask to unsigned 16-bit integer (0-65535).
uint16() {
	echo $(($1 & 0xffff))
}

# int32 <value>
# Convert to signed 32-bit integer via two's complement.
# Values >= 0x80000000 are negative: subtract 0x100000000 (2^32).
int32() {
	local int=$(($1 & 0xffffffff))
	[ "$int" -ge $((0x80000000)) ] && echo $((int - 0x100000000)) || echo $int
}

# uint32 <value>
# Mask to unsigned 32-bit integer (0-4294967295).
uint32() {
	echo $(($1 & 0xffffffff))
}

# int64 <value>
# Return as a 64-bit signed integer (shell arithmetic is native 64-bit).
int64() {
	echo $(($1))
}

# uint64 <value>
# Format as unsigned 64-bit integer. Uses printf %u to ensure the
# value is printed as unsigned even if the shell treats it as signed.
uint64() {
	printf '%u\n' "$(int64 "$1")"
}
