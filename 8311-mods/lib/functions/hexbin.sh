#!/bin/sh
# Hex and binary string conversion utilities.
#
# Provides pipeline-oriented functions for converting between raw binary
# data, hex-encoded strings, and printable representations. Used by
# 8311-omci-lib.sh (attribute data extraction) and 8311_backend.sh
# (registration ID formatting).
#
# All functions operate on stdin/stdout for easy pipeline composition.

# Guard function: allows callers to test if this library is already loaded.
_lib_hexbin() {
	return 0
}

# filterhex (stdin -> stdout)
# Validate and normalize a hex string from stdin. Strips all whitespace,
# then passes through only if the result is a valid even-length hex string
# (pairs of hex digits). Returns nothing (grep fails) for invalid input.
filterhex() {
	sed -r 's/[[:space:]]+//g' | grep -E '^([0-9A-Fa-f]{2})+$'
}

# str2hex (stdin -> stdout)
# Convert raw binary bytes to a lowercase hex string (no separators).
str2hex() {
	hexdump -v -e '1/1 "%02x"'
}

# hex2str (stdin -> stdout)
# Convert a hex-encoded string to raw binary bytes.
# Validates input via filterhex first; produces no output if input is invalid.
# Builds a sequence of \xNN escape codes and uses printf to emit raw bytes.
hex2str() {
	HEX=$(filterhex)
	# sed converts each hex pair "AB" into the printf escape "\\xAB";
	# the triple-backslash is needed so xargs+printf see a literal \xNN.
	[ -n "$HEX" ] && echo "$HEX" | sed 's/\([0-9A-F]\{2\}\)/\\\\\\x\1/gI' | xargs printf
}

# str2printable (stdin -> stdout)
# Convert raw binary bytes to a printable representation, replacing
# non-printable characters with dots (hexdump's %_p format).
str2printable() {
	hexdump -v -e '"%_p"'
}

# hex2printable (stdin -> stdout)
# Convenience: hex string -> raw bytes -> printable representation.
hex2printable() {
	hex2str | str2printable
}
