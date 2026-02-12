#!/bin/bash
# ghidra-decompile.sh — Decompile functions from the shipping omcid binary via Ghidra
#
# Prerequisites:
#   - Ghidra 12.x at C:\devel\ghidra_12.0.3_PUBLIC
#   - JDK 21 at C:\Users\johne\.jdk\jdk-21.0.8+9
#   - 8311 project at C:\Users\johne\8311.gpr with omcid already imported+analyzed
#   - Ghidra GUI must be CLOSED (project lock)
#   - Scripts in /tmp/ghidra_scripts/ (G8311_Decompile.java, G8311_ListFunctions.java)
#
# Usage:
#   ./ghidra-decompile.sh <query> [all]
#   ./ghidra-decompile.sh 0x438b4c           # Decompile function at address
#   ./ghidra-decompile.sh ext_vlan           # Decompile first function matching name
#   ./ghidra-decompile.sh ext_vlan all       # Decompile ALL matching functions
#   ./ghidra-decompile.sh --list [filter]    # List all functions (optionally filtered)
#
# Output goes to stdout. Log goes to /mnt/c/temp/ghidra_log.txt.
#
set -euo pipefail

# ---- Configuration ----
SCRIPT_DIR_WIN="$(wslpath -w /tmp/ghidra_scripts)"
OUTPUT_WIN="C:\\temp\\ghidra_out.c"
OUTPUT_WSL="/mnt/c/temp/ghidra_out.c"
LOG_WSL="/mnt/c/temp/ghidra_log.txt"

usage() {
	echo "Usage: $0 <query> [all]"
	echo "       $0 --list [filter]"
	echo ""
	echo "  query:   hex address (0x...) or function name substring"
	echo "  all:     decompile all matching functions (default: first match)"
	echo "  --list:  list all functions (optionally filtered by substring)"
	exit 1
}

[ $# -lt 1 ] && usage

# ---- Build script args ----
mkdir -p /mnt/c/temp 2>/dev/null || true
rm -f "${OUTPUT_WSL}" "${LOG_WSL}"

if [ "$1" = "--list" ]; then
	SCRIPT="G8311_ListFunctions.java"
	SCRIPT_ARGS="${OUTPUT_WIN}"
	[ $# -gt 1 ] && SCRIPT_ARGS="${OUTPUT_WIN} $2"
else
	SCRIPT="G8311_Decompile.java"
	SCRIPT_ARGS="$1 ${OUTPUT_WIN}"
	[ "${2:-}" = "all" ] && SCRIPT_ARGS="$1 ${OUTPUT_WIN} all"
fi

# ---- Generate and run batch file ----
cat > /mnt/c/temp/run_ghidra_query.bat << BATEOF
@echo off
set JAVA_HOME=C:\Users\johne\.jdk\jdk-21.0.8+9
cd /d C:\devel\ghidra_12.0.3_PUBLIC\support
call analyzeHeadless.bat C:\Users\johne 8311 -process omcid -noanalysis -scriptPath ${SCRIPT_DIR_WIN} -postScript ${SCRIPT} ${SCRIPT_ARGS} > C:\temp\ghidra_log.txt 2>&1
BATEOF

echo "Querying Ghidra: ${SCRIPT} ${SCRIPT_ARGS}" >&2
cmd.exe /c "C:\\temp\\run_ghidra_query.bat" 2>/dev/null

# ---- Output result ----
if [ -f "${OUTPUT_WSL}" ] && [ -s "${OUTPUT_WSL}" ]; then
	cat "${OUTPUT_WSL}"
else
	echo "ERROR: No output. Check ${LOG_WSL}" >&2
	tail -15 "${LOG_WSL}" 2>/dev/null >&2
	exit 1
fi
