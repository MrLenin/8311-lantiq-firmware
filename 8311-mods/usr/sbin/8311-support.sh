#!/bin/sh
# 8311-support.sh — Generate a diagnostic support archive
#
# Collects firmware environment, GPON status, OMCI state, VLAN tables,
# and system logs into /tmp/support.tar.gz for troubleshooting.
#
# Adapted from the WAS-110 version for the G-010S-P platform.

echo "Generating support archive ..."
echo

OUT="/tmp/support.tar.gz"
TMPDIR=$(mktemp -d)
OUTDIR="$TMPDIR/support"

mkdir -p "$OUTDIR"

echo -n "Dumping system info ..."
/opt/lantiq/bin/system_info.sh summary > "$OUTDIR/system_info.txt"
echo " done"

echo -n "Dumping FW ENVs ..."
/usr/sbin/fw_printenv 2>&- | sort > "$OUTDIR/fwenvs.txt"
echo " done"

echo -n "Dumping UCI config ..."
/sbin/uci show 8311 > "$OUTDIR/uci_8311.txt" 2>&1
echo " done"

echo -n "Dumping GPON status pages ..."
{
	for page in "Status" "GTC alarms" "GTC counters" "GPE info" \
	            "GEM port" "Alloc ID" "GPE VLAN" "GPE extended VLAN" \
	            "GPE VLAN rule" "GPE VLAN treatment" "GPE LAN port General" \
	            "GPE bridge port" "Bridge port counter"; do
		printf '=== %s ===\n' "$page"
		/opt/lantiq/bin/gtop -b -g "$page" 2>&1
		echo
	done
} > "$OUTDIR/gtop.txt"
echo " done"

echo -n "Dumping optic status ..."
{
	for page in "status (1)" "configuration" "alarms"; do
		printf '=== %s ===\n' "$page"
		/opt/lantiq/bin/otop -b -g "$page" 2>&1
		echo
	done
} > "$OUTDIR/otop.txt"
echo " done"

echo -n "Dumping OMCI MEs ..."
/opt/lantiq/bin/omci_pipe.sh md > "$OUTDIR/omci_pipe_md.txt" 2>&1
/opt/lantiq/bin/omci_pipe.sh mda > "$OUTDIR/omci_pipe_mda.txt" 2>&1
echo " done"

echo -n "Dumping VLAN tables ..."
/usr/sbin/8311-extvlan-decode.sh -t > "$OUTDIR/extvlan-tables.txt" 2>&1 && {
	printf '\n\n'
	/usr/sbin/8311-extvlan-decode.sh 2>&1
} >> "$OUTDIR/extvlan-tables.txt"
echo " done"

echo -n "Dumping system log ..."
logread > "$OUTDIR/system_log.txt" 2>&1
echo " done"

echo
echo -n "Writing support archive '$OUT' ..."
rm -f "$OUT"
tar -cz -f "$OUT" -C "$TMPDIR" -- support
rm -rf "$TMPDIR"

echo " done"
echo
echo "WARNING: This support archive contains potentially sensitive information. Do not share it publicly."
