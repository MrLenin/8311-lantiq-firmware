#!/bin/sh
onu="/opt/lantiq/bin/onu"
uci="/sbin/uci"
lct_wait_count=0
lct_try_count=0
lct_restart_try=$($uci -q get 8311.config.lct_restart_try)
total_lct_wait=$($uci -q get 8311.config.total_lct_wait)
total_lct_try=$($uci -q get 8311.config.total_lct_try)
trackip1=$($uci -q get 8311.config.trackip1)
trackip2=$($uci -q get 8311.config.trackip2)
persist_log_on_reboot=$($uci -q get 8311.config.persist_log_on_reboot)

check_onu_status() {
	local fifo_overflow_count
	fifo_overflow_count=$(dmesg | grep -c "FIFO\[device\] overflow")
	if [ "$fifo_overflow_count" -gt 50 ]; then
		if [ "$persist_log_on_reboot" = "1" ]; then
			/opt/lantiq/bin/debug
			cp /tmp/log/one_click /root
		fi
		fw_setenv rebootcause 2
		reboot -f
	fi
}

check_cop_error() {
	local cop_result
	local cop_status
	local error_code

	cop_result=$($onu gpetr 10 1)
	cop_status=${cop_result%% *}
	error_code=${cop_status#*=}
	#error_code=-4512
	#define ONU_TSE_ERROR_BASE -4000
	#COP_STATUS_ERR_RESP_LEN = 512
	#cop_to_onu_errorcode()	return ONU_TSE_ERROR_BASE - st;
	if [ "$error_code" -lt -4000 ]; then
		/opt/lantiq/bin/debug
		cp /tmp/log/one_click /root
		#send_cop_alarm
		#6 ONU self-test failure ONU has failed autonomous self-test
		/opt/lantiq/bin/omci_pipe.sh managed_entity_alarm_set 256 0 6 1
		sleep 10
		fw_setenv rebootcause 4
		reboot -f

		#after rebooting, the alarm sequence number is reset, no need to clear cop alarm
		#At initialization, periodically, or when the OLT detects a gap in the alarm sequence number, it reconciles its view of the ONU's alarm status by sending a get all alarms command targeted at the ONU data ME
		#When it receives the get all alarms request, the ONU resets the alarm sequence number to zero.
		#When the upload is complete, the OLT compares the received alarm statuses with its own alarm table entries for that ONU, along with any alarm notifications received during the upload process, and notifies the network manager of any changes.
		#else
		#clear_cop_alarm
	fi
}

reset_lct_wait() {
	lct_wait_count=0
}

restart_lct_port() {
	if [ "$lct_try_count" -lt "$total_lct_try" ]; then
		$onu lan_port_disable 0
		sleep 5
		$onu lan_port_enable 0
		sleep 5
		lct_try_count=$((lct_try_count + 1))
		reset_lct_wait
	else
		logger -t "[monitomcid]" "LCT total restart reached, current lct try times: $lct_try_count, giving up ..."
	fi
}

check_lct_status() {
	local ping_status_1
	local ping_status_2
	if [ "$lct_restart_try" = "1" ] && [ -n "$total_lct_wait" ] && [ -n "$total_lct_try" ] && [ -n "$trackip1" ] && [ -n "$trackip2" ]; then
		ping_status_1=$(ping -W 1 -c 3 "$trackip1" | grep -c "100% packet loss")
		ping_status_2=$(ping -W 1 -c 3 "$trackip2" | grep -c "100% packet loss")
		if [ "$ping_status_1" = "1" ] && [ "$ping_status_2" = "1" ] && [ "$lct_wait_count" -lt "$total_lct_wait" ]; then
			logger -t "[monitomcid]" "LCT port link error detected, current lct wait times: $lct_wait_count ,waiting ..."
			lct_wait_count=$((lct_wait_count + 1))
		fi
		if [ "$ping_status_1" != "1" ] || [ "$ping_status_2" != "1" ]; then
			reset_lct_wait
		fi
		if [ "$lct_wait_count" -eq "$total_lct_wait" ]; then
			logger -t "[monitomcid]" "LCT total wait times: $lct_wait_count reached, restarting ..."
			restart_lct_port
		fi
	fi
}

monitomcid() {
	while true; do
		check_lct_status
		check_onu_status
		check_cop_error
		sleep 15
	done
}

monitomcid
