/******************************************************************************

                               Copyright (c) 2010
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "sce_counter.h"
#include "gtop.h"
#include "pe_abort_reasons.h"

#include <stdio.h>
#include <sys/time.h>

#include <sys/ioctl.h>
#include "drv_onu_resource.h"
#include "drv_onu_common_interface.h"
#include "drv_onu_ploam_interface.h"
#include "drv_onu_gpe_interface.h"
#include "drv_onu_event_interface.h"
#include "drv_onu_gpe_tables_interface.h"
#include "common.h"

#include <unistd.h>
#include <pthread.h>

#define FW_PERFMETER_INTERVAL_NUM	20
#define FW_PERFMETER_POLL_TIME		(1000 / FW_PERFMETER_INTERVAL_NUM)
#define FW_THREAD_MAX			(6 * 3)

#ifndef KSEG1
#define KSEG1 0xA0000000
#endif
#define ONU_FSQM_BASE		(KSEG1 | 0x1D500000)
#define ONU_FSQM_OFSC		(ONU_FSQM_BASE + 0x0000002C)

static pthread_t thread;
static bool thread_run;
static uint32_t fw_perfmeter, fw_perfmeter_perc, fw_perfmeter_acc;
static uint32_t ofsc, ofsc_acc;
static int update_interval;

int fw_perfmeter_table_get(const int fd, const char *dummy)
{
	return 2;
}

char *fw_perfmeter_entry_get(const int entry, char *text)
{
	if (entry == -1)
		return NULL;

	switch (entry) {
	case 0:
		sprintf(text, "TSTAT0 perfmeter"
			"                "
			"%u of %u (%u%%)", fw_perfmeter,
			FW_THREAD_MAX, fw_perfmeter_perc);
		break;

	case 1:
		sprintf(text, "OFSC perfmeter"
			"                  "
			"%u", ofsc);
		break;

	}

	return NULL;
}

static int bits_num_get(uint32_t n)
{
	int i, sum = 0;

	for (i = 0; i < 32; i++)
		if (n & (1 << i))
			sum++;

	return sum;
}

static uint32_t tstat0_get(void)
{
	int ret;
	struct sce_status status;

	ret = onu_iocmd(g_dev_fd, FIO_GPE_SCE_STATUS_GET, &status, sizeof(status));
	if (ret)
		return 0;

	return status.tstat0;
}

static uint32_t ofsc_get(void)
{
	int ret;
	union onu_register_get_u reg;

	reg.in.form = 32;
	reg.in.address = (ulong_t)ONU_FSQM_OFSC;

	ret = onu_iocmd(g_dev_fd, FIO_ONU_REGISTER_GET, &reg, sizeof(reg));
	if (ret)
		return 0;

	return reg.out.value;
}

static void *fw_perfmeter_update(void *p)
{
	volatile bool *run = (bool *)p;

	while (*run) {
		fw_perfmeter_acc += bits_num_get(tstat0_get());
		ofsc_acc += ofsc_get();

		--update_interval;

		if (update_interval <= 0) {
			update_interval = FW_PERFMETER_INTERVAL_NUM;
			fw_perfmeter = fw_perfmeter_acc / FW_PERFMETER_INTERVAL_NUM;
			fw_perfmeter_perc = fw_perfmeter_acc * 100 / FW_THREAD_MAX / FW_PERFMETER_INTERVAL_NUM;
			fw_perfmeter_acc = 0;

			ofsc = ofsc_acc / FW_PERFMETER_INTERVAL_NUM;
			ofsc_acc = 0;
		}

		(void)usleep(FW_PERFMETER_POLL_TIME);
	}

	pthread_exit(NULL);
}

void fw_perfmeter_on_enter(void)
{
	fw_perfmeter = fw_perfmeter_perc = fw_perfmeter_acc = 0;
	ofsc = ofsc_acc = 0;
	update_interval = FW_PERFMETER_INTERVAL_NUM;
	thread_run = 1;
	(void)pthread_create(&thread, NULL, fw_perfmeter_update, &thread_run);
}

void fw_perfmeter_on_leave(void)
{
	thread_run = 0;
	(void)pthread_join(thread, NULL);
}

/* #define PE_NUM		(6) */
#define PE_NUM		(1)
#define HW_THR_NUM	(3)
#define SW_THR_NUM	(4)
#define THR_NUM		(HW_THR_NUM * SW_THR_NUM)

struct thr_status {
	uint8_t qid;
	uint8_t first_pass;
	uint8_t second_pass;
	uint8_t third_pass;

	uint8_t fourth_pass;
	uint8_t fifth_pass;
	uint8_t sixth_pass;
	uint8_t err;
};

static struct thr_status thr_status[PE_NUM][THR_NUM];

static int fw_status_read(unsigned int pe,
			  unsigned int sw,
			  unsigned int hw,
			  uint32_t *hi,
			  uint32_t *lo)
{
	uint32_t index;
	struct gpe_table_entry entry;

	index = (hw * 4 + sw) * 2;

	if (table_read(g_dev_fd, ONU_GPE_STATUS_TABLE_ID,
			index,
			sizeof(struct gpe_status_table), &entry))
	    return -1;

	*hi = entry.data.status.entry_data;

	if (table_read(g_dev_fd, ONU_GPE_STATUS_TABLE_ID,
			index + 1,
			sizeof(struct gpe_status_table), &entry))
	    return -1;

	*lo = entry.data.status.entry_data;

	/*
	fprintf(stderr, "sw = %d hw = %d index = %d hi = 0x%x lo = 0x%x\n",
		sw, hw, index, *hi, *lo);
	*/

	return 0;
}

static inline uint8_t get_byte(uint32_t word, int byte)
{
	return (word & (0xff << byte * 8)) >> byte * 8;
}

int fw_status_table_get(const int fd, const char *dummy)
{
	unsigned int i, j;
	uint32_t hi, lo;

	for (i = 0; i < PE_NUM; i++) {
		for (j = 0; j < THR_NUM; j++) {
			if (fw_status_read(i, j % 4, j / 4, &hi, &lo))
				return 0;

			thr_status[i][j].qid = get_byte(hi, 3);
			thr_status[i][j].first_pass = get_byte(hi, 2);
			thr_status[i][j].second_pass = get_byte(hi, 1);
			thr_status[i][j].third_pass = get_byte(hi, 0);

			thr_status[i][j].fourth_pass = get_byte(lo, 3);
			thr_status[i][j].fifth_pass = get_byte(lo, 2);
			thr_status[i][j].sixth_pass = get_byte(lo, 1);
			thr_status[i][j].err = get_byte(lo, 0);
		}
	}

	return PE_NUM * THR_NUM;
}

char *fw_status_entry_get(int entry, char *text)
{
	int pe = entry / THR_NUM;
	uint16_t thr = entry % THR_NUM;

	if (entry == -1) {
		sprintf(text, "PE %-25s Softthread   Virtual Machine (HW Thread)",
			"Reasons");

		return NULL;
	}

	sprintf(text, "%-2d "
		"%02hhx %02hhx %02hhx %02hhx %02hhx %02hhx %02hhx %02hhx "
		"  "
		"%hhu   "
		"         "
		"%hhu",
		pe,
		thr_status[pe][thr].qid,
		thr_status[pe][thr].first_pass,
		thr_status[pe][thr].second_pass,
		thr_status[pe][thr].third_pass,
		thr_status[pe][thr].fourth_pass,
		thr_status[pe][thr].fifth_pass,
		thr_status[pe][thr].sixth_pass,
		thr_status[pe][thr].err,

		thr % 4,
		thr / 4);

	return NULL;
}

#define DETAIL_LINES	(9 + 1)

int fw_detailed_status_table_get(const int fd, const char *dummy)
{
	return fw_status_table_get(fd, dummy) * DETAIL_LINES;
}

struct def {
	const char *name;
	uint32_t value;
};

#define define(DEFINE)	{ #DEFINE, DEFINE }

static inline const char *parser_err_get(uint8_t value)
{
	unsigned int i;

	static const struct def err_defines[] = {
		define(PDUT_ERR_OFFS),
		define(EthLength_ERR_OFFS),
		define(VLAN_ERR_OFFS),
		define(IP_ERR_OFFS),
		define(INGR_AGING_ERR_OFFS),
	};
	static char buf[256];

	buf[0] = '\0';
	for (i = 0; i < ARRAY_SIZE(err_defines); i++) {
		if ((value & err_defines[i].value) == 0)
			continue;

		if (strlen(buf) != 0)
			strcat(buf, " | ");

		strcat(buf, err_defines[i].name);
	}

	return strlen(buf) ? buf : "NO ERROR";
}

static inline const char *pass_define_get(uint8_t value)
{
	unsigned int i;

	static const struct def pass_defines[] = {
		define(NO_ERROR),
		define(REASON_INGR_PARSER_ERROR),
		define(REASON_INGR_EXCEPTION),
		define(REASON_INGR_INTERWORKING_OPT),
		define(REASON_INGR_ETHERTYPE_FILT_B),
		define(REASON_INGR_ETHERTYPE_FILT_W),
		define(REASON_INGR_PPPoE_FILTER),
		define(REASON_INGR_VLAN_COPERR),
		define(REASON_INGR_BRIDGEPORT_INVALID),
		define(REASON_INGR_BRIDGEPORT_PSTATE),
		define(REASON_INGR_TAG_FILTER),
		define(REASON_INGR_ACL_FILTER),
		define(REASON_INGR_SIMPLE_POLICER),
		define(REASON_LEARN_PORT_LOCK),
		define(REASON_LEARN_STATIC),
		define(REASON_LEARN_ADD_ERR_NOT0_4),
		define(REASON_LEARN_PSTATE_NOT_FWD),
		define(REASON_FWD1_NO_KEY_BUILD),
		define(REASON_FWD_UNKNOWN_MC),
		define(REASON_FWD_UNKNOWN),
		define(REASON_FWD_UUC_FLOOD_DISABLED),
		define(REASON_METER_DISCARD),
		define(REASON_FWD_UNKOWN_L3_MC),
		define(REASON_EGR_EXCEPTION),
		define(REASON_EGR_PMAPPER_INVALID),
		define(REASON_EGR_ANI_US_GEM_ERR),
		define(REASON_EGR_UNI_INVALID),
		define(REASON_EGR_VLAN_COPERR),
		define(REASON_EGR_BRIDGEPORT_INVALID),
		define(REASON_EGR_BRIDGEPORT_PSTATE),
		define(REASON_EGR_TAG_FILTER),
		define(REASON_EGR_BRIDGE_NO_LOC_SWITCH),
		define(REASON_EGR_BRIDGE2_FILTERING),
		define(REASON_SA_FILTERING),
		define(REASON_DA_FILTERING),
	};

	for (i = 0; i < ARRAY_SIZE(pass_defines); i++)
		if (value == pass_defines[i].value)
			return pass_defines[i].name;

	return "?";
}

static inline void detail_entry_get(char *text,
				    unsigned int entry,
				    unsigned int pe,
				    unsigned int thr)
{
	switch (entry) {
	case 0:
		sprintf(text, "Detail page PE %u Softthread %u HWThread %u",
			pe, thr % 4, thr / 4);
		break;
	case 1:
		sprintf(text, "%-40s %u",
			"Egress QID of last transmitted PDU",
			thr_status[pe][thr].qid);
		break;
	case 2:
		sprintf(text, "%-40s %s (%u)",
			"Parser error code",
			parser_err_get(thr_status[pe][thr].err),
			thr_status[pe][thr].err);

		break;
	case 3:
		sprintf(text, "%-40s %s (%u)",
			"First FW pass",
			pass_define_get(thr_status[pe][thr].first_pass),
			thr_status[pe][thr].first_pass);
		break;
	case 4:
		sprintf(text, "%-40s %s (%u)",
			"Second replication/pass",
			pass_define_get(thr_status[pe][thr].second_pass),
			thr_status[pe][thr].second_pass);
		break;
	case 5:
		sprintf(text, "%-40s %s (%u)",
			"Third replication/pass",
			pass_define_get(thr_status[pe][thr].third_pass),
			thr_status[pe][thr].third_pass);
		break;
	case 6:
		sprintf(text, "%-40s %s (%u)",
			"Fourth replication/pass",
			pass_define_get(thr_status[pe][thr].fourth_pass),
			thr_status[pe][thr].fourth_pass);
		break;
	case 7:
		sprintf(text, "%-40s %s (%u)",
			"Fifth replication/pass",
			pass_define_get(thr_status[pe][thr].fifth_pass),
			thr_status[pe][thr].fifth_pass);
		break;
	case 8:
		sprintf(text, "%-40s %s (%u)",
			"Sixth replication/pass",
			pass_define_get(thr_status[pe][thr].sixth_pass),
			thr_status[pe][thr].sixth_pass);
		break;
	case 9:
		text[0] = '\0';
		break;
	}
}

char *fw_detailed_status_entry_get(const int entry, char *text)
{
	int real_entry = entry / DETAIL_LINES;
	int detail_entry = entry % DETAIL_LINES;
	int pe = real_entry / THR_NUM;
	int thr = real_entry % THR_NUM;

	if (entry != -1)
		detail_entry_get(text, detail_entry, pe, thr);

	return NULL;
}
