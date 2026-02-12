/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#include "drv_optic_std_defs.h"
#include "drv_optic_error.h"
#include "drv_optic_cli_core.h"
#include "drv_optic_api.h"
#include "drv_optic_interface.h"
#include "drv_optic_goi_interface.h"
#include "drv_optic_bert_interface.h"

#include "ifxos_memory_alloc.h"

#ifdef INCLUDE_CLI_SUPPORT

extern int optic_cli_check_help(
	const char *p_cmd,
	const char *p_usage,
	const uint32_t bufsize_max,
	char *p_out);

/** \addtogroup OPTIC_CLI_COMMANDS
   @{
*/

/** Handle command

   \param[in] p_dev     OPTIC device pointer
   \param[in] p_cmd     Input commands
   \param[in] p_out     Output FD
*/
static int cli_goi_lts_cfg_set(
	struct optic_device *p_dev,
	const char *p_cmd,
	const uint32_t bufsize_max,
	char *p_out)
{
	int ret = 0;
	enum optic_errorcode fct_ret = (enum optic_errorcode) 0;
	struct optic_lts_config param;

#ifndef OPTIC_DEBUG_DISABLE
	static const char usage[] =
		"Long Form: goi_lts_cfg_set" OPTIC_CRLF
		"Short Form: goilcs" OPTIC_CRLF
		OPTIC_CRLF
		"Input Parameter" OPTIC_CRLF
		"- bool enable" OPTIC_CRLF
		"- uint8_t pattern_length" OPTIC_CRLF
		"- uint8_t pattern[78]" OPTIC_CRLF
		OPTIC_CRLF
		"Output Parameter" OPTIC_CRLF
		"- enum optic_errorcode errorcode" OPTIC_CRLF
		OPTIC_CRLF;
#else
#undef usage
#define usage ""
#endif

	if ((ret = optic_cli_check_help(p_cmd, usage, bufsize_max, p_out)) >= 0) {
		return ret;
	}
	ret = optic_cli_sscanf(p_cmd, "%bu %bu %bu[78]", &param.enable, &param.pattern_length, &param.pattern[0]);
	if (ret != 80) {
		return optic_cli_check_help("-h", usage, bufsize_max, p_out);
	}
	fct_ret = goi_lts_cfg_set(p_dev, &param);
	return sprintf(p_out, "errorcode=%d " OPTIC_CRLF, (int)fct_ret);
}

/** Handle command

   \param[in] p_dev     OPTIC device pointer
   \param[in] p_cmd     Input commands
   \param[in] p_out     Output FD
*/
static int cli_goi_lts_cfg_get(
	struct optic_device *p_dev,
	const char *p_cmd,
	const uint32_t bufsize_max,
	char *p_out)
{
	int ret = 0;
	enum optic_errorcode fct_ret = (enum optic_errorcode) 0;
	struct optic_lts_config param;

#ifndef OPTIC_DEBUG_DISABLE
	static const char usage[] =
		"Long Form: goi_lts_cfg_get" OPTIC_CRLF
		"Short Form: goilcg" OPTIC_CRLF
		OPTIC_CRLF
		"Output Parameter" OPTIC_CRLF
		"- enum optic_errorcode errorcode" OPTIC_CRLF
		"- bool enable" OPTIC_CRLF
		"- uint8_t pattern_length" OPTIC_CRLF
		"- uint8_t pattern[78]" OPTIC_CRLF
		OPTIC_CRLF;
#else
#undef usage
#define usage ""
#endif

	if ((ret = optic_cli_check_help(p_cmd, usage, bufsize_max, p_out)) >= 0) {
		return ret;
	}
	fct_ret = goi_lts_cfg_get(p_dev, &param);
	return sprintf(p_out, "errorcode=%d enable=%u pattern_length=%u pattern=\"%u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u\" " OPTIC_CRLF, (int)fct_ret, param.enable, param.pattern_length, param.pattern[0], param.pattern[1], param.pattern[2], param.pattern[3], param.pattern[4], param.pattern[5], param.pattern[6], param.pattern[7], param.pattern[8], param.pattern[9], param.pattern[10], param.pattern[11], param.pattern[12], param.pattern[13], param.pattern[14], param.pattern[15], param.pattern[16], param.pattern[17], param.pattern[18], param.pattern[19], param.pattern[20], param.pattern[21], param.pattern[22], param.pattern[23], param.pattern[24], param.pattern[25], param.pattern[26], param.pattern[27], param.pattern[28], param.pattern[29], param.pattern[30], param.pattern[31], param.pattern[32], param.pattern[33], param.pattern[34], param.pattern[35], param.pattern[36], param.pattern[37], param.pattern[38], param.pattern[39], param.pattern[40], param.pattern[41], param.pattern[42], param.pattern[43], param.pattern[44], param.pattern[45], param.pattern[46], param.pattern[47], param.pattern[48], param.pattern[49], param.pattern[50], param.pattern[51], param.pattern[52], param.pattern[53], param.pattern[54], param.pattern[55], param.pattern[56], param.pattern[57], param.pattern[58], param.pattern[59], param.pattern[60], param.pattern[61], param.pattern[62], param.pattern[63], param.pattern[64], param.pattern[65], param.pattern[66], param.pattern[67], param.pattern[68], param.pattern[69], param.pattern[70], param.pattern[71], param.pattern[72], param.pattern[73], param.pattern[74], param.pattern[75], param.pattern[76], param.pattern[77]);
}

/** Handle command

   \param[in] p_dev     OPTIC device pointer
   \param[in] p_cmd     Input commands
   \param[in] p_out     Output FD
*/
static int cli_bert_cfg_set(
	struct optic_device *p_dev,
	const char *p_cmd,
	const uint32_t bufsize_max,
	char *p_out)
{
	int ret = 0;
	enum optic_errorcode fct_ret = (enum optic_errorcode) 0;
	struct optic_bert_cfg param;

#ifndef OPTIC_DEBUG_DISABLE
	static const char usage[] =
		"Long Form: bert_cfg_set" OPTIC_CRLF
		"Short Form: bertcs" OPTIC_CRLF
		OPTIC_CRLF
		"Input Parameter" OPTIC_CRLF
		"- uint8_t pattern_mode" OPTIC_CRLF
		"- uint8_t pattern_type[4]" OPTIC_CRLF
		"- uint8_t pattern_length[4]" OPTIC_CRLF
		"- uint8_t fixed_pattern[78]" OPTIC_CRLF
		"- uint8_t clock_period" OPTIC_CRLF
		"- uint8_t clock_high" OPTIC_CRLF
		"- uint8_t prbs_type" OPTIC_CRLF
		"- bool datarate_tx_high \n   false = 0\n   true = 1" OPTIC_CRLF
		"- bool datarate_rx_high \n   false = 0\n   true = 1" OPTIC_CRLF
		"- bool loop_enable \n   false = 0\n   true = 1" OPTIC_CRLF
		OPTIC_CRLF
		"Output Parameter" OPTIC_CRLF
		"- enum optic_errorcode errorcode" OPTIC_CRLF
		OPTIC_CRLF;
#else
#undef usage
#define usage ""
#endif

	if ((ret = optic_cli_check_help(p_cmd, usage, bufsize_max, p_out)) >= 0) {
		return ret;
	}
	ret = optic_cli_sscanf(p_cmd, "%bu %bu[4] %bu[4] %bu[78] %bu %bu %bu %bu %bu %bu", &param.pattern_mode, &param.pattern_type[0], &param.pattern_length[0], &param.fixed_pattern[0], &param.clock_period, &param.clock_high, &param.prbs_type, &param.datarate_tx_high, &param.datarate_rx_high, &param.loop_enable);
	if (ret != 93) {
		return optic_cli_check_help("-h", usage, bufsize_max, p_out);
	}
	fct_ret = bert_cfg_set(p_dev, &param);
	return sprintf(p_out, "errorcode=%d " OPTIC_CRLF, (int)fct_ret);
}

/** Handle command

   \param[in] p_dev     OPTIC device pointer
   \param[in] p_cmd     Input commands
   \param[in] p_out     Output FD
*/
static int cli_bert_cfg_get(
	struct optic_device *p_dev,
	const char *p_cmd,
	const uint32_t bufsize_max,
	char *p_out)
{
	int ret = 0;
	enum optic_errorcode fct_ret = (enum optic_errorcode) 0;
	struct optic_bert_cfg param;

#ifndef OPTIC_DEBUG_DISABLE
	static const char usage[] =
		"Long Form: bert_cfg_get" OPTIC_CRLF
		"Short Form: bertcg" OPTIC_CRLF
		OPTIC_CRLF
		"Output Parameter" OPTIC_CRLF
		"- enum optic_errorcode errorcode" OPTIC_CRLF
		"- uint8_t pattern_mode" OPTIC_CRLF
		"- uint8_t pattern_type[4]" OPTIC_CRLF
		"- uint8_t pattern_length[4]" OPTIC_CRLF
		"- uint8_t fixed_pattern[78]" OPTIC_CRLF
		"- uint8_t clock_period" OPTIC_CRLF
		"- uint8_t clock_high" OPTIC_CRLF
		"- uint8_t prbs_type" OPTIC_CRLF
		"- bool datarate_tx_high \n   false = 0\n   true = 1" OPTIC_CRLF
		"- bool datarate_rx_high \n   false = 0\n   true = 1" OPTIC_CRLF
		"- bool loop_enable \n   false = 0\n   true = 1" OPTIC_CRLF
		OPTIC_CRLF;
#else
#undef usage
#define usage ""
#endif

	if ((ret = optic_cli_check_help(p_cmd, usage, bufsize_max, p_out)) >= 0) {
		return ret;
	}



	fct_ret = bert_cfg_get(p_dev, &param);
	return sprintf(p_out, "errorcode=%d pattern_mode=%u pattern_type=\"%u %u %u %u\" pattern_length=\"%u %u %u %u\" fixed_pattern=\"%u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u\" clock_period=%u clock_high=%u prbs_type=%u datarate_tx_high=%u datarate_rx_high=%u loop_enable=%u " OPTIC_CRLF, (int)fct_ret, param.pattern_mode, param.pattern_type[0], param.pattern_type[1], param.pattern_type[2], param.pattern_type[3], param.pattern_length[0], param.pattern_length[1], param.pattern_length[2], param.pattern_length[3], param.fixed_pattern[0], param.fixed_pattern[1], param.fixed_pattern[2], param.fixed_pattern[3], param.fixed_pattern[4], param.fixed_pattern[5], param.fixed_pattern[6], param.fixed_pattern[7], param.fixed_pattern[8], param.fixed_pattern[9], param.fixed_pattern[10], param.fixed_pattern[11], param.fixed_pattern[12], param.fixed_pattern[13], param.fixed_pattern[14], param.fixed_pattern[15], param.fixed_pattern[16], param.fixed_pattern[17], param.fixed_pattern[18], param.fixed_pattern[19], param.fixed_pattern[20], param.fixed_pattern[21], param.fixed_pattern[22], param.fixed_pattern[23], param.fixed_pattern[24], param.fixed_pattern[25], param.fixed_pattern[26], param.fixed_pattern[27], param.fixed_pattern[28], param.fixed_pattern[29], param.fixed_pattern[30], param.fixed_pattern[31], param.fixed_pattern[32], param.fixed_pattern[33], param.fixed_pattern[34], param.fixed_pattern[35], param.fixed_pattern[36], param.fixed_pattern[37], param.fixed_pattern[38], param.fixed_pattern[39], param.fixed_pattern[40], param.fixed_pattern[41], param.fixed_pattern[42], param.fixed_pattern[43], param.fixed_pattern[44], param.fixed_pattern[45], param.fixed_pattern[46], param.fixed_pattern[47], param.fixed_pattern[48], param.fixed_pattern[49], param.fixed_pattern[50], param.fixed_pattern[51], param.fixed_pattern[52], param.fixed_pattern[53], param.fixed_pattern[54], param.fixed_pattern[55], param.fixed_pattern[56], param.fixed_pattern[57], param.fixed_pattern[58], param.fixed_pattern[59], param.fixed_pattern[60], param.fixed_pattern[61], param.fixed_pattern[62], param.fixed_pattern[63], param.fixed_pattern[64], param.fixed_pattern[65], param.fixed_pattern[66], param.fixed_pattern[67], param.fixed_pattern[68], param.fixed_pattern[69], param.fixed_pattern[70], param.fixed_pattern[71], param.fixed_pattern[72], param.fixed_pattern[73], param.fixed_pattern[74], param.fixed_pattern[75], param.fixed_pattern[76], param.fixed_pattern[77], param.clock_period, param.clock_high, param.prbs_type, param.datarate_tx_high, param.datarate_rx_high, param.loop_enable);
}

/** Handle command

   \param[in] p_dev     OPTIC device pointer
   \param[in] p_cmd     Input commands
   \param[in] p_out     Output FD
*/
static int cli_cal_measure_rssi_1490_get(
	struct optic_device *p_dev,
	const char *p_cmd,
	const uint32_t bufsize_max,
	char *p_out)
{
	int ret = 0, length = 0;
	enum optic_errorcode fct_ret = (enum optic_errorcode) 0;
	union optic_measure_rssi_1490_get param;
	uint8_t i, number;
	uint16_t *p_data;

#ifndef OPTIC_DEBUG_DISABLE
	static const char usage[] =
		"Long Form: cal_measure_rssi_1490_get" OPTIC_CRLF
		"Short Form: calmr1490" OPTIC_CRLF
		OPTIC_CRLF
		"Input Parameter" OPTIC_CRLF
		"- uint8_t number" OPTIC_CRLF
		OPTIC_CRLF
		"Output Parameter" OPTIC_CRLF
		"- enum optic_errorcode errorcode" OPTIC_CRLF
		"- uint16_t measure_buffer" OPTIC_CRLF
		OPTIC_CRLF;
#else
#undef usage
#define usage ""
#endif

	if ((ret = optic_cli_check_help(p_cmd, usage, bufsize_max, p_out)) >= 0) {
		return ret;
	}

	ret = optic_cli_sscanf(p_cmd, "%bu ", &param.in.number);
	if (ret != 1) {
		return optic_cli_check_help("-h", usage, bufsize_max, p_out);
	}

	param.in.p_data = IFXOS_MemAlloc ( sizeof(uint16_t) * param.in.number);
	number = param.in.number;
	p_data = param.in.p_data;
	if (p_data == IFX_NULL) {
		length = sprintf(p_out, "errorcode=-1");
		return length;
	}

	fct_ret = cal_measure_rssi_1490_get(p_dev, &param.in, &param.out);
	length = sprintf(p_out, "errorcode=%d", (int)fct_ret);

	if (fct_ret >= 0) {
		length += sprintf(&(p_out[length]), " measure_buffer[%u]= ", number);
		for (i=0; i<number; i++)
			length += sprintf(&(p_out[length]), "%hu ", p_data[i] );
	}

	IFXOS_MemFree (p_data);

	length += sprintf(&(p_out[length]), "measure_average= %d", param.out.average );

	length += sprintf(&(p_out[length]), OPTIC_CRLF );

	return length;
}

/** Register misc commands */
void optic_cli_misc_register ( void )
{
optic_cli_command_add("goilcs", "goi_lts_cfg_set", cli_goi_lts_cfg_set);
optic_cli_command_add("goilcg", "goi_lts_cfg_get", cli_goi_lts_cfg_get);
optic_cli_command_add("bertcs", "bert_cfg_set", cli_bert_cfg_set);
optic_cli_command_add("bertcg", "bert_cfg_get", cli_bert_cfg_get);
optic_cli_command_add("calmr1490g", "cal_measure_rssi_1490_get", cli_cal_measure_rssi_1490_get);
}

/*! @} */

#endif
