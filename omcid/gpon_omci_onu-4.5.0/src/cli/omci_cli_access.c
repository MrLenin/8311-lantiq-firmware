/******************************************************************************

                              Copyright (c) 2012
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include <stdlib.h>		/* strtol */
#include <string.h>		/* strstr, strcmp, strtok_r */

#include "ifx_types.h"
#include "ifxos_common.h"
#include "ifxos_memory_alloc.h"
#include "ifxos_print.h"
#include "omci_interface.h"

#include "omci_api.h"
#include "voip/omci_api_voip.h"
#include "me/omci_onu_power_shedding.h"
#include "omci_core.h"


#ifdef INCLUDE_CLI_SUPPORT

#include "lib_cli_config.h"
#include "lib_cli_core.h"

/** \addtogroup OMCI_CLI
   @{
*/

/** \defgroup OMCI_CLI_COMMANDS Optical Network Unit - Commands
   @{
*/

/** Receive OMCI message (from the OLT) command

   \param[in] p_ctx OMCI context pointer
   \param[in] cmd   Input commands
   \param[in] out   Output FD
*/
static int cli_omci_message_receive(void *p_ctx,
				    const char *cmd,
				    clios_file_t *out)
{
	int ret;
	struct omci_context *context = (struct omci_context*)p_ctx;
	uint8_t msg[48];
	int curr_byte;
	enum omci_error fct_ret = OMCI_SUCCESS;
	char *sep = " ";
	char *byte;
	char *cmd_tok;

#ifndef OMCI_DEBUG_DISABLE
	static const char USAGE[] =
	    "Long Form: raw_message_recv" IFXOS_CRLF
	    "Short Form: rmr" IFXOS_CRLF
	    IFXOS_CRLF
	    "Input Parameter" IFXOS_CRLF
	    "- union omci_msg msg[1-40] (hex)" IFXOS_CRLF
	    IFXOS_CRLF
	    "Output Parameter" IFXOS_CRLF "- enum omci_error errorcode" IFXOS_CRLF IFXOS_CRLF;
#else
#undef USAGE
#define USAGE ""
#endif

	if ((ret = cli_check_help__file(cmd, USAGE, out)) > 0)
		return ret;

	if (strlen(cmd) == 0) {
		return cli_check_help__file("-h", USAGE, out);
	}

	memset(msg, 0, sizeof(msg));
	byte = strtok_r((char *)cmd, sep, &cmd_tok);

	curr_byte = 0;
	while (byte != NULL) {
		if (curr_byte > 39) {
			return IFXOS_FPrintf(out,
					     "Parse error: too long command!");
		}

		msg[curr_byte] = (uint8_t)strtol(byte, 0, 16);

		byte = strtok_r(0, sep, &cmd_tok);
		curr_byte++;
	}

	fct_ret = omci_msg_recv(context, (union omci_msg *)msg);
	return IFXOS_FPrintf(out, "errorcode=%d" IFXOS_CRLF, fct_ret);
}

/** Sent OMCI message (to the OLT) command

   \param[in] p_ctx OMCI context pointer
   \param[in] cmd   Input commands
   \param[in] out   Output FD
*/
static int cli_omci_message_send(void *p_ctx,
				 const char *cmd,
				 clios_file_t *out)
{
	struct omci_context *context = (struct omci_context*)p_ctx;
	uint8_t msg[sizeof(union omci_msg)];
	int curr_byte;
	char *sep = " ";
	char *byte;
	int ret;
	enum omci_error fct_ret = OMCI_SUCCESS;
	char *cmd_tok;

#ifndef OMCI_DEBUG_DISABLE
	static const char USAGE[] =
	    "Note: This function is not implemented!" IFXOS_CRLF
	    "Long Form: raw_message_send" IFXOS_CRLF
	    "Short Form: rms" IFXOS_CRLF
	    IFXOS_CRLF
	    "Input Parameter" IFXOS_CRLF
	    "- uint8_t msg[1-40] (hex)" IFXOS_CRLF
	    IFXOS_CRLF
	    "Output Parameter" IFXOS_CRLF "- enum omci_error errorcode" IFXOS_CRLF IFXOS_CRLF;
#else
#undef USAGE
#define USAGE ""
#endif

	(void)context;

	if ((ret = cli_check_help__file(cmd, USAGE, out)) > 0) {
		return ret;
	}

	if (strlen(cmd) == 0) {
		return cli_check_help__file("-h", USAGE, out);
	}
	memset(msg, 0, sizeof(msg));
	byte = strtok_r((char *)cmd, sep, &cmd_tok);

	curr_byte = 0;
	while (byte != NULL) {
		if (curr_byte > 39) {
			return IFXOS_FPrintf(out,
					     "Parse error: too long command!");
		}

		msg[curr_byte] = (uint8_t)strtol(byte, 0, 16);

		byte = strtok_r(0, sep, &cmd_tok);
		curr_byte++;
	}

	fct_ret = omci_msg_send(context, (const union omci_msg *)msg);

	return IFXOS_FPrintf(out, "errorcode=%d" IFXOS_CRLF, fct_ret);
}

/** Dump MIB (show MIB contents)

   \param[in] p_ctx OMCI context pointer
   \param[in] cmd   Input commands
   \param[in] out   Output FD
*/
static int cli_omci_mib_dump(void *p_ctx,
			     const char *cmd,
			     clios_file_t *out)
{
	int ret;
	struct omci_context *context = (struct omci_context*)p_ctx;
	unsigned int i;
	size_t me_count;
	struct omci_me *me_list;
	uint16_t class_id;
	uint16_t instance_id;

#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	char *class_names;
#endif
	enum omci_error fct_ret = OMCI_SUCCESS;

#ifndef OMCI_DEBUG_DISABLE
	static const char USAGE[] =
	    "Long Form: mib_dump" IFXOS_CRLF
	    "Short Form: md" IFXOS_CRLF
	    IFXOS_CRLF
	    "Output Parameter" IFXOS_CRLF "- enum omci_error errorcode" IFXOS_CRLF IFXOS_CRLF;
#else
#undef USAGE
#define USAGE ""
#endif

	if ((ret = cli_check_help__file(cmd, USAGE, out)) > 0) {
		return ret;
	}

	/* get ME count */
	fct_ret = omci_me_count_get(context, &me_count);
	if (fct_ret != OMCI_SUCCESS) {
		return IFXOS_FPrintf(out, "errorcode=%d " IFXOS_CRLF, fct_ret);
	}

	/* allocate space for ME list */
	me_list = IFXOS_MemAlloc(sizeof(struct omci_me) * me_count);
	if (me_list == NULL) {
		return IFXOS_FPrintf(out, "errorcode=%d " IFXOS_CRLF,
				     OMCI_ERROR_MEMORY);
	}

	/* get ME list */
	fct_ret = omci_me_list_get(context, me_list,
				   sizeof(struct omci_me) * me_count);
	if (fct_ret != OMCI_SUCCESS) {
		IFXOS_MemFree(me_list);
		return IFXOS_FPrintf(out, "errorcode=%d " IFXOS_CRLF, fct_ret);
	}
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	class_names = IFXOS_MemAlloc(26 * me_count);

	if (class_names == NULL) {
		IFXOS_MemFree(me_list);
		return IFXOS_FPrintf(out, "errorcode=%d " IFXOS_CRLF,
				     OMCI_ERROR_MEMORY);
	}

	for (i = 0; i < me_count; i++) {
		(void)omci_me_name_get(context, me_list[i].class_id,
					   &class_names[26 * i]);
	}
#endif

	/* print ME list */
	ret = IFXOS_FPrintf(out, "Found %d Managed Entitites in the MIB:" IFXOS_CRLF,
			    me_count);

	ret += IFXOS_FPrintf(out, "+----------+----------------+-----------"
			     "---------------------------------------" IFXOS_CRLF);

	ret += IFXOS_FPrintf(out, "| Class id |  Instance id   |");
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	ret += IFXOS_FPrintf(out, " Class name");
#endif
	ret += IFXOS_FPrintf(out, IFXOS_CRLF);

	ret += IFXOS_FPrintf(out, "+----------+----------------+-----------"
			     "---------------------------------------" IFXOS_CRLF);

	for (i = 0; i < me_count; i++) {
		class_id = me_list[i].class_id;
		instance_id = me_list[i].instance_id;

		ret += IFXOS_FPrintf(out,
				     "|    %5d | %5d (0x%04x) | ",
				     class_id, instance_id, instance_id);

#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
		ret += IFXOS_FPrintf(out, "%s", &class_names[26 * i]);
#endif
		ret += IFXOS_FPrintf(out, IFXOS_CRLF);
	}

	ret += IFXOS_FPrintf(out, "+----------+----------------+-----------"
			     "---------------------------------------" IFXOS_CRLF);

	ret += IFXOS_FPrintf(out, "errorcode=%d" IFXOS_CRLF, fct_ret);

	IFXOS_MemFree(me_list);
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	IFXOS_MemFree(class_names);
#endif
	return ret;
}

static void fill_prop_string(const uint32_t prop, const bool xml, char *buf)
{
	uint16_t i, k;
	int l;
	const char *name[] = {
		"r",
		"w",
		"sbc",
		"avc",
		"optional",
		"upload",
		"table",
		"no_swap",
		"not_supported",
		"template",
		"partly"
	};
	const uint16_t code[] = {
		OMCI_ATTR_PROP_RD,
		OMCI_ATTR_PROP_WR,
		OMCI_ATTR_PROP_SBC,
		OMCI_ATTR_PROP_AVC,
		OMCI_ATTR_PROP_OPTIONAL,
		OMCI_ATTR_PROP_NO_UPLOAD,
		OMCI_ATTR_PROP_TABLE,
		OMCI_ATTR_PROP_NO_SWAP,
		OMCI_ATTR_PROP_NOT_SUPPORTED,
		OMCI_ATTR_PROP_TEMPLATE,
		OMCI_ATTR_PROP_PARTLY
	};
	const char c[] = {
		'R',
		'W',
		'S',
		'A',
		'O',
		'U',
		'T',
		'P',
		'N',
		'E',
		'Y'
	};

	buf[0] = 0;
	if(xml) {
		for(i=0, k=0;k<sizeof(code)/sizeof(code[0]);k++) {
			if((prop & code[k]) == 0)
				continue;
			l = sprintf(&buf[i], " %s=\"%s\"", name[k], prop & code[k] ? "x" : " ");
			if(l > -1)
				i += l;
		}
	} else {
		for(i=0, k=0;k<sizeof(code)/sizeof(code[0]);k++) {
			if (prop & code[k])
				buf[i++] = c[k];
			else
				buf[i++] = '-';
		}
		buf[i++] = 0;
	}
}

static int cli_me_get(struct omci_context *context,
		      IFXOS_File_t *out,
		      const bool xml,
		      const uint16_t class_id,
		      const uint16_t instance_id,
		      const enum omci_pm_interval interval,
		      int *cnt)
{
	int ret = 0;
	char *ptr;
	char buf[256];
	unsigned int i,k;
	unsigned int attr;
	enum omci_me_prop me_prop;
	size_t attr_size[16] = { 0 };
	bool attr_valid[16];
	enum omci_attr_prop attr_prop[16] = { OMCI_ATTR_PROP_NONE };

	size_t attr_offset;
	uint8_t attr_data[OMCI_ME_DATA_SIZE_MAX];

	char attr_name[16][26] = { {0} };
	uint8_t alarm_bitmap[OMCI_ALARM_BITMAP_SIZE];
	bool has_alarm_bitmap = true;
	enum omci_attr_type attr_type[16] = { OMCI_ATTR_TYPE_UNKNOWN };

#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	char class_name[26];
#endif

	void *tbl_data;
	size_t tbl_size;

	enum omci_error fct_ret = OMCI_SUCCESS;

	uint16_t tmp16;
	uint32_t tmp32;

	/* get ME properties */
	fct_ret = omci_me_prop_get(context, class_id, &me_prop);
	if (fct_ret != OMCI_SUCCESS) {
		if(!xml)
			*cnt += IFXOS_FPrintf(out, "errorcode=%d" IFXOS_CRLF, fct_ret);
		return -1;
	}

	/* get ME alarm bitmap */
	fct_ret = omci_me_alarm_bitmap_get(context, class_id, instance_id,
					   alarm_bitmap);
	if (fct_ret == OMCI_ERROR_INVALID_ME_ACTION) {
		has_alarm_bitmap = false;
	} else if (fct_ret == OMCI_SUCCESS) {
	} else {
		if(!xml)
			*cnt += IFXOS_FPrintf(out, "errorcode=%d" IFXOS_CRLF, fct_ret);
		return -1;
	}

	/* get ME attribute sizes, properties, values */
	for (attr = 0; attr < 16; attr++) {
		attr_valid[attr] = true;

		fct_ret = omci_me_attr_prop_get(context,
						class_id,
						attr + 1, &attr_prop[attr]);

		if (fct_ret != OMCI_SUCCESS) {
			attr_valid[attr] = false;
			continue;
		}

		fct_ret = omci_me_attr_size_get(context, class_id,
						attr + 1, &attr_size[attr]);

		if (fct_ret != OMCI_SUCCESS) {
			attr_valid[attr] = false;
			continue;
		}

		fct_ret = omci_me_attr_type_get(context, class_id,
						attr + 1, &attr_type[attr]);

		if (fct_ret != OMCI_SUCCESS) {
			attr_valid[attr] = false;
			continue;
		}
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
		fct_ret = omci_me_attr_name_get(context, class_id,
						attr + 1, attr_name[attr]);
		if (fct_ret != OMCI_SUCCESS) {
			attr_valid[attr] = false;
			continue;
		}
#else
		attr_name[attr][0] = 0;
#endif

		if (attr_prop[attr] & OMCI_ATTR_PROP_TABLE)
			continue;
	}

	fct_ret = omci_me_data_get(context, class_id, instance_id,
				   interval, attr_data, sizeof(attr_data));

	if (fct_ret != OMCI_SUCCESS) {
		if(!xml)
			*cnt += IFXOS_FPrintf(out, "errorcode=%d" IFXOS_CRLF, fct_ret);
		return -1;
	}

	/* print ME data */
	if(!xml)
		ret += IFXOS_FPrintf(out, "Class ID    = %d", class_id);
	else
		ret += IFXOS_FPrintf(out, "<me class_id=\"%d\"", class_id);

#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	(void)omci_me_name_get(context, class_id, class_name);
	if(!xml)
		ret += IFXOS_FPrintf(out, " (%s)", class_name);
	else
		ret += IFXOS_FPrintf(out, " name=\"%s\"", class_name);
#endif

	if(!xml)
		ret += IFXOS_FPrintf(out, IFXOS_CRLF "Instance ID = %d" IFXOS_CRLF, instance_id);
	else
		ret += IFXOS_FPrintf(out, " instance_id=\"%d\"", instance_id);

	if (me_prop & OMCI_ME_PROP_NO_UPLOAD) {
		ptr = "no";
	} else {
		if (me_prop & OMCI_ME_PROP_PM)
			ptr = "no_pm";
		else
			ptr = "yes";
	}
	if(!xml)
		ret += IFXOS_FPrintf(out, "Uploaded    = %s" IFXOS_CRLF, ptr);
	else
		ret += IFXOS_FPrintf(out, " uploaded=\"%s\"", ptr);

	if(!xml)
		ret += IFXOS_FPrintf(out, "Alarms      = ");
	else
		ret += IFXOS_FPrintf(out, " alarms=\"");
	if (has_alarm_bitmap == false) {
			ret += IFXOS_FPrintf(out, "-");
	} else {
		for (i = 0; i < OMCI_ALARM_BITMAP_SIZE; i++) {
			ret += IFXOS_FPrintf(out, "0x%02x ", alarm_bitmap[i]);
			if (!xml && i == 13)
				ret +=IFXOS_FPrintf(out, IFXOS_CRLF
						    "              ");
		}
	}
	if(!xml)
		ret += IFXOS_FPrintf(out, IFXOS_CRLF);
	else
		ret += IFXOS_FPrintf(out, "\">" IFXOS_CRLF);

	/* attributes */
	if(!xml)
		ret += IFXOS_FPrintf(out, "----------------------------------------"
			     "---------------------------------------" IFXOS_CRLF);

	attr_offset = 0;
	for (attr = 0; attr < 16; attr++) {
		if (attr_valid[attr] == false) {
			attr_offset += attr_size[attr];
			continue;
		}

		/* header */
		if(!xml)
			ret += IFXOS_FPrintf(out, "%2u %-25s %5db ",
						 attr, attr_name[attr], attr_size[attr]);
		else
			ret += IFXOS_FPrintf(out, "\t<attribute name=\"%s\" size=\"%d\" pos=\"%d\"",
						 attr_name[attr], attr_size[attr], attr);

		/* format */
		ptr = "";
		switch (attr_type[attr]) {
		case OMCI_ATTR_TYPE_PTR:
			ptr="PTR";
			break;

		case OMCI_ATTR_TYPE_BF:
			ptr="BF";
			break;

		case OMCI_ATTR_TYPE_INT:
			ptr="SINT";
			break;

		case OMCI_ATTR_TYPE_UINT:
			ptr="UINT";
			break;

		case OMCI_ATTR_TYPE_STR:
			ptr="STR";
			break;

		case OMCI_ATTR_TYPE_ENUM:
			ptr="ENUM";
			break;

		case OMCI_ATTR_TYPE_TBL:
			ptr="TBL";
			break;

		default:
			break;
		}
		if(!xml)
			ret += IFXOS_FPrintf(out, "%-5s", ptr);
		else
			ret += IFXOS_FPrintf(out, " type=\"%s\"", ptr);

		/* properties */
		fill_prop_string(attr_prop[attr], xml, &buf[0]);

		/* values */
		if(!xml)
			ret += IFXOS_FPrintf(out, "%s" IFXOS_CRLF, buf);
		else
			ret += IFXOS_FPrintf(out, " %s", buf);

		if(!xml)
			ret += IFXOS_FPrintf(out, "   ");
		else
			ret += IFXOS_FPrintf(out, " values=\"");

		if (attr_prop[attr] & OMCI_ATTR_PROP_TABLE) {
			tbl_data = NULL;
			fct_ret = omci_me_tbl_data_get(context,
						       class_id,
						       instance_id,
						       attr + 1,
						       &tbl_data,
						       &tbl_size);

			if (fct_ret) {
				if(!xml)
					ret += IFXOS_FPrintf(out, "table get error(%d)",
									 fct_ret);
				else
					ret += IFXOS_FPrintf(out, "\"/>" IFXOS_CRLF);
				attr_offset += attr_size[attr];
				continue;
			}

			if (tbl_data == NULL) {
				if(xml)
					ret += IFXOS_FPrintf(out, "\"/>" IFXOS_CRLF);
				attr_offset += attr_size[attr];
				continue;
			}

			for (i = 0; i < tbl_size; i++) {
				ret += IFXOS_FPrintf(out, "0x%02x ",
						     *((uint8_t *)tbl_data + i));
				if(!xml)
					if ((i + 1) % attr_size[attr] == 0)
						ret += IFXOS_FPrintf(out, IFXOS_CRLF "   ");
			}

			IFXOS_MemFree(tbl_data);
		} else if (attr_prop[attr] & OMCI_ATTR_PROP_NO_SWAP) {
			for (i = 0; i < attr_size[attr]; i++)
				ret += IFXOS_FPrintf(out, "0x%02x ",
						     *(uint8_t *)(attr_data +
								  attr_offset +
								  i));
			if(!xml) {
				ret += IFXOS_FPrintf(out, IFXOS_CRLF "   ");
				for (i = 0; i < attr_size[attr]; i++)
					ret += IFXOS_FPrintf(out, "%c",
						     *(uint8_t *)(attr_data +
								  attr_offset +
								  i));
			}
		} else {
			switch (attr_size[attr]) {
			case 1:
				ret += IFXOS_FPrintf(out, "0x%02x",
						     *(uint8_t *)(attr_data +
								  attr_offset));
				if(!xml) {
					if (attr_type[attr] == OMCI_ATTR_TYPE_INT) {
						ret += IFXOS_FPrintf(out, " (%d)",
								     *(char *)(attr_data +
									       attr_offset));
					} else {
						ret += IFXOS_FPrintf(out, " (%u)",
								     *(uint8_t *)(attr_data +
										  attr_offset));
					}
				}
				break;

			case 2:
				memcpy(&tmp16, attr_data + attr_offset, 2);
				ret += IFXOS_FPrintf(out, "0x%04x", tmp16);
				if(!xml) {
					if (attr_type[attr] == OMCI_ATTR_TYPE_INT) {
						ret += IFXOS_FPrintf(out, " (%d)", (short)tmp16);
					} else {
						ret += IFXOS_FPrintf(out, " (%u)", tmp16);
					}
				}
				break;

			case 4:
				memcpy(&tmp32, attr_data + attr_offset, 4);
				ret += IFXOS_FPrintf(out, "0x%08x", tmp32);
				if(!xml) {
					if (attr_type[attr] == OMCI_ATTR_TYPE_INT) {
						ret += IFXOS_FPrintf(out, " (%d)", (int)tmp32);
					} else {
						ret += IFXOS_FPrintf(out, " (%u)", tmp32);
					}
				}
				break;

			default:
				for (i = 0; i < attr_size[attr]; i++)
					ret += IFXOS_FPrintf(out, "0x%02x ",
							     *(uint8_t
							       *)(attr_data +
								  attr_offset +
								  i));
			}
		}

		if(!xml) {
			ret += IFXOS_FPrintf(out, IFXOS_CRLF);
			ret += IFXOS_FPrintf(out,
						 "----------------------------------------"
						 "---------------------------------------"
						 IFXOS_CRLF);
		} else {
			ret += IFXOS_FPrintf(out, "\"/>" IFXOS_CRLF);
		}

		attr_offset += attr_size[attr];
	}

	if(xml)
		ret += IFXOS_FPrintf(out, "</me>" IFXOS_CRLF);

	*cnt += ret;
	return 0;
}

static int cli_class_get(struct omci_context *context,
		      IFXOS_File_t *out,
		      const bool xml,
		      const uint16_t class_id)
{
	int ret = 0;
	char *ptr;
	char buf[256];
	unsigned int i,k;
	unsigned int attr;
	enum omci_me_prop me_prop;
	size_t attr_size[16] = { 0 };
	bool attr_valid[16];
	enum omci_attr_prop attr_prop[16] = { OMCI_ATTR_PROP_NONE };

	size_t attr_offset;

	char attr_name[16][26] = { {0} };
	uint8_t alarm_bitmap[OMCI_ALARM_BITMAP_SIZE];
	bool has_alarm_bitmap = true;
	enum omci_attr_type attr_type[16] = { OMCI_ATTR_TYPE_UNKNOWN };

#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	char class_name[26];
#endif

	void *tbl_data;
	size_t tbl_size;

	enum omci_error fct_ret = OMCI_SUCCESS;

	uint16_t tmp16;
	uint32_t tmp32;

	/* get ME properties */
	fct_ret = omci_me_prop_get(context, class_id, &me_prop);
	if (fct_ret != OMCI_SUCCESS) {
		return fct_ret;
	}

	/* get ME attribute sizes, properties, values */
	for (attr = 0; attr < 16; attr++) {
		attr_valid[attr] = true;

		fct_ret = omci_me_attr_prop_get(context,
						class_id,
						attr + 1, &attr_prop[attr]);

		if (fct_ret != OMCI_SUCCESS) {
			attr_valid[attr] = false;
			continue;
		}

		fct_ret = omci_me_attr_size_get(context, class_id,
						attr + 1, &attr_size[attr]);

		if (fct_ret != OMCI_SUCCESS) {
			attr_valid[attr] = false;
			continue;
		}

		fct_ret = omci_me_attr_type_get(context, class_id,
						attr + 1, &attr_type[attr]);

		if (fct_ret != OMCI_SUCCESS) {
			attr_valid[attr] = false;
			continue;
		}
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
		fct_ret = omci_me_attr_name_get(context, class_id,
						attr + 1, attr_name[attr]);
		if (fct_ret != OMCI_SUCCESS) {
			attr_valid[attr] = false;
			continue;
		}
#else
		attr_name[attr][0] = 0;
#endif

		if (attr_prop[attr] & OMCI_ATTR_PROP_TABLE)
			continue;
	}

	/* print ME data */
	if(!xml)
		ret += IFXOS_FPrintf(out, "Class ID    = %d", class_id);
	else
		ret += IFXOS_FPrintf(out, "<class id=\"%d\"", class_id);

#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	(void)omci_me_name_get(context, class_id, class_name);
	if(!xml)
		ret += IFXOS_FPrintf(out, " (%s)", class_name);
	else
		ret += IFXOS_FPrintf(out, " class_name=\"%s\"", class_name);
#endif

	if (me_prop & OMCI_ME_PROP_REVIEW) {
		if(xml)
			ret += IFXOS_FPrintf(out, " review=\"x\"");
	}

	if(!xml)
		ret += IFXOS_FPrintf(out, IFXOS_CRLF);
	else
		ret += IFXOS_FPrintf(out, ">" IFXOS_CRLF);

	attr_offset = 0;
	for (attr = 0; attr < 16; attr++) {
		if (attr_valid[attr] == false) {
			attr_offset += attr_size[attr];
			continue;
		}

		/* header */
		if(!xml)
			ret += IFXOS_FPrintf(out, "%2u %-25s %5db ",
						 attr, attr_name[attr], attr_size[attr]);
		else
			ret += IFXOS_FPrintf(out, "\t<attribute attr_name=\"%s\" size=\"%d\" pos=\"%d\"",
						 attr_name[attr], attr_size[attr], attr);

		/* format */
		ptr = "";
		switch (attr_type[attr]) {
		case OMCI_ATTR_TYPE_PTR:
			ptr="PTR";
			break;

		case OMCI_ATTR_TYPE_BF:
			ptr="BF";
			break;

		case OMCI_ATTR_TYPE_INT:
			ptr="SINT";
			break;

		case OMCI_ATTR_TYPE_UINT:
			ptr="UINT";
			break;

		case OMCI_ATTR_TYPE_STR:
			ptr="STR";
			break;

		case OMCI_ATTR_TYPE_ENUM:
			ptr="ENUM";
			break;

		case OMCI_ATTR_TYPE_TBL:
			ptr="TBL";
			break;

		default:
			break;
		}
		if(!xml)
			ret += IFXOS_FPrintf(out, "%-5s", ptr);
		else
			ret += IFXOS_FPrintf(out, " type=\"%s\"", ptr);

		/* properties */
		fill_prop_string(attr_prop[attr], xml, &buf[0]);

		/* values */
		if(!xml)
			ret += IFXOS_FPrintf(out, "%s" IFXOS_CRLF, buf);
		else
			ret += IFXOS_FPrintf(out, " %s", buf);

		if(xml) {
			ret += IFXOS_FPrintf(out, "/>" IFXOS_CRLF);
		}

		attr_offset += attr_size[attr];
	}

	if(xml)
		ret += IFXOS_FPrintf(out, "</class>" IFXOS_CRLF);

	return 0;
}

/** Dump all Managed Entities

   \param[in] p_ctx OMCI context pointer
   \param[in] cmd   Input commands
   \param[in] out   Output FD
*/
static int cli_omci_mib_dump_all(void *p_ctx,
				 const char *cmd,
				 clios_file_t *out)
{
	int ret;
	struct omci_context *context = (struct omci_context*)p_ctx;
	unsigned int i;
	size_t me_count;
	struct omci_me *me_list;
	uint16_t class_id;
	uint16_t instance_id;

	enum omci_error fct_ret = OMCI_SUCCESS;

#ifndef OMCI_DEBUG_DISABLE
	static const char USAGE[] =
	    "Long Form: mib_dump_all" IFXOS_CRLF
	    "Short Form: mda" IFXOS_CRLF
	    IFXOS_CRLF
	    "Output Parameter" IFXOS_CRLF "- enum omci_error errorcode" IFXOS_CRLF IFXOS_CRLF;
#else
#undef USAGE
#define USAGE ""
#endif

	if ((ret = cli_check_help__file(cmd, USAGE, out)) > 0) {
		return ret;
	}

	/* get ME count */
	fct_ret = omci_me_count_get(context, &me_count);
	if (fct_ret != OMCI_SUCCESS) {
		return IFXOS_FPrintf(out, "errorcode=%d " IFXOS_CRLF, fct_ret);
	}

	/* allocate space for ME list */
	me_list = IFXOS_MemAlloc(sizeof(struct omci_me) * me_count);
	if (me_list == NULL) {
		return IFXOS_FPrintf(out, "errorcode=%d " IFXOS_CRLF,
				     OMCI_ERROR_MEMORY);
	}

	/* get ME list */
	fct_ret = omci_me_list_get(context, me_list,
				   sizeof(struct omci_me) * me_count);
	if (fct_ret != OMCI_SUCCESS) {
		IFXOS_MemFree(me_list);
		return IFXOS_FPrintf(out, "errorcode=%d " IFXOS_CRLF, fct_ret);
	}

	for (i = 0; i < me_count; i++) {
		class_id = me_list[i].class_id;
		instance_id = me_list[i].instance_id;

		fct_ret = cli_me_get(context, out, false, class_id, instance_id,
				     OMCI_PM_INTERVAL_CURR,
				     &ret);

		if (fct_ret)
			break;
	}

	ret += IFXOS_FPrintf(out, "errorcode=%d" IFXOS_CRLF, fct_ret);

	IFXOS_MemFree(me_list);
	return ret;
}

/** Dump all Managed Entities

   \param[in] p_ctx OMCI context pointer
   \param[in] cmd   Input commands
   \param[in] out   Output FD
*/
static int cli_omci_class_dump_all(void *p_ctx,
				 const char *cmd,
				 clios_file_t *out)
{
	int ret;
	struct omci_context *context = (struct omci_context*)p_ctx;
	unsigned int i;
	struct me_class *me_class;
	enum omci_error fct_ret = OMCI_SUCCESS;

#ifndef OMCI_DEBUG_DISABLE
	static const char USAGE[] =
	    "Long Form: class_dump_all" IFXOS_CRLF
	    "Short Form: cda" IFXOS_CRLF
	    IFXOS_CRLF
	    "Output Parameter" IFXOS_CRLF "- enum omci_error errorcode" IFXOS_CRLF IFXOS_CRLF;
#else
#undef USAGE
#define USAGE ""
#endif

	if ((ret = cli_check_help__file(cmd, USAGE, out)) > 0) {
		return ret;
	}

	for (i = 0; i < OMCI_ME_CLASS_NUM; i++) {
		me_class = me_def_class_array[i];
		if (!me_class)
			continue;
		fct_ret = cli_class_get(context, out, false, me_class->class_id);
		if(fct_ret != OMCI_SUCCESS)
			break;
	}

	IFXOS_FPrintf(out, "errorcode=%d" IFXOS_CRLF, fct_ret);

	return ret;
}

/** Dump all Managed Entities

   \param[in] p_ctx OMCI context pointer
   \param[in] cmd   Input commands
   \param[in] out   Output FD
*/
static int cli_omci_mib_dump_xml(void *p_ctx,
				 const char *cmd,
				 clios_file_t *out)
{
	int ret;
	struct omci_context *context = (struct omci_context*)p_ctx;
	unsigned int i;
	size_t me_count;
	struct omci_me *me_list;
	uint16_t class_id;
	uint16_t instance_id;

	enum omci_error fct_ret = OMCI_SUCCESS;

#ifndef OMCI_DEBUG_DISABLE
	static const char USAGE[] =
	    "Long Form: mib_dump_xml" IFXOS_CRLF
	    "Short Form: mdx" IFXOS_CRLF
	    IFXOS_CRLF
	    "Output Parameter" IFXOS_CRLF "- enum omci_error errorcode" IFXOS_CRLF IFXOS_CRLF;
#else
#undef USAGE
#define USAGE ""
#endif

	if ((ret = cli_check_help__file(cmd, USAGE, out)) > 0) {
		return ret;
	}

	/* get ME count */
	fct_ret = omci_me_count_get(context, &me_count);
	if (fct_ret != OMCI_SUCCESS) {
		return 0;
	}

	/* allocate space for ME list */
	me_list = IFXOS_MemAlloc(sizeof(struct omci_me) * me_count);
	if (me_list == NULL) {
		return 0;
	}

	/* get ME list */
	fct_ret = omci_me_list_get(context, me_list,
				   sizeof(struct omci_me) * me_count);
	if (fct_ret != OMCI_SUCCESS) {
		IFXOS_MemFree(me_list);
		return 0;
	}

	IFXOS_FPrintf(out, "<mib>");
	for (i = 0; i < me_count; i++) {
		class_id = me_list[i].class_id;
		instance_id = me_list[i].instance_id;

		fct_ret = cli_me_get(context, out, true, class_id, instance_id,
				     OMCI_PM_INTERVAL_CURR,
				     &ret);

		if (fct_ret)
			break;
	}
	IFXOS_FPrintf(out, "</mib>");

	IFXOS_MemFree(me_list);
	return ret;
}

/** Dump all classes

   \param[in] p_ctx OMCI context pointer
   \param[in] cmd   Input commands
   \param[in] out   Output FD
*/
static int cli_omci_class_dump_xml(void *p_ctx,
				 const char *cmd,
				 clios_file_t *out)
{
	int ret;
	struct omci_context *context = (struct omci_context*)p_ctx;
	unsigned int i;
	struct me_class *me_class;
	enum omci_error fct_ret = OMCI_SUCCESS;

#ifndef OMCI_DEBUG_DISABLE
	static const char USAGE[] =
	    "Long Form: class_dump_xml" IFXOS_CRLF
	    "Short Form: cdx" IFXOS_CRLF
	    IFXOS_CRLF
	    "Output Parameter" IFXOS_CRLF "- enum omci_error errorcode" IFXOS_CRLF IFXOS_CRLF;
#else
#undef USAGE
#define USAGE ""
#endif

	if ((ret = cli_check_help__file(cmd, USAGE, out)) > 0) {
		return ret;
	}

	IFXOS_FPrintf(out, "<classes>");
	for (i = 0; i < OMCI_ME_CLASS_NUM; i++) {
		me_class = me_def_class_array[i];
		if (!me_class)
			continue;
		cli_class_get(context, out, true, me_class->class_id);
	}
	IFXOS_FPrintf(out, "</classes>");

	return ret;
}

/** Dump Managed Entity (show Managed Entity contents)

   \param[in] p_ctx OMCI context pointer
   \param[in] cmd   Input commands
   \param[in] out   Output FD
*/
static int cli_omci_managed_entity_get(void *p_ctx,
				       const char *cmd,
				       clios_file_t *out)
{
	int ret = 0, tmp;
	struct omci_context *context = (struct omci_context*)p_ctx;
	uint16_t class_id;
	uint16_t instance_id;
	enum omci_pm_interval interval;

	enum omci_error fct_ret = OMCI_SUCCESS;

#ifndef OMCI_DEBUG_DISABLE
	static const char USAGE[] =
	    "Long Form: managed_entity_get" IFXOS_CRLF
	    "Short Form: meg" IFXOS_CRLF
	    IFXOS_CRLF
	    "Input Parameter" IFXOS_CRLF
	    "- uint16_t class_id" IFXOS_CRLF
	    "- uint16_t instance_id" IFXOS_CRLF
	    "- enum omci_pm_interval interval (optional)" IFXOS_CRLF
	    IFXOS_CRLF
	    "Output Parameter" IFXOS_CRLF "- enum omci_error errorcode" IFXOS_CRLF IFXOS_CRLF;
#else
#undef USAGE
#define USAGE ""
#endif

	if ((ret = cli_check_help__file(cmd, USAGE, out)) > 0) {
		return ret;
	}

	fct_ret = (enum omci_error)cli_sscanf(cmd, "%hi %hi %d", &class_id,
					  &instance_id, &tmp);
	/* avoid type-punned pointer */
	interval = (enum omci_pm_interval)tmp;
	if ((int)fct_ret < 2) {
		return cli_check_help__file("-h", USAGE, out);
	}

	if ((int)fct_ret != 3)
		interval = OMCI_PM_INTERVAL_CURR;

	if (cli_me_get(context, out, false, class_id, instance_id, interval, &ret))
		return ret;

	ret += IFXOS_FPrintf(out,
			     "R - Readable          "
			     "O - Not supported (optional)" IFXOS_CRLF
			     "W - Writable          "
			     "E - Excluded from MIB upload" IFXOS_CRLF
			     "S - set-by-create     "
			     "T - Table" IFXOS_CRLF
			     "A - Send AVC          "
			     "V - Volatile" IFXOS_CRLF
			     "                      "
			     "N - No swap" IFXOS_CRLF IFXOS_CRLF);

	ret += IFXOS_FPrintf(out, "errorcode=%d" IFXOS_CRLF, OMCI_SUCCESS);
	return ret;
}

/** Dump Class (show Class implementation)

   \param[in] p_ctx OMCI context pointer
   \param[in] cmd   Input commands
   \param[in] out   Output FD
*/
static int cli_omci_class_get(void *p_ctx,
				       const char *cmd,
				       clios_file_t *out)
{
	int ret = 0;
	struct omci_context *context = (struct omci_context*)p_ctx;
	uint16_t class_id;
	enum omci_error fct_ret = OMCI_SUCCESS;

#ifndef OMCI_DEBUG_DISABLE
	static const char USAGE[] =
	    "Long Form: class_get" IFXOS_CRLF
	    "Short Form: cg" IFXOS_CRLF
	    IFXOS_CRLF
	    "Input Parameter" IFXOS_CRLF
	    "- uint16_t class_id" IFXOS_CRLF
	    IFXOS_CRLF
	    "Output Parameter" IFXOS_CRLF "- enum omci_error errorcode" IFXOS_CRLF IFXOS_CRLF;
#else
#undef USAGE
#define USAGE ""
#endif

	if ((ret = cli_check_help__file(cmd, USAGE, out)) > 0) {
		return ret;
	}

	fct_ret = (enum omci_error)cli_sscanf(cmd, "%hi", &class_id);
	if ((int)fct_ret != 1)
		ret = OMCI_ERROR;
	else
		ret = cli_class_get(context, out, false, class_id);

	ret += IFXOS_FPrintf(out, "errorcode=%d" IFXOS_CRLF, ret);
	return ret;
}

#if !defined(OMCI_DEBUG_DISABLE)
/** Handle command

   \param[in] p_ctx OMCI context pointer
   \param[in] cmd   Input commands
   \param[in] out   Output FD
*/
static int cli_omci_debug_level_get(void *p_ctx,
				    const char *cmd,
				    clios_file_t *out)
{
	int ret;
	struct omci_context *context = (struct omci_context*)p_ctx;
	enum omci_dbg_module mod;
	enum omci_dbg dbg_mods[OMCI_DBG_MODULE_NUM];
	enum omci_error fct_ret;

#ifndef OMCI_DEBUG_DISABLE
	static const char USAGE[] =
	    "Long Form: dbg_level_get" IFXOS_CRLF
	    "Short Form: dlg" IFXOS_CRLF
	    IFXOS_CRLF
	    "Output Parameter" IFXOS_CRLF "- enum omci_error errorcode" IFXOS_CRLF IFXOS_CRLF;
#else
#undef USAGE
#define USAGE ""
#endif

	(void)context;

	if ((ret = cli_check_help__file(cmd, USAGE, out)) > 0) {
		return ret;
	}

	/* read debug modules levels */
	for (mod = OMCI_DBG_MODULE_MIN; mod <= OMCI_DBG_MODULE_MAX; mod++) {
		fct_ret = omci_dbg_module_level_get(mod, &dbg_mods[mod]);
		if (fct_ret != OMCI_SUCCESS) {
			return IFXOS_FPrintf(out, "errorcode=%d" IFXOS_CRLF, fct_ret);
		}

	}

	/* print */
	ret = IFXOS_FPrintf(out, "+----+-------+---------+-"
			    "--------+---------+---------+"
			    "---------+---------------" IFXOS_CRLF);
	ret += IFXOS_FPrintf(out,
			     "| No | name  |"
			     " MSG (%u) |"
			     " PRN (%u) |"
			     " WRN (%u) |"
			     " ERR (%u) |"
			     " OFF (%u) |"
			     IFXOS_CRLF,
			     OMCI_DBG_MSG,
			     OMCI_DBG_PRN,
			     OMCI_DBG_WRN, OMCI_DBG_ERR,
			     OMCI_DBG_OFF);
	ret = IFXOS_FPrintf(out, "+----+-------+---------+-"
			    "--------+---------+---------+"
			    "---------+---------------" IFXOS_CRLF);

	for (mod = (enum omci_dbg_module)
	     ((unsigned int)OMCI_DBG_MODULE_MIN + 1);
	     mod <= OMCI_DBG_MODULE_MAX; mod++) {
		ret += IFXOS_FPrintf(out, "| %2d | ", mod);

		switch (mod) {
		case OMCI_DBG_MODULE_NO:
			ret += IFXOS_FPrintf(out, "-----");
			break;

		case OMCI_DBG_MODULE_CORE:
			ret += IFXOS_FPrintf(out, "CORE ");
			break;

		case OMCI_DBG_MODULE_API:
			ret += IFXOS_FPrintf(out, "API  ");
			break;

		case OMCI_DBG_MODULE_MIB:
			ret += IFXOS_FPrintf(out, "MIB  ");
			break;

		case OMCI_DBG_MODULE_ME:
			ret += IFXOS_FPrintf(out, "ME   ");
			break;

		case OMCI_DBG_MODULE_MSG_DUMP:
			ret += IFXOS_FPrintf(out, "MSG  ");
			break;

		case OMCI_DBG_MODULE_PM:
			ret += IFXOS_FPrintf(out, "PM   ");
			break;

		case OMCI_DBG_MODULE_MIB_RESET:
			ret += IFXOS_FPrintf(out, "MIBRS");
			break;

		case OMCI_DBG_MODULE_IFXOS:
			ret += IFXOS_FPrintf(out, "IFXOS");
			break;

		case OMCI_DBG_MODULE_VOIP:
			ret += IFXOS_FPrintf(out, "VoIP ");
			break;

		case OMCI_DBG_MODULE_MCC:
			ret += IFXOS_FPrintf(out, "MCC  ");
			break;

		default:
			ret += IFXOS_FPrintf(out, "????");
		}

		ret += IFXOS_FPrintf(out, " |");

		switch (dbg_mods[mod]) {
		case OMCI_DBG_MSG:
			ret += IFXOS_FPrintf(out,
					     "   (+)   |"
					     "         |"
					     "         |" "         |"
					     "         |");
			break;

		case OMCI_DBG_PRN:
			ret += IFXOS_FPrintf(out,
					     "         |"
					     "   (+)   |"
					     "         |" "         |"
					     "         |");
			break;

		case OMCI_DBG_WRN:
			ret += IFXOS_FPrintf(out,
					     "         |"
					     "         |"
					     "   (+)   |" "         |"
					     "         |");
			break;

		case OMCI_DBG_ERR:
			ret += IFXOS_FPrintf(out,
					     "         |"
					     "         |"
					     "         |" "   (+)   |"
					     "         |");
			break;

		case OMCI_DBG_OFF:
			ret += IFXOS_FPrintf(out,
					     "         |"
					     "         |"
					     "         |" "         |"
					     "   (+)   |");
			break;

		default:
			ret += IFXOS_FPrintf(out,
					     "    ?    |"
					     "    ?    |"
					     "    ?    |" "    ?    |"
					     "    ?    |");
		}

		ret += IFXOS_FPrintf(out, IFXOS_CRLF);
	}

	ret = IFXOS_FPrintf(out, "+----+-------+---------+-"
			    "--------+---------+---------+"
			    "---------+---------------" IFXOS_CRLF);

	ret += IFXOS_FPrintf(out, "errorcode=%d " IFXOS_CRLF, fct_ret);
	return ret;
}
#endif				/* !defined(OMCI_DEBUG_DISABLE) */

#if !defined(OMCI_DEBUG_DISABLE)
/** Handle command

   \param[in] p_ctx OMCI context pointer
   \param[in] cmd   Input commands
   \param[in] out   Output FD
*/
static int cli_omci_mapper_dump(void *p_ctx,
				const char *cmd,
				clios_file_t *out)
{
	int ret;
	struct omci_context *context = (struct omci_context*)p_ctx;
	enum omci_error fct_ret;

#ifndef OMCI_DEBUG_DISABLE
	static const char USAGE[] =
	    "Long Form: AL_MapperDump" IFXOS_CRLF
	    "Short Form: almd" IFXOS_CRLF
	    IFXOS_CRLF
	    "Output Parameter" IFXOS_CRLF "- enum omci_error errorcode" IFXOS_CRLF IFXOS_CRLF;
#else
#undef USAGE
#define USAGE ""
#endif

	(void)context;

	if ((ret = cli_check_help__file(cmd, USAGE, out)) > 0) {
		return ret;
	}

	fct_ret = (enum omci_error)omci_api_mapper_dump(omci_api_ctx_get(context));

	ret += IFXOS_FPrintf(out, "errorcode=%d " IFXOS_CRLF, fct_ret);
	return ret;
}
#endif

#ifdef INCLUDE_OMCI_ONU_VOIP
static int cli_omci_sip_call(void *p_ctx,
			     const char *cmd,
			     clios_file_t *out)
{
	int ret = 0;
	struct omci_context *context = (struct omci_context*)p_ctx;
	int user_id;
	char uri[256];
	enum omci_error fct_ret = OMCI_SUCCESS;
	struct voip_call_info info;

#ifndef OMCI_DEBUG_DISABLE
	static const char USAGE[] =
	    "Long Form: sip_call" IFXOS_CRLF
	    "Short Form: sipc" IFXOS_CRLF
	    IFXOS_CRLF
	    "Input Parameter" IFXOS_CRLF
	    "- int user_id" IFXOS_CRLF
	    "- char[256] uri (e.g. sip:user@ip)" IFXOS_CRLF
	    IFXOS_CRLF
	    "Output Parameter" IFXOS_CRLF
	    "- enum omci_error errorcode" IFXOS_CRLF IFXOS_CRLF;
#else
#undef USAGE
#define USAGE ""
#endif

	if ((ret = cli_check_help__file(cmd, USAGE, out)) > 0) {
		return ret;
	}

	fct_ret = (enum omci_error)sscanf(cmd, "%d %256s", &user_id, (char *)&uri);
	if ((int)fct_ret != 2) {
		return cli_check_help__file("-h", USAGE, out);
	}

	info.user_id = user_id;
	info.dst_uri = uri;

	fct_ret = (enum omci_error)omci_api_voip_call_make(omci_api_ctx_get(context), &info);

	ret += IFXOS_FPrintf(out, "errorcode=%d" IFXOS_CRLF, fct_ret);
	return ret;
}
#endif

#ifdef INCLUDE_OMCI_ONU_VOIP
static int cli_omci_sip_answer(void *p_ctx,
			       const char *cmd,
			       clios_file_t *out)
{
	int ret = 0;
	struct omci_context *context = (struct omci_context*)p_ctx;
	int user_id;
	enum omci_error fct_ret = OMCI_SUCCESS;

#ifndef OMCI_DEBUG_DISABLE
	static const char USAGE[] =
	    "Long Form: sip_answer" IFXOS_CRLF
	    "Short Form: sipa" IFXOS_CRLF
	    IFXOS_CRLF
	    "Input Parameter" IFXOS_CRLF
	    "- int user_id" IFXOS_CRLF
	    IFXOS_CRLF
	    "Output Parameter" IFXOS_CRLF
	    "- enum omci_error errorcode" IFXOS_CRLF IFXOS_CRLF;
#else
#undef USAGE
#define USAGE ""
#endif

	if ((ret = cli_check_help__file(cmd, USAGE, out)) > 0) {
		return ret;
	}

	fct_ret = (enum omci_error)sscanf(cmd, "%d", &user_id);
	if ((int)fct_ret != 1) {
		return cli_check_help__file("-h", USAGE, out);
	}

	fct_ret = (enum omci_error) omci_api_voip_call_answer(omci_api_ctx_get(context),
							      (uint8_t)user_id);

	ret += IFXOS_FPrintf(out, "errorcode=%d" IFXOS_CRLF, fct_ret);
	return ret;
}
#endif

#ifdef INCLUDE_OMCI_ONU_VOIP
static int cli_omci_sip_hangup(void *p_ctx,
			       const char *cmd,
			       clios_file_t *out)
{
	int ret = 0;
	struct omci_context *context = (struct omci_context*)p_ctx;
	int user_id;
	enum omci_error fct_ret = OMCI_SUCCESS;

#ifndef OMCI_DEBUG_DISABLE
	static const char USAGE[] =
	    "Long Form: sip_hangup" IFXOS_CRLF
	    "Short Form: siph" IFXOS_CRLF
	    IFXOS_CRLF
	    "Input Parameter" IFXOS_CRLF
	    "- int user_id" IFXOS_CRLF
	    IFXOS_CRLF
	    "Output Parameter" IFXOS_CRLF
	    "- enum omci_error errorcode" IFXOS_CRLF IFXOS_CRLF;
#else
#undef USAGE
#define USAGE ""
#endif

	if ((ret = cli_check_help__file(cmd, USAGE, out)) > 0) {
		return ret;
	}

	fct_ret = (enum omci_error)sscanf(cmd, "%d", &user_id);
	if ((int)fct_ret != 1) {
		return cli_check_help__file("-h", USAGE, out);
	}

	fct_ret = (enum omci_error)omci_api_voip_call_end(omci_api_ctx_get(context),
							  (uint8_t)user_id);

	ret += IFXOS_FPrintf(out, "errorcode=%d" IFXOS_CRLF, fct_ret);
	return ret;
}
#endif

#ifdef INCLUDE_OMCI_ONU_VOIP
static int cli_omci_sip_agent_cfg_get(void *p_ctx,
				      const char *cmd,
				      clios_file_t *out)
{
	int ret = 0;
	struct omci_context *context = (struct omci_context*)p_ctx;
	enum omci_error fct_ret = OMCI_SUCCESS;
	struct sip_agent agt;

#ifndef OMCI_DEBUG_DISABLE
	static const char USAGE[] =
	    "Long Form: sip_agent_cfg_get" IFXOS_CRLF
	    "Short Form: sipacg" IFXOS_CRLF
	    IFXOS_CRLF
	    "Output Parameter" IFXOS_CRLF
	    "- enum omci_error errorcode" IFXOS_CRLF
	    "- uint16_t agent_port" IFXOS_CRLF
	    "- char agent_ip[16]" IFXOS_CRLF
	    "- uint16_t agent_proto" IFXOS_CRLF
	    "- uint32_t reg_exp_time" IFXOS_CRLF
	    "- char registrar[" _MKSTR(OMCI_API_URI_MAX) "]" IFXOS_CRLF
	    "- char proxy[" _MKSTR(OMCI_API_URI_MAX) "]" IFXOS_CRLF
	    IFXOS_CRLF;
#else
#undef USAGE
#define USAGE ""
#endif

	if ((ret = cli_check_help__file(cmd, USAGE, out)) > 0) {
		return ret;
	}

	fct_ret = (enum omci_error)omci_api_voip_agent_cfg_get(omci_api_ctx_get(context),
							       &agt);

	ret += IFXOS_FPrintf(out, "errorcode=%d "
			     "agent_port=%hu "
			     "agent_ip=%d.%d.%d.%d "
			     "agent_proto=%hu "
			     "reg_exp_time=%u "
			     "registrar=%s "
			     "proxy=%s"
			     IFXOS_CRLF,
			     fct_ret,
			     agt.agent_port,
			     (agt.agent_ip & 0xFF000000) >> 24,
			     (agt.agent_ip & 0x00FF0000) >> 16,
			     (agt.agent_ip & 0x0000FF00) >> 8,
			     (agt.agent_ip & 0x000000FF) >> 0,
			     agt.agent_proto,
			     agt.reg_exp_time,
			     agt.registrar,
			     agt.proxy);
	return ret;
}
#endif

#ifdef INCLUDE_OMCI_ONU_VOIP
static int cli_omci_sip_agent_cfg_set(void *p_ctx,
				      const char *cmd,
				      clios_file_t *out)
{
	int ret = 0;
	struct omci_context *context = (struct omci_context*)p_ctx;
	enum omci_error fct_ret = OMCI_SUCCESS;
	struct sip_agent agt;
	unsigned char ip_part[4];

#ifndef OMCI_DEBUG_DISABLE
	static const char USAGE[] =
	    "Long Form: sip_agent_cfg_set" IFXOS_CRLF
	    "Short Form: sipacs" IFXOS_CRLF
	    IFXOS_CRLF
	    "Include Parameter" IFXOS_CRLF
	    "- uint16_t agent_port" IFXOS_CRLF
	    "- char agent_ip[16]" IFXOS_CRLF
	    "- uint16_t agent_proto" IFXOS_CRLF
	    "- uint32_t reg_exp_time" IFXOS_CRLF
	    "- char registrar[" _MKSTR(OMCI_API_URI_MAX) "] (optional)"IFXOS_CRLF
	    "- char proxy[" _MKSTR(OMCI_API_URI_MAX) "] (optional)" IFXOS_CRLF
	    "Output Parameter" IFXOS_CRLF
	    "- enum omci_error errorcode" IFXOS_CRLF
	    IFXOS_CRLF;
#else
#undef USAGE
#define USAGE ""
#endif

	memset(&agt, 0, sizeof(agt));

	if ((ret = cli_check_help__file(cmd, USAGE, out)) > 0) {
		return ret;
	}

	fct_ret = (enum omci_error)sscanf(cmd, "%hu "
					  "%hhu.%hhu.%hhu.%hhu "
					  "%hu %u "
					  "%" _MKSTR(OMCI_API_URI_MAX) "s"
					  "%" _MKSTR(OMCI_API_URI_MAX) "s",
					  &agt.agent_port,
					  &ip_part[3],
					  &ip_part[2],
					  &ip_part[1],
					  &ip_part[0],
					  &agt.agent_proto,
					  &agt.reg_exp_time,
					  agt.registrar,
					  agt.proxy);

	if ((int)fct_ret < 7) {
		return cli_check_help__file("-h", USAGE, out);
	}

	agt.agent_ip = ip_part[3] << 24 | ip_part[2] << 16 | ip_part[1] << 8 |
		ip_part[0];

	fct_ret = (enum omci_error)omci_api_voip_agent_cfg_set(omci_api_ctx_get(context),
							       &agt);

	ret += IFXOS_FPrintf(out, "errorcode=%d " IFXOS_CRLF, fct_ret);
	return ret;
}
#endif

#ifdef INCLUDE_OMCI_ONU_VOIP
static int cli_omci_sip_agent_update(void *p_ctx,
				     const char *cmd,
				     clios_file_t *out)
{
	int ret = 0;
	struct omci_context *context = (struct omci_context*)p_ctx;
	enum omci_error fct_ret = OMCI_SUCCESS;

#ifndef OMCI_DEBUG_DISABLE
	static const char USAGE[] =
	    "Long Form: sip_agent_update" IFXOS_CRLF
	    "Short Form: sipau" IFXOS_CRLF
	    IFXOS_CRLF
	    "Output Parameter" IFXOS_CRLF
	    "- enum omci_error errorcode" IFXOS_CRLF
	    IFXOS_CRLF;
#else
#undef USAGE
#define USAGE ""
#endif

	if ((ret = cli_check_help__file(cmd, USAGE, out)) > 0) {
		return ret;
	}

	fct_ret = (enum omci_error)omci_api_voip_agent_update(omci_api_ctx_get(context));

	ret += IFXOS_FPrintf(out, "errorcode=%d " IFXOS_CRLF, fct_ret);
	return ret;
}
#endif

#ifdef INCLUDE_OMCI_ONU_VOIP
static int cli_omci_sip_user_cfg_get(void *p_ctx,
				     const char *cmd,
				     clios_file_t *out)
{
	int ret = 0;
	struct omci_context *context = (struct omci_context*)p_ctx;
	enum omci_error fct_ret = OMCI_SUCCESS;
	struct sip_user usr;
	uint8_t user_id;

#ifndef OMCI_DEBUG_DISABLE
	static const char USAGE[] =
	    "Long Form: sip_user_cfg_get" IFXOS_CRLF
	    "Short Form: sipucg" IFXOS_CRLF
	    IFXOS_CRLF
	    "Input Parameter" IFXOS_CRLF
	    "- uint8_t id" IFXOS_CRLF
	    "Output Parameter" IFXOS_CRLF
	    "- enum omci_error errorcode" IFXOS_CRLF
	    "- char username[" _MKSTR(OMCI_API_USERNAME_MAX) "]" IFXOS_CRLF
	    "- char password[25]" IFXOS_CRLF
	    "- char realm[25]" IFXOS_CRLF
	    "- uint16_t user_port" IFXOS_CRLF
	    "- char user_ip[16]" IFXOS_CRLF
	    "- uint8_t media_channel" IFXOS_CRLF
	    "- enum voip_codec media_codec" IFXOS_CRLF
	    IFXOS_CRLF;
#else
#undef USAGE
#define USAGE ""
#endif

	if ((ret = cli_check_help__file(cmd, USAGE, out)) > 0) {
		return ret;
	}

	fct_ret = (enum omci_error)sscanf(cmd, "%hhu", &user_id);
	if ((int)fct_ret != 1) {
		return cli_check_help__file("-h", USAGE, out);
	}

	fct_ret = (enum omci_error)omci_api_voip_user_cfg_get(omci_api_ctx_get(context),
							      user_id,
							      &usr);

	ret += IFXOS_FPrintf(out, "errorcode=%d "
			     "username=%s "
			     "password=%s "
			     "realm=%s "
			     "user_port=%hu "
			     "user_ip=%s "
			     "media_channel=%hhu "
			     "media_codec=%u"
			     IFXOS_CRLF,
			     fct_ret,
			     usr.username,
			     usr.password,
			     usr.realm,
			     usr.user_port,
			     usr.user_ip_s,
			     usr.media_channel,
			     usr.media_codec);
	return ret;
}
#endif

#ifdef INCLUDE_OMCI_ONU_VOIP
static int cli_omci_sip_user_cfg_set(void *p_ctx,
				     const char *cmd,
				     clios_file_t *out)
{
	int ret = 0;
	struct omci_context *context = (struct omci_context*)p_ctx;
	enum omci_error fct_ret = OMCI_SUCCESS;
	struct sip_user usr;
	uint8_t user_id;
	unsigned char ip_part[4];

#ifndef OMCI_DEBUG_DISABLE
	static const char USAGE[] =
	    "Long Form: sip_user_cfg_set" IFXOS_CRLF
	    "Short Form: sipucs" IFXOS_CRLF
	    IFXOS_CRLF
	    "Input Parameter" IFXOS_CRLF
	    "- uint8_t id" IFXOS_CRLF
	    "- char username[" _MKSTR(OMCI_API_USERNAME_MAX) "]" IFXOS_CRLF
	    "- char password[25] (use \"-\" to set empty)" IFXOS_CRLF
	    "- char realm[25] (use \"-\" to set empty, no auth; use \"*\" to "
				"authenticate against any challenges)" IFXOS_CRLF
	    "- uint16_t user_port" IFXOS_CRLF
	    "- char user_ip[16]" IFXOS_CRLF
	    "- uint8_t media_channel" IFXOS_CRLF
	    "- enum voip_codec media_codec" IFXOS_CRLF
	    "Output Parameter" IFXOS_CRLF
	    "- enum omci_error errorcode" IFXOS_CRLF
	    IFXOS_CRLF;
#else
#undef USAGE
#define USAGE ""
#endif

	if ((ret = cli_check_help__file(cmd, USAGE, out)) > 0) {
		return ret;
	}

	fct_ret = (enum omci_error)sscanf(cmd, "%hhu %s %s %s %hu "
					  "%hhu.%hhu.%hhu.%hhu "
					  "%hhu %u"
					  IFXOS_CRLF,
					  &user_id,
					  usr.username,
					  usr.password,
					  usr.realm,
					  &usr.user_port,
					  &ip_part[3],
					  &ip_part[2],
					  &ip_part[1],
					  &ip_part[0],
					  &usr.media_channel,
					  (unsigned int *)&usr.media_codec);

	if ((int)fct_ret != 11) {
		return cli_check_help__file("-h", USAGE, out);
	}

	usr.user_ip = ip_part[3] << 24 | ip_part[2] << 16 | ip_part[1] << 8 |
		ip_part[0];

	if (strlen(usr.password) == 1 && usr.password[0] == '-')
		usr.password[0] = '\0';

	if (strlen(usr.realm) == 1 && usr.realm[0] == '-')
		usr.realm[0] = '\0';

	fct_ret = (enum omci_error)omci_api_voip_user_cfg_set(omci_api_ctx_get(context),
							      user_id,
							      &usr);

	ret += IFXOS_FPrintf(out, "errorcode=%d" IFXOS_CRLF, fct_ret);
	return ret;
}
#endif

#ifdef INCLUDE_OMCI_ONU_VOIP
static int cli_omci_sip_user_register(void *p_ctx,
				      const char *cmd,
				      clios_file_t *out)
{
	int ret = 0;
	struct omci_context *context = (struct omci_context*)p_ctx;
	enum omci_error fct_ret = OMCI_SUCCESS;
	uint8_t user_id;

#ifndef OMCI_DEBUG_DISABLE
	static const char USAGE[] =
	    "Long Form: sip_user_register" IFXOS_CRLF
	    "Short Form: sipur" IFXOS_CRLF
	    IFXOS_CRLF
	    "Input Parameter" IFXOS_CRLF
	    "- uint8_t user_id" IFXOS_CRLF
	    "Output Parameter" IFXOS_CRLF
	    "- enum omci_error errorcode" IFXOS_CRLF
	    IFXOS_CRLF;
#else
#undef USAGE
#define USAGE ""
#endif

	if ((ret = cli_check_help__file(cmd, USAGE, out)) > 0) {
		return ret;
	}

	fct_ret = (enum omci_error)sscanf(cmd, "%hhu" IFXOS_CRLF, &user_id);

	if ((int)fct_ret != 1) {
		return cli_check_help__file("-h", USAGE, out);
	}

	fct_ret = (enum omci_error)omci_api_voip_user_register(omci_api_ctx_get(context),
							       user_id);

	ret += IFXOS_FPrintf(out, "errorcode=%d" IFXOS_CRLF, fct_ret);
	return ret;
}
#endif

static int cli_ac_power_on(void *p_ctx,
			   const char *cmd,
			   clios_file_t *out)
{
	int ret = 0;
	struct omci_context *context = (struct omci_context*)p_ctx;
	enum omci_error fct_ret = OMCI_SUCCESS;

#ifndef OMCI_DEBUG_DISABLE
	static const char USAGE[] =
	    "Long Form: ac_power_on" IFXOS_CRLF
	    "Short Form: acon" IFXOS_CRLF
	    IFXOS_CRLF
	    "Output Parameter" IFXOS_CRLF
	    "- enum omci_error errorcode" IFXOS_CRLF
	    IFXOS_CRLF;
#else
#undef USAGE
#define USAGE ""
#endif

	if ((ret = cli_check_help__file(cmd, USAGE, out)) > 0)
		return ret;

	ac_power_on_cb(context);

	ret += IFXOS_FPrintf(out, "errorcode=%d" IFXOS_CRLF, fct_ret);
	return ret;
}

static int cli_ac_power_off(void *p_ctx,
			    const char *cmd,
			    clios_file_t *out)
{
	int ret = 0;
	struct omci_context *context = (struct omci_context*)p_ctx;
	enum omci_error fct_ret = OMCI_SUCCESS;

#ifndef OMCI_DEBUG_DISABLE
	static const char USAGE[] =
	    "Long Form: ac_power_off" IFXOS_CRLF
	    "Short Form: acoff" IFXOS_CRLF
	    IFXOS_CRLF
	    "Output Parameter" IFXOS_CRLF
	    "- enum omci_error errorcode" IFXOS_CRLF
	    IFXOS_CRLF;
#else
#undef USAGE
#define USAGE ""
#endif

	if ((ret = cli_check_help__file(cmd, USAGE, out)) > 0)
		return ret;

	ac_power_off_cb(context);

	ret += IFXOS_FPrintf(out, "errorcode=%d" IFXOS_CRLF, fct_ret);
	return ret;
}

/**
   Register the CLI commands.
*/
int cli_access_commands_register(struct cli_core_context_s *p_core_ctx)
{
	unsigned int group_mask = 0;

#ifndef OMCI_DEBUG_DISABLE
	(void)cli_core_key_add__file(p_core_ctx, group_mask,
					"dlg", "dbg_level_get",
					cli_omci_debug_level_get);
	(void)cli_core_key_add__file(p_core_ctx, group_mask,
					"rmr", "raw_message_recv",
					cli_omci_message_receive);
	(void)cli_core_key_add__file(p_core_ctx, group_mask,
					"almd", "al_mapper_dump",
					cli_omci_mapper_dump);
#endif

#ifdef INCLUDE_OMCI_ONU_VOIP
	(void)cli_core_key_add__file(p_core_ctx, group_mask,
					"sipc", "sip_call",
					cli_omci_sip_call);
	(void)cli_core_key_add__file(p_core_ctx, group_mask,
					"sipa", "sip_answer",
					cli_omci_sip_answer);
	(void)cli_core_key_add__file(p_core_ctx, group_mask,
					"siph", "sip_hangup",
					cli_omci_sip_hangup);
	(void)cli_core_key_add__file(p_core_ctx, group_mask,
					"sipacg", "sip_agent_cfg_get",
					cli_omci_sip_agent_cfg_get);
	(void)cli_core_key_add__file(p_core_ctx, group_mask,
					"sipacs", "sip_agent_cfg_set",
					cli_omci_sip_agent_cfg_set);
	(void)cli_core_key_add__file(p_core_ctx, group_mask,
					"sipau", "sip_agent_update",
					cli_omci_sip_agent_update);
	(void)cli_core_key_add__file(p_core_ctx, group_mask,
					"sipucg", "sip_user_cfg_get",
					cli_omci_sip_user_cfg_get);
	(void)cli_core_key_add__file(p_core_ctx, group_mask,
					"sipucs", "sip_user_cfg_set",
					cli_omci_sip_user_cfg_set);
	(void)cli_core_key_add__file(p_core_ctx, group_mask,
					"sipur", "sip_user_register",
					cli_omci_sip_user_register);
#endif
	(void)cli_core_key_add__file(p_core_ctx, group_mask,
					"rms", "raw_message_send",
					cli_omci_message_send);
	(void)cli_core_key_add__file(p_core_ctx, group_mask,
					"md", "mib_dump",
					cli_omci_mib_dump);
	(void)cli_core_key_add__file(p_core_ctx, group_mask,
					"mda", "mib_dump_all",
					cli_omci_mib_dump_all);
	(void)cli_core_key_add__file(p_core_ctx, group_mask,
					"cda", "class_dump_all",
					cli_omci_class_dump_all);
	(void)cli_core_key_add__file(p_core_ctx, group_mask,
					"mdx", "mib_dump_xml",
					cli_omci_mib_dump_xml);
	(void)cli_core_key_add__file(p_core_ctx, group_mask,
					"cdx", "class_dump_xml",
					cli_omci_class_dump_xml);
	(void)cli_core_key_add__file(p_core_ctx, group_mask,
					"meg", "managed_entity_get",
					cli_omci_managed_entity_get);
	(void)cli_core_key_add__file(p_core_ctx, group_mask,
					"cg", "class_get",
					cli_omci_class_get);
	(void)cli_core_key_add__file(p_core_ctx, group_mask,
					"acon", "ac_power_on",
					cli_ac_power_on);
	(void)cli_core_key_add__file(p_core_ctx, group_mask,
					"acoff", "ac_power_off",
					cli_ac_power_off);
	return 0;
}

/** @} */

/** @} */

#endif
