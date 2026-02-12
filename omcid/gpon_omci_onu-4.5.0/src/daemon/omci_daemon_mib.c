/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \addtogroup OMCI_DAEMON
   @{
*/

#include "ifxos_std_defs.h"
#include "ifxos_file_access.h"
#include "ifxos_print_io.h"

#include <memory.h>
#include "daemon/omci_daemon.h"

#ifdef WIN32
static char mib_default_path[] = "mib.ini";
#else
static char mib_default_path[] = "/etc/mib.ini";
#endif

static char *token_next(char *s)
{
	static char *begin = NULL, *end = NULL, *real_end;
	char closing_char = ' ';
	char *p;

	if (s) {
		begin = s;
		real_end = begin + strlen(s) - 1;
	} else
		begin = end + 1;

	if (begin > real_end)
		return NULL;

	/* eat spaces */
	while (*begin && *begin == ' ')
		begin++;

	/* handle quotes */
	if (*begin == '\'' || *begin == '"') {
		closing_char = *begin;
		begin++;
	}

	p = begin;

	while (*p) {
		if (*p == closing_char || *(p + 1) == 0) {
			if (*p == closing_char)
				*p = 0;

			if (*(p + 1) == 0) {
				p++;
				*p = 0;
			}

			end = p;

			break;
		}

		p++;
	}

	return begin;
}

static unsigned int token_parse_escape(char *p)
{
	char tmp[] = "0xXX";

	tmp[2] = *p;
	tmp[3] = *(p + 1);

	return (unsigned int)strtoul(tmp, NULL, 16);
}

static int token_parse(char *token, unsigned int size)
{
	char tmp[255];
	unsigned int tmp_pos = 0;
	char *p = token;

	while (*p) {

		if (tmp_pos >= sizeof(tmp))
			return -1;

		if (tmp_pos + 1 > size)
			return -1;

		if (*p == '\\') {

			if (!*(p + 1))
				break;

			if (*(p + 1) == '0') {
				tmp[tmp_pos] = '\0';
				p++;
			} else if (*(p + 1) == 's') {
				tmp[tmp_pos] = ' ';
				p++;
			} else if (*(p + 1) == 'x') {
				if (!*(p + 2) || !*(p + 3))
					break;

				tmp[tmp_pos] = (char)token_parse_escape(p + 2);

				p += 3;
			} else {
				return -1;
			}
		} else {
			tmp[tmp_pos] = *p;
		}

		tmp_pos++;

		p++;
	}

	if (tmp_pos >= sizeof(tmp))
		return -1;

	if (tmp_pos + 1 > size)
		return -1;

	tmp[tmp_pos] = 0;

	memcpy(token, tmp, tmp_pos + 1);

	return 0;
}

enum omci_error mib_on_reset(struct omci_context *context)
{
	enum omci_error error = OMCI_SUCCESS;
	enum omci_olt olt;
	char olt_str[32];
	char buff[1024];
	char *buff_tok;
	uint16_t instance_id, class_id;
	unsigned int attr;
	char data[OMCI_ME_DATA_SIZE_MAX];
	bool use_section = false;
	unsigned int line = 0;
	unsigned int len;
	bool active;
	uint16_t tmp16;
	uint32_t tmp32;

	size_t attr_size, attr_offset;
	enum omci_attr_type attr_format;

	char *p;
	FILE *f;

	error = omci_olt_get(context, &olt);
	if (error) {
		omci_printfe(OMCID "Can't get OLT type\n");
		return error;
	}

	sprintf(olt_str, "%u", olt);

	omci_printf( OMCID "Reading MIB configuration from '%s'...\n",
		      (omci_config.mib_config_path ?
				omci_config.mib_config_path :
				mib_default_path));

	f = omci_fopen((omci_config.mib_config_path ?
				omci_config.mib_config_path : mib_default_path),
			"r");
	if (!f) {
		omci_printfe(OMCID "Can't open config file\n");
		return OMCI_ERROR;
	}

	while (omci_fgets(buff, sizeof(buff), f)) {
		line++;

		/* remove comments */
		p = buff;
		while (*p) {
			if (*p == '#') {
				*p = 0;
				break;
			}

			p++;
		}

		len = strlen(buff);
		/* pass empty lines */
		if (len <= 1)
			continue;

		/* remove trailing \n */
		if (len > 0) {
			if (buff[len - 1] == '\n')
				buff[len - 1] = 0;
		}

		/* remove trailing \r */
		if (len > 1) {
			if (buff[len - 2] == '\r')
				buff[len - 2] = 0;
		}

		/* parse section header */
		if (buff[0] == '[') {
			use_section = false;

			p = &buff[1];
			while (*p) {
				if (*p == ']') {
					*p = 0;
					break;
				}
				p++;
			}

			for (p = strtok_r(buff + 1, " ", &buff_tok); p;
			     p = strtok_r(NULL, " ", &buff_tok)) {
				if (strcmp("common", p) == 0
				    || strcmp(olt_str, p) == 0) {
					use_section = true;
				}
			}

			continue;
		}

		if (!use_section)
			continue;

		/* parse section entities */
		p = token_next(buff);
		if (!p)
			continue;
		active = true;
		if (*p == '*') {
			/* don't use the ME implementation, fake for the OLT */
			active = false;
			p = token_next(NULL);
			if (!p)
				continue;
		}
		class_id = (uint16_t)strtol(p, NULL, 0);

		p = token_next(NULL);
		if (!p)
			continue;
		instance_id = (uint16_t)strtoul(p, NULL, 0);

		if (class_id == 0 && instance_id == 0)
			continue;

		if (!active)
			omci_printfe(OMCID "Managed Entity isn't active: "
			      "class_id=%u instance_id=%u (line %d)\n",
						   class_id, instance_id, line);

		error = omci_me_is_supported(context, class_id);
		if (error == OMCI_ERROR_ME_NOT_SUPPORTED) {
			omci_printfe(OMCID "Pass non-supported Managed Entity"
					   " with id=%u (line %d)\n", class_id,
								      line);
			continue;
		}

		memset(&data[0], 0x00, sizeof(data));

		for (attr = 1, p = token_next(NULL);
		     attr <= OMCI_ATTRIBUTES_NUM && p;
		     attr++, p = token_next(NULL)) {

			/* get attribute information */
			error = omci_me_attr_size_get(context, class_id,
							  attr, &attr_size);
			if (error) {
				omci_printfe(OMCID "Can't get attribute #%u"
						   " size of %u@%u (line %d)\n",
							attr, class_id,
							instance_id, line);
				omci_printfe(OMCID "Parameter not yet defined"
						   " in omcid\n");
				break;
			}

			error = omci_me_attr_offset_get(context, class_id,
							    attr, &attr_offset);
			if (error) {
				omci_printfe(OMCID "Can't get attribute #%u"
						 " offset of %u@%u (line %d)\n",
							attr, class_id,
							instance_id, line);
				goto RESET_ERROR;
			}

			error = omci_me_attr_type_get(context, class_id,
							  attr, &attr_format);
			if (error) {
				omci_printfe(OMCID "Can't get attribute #%u"
						 " format of %u@%u (line %d)\n",
							attr, class_id,
							instance_id, line);

				goto RESET_ERROR;
			}

			/* parse escape sequences */
			if (token_parse(p, sizeof(buff))) {
				omci_printfe(OMCID "Can't parse token '%s' on"
						   " line %u\n", p, line);
				error = OMCI_ERROR;
				goto RESET_ERROR;
			}

			/* set attribute data */
			switch (attr_format) {
			case OMCI_ATTR_TYPE_PTR:
			case OMCI_ATTR_TYPE_BF:
			case OMCI_ATTR_TYPE_INT:
			case OMCI_ATTR_TYPE_UINT:
			case OMCI_ATTR_TYPE_ENUM:
				switch (attr_size) {
				case 1:
					*(uint8_t *)(data + attr_offset) =
					    (uint8_t)strtoul(p, NULL, 0);
					break;

				case 2:
					tmp16 = (uint16_t)strtoul(p, NULL, 0);
					memcpy(data + attr_offset, &tmp16, 2);
					break;

				case 4:
					tmp32 = (uint32_t)strtoul(p, NULL, 0);
					memcpy(data + attr_offset, &tmp32, 4);
					break;

				default:
					omci_printfe(OMCID
						"Invalid Managed Entity %u@%u"
						"attribute #%u size = %u\n ",
						      class_id, instance_id,
						      attr, attr_size);
					error = OMCI_ERROR;
					goto RESET_ERROR;
				}

				break;

			case OMCI_ATTR_TYPE_STR:
	       /** \todo check for overflow */
#if 0
				if (strlen(p) < attr_size)
					attr_size = strlen(p);
#endif
				memcpy(data + attr_offset, p, attr_size);
				break;

			case OMCI_ATTR_TYPE_TBL:
				omci_printfe(OMCID "Managed Entities with table" 
						   "attribute could not be "
						   "created!\n");
				error = OMCI_ERROR;
				goto RESET_ERROR;

			case OMCI_ATTR_TYPE_UNKNOWN:
				omci_printfe(OMCID "Unknow ME attribute!\n");
				error = OMCI_ERROR;
				goto RESET_ERROR;
			}
		}

		error = omci_me_create(context, active, class_id, instance_id,
				       data, 0xffff);

		if (error) {
			omci_printfe(OMCID "Managed Entity %u@%u creation "
					   "error %d\n", class_id, instance_id,
							 error);
			goto RESET_ERROR;
		}
	}

RESET_ERROR:
	omci_fclose(f);

	return OMCI_SUCCESS;
}

enum omci_error mib_line_parse(struct omci_context *context,
			       unsigned int line, char *buff)
{
	enum omci_error error = OMCI_SUCCESS;
	uint16_t class_id, instance_id;
	unsigned int attr;
	char data[OMCI_ME_DATA_SIZE_MAX];
	size_t attr_size, attr_offset;
	enum omci_attr_type attr_format;
	uint16_t tmp16;
	uint32_t tmp32;
	bool active = true;
	char *p;

	p = token_next(buff);
	if (!p)
		return OMCI_ERROR;

	if (*p == '*') {
		active = false;
		p = token_next(NULL);
		if (!p)
			return OMCI_ERROR;
	}
	class_id = (uint16_t)strtol(p, NULL, 0);

	p = token_next(NULL);
	if (!p)
		return OMCI_ERROR;
	instance_id = (uint16_t)strtoul(p, NULL, 0);

	if (class_id == 0 && instance_id == 0)
		return OMCI_ERROR;

	error = omci_me_is_supported(context, class_id);
	if (error)
		return error;

	memset(&data[0], 0x00, sizeof(data));

	for (attr = 1, p = token_next(NULL);
	     attr <= OMCI_ATTRIBUTES_NUM && p;
	     attr++, p = token_next(NULL)) {

		error = omci_me_attr_size_get(context, class_id,
					      attr, &attr_size);
		if (error)
			return error;

		error = omci_me_attr_offset_get(context, class_id,
						attr, &attr_offset);
		if (error)
			return error;

		error = omci_me_attr_type_get(context, class_id,
					      attr, &attr_format);
		if (error)
			return error;

		if (token_parse(p, strlen(buff) + (p - buff)))
			return OMCI_ERROR;

		switch (attr_format) {
		case OMCI_ATTR_TYPE_PTR:
		case OMCI_ATTR_TYPE_BF:
		case OMCI_ATTR_TYPE_INT:
		case OMCI_ATTR_TYPE_UINT:
		case OMCI_ATTR_TYPE_ENUM:
			switch (attr_size) {
			case 1:
				*(uint8_t *)(data + attr_offset) =
				    (uint8_t)strtoul(p, NULL, 0);
				break;
			case 2:
				tmp16 = (uint16_t)strtoul(p, NULL, 0);
				memcpy(data + attr_offset, &tmp16, 2);
				break;
			case 4:
				tmp32 = (uint32_t)strtoul(p, NULL, 0);
				memcpy(data + attr_offset, &tmp32, 4);
				break;
			default:
				return OMCI_ERROR;
			}
			break;

		case OMCI_ATTR_TYPE_STR:
			memcpy(data + attr_offset, p, attr_size);
			break;

		case OMCI_ATTR_TYPE_TBL:
		case OMCI_ATTR_TYPE_UNKNOWN:
			return OMCI_ERROR;
		}
	}

	return omci_me_create(context, active, class_id, instance_id,
			      data, 0xffff);
}

/** @} */
