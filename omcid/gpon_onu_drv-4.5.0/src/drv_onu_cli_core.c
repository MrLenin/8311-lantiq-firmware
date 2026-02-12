/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   Device Driver, Command Line Interface - Core Implementation
*/
#ifdef HAVE_CONFIG_H
#include "drv_onu_config.h"
#endif

#ifdef INCLUDE_CLI_SUPPORT

#ifdef ONU_SIMULATION
#  include <stdlib.h>		/* strtol */
#  include <stdarg.h>		/* va_start */
#  include <string.h>		/* strcpy */
#endif

#define PRE_GPE_INIT_CMD(c) #c

#include "drv_onu_api.h"
#include "ifxos_memory_alloc.h"
#include "drv_onu_event_interface.h"
#include "drv_onu_cli_core.h"

#define CLI_WARNING_TABLE_ENTRY_NOT_VALID (-2)
#define CLI_WARNING_TABLE_ENTRY_NOT_FOUND (-3)

#if defined(LINUX) && defined(__KERNEL__)
long onu_strtol(const char *cp, char **endp, unsigned int base)
{
	if (cp && cp[0] != 0 && cp[1] != 0 && cp[0] == '0' && cp[1] == 'x')
		base = 16;

	return simple_strtol(cp, endp, base);
}

long long onu_strtoll(const char *cp, char **endp, unsigned int base)
{
	long long res;

	if (cp && cp[0] != 0 && cp[1] != 0 && cp[0] == '0' && cp[1] == 'x')
		base = 16;
	strict_strtoll(cp, base, &res);
	return res;
}

unsigned long onu_strtoul(const char *cp, char **endp, unsigned int base)
{
	if (cp && cp[0] != 0 && cp[1] != 0 && cp[0] == '0' && cp[1] == 'x')
		base = 16;

	return simple_strtoul(cp, endp, base);
}

unsigned long long onu_strtoull(const char *cp, char **endp, unsigned int base)
{
	if (cp && cp[0] != 0 && cp[1] != 0 && cp[0] == '0' && cp[1] == 'x')
		base = 16;

	return simple_strtoull(cp, endp, base);
}
#endif

STATIC int32_t onu_cli_isspace(char c);
STATIC char *onu_cli_remove_whitespaces(char *str);
STATIC char *onu_cli_remove_prefix(char *str, char *prefix, int8_t length);
int onu_cli_check_help(const char *p_cmd, const char *p_usage,
		       const uint32_t bufsize_max, char *p_out);

/** 'less then' definition for binary tree, (a < b)*/
#define compLT(a,b) (strcmp(a,b) < 0)
/** 'equal' definition for binary tree, (a == b)*/
#define compEQ(a,b) (strcmp(a,b) == 0)
/** device mask */
#define CLI_MASK_DEVICE     0x0001
/** detailed information (-h) */
#define CLI_MASK_DETAILED   0x8000
/** long form of the command */
#define CLI_MASK_LONG       0x4000
/** short form of the command */
#define CLI_MASK_SHORT      0x2000

/** implementation dependend declarations */
enum cli_status {
	CLI_STATUS_OK,
	CLI_STATUS_MEM_EXHAUSTED,
	CLI_STATUS_DUPLICATE_KEY,
	CLI_STATUS_KEY_NOT_FOUND,
	CLI_STATUS_KEY_INVALID
};

/* states of the cli register process */
enum cli_register_state {
	CLI_COUNT,
	CLI_ALLOCATE,
	CLI_ACTIVE,
	CLI_DELETE
};


/** user data stored in tree */
struct cli_rec_type {
	char const *help;
	uint32_t mask;
	onu_cli_entry_t func;
};

struct cli_node_tag {
	/** left child */
	struct cli_node_tag *left;
	/** right child */
	struct cli_node_tag *right;
	/** parent */
	struct cli_node_tag *parent;
	/** key used for searching */
	char const *key;
	/** user data */
	struct cli_rec_type rec;
};

STATIC enum cli_status onu_cli_key_insert(char const *key,
					  struct cli_rec_type *rec);
STATIC enum cli_status onu_cli_key_find(char const *key,
					struct cli_rec_type *rec);
STATIC uint32_t onu_cli_tree_print(struct onu_device *p_dev,
				   const struct cli_node_tag *node,
				   const uint32_t mask);

/** root of binary tree */
STATIC struct cli_node_tag *onu_cli_root = NULL;

/* state of the cli register process */
STATIC enum cli_register_state onu_cli_register_mode = 0;
STATIC uint16_t onu_cli_nodes_number = 0;
STATIC uint16_t onu_cli_nodes_used = 0;
STATIC struct cli_node_tag *onu_cli_node_array = NULL;

/**
   allocate node for data and insert in tree
*/
STATIC enum cli_status onu_cli_key_insert(char const *key,
					  struct cli_rec_type *rec)
{
	struct cli_node_tag *x, *curr, *parent;

	if (key == NULL)
		return CLI_STATUS_KEY_INVALID;

	/* find future parent */
	curr = onu_cli_root;
	parent = NULL;
	while (curr) {
		if (compEQ(key, curr->key))
			return CLI_STATUS_DUPLICATE_KEY;
		parent = curr;
		curr = compLT(key, curr->key) ? curr->left : curr->right;
	}

	/* setup new node */
	if ((onu_cli_node_array != NULL) &&
	    (onu_cli_nodes_used < onu_cli_nodes_number) &&
	    (onu_cli_register_mode == CLI_ALLOCATE)) {
		x = (onu_cli_node_array + onu_cli_nodes_used);
		onu_cli_nodes_used++;
	} else {
		return CLI_STATUS_MEM_EXHAUSTED;
	}
	x->parent = parent;
	x->left = NULL;
	x->right = NULL;
	x->key = key;
	memcpy((void *)&x->rec, (void *)rec, sizeof(struct cli_rec_type));

	/* insert x in tree */
	if (parent)
		if (compLT(x->key, parent->key))
			parent->left = x;
		else
			parent->right = x;
	else
		onu_cli_root = x;

	return CLI_STATUS_OK;
}

/**
   find node containing data
*/
STATIC enum cli_status onu_cli_key_find(char const *key,
					struct cli_rec_type *rec)
{
	struct cli_node_tag *curr = onu_cli_root;

	while (curr != NULL) {
		if (compEQ(key, curr->key)) {
			memcpy((void *)rec, (void *)&curr->rec,
			       sizeof(struct cli_rec_type));
			return CLI_STATUS_OK;
		} else {
			curr =
			    compLT(key, curr->key) ? curr->left : curr->right;
		}
	}
	return CLI_STATUS_KEY_NOT_FOUND;
}

/**
   print binary tree
*/
STATIC uint32_t onu_cli_tree_print(struct onu_device *p_dev,
				   const struct cli_node_tag *node,
				   const uint32_t mask)
{
	int32_t j = 0, ret;
	int32_t nFillChar = 0;
	int32_t nHelpClm = 10;

	if (node == NULL)
		return 0;

	onu_cli_tree_print(p_dev, node->left, mask);

	if ((p_dev->help_out_len + 64) >= p_dev->help_max_len)
		return 0;

	if ((node->rec.mask & mask)
	    && ((node->rec.mask & CLI_MASK_LONG) == (mask & CLI_MASK_LONG))) {
		if ((mask & CLI_MASK_DETAILED) == CLI_MASK_DETAILED) {
			if (node->rec.func) {
				ret =
				    node->rec.func(p_dev, "-h",
						   p_dev->help_max_len -
						   p_dev->help_out_len,
						   p_dev->help_out);
				if (ret < 0)
					ret = 0;
				p_dev->help_out_len += ret;
				p_dev->help_out += ret;
			}
		} else {
			if (strcmp(node->rec.help, CLI_EMPTY_CMD) == 0) {
				ret = sprintf(p_dev->help_out,
					      CLI_EMPTY_CMD_HELP);
			} else {
				ret = sprintf(p_dev->help_out, "%s",
					      node->rec.help);
			}
			if (ret < 0)
				ret = 0;
			p_dev->help_out_len += ret;
			p_dev->help_out += ret;
			nFillChar = nHelpClm - ret;
			if (nFillChar > 0) {
				for (j = 0; j < nFillChar; j++) {
					ret = sprintf(p_dev->help_out, " ");
					if (ret < 0)
						ret = 0;
					p_dev->help_out_len += ret;
					p_dev->help_out += ret;
				}
			}
			ret = sprintf(p_dev->help_out, "%s" ONU_CRLF, node->key);
			if (ret < 0)
				ret = 0;
			p_dev->help_out_len += ret;
			p_dev->help_out += ret;
		}
	}

	return onu_cli_tree_print(p_dev, node->right, mask);
}

/** Handle command

   \param[in] p_dev      Device Context Pointer
   \param[in] commands Input commands
   \param[in] out      Output FD
*/
STATIC int onu_cli_help(struct onu_device *p_dev,
			const char *commands,
			const uint32_t max_buf_size, char *out)
{
	int ret = 0;
	uint32_t mask = CLI_MASK_DEVICE | CLI_MASK_LONG;

	/*enum onu_errorcode fct_ret = (enum onu_errorcode) 0; */

#ifndef ONU_DEBUG_DISABLE
	static const char USAGE[] =
	    "Long Form: Help" ONU_CRLF "Short Form: help" ONU_CRLF
	    ONU_CRLF
	    "Input Parameter" ONU_CRLF
	    ONU_CRLF
	    "Output Parameter" ONU_CRLF
	    "- enum onu_errorcode errorcode" ONU_CRLF ONU_CRLF;
#else
#undef USAGE
#define USAGE ""
#endif

	if ((ret = onu_cli_check_help(commands, USAGE, max_buf_size, out)) >= 0)
		return ret;

	if (strlen(commands)) {
		if (strcmp(commands, "detailed") == 0)
			mask |= CLI_MASK_DETAILED;
		else
			return sprintf(out, "errorcode=-1 (unknown sub command)"
					    ONU_CRLF);
	}

	p_dev->help_out = out;
	p_dev->help_out_len = 0;
	p_dev->help_max_len = max_buf_size;

	onu_cli_tree_print(p_dev, onu_cli_root, mask);
	out[p_dev->help_out_len] = 0;
	return p_dev->help_out_len + 1;
}

/**
   For a detailed description of the function, its arguments and return value
   please refer to the description in the header file 'drv_onu_cli_core.h'
*/
int onu_cli_init(void)
{
	if (onu_cli_node_array != NULL) {
		ONU_DEBUG_WRN("CLI_Init already done.");
		return -1;
	}

	onu_cli_nodes_used = 0;
	/* count necessary number of nodes */
	onu_cli_nodes_number = 0;
	onu_cli_register_mode = CLI_COUNT;
	onu_cli_command_add("help", "Help", onu_cli_help);
	onu_cli_misc_register();
	onu_cli_autogen_register();

	if (onu_cli_nodes_number == 0) {
		ONU_DEBUG_ERR("command list empty");
		return -1;
	}

	ONU_DEBUG_MSG("allocate memory for %d nodes", onu_cli_nodes_number);

	onu_cli_node_array =
	    IFXOS_MemAlloc(onu_cli_nodes_number * sizeof(struct cli_node_tag));
	if (onu_cli_node_array == NULL) {
		ONU_DEBUG_ERR("memory allocation error");
		return -1;
	}
	memset(onu_cli_node_array, 0,
	       onu_cli_nodes_number * sizeof(struct cli_node_tag));

	onu_cli_register_mode = CLI_ALLOCATE;
	onu_cli_command_add("help", "Help", onu_cli_help);
	onu_cli_misc_register();
	onu_cli_autogen_register();
	onu_cli_register_mode = CLI_ACTIVE;

	ONU_DEBUG_MSG("%d commands registered", onu_cli_nodes_used);

	return 0;
}

/**
   Detect spaces.
*/
STATIC int32_t onu_cli_isspace(char c)
{
	if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
		return 1;
	return 0;
}

/**
   Remove leading, tailing and double whitespaces
   Arguments has to have only one space in between to get sure that the CLI
   comments are working correctly.
*/
STATIC char *onu_cli_remove_whitespaces(char *str)
{
	char *buf;
	char *rd, *wr;
	int32_t i = 0;

	/* remove leading whitespaces */
	for (buf = str; buf && *buf && onu_cli_isspace(*buf); ++buf) {
		;
	}

	/* remove double spaces in between and at the end */
	rd = buf;
	wr = buf;
	for (i = 0; wr && rd && *rd != '\0'; ++rd) {
		if (onu_cli_isspace(*rd)) {
			if ((i == 0) && (*(rd + 1) != '\0')) {
				*wr = *rd;
				wr++;
				i++;
			}
		} else {
			i = 0;
			*wr = *rd;
			wr++;
		}
	}

	/* Write string termination */
	if (wr && (wr != rd))
		*wr = '\0';

	return buf;
}

/**
   Remove leading, tailing and double whitespaces
   Arguments has to have only one space in between to get sure that the CLI
   comments are working correctly.
*/
STATIC char *onu_cli_remove_prefix(char *str, char *prefix, int8_t length)
{
	char *buf;
	char *rd, *wr;
	int32_t i = 0;
	uint8_t l = 0;

	buf = str;

	/* remove prefix at front */
	for (rd = buf, wr = buf; wr && rd && *rd != '\0';
	     ++rd) {
		if (l < length) {
			/* prefix check */
			if (*rd == prefix[l]) {
				l++;
			} else {
				for (i = 0; i < l; i++) {
					*wr = prefix[i];
					wr++;
				}
				l = length;

				*wr = *rd;
				wr++;
			}
		} else {
			*wr = *rd;
			wr++;
		}
	}

	/* Write string termination */
	if (wr && (wr != rd))
		*wr = '\0';

	return buf;
}

/**
   Check whether given CLI command (with full or short name passed via `cmd`,
   and handler passed via `f`) is allowed to be executed. All commands are
   allowed after GPE init, only a subset of
   commands - \ref PRE_GPE_INIT_COMMANDS - is allowed prior to GPE init.
*/
STATIC bool is_cli_allowed(struct onu_device *p_dev, char *cmd, void *f)
{
	static const char *preinit_cmds[] = { PRE_GPE_INIT_COMMANDS };
	struct cli_rec_type rec = { NULL, 0, NULL };
	unsigned int i;

	if (((struct onu_control*)p_dev->ctrl)->gpe_init == false) {
		for (i = 0; i < ARRAY_SIZE(preinit_cmds); i++) {
			if (strcmp(preinit_cmds[i], cmd) == 0) {
				return true;
			} else {
				/* we may be called via short form, check
				 * it here */
				if (onu_cli_key_find(preinit_cmds[i], &rec) !=
				    CLI_STATUS_OK)
					return false;

				if (f == rec.func)
					return true;
			}
		}

		return false;
	} else {
		return true;
	}
}

/**
   For a detailed description of the function, its arguments and return value
   please refer to the description in the header file 'drv_cli_cli.h'
*/
int onu_cli_command_execute(struct onu_device *dev_ctx, char *buffer,
			    const uint32_t max_buffer_size)
{
	struct cli_rec_type rec = { NULL, 0, NULL };
	char *cmd = NULL;
	char *arg = NULL;

	if (buffer == NULL)
		return -1;

	buffer = onu_cli_remove_whitespaces(buffer);
	buffer = onu_cli_remove_prefix(buffer, "CLI_", 3);

	cmd = buffer;
	arg = buffer;

	/* strip the command word */
	while (*arg) {
		if (onu_cli_isspace(*arg)) {
			*arg = 0;
			arg++;
			break;
		}
		arg++;
	}

	switch (onu_cli_key_find(cmd, &rec)) {
	case CLI_STATUS_OK:
		if (!is_cli_allowed(dev_ctx, cmd, rec.func))
			return sprintf(buffer, "errorcode=%d",
				       ONU_STATUS_GPE_NOT_INITIALIZED);

		if (rec.func != NULL)
			return rec.func(dev_ctx, arg, max_buffer_size, buffer);
		else
			return sprintf(buffer,
				       "errorcode=-1 (internal error, "
				       "no function pointer)");

		break;

	default:
		return sprintf(buffer, "errorcode=-1 (unknown command)");
	}

	return 0;
}

/**
   For a detailed description of the function, its arguments and return value
   please refer to the description in the header file 'drv_cli_cli.h'
*/
int onu_cli_command_add(char const *short_name, char const *long_name,
			onu_cli_entry_t cliEntry)
{
	struct cli_rec_type rec;

	if (onu_cli_register_mode == CLI_COUNT) {
		onu_cli_nodes_number += 2;
		return 0;
	}
	if (onu_cli_register_mode != CLI_ALLOCATE)
		return -1;

	rec.mask = 0;

	if (short_name == NULL) {
		ONU_DEBUG_ERR("short_name pointer is invalid");
		return -1;
	}

	if (long_name == NULL) {
		ONU_DEBUG_ERR("long_name pointer is invalid");
		return -1;
	}

	rec.func = cliEntry;
	rec.mask |= CLI_MASK_DEVICE;
	rec.help = long_name;

	switch (onu_cli_key_insert(short_name, &rec)) {
	case CLI_STATUS_KEY_INVALID:
		ONU_DEBUG_ERR("invalid key %s for %s", short_name, rec.help);
		return -1;

	case CLI_STATUS_DUPLICATE_KEY:
		ONU_DEBUG_WRN("duplicate key %s for %s", short_name, rec.help);
		/* this is non fatal error ;-)
		   return -1; */
		break;

	case CLI_STATUS_MEM_EXHAUSTED:
		ONU_DEBUG_ERR("memory allocation error");
		return -1;

	case CLI_STATUS_OK:
		break;

	default:
		ONU_DEBUG_ERR("insert key aborted");
		return -1;
	}

	rec.mask |= CLI_MASK_LONG;
	rec.help = short_name;

	switch (onu_cli_key_insert(long_name, &rec)) {
	case CLI_STATUS_KEY_INVALID:
		ONU_DEBUG_ERR("invalid key %s for %s", long_name, rec.help);
		return -1;

	case CLI_STATUS_DUPLICATE_KEY:
		ONU_DEBUG_ERR("duplicate key %s for %s", long_name, rec.help);
		return -1;

	case CLI_STATUS_MEM_EXHAUSTED:
		ONU_DEBUG_ERR("memory allocation error");
		return -1;

	case CLI_STATUS_OK:
		break;

	default:
		ONU_DEBUG_ERR("insert key aborted");
		return -1;
	}

	return 0;
}

/*
   For a detailed description of the function, its arguments and return value
   please refer to the description in the header file 'drv_cli_cli.h'
*/
int onu_cli_shutdown(void)
{
	struct cli_node_tag *tmp_root = onu_cli_node_array;

	onu_cli_register_mode = CLI_DELETE;

	/* set to NULL to disable future executions */
	onu_cli_root = NULL;
	onu_cli_node_array = NULL;

	IFXOS_MemFree(tmp_root);

	onu_cli_register_mode = CLI_COUNT;

	return 0;
}

/**
   sscanf implementation with uint8 support.
*/
int32_t onu_cli_sscanf(const char *buf, char const *fmt, ...)
{
#ifndef _lint
	va_list marker;
#endif
	char const *p, *a;
	char *r = 0;
	const char *s = buf;
	int ret = 0, mode = 32, base = 10, array = 0, i;
	int *v32 = 0;
	long long *v64 = 0;
	short *v16 = 0;
	char *v8 = 0;
	unsigned int *vu32 = 0;
	uint64_t *vu64 = 0;
	unsigned short *vu16 = 0;
	unsigned char *vu8 = 0;

#ifndef _lint
	va_start(marker, fmt);
#endif

	if (s == NULL)
		goto SF_END;

	for (p = fmt; *p; p++) {
		if (*p != '%')
			continue;

		if (s == NULL)
			goto SF_END;

		/* skip spaces and tabs */
		while ((*s == ' ') || (*s == '\t'))
			s++;

		if (s == 0 || *s == 0)
			goto SF_END;

		switch (*++p) {
		case 0:
			/* ret = 0; */
			goto SF_END;

			/* 8 bit */
		case 'b':
			mode = 8;
			p++;
			break;

			/* 16 bit */
		case 'h':
			mode = 16;
			p++;
			break;

			/* 32 bit */
		case 'l':
			mode = 32;
			p++;
			if (*p == 'l') {
				/* 64 bit */
				mode = 64;
				p++;
			}
			break;

			/* 32 bit */
		default:
			mode = 32;
			break;
		}

		switch (*p) {
		case 'd':
		case 'i':
		case 'u':
			base = 10;
			break;

		case 'x':
			base = 16;
			break;

		default:
			break;
		}

		a = p + 1;
		i = 0;

		array = 1;

		switch (*a) {
		case '[':
			a++;
			if (*a) {
				array = (char)onu_strtol(a, NULL, 10);
				if (array > 256) {
					array = 0;
				}
				do {
					a++;
					if (*a == ']') {
						a++;
						break;
					}
				} while (*a);
			}
			break;

		default:
			break;
		}

		switch (*p) {
		case 0:
			/* ret = 0; */
			goto SF_END;

			/* string */
		case 's':
			{
#ifndef _lint
				r = va_arg(marker, char *);
#endif
				if (r != NULL) {
					const char *q = s;
					do {
						if ((*q == ' ') || (*q == '\t'))
							q++;
						else
							break;
					} while (*q);
					if (*q) {
						do {
							if ((*q != ' ')
							    && (*q != '\t')
							    && (*q != '\n')
							    && (*q != '\r'))
								*r++ = *q++;
							else
								break;
						} while (*q);
						s = q;
						*r = 0;
						ret++;
					}
				}
				break;
			}

			/* signed */
		case 'd':
		case 'i':
			{
				switch (mode) {
				case 8:
#ifndef _lint
					v8 = va_arg(marker, char *);
#endif
					if (v8 != NULL) {
						for (i = 0; i < array; i++) {
							if (s && *s != 0) {
								char *ptr =
								    NULL;
								v8[i] =
								    (char)
								    onu_strtol
								    (s, &ptr,
								     base);
								if (ptr) {
									while ((*ptr == ' ') || (*ptr == '\t') || (*ptr == '\n') || (*ptr == '\r'))
										ptr++;
								}
								s = ptr;
								ret++;
							} else {
								break;
							}
						}
					}
					break;

				case 16:
#ifndef _lint
					v16 = va_arg(marker, short *);
#endif
					if (v16 != NULL) {
						for (i = 0; i < array; i++) {
							if (s && *s != 0) {
								char *ptr =
								    NULL;
								v16[i] =
								    (short)
								    onu_strtol
								    (s, &ptr,
								     base);
								if (ptr) {
									while ((*ptr == ' ') || (*ptr == '\t') || (*ptr == '\n') || (*ptr == '\r'))
										ptr++;
								}
								s = ptr;
								ret++;
							} else {
								break;
							}
						}
					}
					break;

				case 32:
#ifndef _lint
					v32 = va_arg(marker, int *);
#endif
					if (v32 != NULL) {
						for (i = 0; i < array; i++) {
							if (s && *s != 0) {
								char *ptr =
								    NULL;
								v32[i] =
								    (int)
								    onu_strtol
								    (s, &ptr,
								     base);
								if (ptr) {
									while ((*ptr == ' ') || (*ptr == '\t') || (*ptr == '\n') || (*ptr == '\r'))
										ptr++;
								}
								s = ptr;
								ret++;
							} else {
								break;
							}
						}
					}
					break;

				case 64:
#ifndef _lint
					v64 = va_arg(marker, long long *);
#endif
					if (v64 != NULL) {
						for (i = 0; i < array; i++) {
							if (s && *s != 0) {
								char *ptr =
								    NULL;
								v64[i] =
								    (long long)
								    onu_strtoll(s, &ptr, base);
								if (ptr) {
									while ((*ptr == ' ') || (*ptr == '\t') || (*ptr == '\n') || (*ptr == '\r'))
										ptr++;
								}
								s = ptr;
								ret++;
							} else {
								break;
							}
						}
					}
					break;
				default:
					break;
				}
				break;
			}

			/* unsigned */
		case 'u':
			/* hexadecimal */
		case 'x':
			{
				switch (mode) {
				case 8:
#ifndef _lint
					vu8 = va_arg(marker, unsigned char *);
#endif
					if (vu8 != NULL) {
						for (i = 0; i < array; i++) {
							if (s && *s != 0) {
								char *ptr =
								    NULL;
								vu8[i] =
								    (unsigned
								     char)
								    onu_strtoul
								    (s, &ptr,
								     base);
								if (ptr) {
									while ((*ptr == ' ') || (*ptr == '\t') || (*ptr == '\n') || (*ptr == '\r'))
										ptr++;
								}
								s = ptr;
								ret++;
							} else {
								break;
							}
						}
					}
					break;

				case 16:
#ifndef _lint
					vu16 = va_arg(marker, unsigned short *);
#endif
					if (vu16 != NULL) {
						for (i = 0; i < array; i++) {
							if (s && *s != 0) {
								char *ptr =
								    NULL;
								vu16[i] =
								    (unsigned
								     short)
								    onu_strtoul
								    (s, &ptr,
								     base);
								if (ptr) {
									while ((*ptr == ' ') || (*ptr == '\t') || (*ptr == '\n') || (*ptr == '\r'))
										ptr++;
								}
								s = ptr;
								ret++;
							} else {
								break;
							}
						}
					}
					break;

				case 32:
#ifndef _lint
					vu32 = va_arg(marker, unsigned int *);
#endif
					if (vu32 != NULL) {
						for (i = 0; i < array; i++) {
							if (s && *s != 0) {
								char *ptr =
								    NULL;
								vu32[i] =
								    (unsigned
								     int)
								    onu_strtoul
								    (s, &ptr,
								     base);
								if (ptr) {
									while ((*ptr == ' ') || (*ptr == '\t') || (*ptr == '\n') || (*ptr == '\r'))
										ptr++;
								}
								s = ptr;
								ret++;
							} else {
								break;
							}
						}
					}
					break;

				case 64:
#ifndef _lint
					vu64 = va_arg(marker, uint64_t *);
#endif
					if (vu64 != NULL) {
						for (i = 0; i < array; i++) {
							if (s && *s != 0) {
								char *ptr =
								    NULL;
								vu64[i] =
								    (uint64_t)
								    onu_strtoull
								    (s, &ptr,
								     base);
								if (ptr) {
									while ((*ptr == ' ') || (*ptr == '\t') || (*ptr == '\n') || (*ptr == '\r'))
										ptr++;
								}
								s = ptr;
								ret++;
							} else {
								break;
							}
						}
					}
					break;

				default:
					break;
				}
				break;

			}
		default:
			break;
		}

		if (a != (p + 1)) {
			p = a;
		}
		if (!*p)
			break;
	}

SF_END:

#ifndef _lint
	va_end(marker);
#endif

	return ret;
}

int onu_cli_check_help(const char *p_cmd, const char *p_usage,
		       const uint32_t bufsize_max, char *p_out)
{
	if (p_cmd && (strstr(p_cmd, "-h") || strstr(p_cmd, "--help")
		      || strstr(p_cmd, "/h") || strstr(p_cmd, "-?"))) {
		if (strlen(p_usage) < bufsize_max)
			return sprintf(p_out, "%s", p_usage);
		else
			return 0;
	}
	return -1;
}

#endif				/* INCLUDE_CLI_SUPPORT */
