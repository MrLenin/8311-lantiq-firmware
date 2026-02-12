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
#include "drv_optic_config.h"
#endif

#ifdef INCLUDE_CLI_SUPPORT
#include "drv_optic_common.h"

#ifdef OPTIC_SIMULATION
#  include <stdlib.h>           /* strtol */
#  include <stdarg.h>           /* va_start */
#  include <string.h>           /* strcpy */
#endif

#include "drv_optic_api.h"

#include "ifxos_memory_alloc.h"

#include "drv_optic_cli_core.h"


#define CLI_WARNING_TABLE_ENTRY_NOT_VALID (-2)
#define CLI_WARNING_TABLE_ENTRY_NOT_FOUND (-3)

#if defined(LINUX) && defined(__KERNEL__)
long optic_strtol ( const char *cp, char **endp, unsigned int base)
{
	if (cp && cp[0] != 0 && cp[1] != 0 && cp[0] == '0' && cp[1] == 'x')
		base = 16;

	return simple_strtol(cp, endp, base);
}

unsigned long optic_strtoul ( const char *cp, char ** endp, unsigned int base )
{
	if (cp && cp[0] != 0 && cp[1] != 0 && cp[0] == '0' && cp[1] == 'x')
		base = 16;

	return simple_strtoul(cp, endp, base);
}
#else
#include "ifxos_std_defs.h"
   #define optic_strtol strtol
   #define optic_strtoul strtoul
#endif

STATIC int32_t optic_cli_isspace ( char c );
STATIC char *optic_cli_remove_whitespaces ( char *str );
STATIC char *optic_cli_remove_prefix( char *str, char *prefix,
				      int8_t length );
int optic_cli_check_help ( const char *p_cmd, const char *p_usage,
			   const uint32_t bufsize_max, char *p_out );

/** 'less then' defintion for binary tree, (a < b)*/
#define comp_lt(a,b) (strcmp(a,b) < 0)
/** 'equal' defintion for binary tree, (a == b)*/
#define comp_eq(a,b) (strcmp(a,b) == 0)
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
enum cli_registerstate {
	CLI_COUNT,
	CLI_ALLOCATE,
	CLI_ACTIVE,
	CLI_DELETE
};

/** user data stored in tree */
struct cli_rectype {
	char const *help;
	uint32_t mask;
	optic_cli_entry func;
};

struct cli_node {
	/** left child */
	struct cli_node *left;
	/** right child */
	struct cli_node *right;
	/** parent */
	struct cli_node *parent;
	/** key used for searching */
	char const *key;
	/** user data */
	struct cli_rectype rec;
};

STATIC enum cli_status optic_cli_key_insert ( char const *key,
					      struct cli_rectype *rec) ;
STATIC enum cli_status optic_cli_key_find ( char const *key,
					    struct cli_rectype *rec );
STATIC uint32_t optic_cli_tree_print ( struct optic_device *p_dev,
				       const struct cli_node *node,
				       const uint32_t mask );

/** root of binary tree */
STATIC struct cli_node *optic_cli_root = NULL;

/* state of the cli register process */
STATIC enum cli_registerstate optic_cli_register_mode = 0;
STATIC uint16_t optic_cli_nodes_number = 0;
STATIC uint16_t optic_cli_nodes_used = 0;
STATIC struct cli_node *optic_cli_node_array = NULL;

/**
   allocate node for data and insert in tree
*/
STATIC enum cli_status optic_cli_key_insert ( char const *key,
					      struct cli_rectype *rec )
{
	struct cli_node *x, *curr, *parent;

	if (key == NULL)
		return CLI_STATUS_KEY_INVALID;

	/* find future parent */
	curr = optic_cli_root;
	parent = NULL;
	while (curr) {
		if (comp_eq(key, curr->key))
			return CLI_STATUS_DUPLICATE_KEY;
		parent = curr;
		curr = comp_lt(key, curr->key) ? curr->left : curr->right;
	}

	/* setup new node */
	if ((optic_cli_node_array != NULL) &&
	    (optic_cli_nodes_used < optic_cli_nodes_number) &&
	    (optic_cli_register_mode == CLI_ALLOCATE)) {
		x = (optic_cli_node_array + optic_cli_nodes_used);
		optic_cli_nodes_used++;
	} else {
		return CLI_STATUS_MEM_EXHAUSTED;
	}
	x->parent = parent;
	x->left = NULL;
	x->right = NULL;
	x->key = key;
	memcpy((void *)&x->rec, (void *)rec, sizeof(struct cli_rectype));

	/* insert x in tree */
	if (parent)
		if (comp_lt(x->key, parent->key))
			parent->left = x;
		else
			parent->right = x;
	else
		optic_cli_root = x;

	return CLI_STATUS_OK;
}

/**
   find node containing data
*/
STATIC enum cli_status optic_cli_key_find ( char const *key,
					    struct cli_rectype *rec )
{
	struct cli_node *curr = optic_cli_root;

	while (curr != NULL) {
		if (comp_eq(key, curr->key)) {
			memcpy((void *)rec, (void *)&curr->rec,
				sizeof(struct cli_rectype));
			return CLI_STATUS_OK;
		} else {
 			curr = comp_lt(key, curr->key) ?
 				curr->left : curr->right;
		}
	}
	return CLI_STATUS_KEY_NOT_FOUND;
}

/**
   print binary tree
*/
STATIC uint32_t optic_cli_tree_print ( struct optic_device *p_dev,
				       const struct cli_node *node,
				       const uint32_t mask )
{
	int32_t j = 0, ret;
	int32_t fill_char = 0;
	int32_t help_clm = 10;

	if (node == NULL)
		return 0;

	optic_cli_tree_print (p_dev, node->left, mask);

	if ((p_dev->help_out_len + 64) >= p_dev->help_max_len)
		return 0;

	if ((node->rec.mask & mask) &&
	    ((node->rec.mask & CLI_MASK_LONG) == (mask & CLI_MASK_LONG))) {
		if ((mask & CLI_MASK_DETAILED) == CLI_MASK_DETAILED) {
			if (node->rec.func) {
				ret = node->rec.func(p_dev, "-h",
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
			fill_char = help_clm - ret;
			if (fill_char > 0) {
				for (j = 0; j < fill_char; j++) {
					ret = sprintf(p_dev->help_out, " ");
					if (ret < 0)
						ret = 0;
               				p_dev->help_out_len += ret;
					p_dev->help_out += ret;
				}
			}
			ret = sprintf(p_dev->help_out, "%s" OPTIC_CRLF,
								node->key);
			if (ret < 0)
				ret = 0;
			p_dev->help_out_len += ret;
			p_dev->help_out += ret;
		}
	}

	return optic_cli_tree_print (p_dev, node->right, mask);
}

/** Handle command

   \param[in] p_dev     Device Context Pointer
   \param[in] pcmds     Input commands
   \param[in] p_out     Output FD
*/
STATIC int optic_cli_help ( struct optic_device *p_dev,
			    const char *p_cmds,
			    const uint32_t bufsize_max,
			    char *p_out)
{
	int ret = 0;
	uint32_t mask = CLI_MASK_DEVICE | CLI_MASK_LONG;

	/*enum optic_errorcode fct_ret = (enum optic_errorcode) 0; */

#ifndef OPTIC_DEBUG_DISABLE
	static const char usage[] =
		"Long Form: Help" OPTIC_CRLF
		"Short Form: help" OPTIC_CRLF
		OPTIC_CRLF
		"Input Parameter" OPTIC_CRLF
		OPTIC_CRLF
		"Output Parameter" OPTIC_CRLF
		"- enum optic_errorcode errorcode" OPTIC_CRLF OPTIC_CRLF;
#else
#undef USAGE
#define USAGE ""
#endif

	if ((ret = optic_cli_check_help ( p_cmds, usage, bufsize_max, p_out ))
	    >= 0) {
		return ret;
   	}

	if (strlen(p_cmds)) {
		if (strcmp(p_cmds, "detailed") == 0) {
			mask |= CLI_MASK_DETAILED;
		} else {
			return sprintf ( p_out,
			   "errorcode=-1 (unknown sub command)" OPTIC_CRLF );
		}
	}

	p_dev->help_out = p_out;
	p_dev->help_out_len = 0;
	p_dev->help_max_len = bufsize_max;

	optic_cli_tree_print (p_dev, optic_cli_root, mask);
	p_out[p_dev->help_out_len] = 0;
	return p_dev->help_out_len + 1;
}


static int optic_cli_version_info_get ( struct optic_device *p_dev,
	                                const char *p_cmd,
	                                const uint32_t bufsize_max,
	                                char *p_out )
{
	(void) p_dev;
	(void) p_cmd;
	(void) bufsize_max;

	return sprintf(p_out,
	               "errorcode=%d version=\"%s\" type=\"%s\" " OPTIC_CRLF,
	               (int)OPTIC_STATUS_OK, OPTIC_VER_STR, GPON_OPTIC_TYPE);
}

/**
   For a detailed description of the function, its arguments and return value
   please refer to the description in the header file 'drv_optic_cli_core.h'
*/
int optic_cli_init ( void )
{
	if (optic_cli_node_array != NULL) {
		OPTIC_DEBUG_WRN("CLI_Init already done.");
		return -1;
	}

	optic_cli_nodes_used = 0;
	/* count necessary number of nodes */
	optic_cli_nodes_number = 0;
	optic_cli_register_mode = CLI_COUNT;
	optic_cli_command_add("help", "Help", optic_cli_help);
	optic_cli_command_add("vig", "version_info_get",
	                             optic_cli_version_info_get);
	optic_cli_misc_register();
	optic_cli_autogen_register();

	if (optic_cli_nodes_number == 0) {
		OPTIC_DEBUG_ERR("command list empty");
		return -1;
	}

	OPTIC_DEBUG_MSG("allocate memory for %d nodes",
			optic_cli_nodes_number);

	optic_cli_node_array =
		IFXOS_MemAlloc(optic_cli_nodes_number * sizeof(struct cli_node));
	if (optic_cli_node_array == NULL) {
		OPTIC_DEBUG_ERR("memory allocation error");
		return -1;
	}
	memset ( optic_cli_node_array, 0,
		 optic_cli_nodes_number * sizeof(struct cli_node) );

	optic_cli_register_mode = CLI_ALLOCATE;
	optic_cli_command_add("help", "Help", optic_cli_help);
	optic_cli_command_add("vig", "version_info_get",
	                             optic_cli_version_info_get);
	optic_cli_misc_register();
	optic_cli_autogen_register();
	optic_cli_register_mode = CLI_ACTIVE;

	OPTIC_DEBUG_MSG("%d commands registered", optic_cli_nodes_used);

	return 0;
}

/**
   Detect spaces.
*/
STATIC int32_t optic_cli_isspace ( char c )
{
	if ((c == ' ') || (c == '\t') || (c == '\n') || (c == '\r'))
		return 1;
	return 0;
}

/**
   Remove leading, tailing and double whitespaces
   Arguments has to have only one space in between to get sure that the CLI
   comments are working correctly.
*/
STATIC char *optic_cli_remove_whitespaces ( char *str )
{
	char *buf = str;
	char *p_read, *p_write;
	int32_t i = 0;

	if (buf == NULL)
		return buf;

	/* remove leading whitespaces */
	while ((*buf) && (optic_cli_isspace(*buf))) {
		++buf;
	}

	/* remove double spaces in between and at the end */
	p_read = buf;
	p_write = buf;

	for (i = 0; *p_read != '\0'; ++p_read) {
		if (optic_cli_isspace(*p_read)) {
			if ((i == 0) && (*(p_read + 1) != '\0')) {
				*p_write = *p_read;
				p_write++;
				i++;
			}
		} else {
			i = 0;
			*p_write = *p_read;
			p_write++;
		}
	}

	/* Write string termination */
	if (p_write != p_read)
		*p_write = '\0';

	return buf;
}

/**
   Remove leading, tailing and double whitespaces
   Arguments has to have only one space in between to get sure that the CLI
   comments are working correctly.
*/
STATIC char *optic_cli_remove_prefix ( char *str, char *prefix,
				       int8_t length )
{
	char *buf;
	char *p_read, *p_write;
	int32_t i = 0;
	uint8_t l = 0;

	buf = str;
	if (buf == NULL)
		return buf;

	p_read = buf;
	p_write = buf;
	/* remove prefix at front */
	while (*p_read != '\0') {
		if (l < length) {
			/* prefix check */
			if (*p_read == prefix[l]) {
				l++;
			} else {
				for (i = 0; i < l; i++) {
					*p_write = prefix[i];
					p_write++;
				}
				l = length;

				*p_write = *p_read;
				p_write++;
			}
		} else {
			*p_write = *p_read;
			p_write++;
		}

		p_read++;
	}

	/* Write string termination */
	if (p_write != p_read)
		*p_write = '\0';

	return buf;
}

/**
   For a detailed description of the function, its arguments and return value
   please refer to the description in the header file 'drv_cli_cli.h'
*/
int optic_cli_command_execute ( struct optic_device *p_dev,
				char *buffer,
		                const uint32_t bufsize_max )
{
	struct cli_rectype rec = { NULL, 0, NULL };
	char *cmd = NULL;
	char *arg = NULL;

	if (buffer == NULL) {
		return -1;
	}

	buffer = optic_cli_remove_whitespaces ( buffer );
	buffer = optic_cli_remove_prefix ( buffer, "cli_", 3 );

	cmd = buffer;
	arg = buffer;

	/* strip the command word */
	while (*arg) {
		if (optic_cli_isspace(*arg)) {
			*arg = 0;
			arg++;
			break;
		}
		arg++;
	}

	switch (optic_cli_key_find ( cmd, &rec )) {
	case CLI_STATUS_OK:
		if (rec.func != NULL)
			return rec.func(p_dev, arg, bufsize_max, buffer);
		else
			return sprintf ( buffer,
			"errorcode=-1 (internal error, "
			"no function pointer)");
		break;

	default:
		return sprintf ( buffer, "errorcode=-1 (unknown command)");
	}

	return 0;
}

/**
   For a detailed description of the function, its arguments and return value
   please refer to the description in the header file 'drv_cli_cli.h'
*/
int optic_cli_command_add ( char const *short_name,
		            char const *long_name,
			    optic_cli_entry cli_entry)
{
	struct cli_rectype rec;

	if (optic_cli_register_mode == CLI_COUNT) {
		optic_cli_nodes_number += 2;
		return 0;
	}
	if (optic_cli_register_mode != CLI_ALLOCATE) {
		return -1;
	}

	rec.mask = 0;

	if (short_name == NULL) {
		OPTIC_DEBUG_ERR("short_name pointer is invalid");
		return -1;
	}

	if (long_name == NULL) {
		OPTIC_DEBUG_ERR("long_name pointer is invalid");
		return -1;
	}

	rec.func = cli_entry;
	rec.mask |= CLI_MASK_DEVICE;
	rec.help = long_name;

	switch (optic_cli_key_insert(short_name, &rec)) {
	case CLI_STATUS_KEY_INVALID:
		OPTIC_DEBUG_ERR("invalid key %s for %s", short_name, rec.help);
		return -1;
	case CLI_STATUS_DUPLICATE_KEY:
		OPTIC_DEBUG_WRN("duplicate key %s for %s", short_name,
				rec.help);
		/* this is non fatal error ;-)
		return -1; */
		break;
	case CLI_STATUS_MEM_EXHAUSTED:
		OPTIC_DEBUG_ERR("memory allocation error");
		return -1;
	case CLI_STATUS_OK:
		break;
	default:
		OPTIC_DEBUG_ERR("insert key aborted");
		return -1;
	}

	rec.mask |= CLI_MASK_LONG;
	rec.help = short_name;

	switch (optic_cli_key_insert ( long_name, &rec )) {
	case CLI_STATUS_KEY_INVALID:
		OPTIC_DEBUG_ERR("invalid key %s for %s", long_name, rec.help);
		return -1;
	case CLI_STATUS_DUPLICATE_KEY:
		OPTIC_DEBUG_ERR("duplicate key %s for %s", long_name, rec.help);
		return -1;
	case CLI_STATUS_MEM_EXHAUSTED:
		OPTIC_DEBUG_ERR("memory allocation error");
		return -1;
	case CLI_STATUS_OK:
		break;
	default:
		OPTIC_DEBUG_ERR("insert key aborted");
		return -1;
	}

	return 0;
}

/*
   For a detailed description of the function, its arguments and return value
   please refer to the description in the header file 'drv_cli_cli.h'
*/
int optic_cli_shutdown ( void )
{
	struct cli_node *tmp_root = optic_cli_node_array;

	optic_cli_register_mode = CLI_DELETE;

	/* set to NULL to disable future executions */
	optic_cli_root = NULL;
	optic_cli_node_array = NULL;

	IFXOS_MemFree(tmp_root);

	optic_cli_register_mode = CLI_COUNT;

	return 0;
}

/**
   sscanf implementation with uint8 support.
*/
int32_t optic_cli_sscanf ( const char *buf, char const *fmt, ... )
{
#ifndef _lint
	va_list marker;
#endif
	char const *q, *p, *a;
	char *r=0;
	const char *s = buf;
	int ret = 0, mode = 32, base = 10, array = 0, i;
	int *v32=0;
	short *v16=0;
	char *v8=0;
	unsigned int *vu32=0;
	unsigned short *vu16=0;
	unsigned char *vu8=0;
	char *ptr = NULL;

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

		if ((s == NULL) || (*s == 0))
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
			if (*a == 0)
				break;

			array = (char) optic_strtol(a, NULL, 10);
			if (array > 256)
				array = 0;

			do {
				a++;
				if (*a == ']') {
					a++;
					break;
				}
			} while (*a);

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
			if (r == NULL)
				break;

			q = s;
			do {
				if ((*q != ' ') && (*q != '\t'))
					break;
				q++;
			} while (*q);

			if (*q == 0)
				break;

			do {

				if ((*q == ' ') || (*q == '\t') ||
				    (*q != '\n') || (*q != '\r'))
				    	break;

				*r++ = *q++;
			} while(*q);
			s = q;
			*r = 0;
			ret++;

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
				if (v8 == NULL)
					break;

				for (i = 0; i < array; i++) {
					if ((s == NULL) || (*s == 0))
						break;

					ptr = NULL;
					v8[i] = (char) optic_strtol(s, &ptr,
								    base);

					if (ptr == NULL) {
						s = NULL;
						ret++;
						break;
					}
					while ((*ptr == ' ') || (*ptr == '\t')
					     ||(*ptr == '\n') || (*ptr == '\r'))
						ptr++;

					s = ptr;
					ret++;
				}
				break;
			case 16:
#ifndef _lint
				v16 = va_arg(marker, short *);
#endif
				if (v16 == NULL)
					break;

				for (i = 0; i < array; i++) {
					if ((s == NULL) || (*s == 0))
						break;

					ptr = NULL;
					v16[i] = (short) optic_strtol(s, &ptr,
					                              base);

					if (ptr == NULL) {
						s = NULL;
						ret++;
						break;
					}
					while ((*ptr == ' ') || (*ptr == '\t')
					     ||(*ptr == '\n') || (*ptr == '\r'))
						ptr++;

					s = ptr;
					ret++;
				}
				break;
			case 32:
#ifndef _lint
				v32 = va_arg(marker, int *);
#endif
				if (v32 == NULL)
					break;

				for (i = 0; i < array; i++) {
					if ((s == NULL) || (*s == 0))
						break;

					ptr = NULL;
					v32[i] = (int) optic_strtol(s, &ptr,
								    base);

					if (ptr == NULL) {
						s = NULL;
						ret++;
						break;
					}
					while ((*ptr == ' ') || (*ptr == '\t')
					     ||(*ptr == '\n') || (*ptr == '\r'))
						ptr++;

					s = ptr;
					ret++;
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
				if (vu8 == NULL)
					break;

				for (i = 0; i < array; i++) {
					if ((s == NULL) || (*s == 0))
						break;

					ptr = NULL;
					vu8[i] = (unsigned char)
						 optic_strtol(s, &ptr, base);


					if (ptr == NULL) {
						s = NULL;
						ret++;
						break;
					}
					while ((*ptr == ' ') || (*ptr == '\t')
					     ||(*ptr == '\n') || (*ptr == '\r'))
						ptr++;

					s = ptr;
					ret++;
				}
				break;
			case 16:
#ifndef _lint
				vu16 = va_arg(marker, unsigned short *);
#endif

				if (vu16 == NULL)
					break;

				for (i = 0; i < array; i++) {
					if ((s == NULL) || (*s == 0))
						break;

					ptr = NULL;
					vu16[i] = (unsigned short)
						  optic_strtol(s, &ptr, base);

					if (ptr == NULL) {
						s = NULL;
						ret++;
						break;
					}
					while ((*ptr == ' ') || (*ptr == '\t')
					     ||(*ptr == '\n') || (*ptr == '\r'))
						ptr++;

					s = ptr;
					ret++;
				}
				break;

			case 32:
#ifndef _lint
				vu32 = va_arg(marker, unsigned int *);
#endif
				if (vu32 == NULL)
					break;

				for (i = 0; i < array; i++) {
					if ((s == NULL) || (*s == 0))
						break;

					ptr = NULL;
					vu32[i] = (unsigned int)
						  optic_strtol(s, &ptr, base);

					if (ptr == NULL) {
						s = NULL;
						ret++;
						break;
					}
					while ((*ptr == ' ') || (*ptr == '\t')
					     ||(*ptr == '\n') || (*ptr == '\r'))
						ptr++;

					s = ptr;
					ret++;
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

		if (a != (p + 1))
			p = a;

		if (*p == 0)
			break;
	}

SF_END:

#ifndef _lint
	va_end(marker);
#endif

	return ret;
}

int optic_cli_check_help ( const char *p_cmds, const char *p_usage,
			   const uint32_t bufsize_max, char *p_out)
{
	if ((p_cmds == NULL) || (p_usage == NULL))
		return -1;

	if ((strstr(p_cmds, "-h")) || (strstr(p_cmds, "--help")) ||
	    (strstr(p_cmds, "/h")) || (strstr(p_cmds, "-?"))) {
		if (strlen(p_usage) < bufsize_max)
			return sprintf(p_out, "%s", p_usage);
		else
			return 0;
	}

	return -1;
}

#endif                          /* INCLUDE_CLI_SUPPORT */
