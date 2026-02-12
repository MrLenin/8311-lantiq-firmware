/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#include "ifx_types.h"
#include "ifx_getopt.h"
#include "ifxos_std_defs.h"

#ifndef IFXOS_HAVE_GET_OPT
#	define IFXOS_HAVE_GET_OPT	1
#endif

#ifndef IFXOS_HAVE_GET_OPT_R
#	define IFXOS_HAVE_GET_OPT_R	1
#endif

#if defined(IFXOS_HAVE_GET_OPT) && (IFXOS_HAVE_GET_OPT == 1)
char *optarg = 0;
int optind = 0;

int getopt_long(
	int argc,
	char *argv[],
	const char *long_option_string,
	struct option *pOptions,
	int *option_index)
{
	static unsigned char idx=1;
	int ret = -1;
	unsigned int i;
	char c;

	if (idx >= argc)
	{
		idx = 1;
		return ret;
	}

	optarg = IFX_NULL;

	if (argv[idx][0] == '-' && argv[idx][1] == '-')
	{
		for (i=0;;i++)
		{
			if (pOptions == 0 || pOptions->name == 0)
				{break;}

			if (strncmp(pOptions->name, &argv[idx][2], strlen(&argv[idx][2])) == 0)
			{
				/* option found */
				ret = pOptions->val;
				if(pOptions->parameter)
					{optarg = &argv[++idx][0];}

				break;
			}
			pOptions++;
		}
	}
	else if(argv[idx][0] == '-')
	{
		c = argv[idx][1];
		for (i=0; i<strlen(long_option_string); i++)
		{
			if(long_option_string[i] == ':')
				{continue;}

			if(long_option_string[i] == c)
			{
				/* option found */
				ret = c;
				if (argv[idx][2] == 0)
					{optarg = &argv[(unsigned char)(idx + 1)][0];}
				else
					{optarg = &argv[idx][2];}

				break;
			}
		}
	}
	else
	{
		ret = 0;
	}

	optind = idx++;

	return ret;
}
#endif /* #if defined(IFXOS_HAVE_GET_OPT) && (IFXOS_HAVE_GET_OPT == 1) */


#if defined(IFXOS_HAVE_GET_OPT_R) && (IFXOS_HAVE_GET_OPT_R == 1)
int getopt_long_r(
	int argc,
	char *argv[],
	const char *long_option_string,
	struct option *pOptions,
	int *option_index,
	char **pp_optarg,
	int *p_optind)
{
	static unsigned char idx=1;
	int ret = -1;
	unsigned int i;
	char c;

	if (idx >= argc)
	{
		idx = 1;
		return ret;
	}

	*pp_optarg = IFX_NULL;

	if (argv[idx][0] == '-' && argv[idx][1] == '-')
	{
		for (i=0;;i++)
		{
			if (pOptions == 0 || pOptions->name == 0)
				{break;}

			if (strncmp(pOptions->name, &argv[idx][2], strlen(&argv[idx][2])) == 0)
			{
				/* option found */
				ret = pOptions->val;
				if(pOptions->parameter)
					{*pp_optarg = &argv[++idx][0];}

				break;
			}
			pOptions++;
		}
	}
	else if(argv[idx][0] == '-')
	{
		c = argv[idx][1];
		for (i=0; i<strlen(long_option_string); i++)
		{
			if(long_option_string[i] == ':')
				{continue;}

			if(long_option_string[i] == c)
			{
				/* option found */
				ret = c;
				if (argv[idx][2] == 0)
					{*pp_optarg = &argv[(unsigned char)(idx + 1)][0];}
				else
					{*pp_optarg = &argv[idx][2];}

				break;
			}
		}
	}
	else
	{
		ret = 0;
	}

	*p_optind = idx++;

   return ret;
}
#endif	/* #if defined(IFXOS_HAVE_GET_OPT_R) && (IFXOS_HAVE_GET_OPT_R == 1) */


