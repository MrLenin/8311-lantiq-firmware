#ifndef LIB_DSL_GETOPT_H
#define LIB_DSL_GETOPT_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

#define IFXOS_SUPPORT_GET_OPT_R	1

#define no_argument		0
#define required_argument	1

/* define own externals */
extern char *optarg;
extern int optind;

/* if no getopt_long implementation is available, assume also the struct option
   is also not defined */
struct option
{
	char *name;
	int parameter;
	int dummy;
	char val;
};

extern int getopt_long(
	int argc,
	char *argv[],
	const char *long_option_string,
	struct option *pOptions,
	int *option_index);

extern int getopt_long_r(
	int argc,
	char *argv[],
	const char *long_option_string,
	struct option *pOptions,
	int *option_index,
	char **pp_optarg,
	int *p_optind);

#ifdef __cplusplus
}
#endif

#endif /* LIB_DSL_GETOPT_H */

