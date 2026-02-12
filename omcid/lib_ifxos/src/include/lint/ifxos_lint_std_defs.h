#ifndef _IFXOS_LINT_STD_DEFS_H
#define _IFXOS_LINT_STD_DEFS_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   Function proto-types for LINT processing of the IFXOS based SW.
*/

#ifdef __cplusplus
extern "C"
{
#endif

#ifdef _lint

/**
\para Not Mapped Functions clib functions
   For this function there is no special mapped IFXOS function. They are only 
   mapped to the corresponding standard function.

   For LINT processing only the proto-types are defined.

*/

/* ==========================================================================
   defines
   ========================================================================== */

#define NULL               IFX_NULL
#define EXIT_SUCCESS       0

#define	IOC_VOID	         0x20000000

#ifndef _IO
#define	_IO(x,y)	         (IOC_VOID|((x)<<8)|y)
#endif

/** size_t for proto type definitons */
typedef  int      size_t;
typedef struct 
{
   int      dummy;
} FILE;

/* ==========================================================================
   Function proto-types - stdio.h.
   ========================================================================== */

extern FILE    *stdout;

/**
   Define the function proto type for "printf"

   Proto Type:    printf
   defined in:    stdio.h
*/
int printf(const char *format, ...);

/**
   Define the function proto type for "sprintf"

   Proto Type:    sprintf
   defined in:    stdio.h
*/
int sprintf(char *str, const char *format, ...);

/**
   Define the function proto type for "sscanf"

   Proto Type:    sscanf
   defined in:    stdio.h
*/
int sscanf(const char *str, const char *format, ...);

/* ==========================================================================
   Function proto-types - string.h
   ========================================================================== */

/**
   Define the function proto type for "strlen"

   Proto Type:    strlen
   defined in:    string.h
*/
size_t strlen(const char *s);

/**
   Define the function proto type for "strcpy"

   Proto Type:    strcpy
   defined in:    string.h
*/
char *strcpy(char *dest, const char *src);

/**
   Define the function proto type for "strncpy"

   Proto Type:    strncpy
   defined in:    string.h
*/
char *strncpy(char *dest, const char *src, size_t n);

/**
   Define the function proto type for "strncmp"

   Proto Type:    strncmp
   defined in:    string.h
*/
int strncmp(const char *s1, const char *s2, size_t n);

/**
   Define the function proto type for "memset"

   Proto Type:    memset
   defined in:    string.h
*/
void *memset(void *s, int c, size_t n);

/**
   Define the function proto type for "memcpy"

   Proto Type:    memcpy
   defined in:    string.h
*/
void *memcpy(void *dest, const void *src, size_t n);


/**
   Define the function proto type for "strerror"

   Proto Type:    strerror
   defined in:    string.h
*/
char *strerror(int errnum);

/* ==========================================================================
   Function proto-types - stdlib.h
   ========================================================================== */

/**
   Define the function proto type for "strtoul"

   Proto Type:    strtoul
   defined in:    stdlib.h
*/
unsigned long int strtoul(const char *nptr, char **endptr, int base);


/* ==========================================================================
   Function proto-types - ctype.h
   ========================================================================== */

/**
   Define the function proto type for "isxdigit"

   Proto Type:    isxdigit
   defined in:    ctype.h
*/
int isxdigit(int c);

/**
   Define the function proto type for "isspace"

   Proto Type:    isspace
   defined in:    ctype.h
*/
int isspace(int c);

/**
   Define the function proto type for "isprint"

   Proto Type:    isprint
   defined in:    ctype.h
*/
int isprint(int c);

/**
   Define the function proto type for "isdigit"

   Proto Type:    isdigit
   defined in:    ctype.h
*/
int isdigit(int c);

/**
   Define the function proto type for "isalpha"

   Proto Type:    isalpha
   defined in:    ctype.h
*/
int isalpha(int c);

/**
   Define the function proto type for "isalnum"

   Proto Type:    isalnum
   defined in:    ctype.h
*/
int isalnum(int c);

/* ==========================================================================
   Extern Data declaration - errno.h
   ========================================================================== */

extern int errno;

/* ==========================================================================
   Definitons for socket handling
   ========================================================================== */

#define	AF_INET		   2

/* ==========================================================================
   Function proto-types - netinet/in.h
   ========================================================================== */

/**
   Define the function proto type for "htonl"

   Proto Type:    htonl
   defined in:    netinet/in.h
*/
unsigned int htonl(unsigned int c);

/**
   Define the function proto type for "htons"

   Proto Type:    htons
   defined in:    netinet/in.h
*/
unsigned short htons(unsigned short c);

/**
   Define the function proto type for "ntohl"

   Proto Type:    ntohl
   defined in:    netinet/in.h
*/
unsigned int ntohl(unsigned int c);

/**
   Define the function proto type for "ntohs"

   Proto Type:    ntohs
   defined in:    netinet/in.h
*/
unsigned short ntohs(unsigned short c);


#endif   /* #ifdef _lint */

#ifdef __cplusplus
/* extern "C" */
}
#endif

#endif      /* #define _IFXOS_LINT_STD_DEFS_H */

