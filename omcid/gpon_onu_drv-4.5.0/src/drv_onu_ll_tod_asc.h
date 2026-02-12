/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#if defined(ONU_TOD_ASC1) && defined(LINUX) && defined(__KERNEL__)
/** Initialize ASC1

   \note SLIC functionality should be disabled beforehand!
*/
int onu_asc1_init(void);

/** Print string to ASC1

   \param[in] s String to print
*/
void onu_asc1_puts(const char *s);
#else
static inline int onu_asc1_init(void) { return 0; }
static inline void onu_asc1_puts(const char *s) { };
#endif
