/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_config_api_h
#define _omci_config_api_h

/** \defgroup OMCI_CONFIG_API OMCI Config API
    @{
*/

/** U-boot environment variable name for Logical ONU ID */
#define OMCI_CFG_UBOOT_LOID_NAME	"omci_loid"
/** U-boot environment variable name for Logical Password */
#define OMCI_CFG_UBOOT_LPWD_NAME	"omci_lpwd"

/** Maximum LOID length (24 bytes per G.988) */
#define OMCI_CFG_LOID_LEN		24
/** Maximum LPWD length (12 bytes per G.988) */
#define OMCI_CFG_LPWD_LEN		12

/** Get Logical ONU ID from firmware environment
 *
 *  Reads "omci_loid" firmware env variable. Used for Chinese ISP
 *  LOID-based authentication.
 *
 *  \param[in]  context   OMCI context pointer
 *  \param[in]  me        Managed Entity pointer (unused, for getter compat)
 *  \param[out] data      Buffer to receive LOID string
 *  \param[in]  data_size Must be OMCI_CFG_LOID_LEN (24)
 *
 *  \return OMCI_SUCCESS on success
 */
enum omci_error omci_cfg_logical_onu_id_get(struct omci_context *context,
					    struct me *me,
					    void *data,
					    size_t data_size);

/** Get Logical Password from firmware environment
 *
 *  Reads "omci_lpwd" firmware env variable. Used for Chinese ISP
 *  LOID-based authentication.
 *
 *  \param[in]  context   OMCI context pointer
 *  \param[in]  me        Managed Entity pointer (unused, for getter compat)
 *  \param[out] data      Buffer to receive LPWD string
 *  \param[in]  data_size Must be OMCI_CFG_LPWD_LEN (12)
 *
 *  \return OMCI_SUCCESS on success
 */
enum omci_error omci_cfg_logical_password_get(struct omci_context *context,
					      struct me *me,
					      void *data,
					      size_t data_size);

/** Map network interface name to IP Host Config Data ME instance ID
 *
 *  \param[in]  ifname  Interface name ("host" or "lan")
 *
 *  \return ME instance ID (0 for "host", 1 for "lan", 0xFFFF for unknown)
 */
uint16_t omci_cfg_ip_host_me_id_get(const char *ifname);

/** @} */

#endif
