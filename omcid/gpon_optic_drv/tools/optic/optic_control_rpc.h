/******************************************************************************

                              Copyright (c) 2012
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _onu_control_rpc_h
#define _onu_control_rpc_h

/** \defgroup ONU_CONTROL_RPC RPC interface

   @{
*/

/** Initialize remote device connection

   \param[in] remote_ip   Remote IP address
*/
int remote_init(const char *remote_ip);

/** Terminate remote device */
int remote_shutdown(void);

/** Device open wrapper, it opens the remote connection.

   \param[in] dev_name_str   device name
*/
int remote_device_open(const char *dev_name_str);

/** Device close wrapper, it closes the remote connection.
   \param[in]     fd device descriptor
*/
int remote_device_close(const int fd);

/** Wait for events from remote device

   \param[in] fd1 first device descriptor
   \param[in] fd2 first device descriptor
   \param[in] timeout Wait timeout in ms
*/
int remote_device_event_wait(const int fd, void *data, const unsigned int max_size);

/** Device control wrapper

   \param[in]     fd device descriptor
   \param[in]     cmd Command
   \param[in,out] p_data Additional data
*/
int remote_dev_ctl(const int fd,
		  const unsigned int cmd, void *p_data, unsigned int size);

/** Device control wrapper

   \param[in]     fd device descriptor
   \param[in,out] p_data Destination data pointer
   \param[in]     max_sz Max. destination buffer size
*/
int remote_notification_read(const int fd,
			    void *p_data, const unsigned int max_sz);

/** @} */

#endif
