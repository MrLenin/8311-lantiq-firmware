/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   This file contains a OS independent device IO control layer - 
   Device Input, Output, Control
*/
#include <string.h>     /* strncmp */

#if (defined(IFXOS_USE_DEV_IO) && (IFXOS_USE_DEV_IO == 1))

/* ============================================================================
   Device IO - Includes
   ========================================================================= */
#include "ifxos_device_io.h"
#include "ifxos_time.h"
#include "ifxos_mutex.h"
#include "ifxos_thread.h"

/* ============================================================================
   Device IO - Local Defines and Types
   ========================================================================= */

/**
   Device IO - device driver function table
*/
typedef struct
{
   unsigned int         in_use;
   DEVIO_device_open    device_open;
   DEVIO_device_close   device_close;
   DEVIO_device_read    device_read;
   DEVIO_device_write   device_write;
   DEVIO_device_ioctl   device_ioctl;
   DEVIO_device_poll    device_poll;
} DEVIO_driver_t;


/**
   Device IO - device private data.
*/
typedef struct
{
   unsigned int   in_use;
   unsigned int   driver_number;
   char           name[DEVIO_MAXDEVNAME];
   void           *device;
} DEVIO_device_t;


/**
   Device IO - open instance
*/
typedef struct
{
   int   device_number;
   void  *priv;
} DEVIO_fd_t;


/** Device IO - driver table */
static DEVIO_driver_t DEVIO_driver_table[DEVIO_MAXDRIVERS];
/** Device IO - device table */
static DEVIO_device_t DEVIO_device_table[DEVIO_MAXDEVICES];
/** Device IO - open instances of devices */
static DEVIO_fd_t DEVIO_fd_table[DEVIO_MAXFDS];
/** Mutex to protect the tables */
static IFXOS_mutex_t mutex;


/* ============================================================================
   Device IO - Device and driver functions
   ========================================================================= */

/**
   Device IO - Install a new driver to the Device IO Layer.
*/
unsigned int DEVIO_driver_install ( 
                        DEVIO_device_open   device_open,
                        DEVIO_device_close  device_close,
                        DEVIO_device_read   device_read,
                        DEVIO_device_write  device_write,
                        DEVIO_device_ioctl  device_ioctl, 
                        DEVIO_device_poll   device_poll )
{
   unsigned int i, nRet = ( unsigned int ) -1;
   static unsigned int first;

   IFXOS_ThreadLock();

   if ( first == 0 )
   {
      IFXOS_MutexInit(&mutex);

      first = 1;
      for ( i = 0; i < DEVIO_MAXFDS; i++ )
      {
         DEVIO_fd_table[i].device_number = -1;
         memset ( &DEVIO_driver_table, 0x00, sizeof ( DEVIO_driver_table ) );
      }
   }

   IFXOS_ThreadUnlock();

   IFXOS_MutexGet(&mutex);

   for ( i = 0; i < DEVIO_MAXDRIVERS; i++ )
   {
      if ( DEVIO_driver_table[i].in_use == 0 )
      {
         DEVIO_driver_table[i].in_use = 1;

         DEVIO_driver_table[i].device_open   = device_open;
         DEVIO_driver_table[i].device_close  = device_close;
         DEVIO_driver_table[i].device_read   = device_read;
         DEVIO_driver_table[i].device_write  = device_write;
         DEVIO_driver_table[i].device_ioctl  = device_ioctl;
         DEVIO_driver_table[i].device_poll   = device_poll;
         nRet = i;
         break;
      }
   }

   IFXOS_MutexRelease(&mutex);

   return ( nRet );
}

/**
   Device IO - Remove a driver from the Device IO Layer.
*/
void DEVIO_driver_remove(
                        unsigned int   driver_num, 
                        int            force )
{
   IFXOS_MutexGet(&mutex);

   if ( ( driver_num < DEVIO_MAXDRIVERS ) && ( DEVIO_driver_table[driver_num].in_use ) )
   {
      DEVIO_driver_table[driver_num].in_use = 0;

      DEVIO_driver_table[driver_num].device_open  = 0;
      DEVIO_driver_table[driver_num].device_close = 0;
      DEVIO_driver_table[driver_num].device_read  = 0;
      DEVIO_driver_table[driver_num].device_write = 0;
      DEVIO_driver_table[driver_num].device_ioctl = 0;
      DEVIO_driver_table[driver_num].device_poll  = 0;
   }

   IFXOS_MutexRelease(&mutex);
}

/**
   Device IO - Add a device to the device IO layer.
*/
unsigned int DEVIO_device_add(
                        void           *device, 
                        const char     *name, 
                        unsigned int   driver_number )
{
   unsigned int i, k, nRet = ( unsigned int ) -1;

   if ( ( name == 0 ) || ( device == 0 ) || ( driver_number >= DEVIO_MAXDRIVERS ) )
   {
      return ( nRet );
   }

   IFXOS_MutexGet(&mutex);

   /* assign next free entry in device table to this device */
   for ( i = 0; i < DEVIO_MAXDEVICES; i++ )
   {
      if ( DEVIO_device_table[i].in_use == 0 )
      {
         DEVIO_device_table[i].in_use = 1;
         DEVIO_device_table[i].device = device;
         DEVIO_device_table[i].driver_number = driver_number;

         for ( k = 0; k < DEVIO_MAXDEVNAME; k++ )
         {
            DEVIO_device_table[i].name[k] = name[k];
            if ( name[k] == 0 )
               break;
         }
         if ( k == DEVIO_MAXDEVNAME )
         {
            DEVIO_device_table[i].name[k - 1] = 0;
         }

         nRet = 0;
         break;
      }
   }

   IFXOS_MutexRelease(&mutex);

   return ( nRet );
}

/**
   Device IO - Delete a device from the device IO layer.
*/
void DEVIO_device_delete(
                        void *device )
{
   unsigned int i;

   IFXOS_MutexGet(&mutex);

   for ( i = 0; i < DEVIO_MAXDEVICES; i++ )
   {
      if ( DEVIO_device_table[i].device != device )
         continue;

      DEVIO_device_table[i].in_use  = 0;
      DEVIO_device_table[i].name[0] = 0;
      DEVIO_device_table[i].driver_number = 0;
      break;
   }

   IFXOS_MutexRelease(&mutex);
}


/**
   Device IO - Open a device.
*/
int DEVIO_open ( const char *name )
{
   int i, nRet = -1, len, lenDevTableEntry;
   int foundDeviceTableEntry = -1, maxMatchingLen = 0;
   void *priv;
   DEVIO_device_t    *pDevice;
   DEVIO_device_open foo = NULL;

   if ( name == NULL || name[0] == '0' )
   {
      return -1;
   }

   len = (int)strlen ( name );
   IFXOS_MutexGet(&mutex);

   for ( i = 0; i < DEVIO_MAXDEVICES; i++ )
   {
      pDevice = &DEVIO_device_table[i];
      lenDevTableEntry = (int)strlen ( pDevice->name );


      if (len < lenDevTableEntry)
      {
         /* goon - no match */
         continue;
      }

      if ( strncmp ( name, pDevice->name, lenDevTableEntry ) )
      {
         continue;
      }

      if (len == lenDevTableEntry)
      {
         /* exact match -> found */
         if (DEVIO_driver_table[pDevice->driver_number].device_open)
         {
            foundDeviceTableEntry = i;
            maxMatchingLen        = lenDevTableEntry;
            break;
         }
      }
      else
      {
         /* check for best match */
         if ( (lenDevTableEntry > maxMatchingLen) &&
              (DEVIO_driver_table[pDevice->driver_number].device_open) )
         {
            foundDeviceTableEntry = i;
            maxMatchingLen        = lenDevTableEntry;
         }
      }
   }

   if (foundDeviceTableEntry != -1)
   {
      /* driver entry found */
      pDevice = &DEVIO_device_table[foundDeviceTableEntry];
      foo     = DEVIO_driver_table[pDevice->driver_number].device_open;
      
      IFXOS_MutexRelease(&mutex);
      
      /* call open function of device driver - best base dev name + appendix */
      priv = ( void * ) foo(pDevice->device, name + maxMatchingLen);

      IFXOS_MutexGet(&mutex);

      /* check if valid ptr */
      if (( ( IFX_intptr_t ) priv != -1 ) && ( ( IFX_intptr_t ) priv != 0 ))
      {
         for ( i = 0; i < DEVIO_MAXFDS; i++ )
         {
            /* assign next free filedescriptor to device */
            if ( DEVIO_fd_table[i].device_number == -1 )
            {
               DEVIO_fd_table[i].device_number = foundDeviceTableEntry;
               DEVIO_fd_table[i].priv          = priv;
               nRet = i;
               break;
            }
         }
      }
   }

   IFXOS_MutexRelease(&mutex);

   return ( nRet );
}

/**
   Device IO - Close a device.
*/
int DEVIO_close ( const int fd )
{
   int nRet = -1;
   unsigned int dev_no, drv_no;
   void *priv = NULL;
   DEVIO_device_close foo = NULL;

   if ( fd < DEVIO_MAXFDS )
   {
      if ( fd >= 0 )
      {
         IFXOS_MutexGet(&mutex);
         
         dev_no = DEVIO_fd_table[fd].device_number;
         priv = DEVIO_fd_table[fd].priv;
         if ( (dev_no < DEVIO_MAXDEVICES)
              && ( ( drv_no = DEVIO_device_table[dev_no].driver_number ) < DEVIO_MAXDRIVERS ) )
         {
            /* clear entry in file descriptor list */
            DEVIO_fd_table[fd].device_number = ( -1 );
            DEVIO_fd_table[fd].priv = NULL;
   
            foo = DEVIO_driver_table[drv_no].device_close ;
         }
      
         IFXOS_MutexRelease(&mutex);
      }
   
      if(foo)
         nRet = foo ( priv );
   }
   
   return ( nRet );
}

/**
   Device IO - Write to a device.
*/
int DEVIO_write ( const int fd, const void *pData, const unsigned int nSize )
{
   unsigned int dev_no, drv_no;
   int nRet = -1;
   void *priv = NULL;
   DEVIO_device_write foo=NULL;

   if ( fd < DEVIO_MAXFDS )
   {
      if ( fd >= 0 )
      {
         IFXOS_MutexGet(&mutex);
      
         dev_no = DEVIO_fd_table[fd].device_number;
         priv = DEVIO_fd_table[fd].priv;
         if ( (dev_no < DEVIO_MAXDEVICES)
              && ( ( drv_no = DEVIO_device_table[dev_no].driver_number ) < DEVIO_MAXDRIVERS ) )
         {
            foo = DEVIO_driver_table[drv_no].device_write;
         }
         
         IFXOS_MutexRelease(&mutex);
      }
      
      if(foo)
          nRet =  foo( priv, (const char *)pData, nSize );
   }
   
   return ( nRet );
}

/**
   Device IO - Read from a device.
*/
int DEVIO_read ( const int fd, void *pData, const unsigned int nSize )
{
   unsigned int dev_no, drv_no;
   int nRet = -1;
   void *priv = NULL;
   DEVIO_device_read foo=NULL;

   if ( fd < DEVIO_MAXFDS )
   {
      if ( fd >= 0 )
      {
         IFXOS_MutexGet(&mutex);
      
         dev_no = DEVIO_fd_table[fd].device_number;
         priv = DEVIO_fd_table[fd].priv;
         if ( (dev_no < DEVIO_MAXDEVICES)
              && ( ( drv_no = DEVIO_device_table[dev_no].driver_number ) < DEVIO_MAXDRIVERS ) )
         {
            foo = DEVIO_driver_table[drv_no].device_read;
         }
      
         IFXOS_MutexRelease(&mutex);
      }
      
      if(foo)
         nRet = foo ( priv, (char *)pData, nSize );    
   }
   
   return ( nRet );
}

/**
   Device IO - ioctl command.
*/
int DEVIO_ioctl ( const int fd, const unsigned int cmd, IFX_ulong_t param )
{
   unsigned int dev_no, drv_no;
   int nRet = -1;
   void *priv = NULL;
   DEVIO_device_ioctl foo = NULL;

   if ( fd < DEVIO_MAXFDS )
   {
      if ( fd >= 0 )
      {
         IFXOS_MutexGet(&mutex);
         
         dev_no = DEVIO_fd_table[fd].device_number;
         priv = DEVIO_fd_table[fd].priv;
         if ( (dev_no < DEVIO_MAXDEVICES)
              && ( ( drv_no = DEVIO_device_table[dev_no].driver_number ) < DEVIO_MAXDRIVERS ) )
         {
            foo = DEVIO_driver_table[drv_no].device_ioctl;
         }
         
         IFXOS_MutexRelease(&mutex);
      }
   
      if(foo)   
         nRet = foo ( priv, cmd, param );
   }
   
   return ( nRet );
}


/**
   Device IO - Device select.

\param
   max_fd         max FD value within the given fd_set struct plus 1
\param
   read_fd_in     given FD's to check [IN]
\param
   read_fd_out    found FD's which contains data [OUT]
\param
   timeout_msec   wait time in [msec]
                  0: used for poll, checks the given FD's and returns immediately.
                  -1 (0xFFFFFFFF): wait forever.
\return
   return 

*/
int DEVIO_select ( const unsigned int max_fd, const DEVIO_fd_set_t * read_fd_in,
                  DEVIO_fd_set_t * read_fd_out, const unsigned int timeout_msec )
{
   int fd, k, nRet = 0;
   unsigned int dev_no, drv_no, t = 0;
   void *priv;

   if(read_fd_out)
   {
      memset(read_fd_out, 0x00, sizeof(DEVIO_fd_set_t));
   }

   if ( read_fd_in == 0 )
   {
      return -1;
   }

   while ( nRet == 0 )
   {
      for ( fd = 0; fd < (int)max_fd; fd++ )
      {
         if (fd >= DEVIO_MAXFDS)
         {
            return -1;
         }
         if ( read_fd_in->fds[fd] == 0 )
         {
            continue;
         }
         dev_no = DEVIO_fd_table[fd].device_number;
         priv = DEVIO_fd_table[fd].priv;
         if ( dev_no < DEVIO_MAXDEVICES
              && ( ( drv_no = DEVIO_device_table[dev_no].driver_number ) < DEVIO_MAXDRIVERS ) )
         {
            if ( DEVIO_driver_table[drv_no].device_poll != NULL )
            {
               k = DEVIO_driver_table[drv_no].device_poll ( priv );
               if ( read_fd_out && k )
               {
                  read_fd_out->fds[fd] = 1;
               }
               nRet |= k;
            }
         }
      }

      if ( ( nRet ) || (timeout_msec == 0) || (t > timeout_msec) )
         break;

      if (timeout_msec != (unsigned int)(-1))
      {
         t += DEVIO_SELECT_POLLING_TIME;
      }

      IFXOS_MSecSleep ( DEVIO_SELECT_POLLING_TIME );
   }

   return nRet;
}



void DEVIO_fd_set(const unsigned int  fd, DEVIO_fd_set_t *set)
{
   if(set && (fd < DEVIO_MAXFDS))
   {
      set->fds[fd] = 1;
   }
}

int DEVIO_fd_isset(const unsigned int  fd, const DEVIO_fd_set_t *set)
{
   if((set == 0) || (fd >= DEVIO_MAXFDS))
   {
      return 0;
   }
   return set->fds[fd];
}

void DEVIO_fd_clear(const unsigned int  fd, DEVIO_fd_set_t *set)
{
   if(set && (fd < DEVIO_MAXFDS))
   {
      set->fds[fd] = 0;
   }
}

void DEVIO_fd_zero(DEVIO_fd_set_t *set)
{
   int i;
   
   if(set == 0)
   {
      return;
   }

   for(i=0;i<DEVIO_MAXFDS;i++)
   {
      set->fds[i] = 0;
   }
}

#endif      /* #if (defined(IFXOS_USE_DEV_IO) && (IFXOS_USE_DEV_IO == 1)) */
