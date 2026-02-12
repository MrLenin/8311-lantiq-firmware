/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   Module for read and write access to files in a windows .ini format.
*/

/* ===========================
   Includes
   =========================== */
#include "ifx_types.h"
#include "ifx_ini_access.h"
#include "ifxos_std_defs.h"
#include "ifxos_memory_alloc.h"

#undef INI_VERBOSE

#ifndef IFX_INI_LINE_LENGTH
/** maximum line length */
#define IFX_INI_LINE_LENGTH 1024
#endif

/* FIXME:
   SetKeyInt and
   SetKeyString are missing */


/**
   The GetKeyInt function retrieves an integer associated with a key in the
   specified section of an initialization file (buffered in array at pFile).

\return
   The return value is the value of the desired key if found,
   otherwise the value of nDefault.
*/
IFX_int32_t GetKeyInt(
   IFX_char_t* pSectionName,  /**< section name */
   IFX_char_t* pKeyName,      /**< key name */
   IFX_int32_t nDefault,      /**< return value if key name not found */
   IFX_char_t* pFile          /**< pointer to file data (array with \0 at end) */)
{
   IFX_char_t  RetString[15], sDefault[15];
   IFX_int32_t ret = nDefault;

   snprintf(sDefault, sizeof(sDefault), "%d", nDefault);
   RetString[sizeof(sDefault)-1] = '\0';

   if ( GetKeyString(pSectionName, pKeyName, sDefault, &RetString[0],
      sizeof(RetString), pFile) > 0 )
   {
      /* get assigned value of the key and return */
      if ( RetString[0] == '0' && RetString[1] == 'x' )
      {
         ret = strtoul(RetString, IFX_NULL, 16);
         #ifdef INI_VERBOSE
         printf("Hexval 0x%X\r\n", ret);
         #endif
      }
      else
      {
         ret = strtoul(RetString, IFX_NULL, 10);
         #ifdef INI_VERBOSE
         printf("Decval %ld\r\n", ret);
         #endif
      }
   }
   return ret;
}


/**
   The GetKeyString function retrieves a string from the specified section in
   an initialization file (buffered in array at pFile).

\return
   The return value is the number of caracters copied to the buffer, not
   including the terminating null caracter.
*/
IFX_int32_t GetKeyString(
   IFX_char_t* pSectionName,  /**< section name */
   IFX_char_t* pKeyName,      /**< key name */
   IFX_char_t* pDefault,      /**< return value if key name not found */
   IFX_char_t* pRetString,    /**< destination buffer */
   IFX_int32_t nSize,           /**< size of destination buffer */
   IFX_char_t* pFile          /**< pointer to file data (array with \0 at end) */
)
{
   IFX_char_t  *pLine=IFX_NULL;
   IFX_int32_t ret = 0;
   IFX_char_t *pInput,
        *pSectEnd,
        *pTok,
        *pKey,
        *pVal;
   IFX_int32_t i;
   IFX_int32_t bSection = 0;

   if (pRetString==IFX_NULL)
      return IFX_ERROR;

   if ((pSectionName==IFX_NULL) || (pKeyName==IFX_NULL))
   {
      *pRetString = '\0';
      return IFX_ERROR;
   }

   pInput = pFile;

   pLine = (IFX_char_t *)IFXOS_MemAlloc(IFX_INI_LINE_LENGTH);
   if (pLine == IFX_NULL) {
      return IFX_ERROR;
   }

   do
   {
      /* get a line from the "file" */
      i = GetNextLine(pInput, pLine, IFX_INI_LINE_LENGTH);
      if ((i==0) || (pLine[0]=='\0'))
         break;
      pInput += i;

      /* look for section name */
      if ( pLine[0]=='[' )
      {
         if (bSection == 1) break; /* next (other) section */
         pSectEnd = strchr(pLine, ']');
         if (pSectEnd!=IFX_NULL)
         {
            *pSectEnd = '\0';  /* mark as string end */

            /* is this our requested section? */
            if (strcmp(pSectionName, &pLine[1]) == 0)
            {
               #ifdef INI_VERBOSE
               printf("Found section '%s'\r\n", pSectionName);
               #endif
               bSection = 1;
            }
         }
         continue;   /* FIXME ??? */
      }
      else
      {
         /* we are in a section */
         if (bSection == 1)
         {
            /* we are in the requested section */
            pKey = strtok_r(pLine, "=", &pTok);
            if(pKey == IFX_NULL)
            {
               continue;
            }
            pVal = strtok_r(IFX_NULL, "\r", &pTok);
            if(pVal == IFX_NULL)
            {
               continue;
            }
            /* is this the requested key? */
            if (strcmp(pKeyName, pKey) == 0)
            {
               #ifdef INI_VERBOSE
               printf("Found pKey '%s' pVal '%s'\r\n", pKey, pVal);
               #endif
               /* get assigned value of the key and return */
               strncpy(pRetString, pVal, nSize-1);
               /* make sure, we have an end marker */
               pRetString[nSize-1] = '\0';
               ret = (IFX_int32_t)strlen(pRetString);
               break;
            }
         }
      }
   }
   while ( *pInput != '\0');

   /* prepare the default string */
   if (ret == 0)
   {
      *pRetString = '\0';
      if (pDefault != IFX_NULL)
      {
         strncpy(pRetString, pDefault, nSize-1);
         /* make sure, we have an end marker */
         pRetString[nSize-1] = '\0';
         ret = (IFX_int32_t)strlen(pRetString);
      }
   }

   IFXOS_MemFree(pLine);

   return ret;
}


/**
   Fill the whole desired section into the given buffer.

\return
   number of caracters copied
*/
IFX_int32_t GetSection(
   IFX_char_t *pSectionName,  /**< Name of the section to retrieve */
   IFX_char_t *pBuffer,       /**< pointer to put copy the data to */
   IFX_int32_t nBufferSize,   /**< size of the given buffer */
   IFX_char_t* pFile          /**< \0 terminated array to search the section in */
)
{
   IFX_char_t  *pLine=IFX_NULL;
   IFX_int32_t nSectLen;
   IFX_char_t *pInput,
        *pSectStart,
        *pSectEnd,
        *pSectNameEnd;
   IFX_int32_t i;
   IFX_boolean_t bSectionFound = IFX_FALSE;

   if (pSectionName==IFX_NULL || pBuffer == IFX_NULL)
      return IFX_ERROR;

   pInput = pFile;

   pLine = (IFX_char_t *)IFXOS_MemAlloc(IFX_INI_LINE_LENGTH);
   if(pLine == IFX_NULL) 
   {
      return IFX_ERROR;
   }

   do
   {
      /* search the section start */
      pSectStart=pInput;
      /* get a line from the "file" */
      i = GetNextLine(pInput, pLine, IFX_INI_LINE_LENGTH);
      if ((i==0) || (pLine[0]=='\0'))
         break;
      pInput += i;

      /* look for section name */
      if ( pLine[0]=='[' )
      {
         pSectNameEnd = strchr(pLine, ']');
         if (pSectNameEnd!=IFX_NULL)
         {
            *pSectNameEnd = '\0';  /* mark as string end */

            /* is this our requested section? */
            if (strcmp(pSectionName, &pLine[1]) == 0)
            {
               #ifdef INI_VERBOSE
               printf("Found section '%s'\r\n", pSectionName);
               #endif
               bSectionFound = IFX_TRUE;
               break;
            }
         }
         continue;   /* FIXME ??? */
      }
   }
   while ( *pInput != '\0');

	if (bSectionFound == IFX_FALSE) {
		IFXOS_MemFree(pLine);
      return 0;
	}

   do
   {
      /* find the end of this section */
      pSectEnd = pInput;

      /* get a line from the "file" */
      i = GetNextLine(pInput, pLine, IFX_INI_LINE_LENGTH);
      if ((i==0) || (pLine[0]=='\0'))
         break;
      pInput += i;

      /* look for section name */
      if ( pLine[0]=='[' )
      {
         break; /* next (other) section starts here */
      }
      else
      {
         /* this line belongs to the required section */
         pSectEnd = pInput;
      }
   }
   while ( *pInput != '\0');

   /* copy the section or as much as fits into the buffer, terminate by \0 */
   nSectLen = (IFX_int32_t)(pSectEnd - (pSectStart - 1));
   if (nSectLen+1 > nBufferSize)
      nSectLen = nBufferSize - 1;

   memcpy (pBuffer, pSectStart, nSectLen);
   pBuffer[nSectLen] = '\0';

   IFXOS_MemFree(pLine);

   return nSectLen+1;
}

/**
   get one line of config file without \r\n, but closing \0 .
   Skips \r and \n until begining of line with data.

\return
   number of caracters from pData to end of line
   (to skip this line in buffer of calling function)

\remark
   The pData buffer should contain a null terminated file.
*/
IFX_int32_t GetNextLine(
   IFX_char_t* pData,      /**< start of data to scan */
   IFX_char_t* pRetLine,   /**< return buffer for line */
   IFX_int32_t nLine         /**< max space in return buffer */
)
{
   IFX_char_t *pIn;
   IFX_int32_t ret=0;
   IFX_int32_t i;

   if (pData==IFX_NULL)
   {
      *pRetLine = '\0';
      return IFX_SUCCESS;
   }
   pIn = pData;
   i=0;

   /* skip line ends */
   while (*pIn=='\r' || *pIn=='\n')
   {
      pIn++;
      ret++;
   }

   while (i<nLine-1)
   {
      *pRetLine = *pIn;
      pIn++;

      /* break on line or string end */
      if ((*pRetLine == '\r') || (*pRetLine == '\n'))
      {
         ret++;
         break;
      }

      /* break on file end */
      if (*pRetLine == '\0')
      {
         break;
      }

      ret++;
      i++;
      pRetLine++;
   }
   *pRetLine = '\0';

   return ret;
}


