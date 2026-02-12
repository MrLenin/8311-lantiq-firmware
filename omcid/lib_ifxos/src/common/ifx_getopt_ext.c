/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   Extention to the getopt library.
*/

/* ==========================================================================
   includes
   ========================================================================== */

#include "ifxos_debug.h"
#include "ifx_getopt_ext.h"
#include "ifxos_std_defs.h"

/* ==========================================================================
   Local Defines
   ========================================================================== */
#define GET_OPT_EXT_StrLen          strlen
#define GET_OPT_EXT_StrNCpy         strncpy
#define GET_OPT_EXT_StrToUl         strtoul
#define GET_OPT_EXT_MemSet          memset
#define GET_OPT_EXT_IsSpace         isspace


/* ==========================================================================
   Local Variables
   ========================================================================== */
static IFXOS_PRN_USR_MODULE_CREATE(GET_OPT_EXT, IFXOS_PRN_LEVEL_OFF);


/* ==========================================================================
   Function Definitons
   ========================================================================== */

/*
   Takeover a required integer argument into the given integer control struct.
*/
IFX_void_t GetOptExt_RequiredDigit(
                              IFX_char_t           *pOptArg, 
                              GetOptExt_IntArg_t   *pUserIntArg,
                              IFX_char_t           *pDesc)
{
   IFX_uint_t temp;
   IFX_char_t *pEndPtr;

   if (pOptArg)
   {
      errno = 0;
      temp = (IFX_uint_t)GET_OPT_EXT_StrToUl(pOptArg, &pEndPtr, 0);
      if (errno)
      {
         IFXOS_PRN_USR_DBG_NL(GET_OPT_EXT, IFXOS_PRN_LEVEL_HIGH,
            ( "%s: invalid argument = 0x%08X (errno %d)" IFXOS_CRLF, 
              pDesc, (unsigned int)temp, errno));
      }
      else
      {
         pUserIntArg->intValue = temp;
         pUserIntArg->bSet     = IFX_TRUE;

         IFXOS_PRN_USR_DBG_NL(GET_OPT_EXT, IFXOS_PRN_LEVEL_LOW,
            ("%s: 0x%08X" IFXOS_CRLF, pDesc, (unsigned int)pUserIntArg->intValue));
      }
   }
   else
   {
      IFXOS_PRN_USR_DBG_NL(GET_OPT_EXT, IFXOS_PRN_LEVEL_HIGH,
         ("%s: missing argument" IFXOS_CRLF, pDesc));
   }

   return;
}

/*
   Takeover a required string argument into the given string control struct.
*/
IFX_void_t GetOptExt_RequiredStr(
                              IFX_char_t           *pOptArg,
                              GetOptExt_StrArg_t   *pUserStrArg,
                              IFX_char_t           *pDesc)
{
   IFX_size_t strLength;

   if (pOptArg)
   {
      if ( (strLength = GET_OPT_EXT_StrLen(pOptArg)) > 0)
      {
         GET_OPT_EXT_MemSet(pUserStrArg->strValue, 0x00, GET_OPT_EXT_MAX_STR_LEN);
         GET_OPT_EXT_StrNCpy(
            pUserStrArg->strValue, 
            (char *)pOptArg, 
            (strLength > (GET_OPT_EXT_MAX_STR_LEN -1)) ? (GET_OPT_EXT_MAX_STR_LEN -1) : strLength);
         pUserStrArg->bSet = IFX_TRUE;

         IFXOS_PRN_USR_DBG_NL(GET_OPT_EXT, IFXOS_PRN_LEVEL_LOW,
            ("%s: %s" IFXOS_CRLF, pDesc, pUserStrArg->strValue));
      }
   }
   else
   {
      IFXOS_PRN_USR_DBG_NL(GET_OPT_EXT, IFXOS_PRN_LEVEL_HIGH,
         ("%s: missing argument" IFXOS_CRLF, pDesc));
   }

   return;
}

/*
   Takeover an optional integer argument into the given integer control struct.
*/
IFX_void_t GetOptExt_OptionalDigit(
                              IFX_char_t           *pOptArg, 
                              GetOptExt_IntArg_t   *pUserIntArg,
                              IFX_char_t           *pDesc)
{
   IFX_uint_t temp;
   IFX_char_t *pEndPtr;

   /* mark command received */
   pUserIntArg->bSet = IFX_TRUE;
   
   if (pOptArg)
   {
      errno = 0;
      temp = (IFX_uint_t)GET_OPT_EXT_StrToUl(pOptArg, &pEndPtr, 0);
      if (errno)
      {
         IFXOS_PRN_USR_DBG_NL(GET_OPT_EXT, IFXOS_PRN_LEVEL_HIGH,
            ("%s: invalid argument = 0x%08X" IFXOS_CRLF, 
             pDesc, (unsigned int)temp));
      }
      else
      {
         IFXOS_PRN_USR_DBG_NL(GET_OPT_EXT, IFXOS_PRN_LEVEL_LOW,
            ("%s: 0x%08X" IFXOS_CRLF, pDesc, (unsigned int)temp));

         /* overwrite flag with optional argument */
         pUserIntArg->intValue = temp;

         IFXOS_PRN_USR_DBG_NL(GET_OPT_EXT, IFXOS_PRN_LEVEL_LOW,
            ("%s: 0x%08X" IFXOS_CRLF, pDesc, (unsigned int)pUserIntArg->intValue));
      }
   }

   return;
}

/**
   Takeover the given integer arguments into a separate array.

\return
   number of set arguments.
*/
IFX_int_t GetOptExt_TakeIntValues(
                                 GetOptExt_IntArg_t   *pIntArgArry,
                                 IFX_int_t            *pIntValueArray)
{
   IFX_int_t i, count = 0;

   for (i = 0; i < GET_OPT_EXT_MAX_INT_PARAMS; i++)
   {
      if (pIntArgArry[i].bSet)
      {
         pIntValueArray[i] = pIntArgArry[i].intValue;
         count++;
      }
   }

   return count;
}



/**
   Parse an given argument string and copy the single args into the given array.
*/
IFX_int_t GetOptExt_ParseArgString(
                              IFX_char_t  *pArgString,
                              IFX_char_t  *pArgArray[],
                              IFX_int_t   maxArgs)
{
   IFX_int_t   i, argIdx = 0;
   IFX_size_t  argStrLen;
   IFX_char_t  *pArgStart = pArgString;

   argStrLen = GET_OPT_EXT_StrLen(pArgStart);

   while(    (argStrLen > 0)
          && (argIdx < maxArgs) )
   {
      while(argStrLen > 0)
      {
         if (GET_OPT_EXT_IsSpace((int)*pArgStart))
         {
            pArgStart++;
            argStrLen--;
         }
         else
         {
            break;
         }
      }

      if (argStrLen > 0)
      {
         /* start found */
         if (   (*pArgStart == '"') || (*pArgStart == '\'') \
             || (*pArgStart == '`') || (*pArgStart == '´') )
         {
            IFX_char_t openTag = *pArgStart;
            /* scan encapsulates string */
            *pArgStart = '\0';
            pArgStart++;
            argStrLen--;

            pArgArray[argIdx] = pArgStart;
            argIdx++;
            
            while (argStrLen > 0)
            {
               if (*pArgStart == openTag)
               {
                  break;
               }
               pArgStart++;
               argStrLen--;
            }

            if ((argStrLen > 0) && (*pArgStart == openTag))
            {
               /* closetag found */
               *pArgStart = '\0';
               pArgStart++;
               argStrLen--;
            }
            
            continue;
         }
         else
         {
            pArgArray[argIdx] = pArgStart;
            argIdx++;
         }

         while(argStrLen > 0)
         {
            if (!GET_OPT_EXT_IsSpace((int)*pArgStart))
            {
               pArgStart++;
               argStrLen--;
            }
            else
            {
               break;
            }
         }

         if (argStrLen > 0)
         {
            /* Next Found, terminate previous */
            *pArgStart = '\0';
            pArgStart++;
            argStrLen--;
         }
#if 0
--> already terminated
         else
         {
            /* End reached, terminate previous */
            pArgStart--;
            *pArgStart = '\0';
         }
#endif
      }
   }

   for (i = argIdx; i < maxArgs; i++)
   {
      pArgArray[i] = IFX_NULL;
   }

   return argIdx;
}



