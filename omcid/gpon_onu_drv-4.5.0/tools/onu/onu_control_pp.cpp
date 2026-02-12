#ifdef LINUX

#include <getopt.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <linux/types.h>
#include <iostream>
#include <fstream>

using namespace std;

#include "drv_onu_std_defs.h"
#include "drv_onu_interface.h"
#include "drv_onu_resource.h"
#include "drv_onu_common_interface.h"
#include "drv_onu_ploam_interface.h"
#include "drv_onu_lan_interface.h"
#include "drv_onu_gpe_interface.h"
#include "drv_onu_gtc_interface.h"

#define ONU_DEVICE_PATH "/dev/onu/0"

/** version string */
#define CTRL_WHAT_STR "@(#)ONU control ++, version " onu_ver_str

/** what string support */
const char CTRL_WHATVERSION[] = CTRL_WHAT_STR;

static struct option long_options[] = {
   {"help", 0, 0, 'h'},
   {"version", 0, 0, 'v'},
   {NULL, 0, 0, 0}
};

/* 1 colon means there is a required parameter */
/* 2 colons means there is an optional parameter */
static const char GETOPT_LONG_OPTSTRING[] = "hv";

/**
   description of command line options
*/
static const char *description[] = {
   "help screen",
   "version"
};

static int g_bHelp;
static int g_bVersion;

/**
   Parse all arguments and enable requested features.

   \param argc number of parameters
   \param argv array of parameter strings

   \return
   - 0 if all parameters decoded
   - -1 if not all parameters could be decoded
*/
static int ONU_ArgsParse(
   char argc,
   char *argv[])
{
   int option_index = 0;

   while (1) {
      int c;

      /* 1 colon means there is a required parameter */
      /* 2 colons means there is an optional parameter */
      c = getopt_long(argc, argv, GETOPT_LONG_OPTSTRING, long_options,
                      &option_index);
      if (c == -1) {
         break;
      }

      switch (c) {
         case 'h':
            g_bHelp = 1;
            break;
         case 'v':
            g_bVersion = 1;
            break;
         default:
            cerr <<"Sorry, there is an unrecognized option" << endl;
            return -1;
      }
   }
   return 0;
}

/**
   Print the help text to the terminal.

   \return
   - 0
   - -1
*/
static int ONU_Usage(
   const char *pAppName)
{
   struct option *ptr;
   const char **desc = &description[0];
   uint32_t len = 0, fillLen = 0;
   static const char *fill = "             ";

   ptr = long_options;

   cout << "usage: " << pAppName << " [options] | <cli command>" << endl;
   cout << "example: " << pAppName << "onuvg" << endl;
   cout << CTRL_WHATVERSION << endl;

   while (ptr->name) {
      len = strlen(ptr->name);
      fillLen = strlen(fill);
      if (fillLen > 1)
         fillLen = (int)(fillLen - 1);
      if (len > fillLen)
         len = fillLen;
      cout << " --" << ptr->name << &fill[len] << "(-" << ptr->val << ")\t- %s" << *desc << endl;
      ptr++;
      desc++;
   }

   return 0;
}

/**
   Print the version info to the terminal.

   \return
   - 0
   - -1
*/
static int ONU_Version(void
   )
{
   int fd, ret = -1;
   struct fio_exchange ex;
   struct onu_version_string data;

   ex.p_data = &data;

   fd = open(ONU_DEVICE_PATH, O_RDWR, 0644);

   if (fd >= 0) {
      ret = ioctl(fd, FIO_ONU_VERSION_GET, (long)&ex);
      if (ret == 0) {
         if (ex.error == 0 && ex.length == 80) {
            cout << &data.onu_version[0] << endl;
         } else {
            cerr <<"ERROR: operation failed" << endl;
         }
      } else {
         cerr <<"ERROR: can't read version from device\n" << endl;
      }
      close(fd);
   } else {
      cerr << "ERROR: can't open device " ONU_DEVICE_PATH "." << endl;
   }

   return ret;
}

#ifdef INCLUDE_CLI_SUPPORT
static int ONU_Cli(
   int argc,
   char *argv[])
{
   int fd, i, ret = -1;
   struct fio_exchange ex;
   char buf[ONU_IO_BUF_SIZE];

   ex.p_data = &buf;

   fd = open(ONU_DEVICE_PATH, O_RDWR, 0644);
   if (fd < 0) {
      printf("oops fd %d (errno=%d)\n", fd, errno);
      cerr << "ERROR: can't open device " << ONU_DEVICE_PATH << "." << endl;
      return ret;
   }

   buf[0] = 0;
   if (argc > 1) {
      for (i = 1; i < argc; i++) {
         strcat(buf, argv[i]);
         strcat(buf, " ");
      }
   } else {
      strcat(buf, "help");
   }
   ex.length = strlen(buf);

   if (ret = ioctl(fd, FIO_ONU_CLI, (long)&ex) == 0) {
      if (ex.error == 0 && ex.length < sizeof(buf)) {
         cout << &buf[0] << endl;
      } else {
         cerr <<"ERROR: operation failed\n" << endl;
      }
   } else {
      cerr <<"ERROR: can't cli from device\n" << endl;
   }
   close(fd);

   return ret;
}
#endif

extern "C" int main(int argc, char *argv[]);

int main(int argc, char *argv[])
{
   g_bHelp = -1;
   g_bVersion = -1;

   if (ONU_ArgsParse(argc, argv) != 0)
      return -1;

   if (g_bHelp == 1)
      return ONU_Usage(argv[0]);

   if (g_bVersion == 1)
      return ONU_Version();

#ifdef INCLUDE_CLI_SUPPORT
   ONU_Cli(argc, argv);
#endif

   return 0;
}

#endif /* LINUX */
