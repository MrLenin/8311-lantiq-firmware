if ENABLE_LINUX

if WITH_KERNEL_MODULE
if KERNEL_2_6
bin_PROGRAMS = drv_ifxos.ko
else
bin_PROGRAMS = drv_ifxos
endif
endif

endif

lib_LIBRARIES = libifxos.a

AM_CPPFLAGS = \
	-I@srcdir@\
	-I@srcdir@/include \
	-I@KERNEL_INCL_PATH@ \
	-I@KERNEL_BUILD_PATH@/include \
	-I@KERNEL_BUILD_PATH@/include2 \
	-I$(TARGET_INCL_PATH)

if HAVE_GCC

used_gcc_cflags = 
	-Wall -Wimplicit -Wunused -Wundef -Wswitch -Wcomment \
	-Wuninitialized -Wparentheses -Wreturn-type

# for debugging: add compile flags for Lauterbach Debugger Support
lauterbach_cflags = -DLAUTERBACH_COMPILE -Wall -Wstrict-prototypes -Wno-trigraphs -O1 -g3 \
	-fno-schedule-insns -fno-schedule-insns2 -fno-strict-aliasing -fno-common -DIFXOS_DEBUG
# AM_CFLAGS += $(lauterbach_cflags)


else !HAVE_GCC

used_gcc_cflags = 

if ENABLE_SUN_OS
AM_LDFLAGS = \
	 -dn -Bstatic
endif

endif !HAVE_GCC

if ENABLE_DEBUG
used_gcc_cflags += -O1 -g
else
used_gcc_cflags += -O3
endif

AM_CFLAGS = \
	$(used_gcc_cflags)

if ENABLE_ECOS

libifxos_additional_cflags=\
	-DECOS \
	-DIFXOS_USE_DEV_IO=1

if HAVE_IFXOS_SYSOBJ_SUPPORT
libifxos_additional_cflags += -DHAVE_IFXOS_SYSOBJ_SUPPORT=1
endif

endif ENABLE_ECOS

if ENABLE_LINUX

libifxos_additional_cflags=\
	-DLINUX \
	-DRW_MULTI_THREAD \
	-D_REENTRANT \
	-D_THREAD_SAFE \
	-D_POSIX_SOURCE -D_GNU_SOURCE

if HAVE_GCC
libifxos_additional_cflags+=\
	-ansi
endif

#	-pedantic
#   -Wstrict-aliasing not working with old 3.2 gcc

if ADD_APPL_CFLAGS_SET
libifxos_additional_cflags += $(ADD_APPL_CFLAGS)
endif

if HAVE_IFXOS_SYSOBJ_SUPPORT
libifxos_additional_cflags += -DHAVE_IFXOS_SYSOBJ_SUPPORT=1
endif

drvifxos_additional_cflags=\
	-DLINUX \
	-D__LINUX__ \
	-O \
	-D__KERNEL__ \
	-DMODULE \
	-DEXPORT_SYMTAB

if HAVE_IFXOS_SYSOBJ_SUPPORT
drvifxos_additional_cflags += -DHAVE_IFXOS_SYSOBJ_SUPPORT=1
endif

if ADD_DRV_CFLAGS_SET
drvifxos_additional_cflags += $(ADD_DRV_CFLAGS)
endif

drv_ifxos_LDFLAGS = -r -nostdlib

endif ENABLE_LINUX

if ENABLE_SUN_OS
libifxos_additional_cflags=\
	-DSUN_OS \
	-DRW_MULTI_THREAD \
	-D_REENTRANT \
	-D_THREAD_SAFE

if ADD_APPL_CFLAGS_SET
libifxos_additional_cflags += $(ADD_APPL_CFLAGS)
endif

if HAVE_IFXOS_SYSOBJ_SUPPORT
libifxos_additional_cflags += -DHAVE_IFXOS_SYSOBJ_SUPPORT=1
endif

endif ENABLE_SUN_OS


if ENABLE_GENERIC

libifxos_additional_cflags=\
	-DGENERIC_OS \
	-ansi \
	-DRW_MULTI_THREAD \
	-D_REENTRANT \
	-D_THREAD_SAFE \
	-D_POSIX_SOURCE -D_GNU_SOURCE \
	-pedantic

#   -Wstrict-aliasing

if HAVE_IFXOS_SYSOBJ_SUPPORT
libifxos_additional_cflags += -DHAVE_IFXOS_SYSOBJ_SUPPORT=1
endif

endif ENABLE_GENERIC

if ENABLE_LINT

endif ENABLE_LINT

lib_ifxos_common = \
	common/ifxos_version.c\
	common/ifxos_debug.c\
	common/ifxos_sys_show.c\
	dev_io/ifxos_device_io.c\
	dev_io/ifxos_device_io_access.c\
	include/ifx_types.h\
	include/ifxos_rt_if_check.h\
	include/ifxos_std_defs.h\
	include/ifxos_common.h\
	include/ifxos_version.h\
	include/ifxos_debug.h\
	include/ifxos_sys_show.h\
	include/ifxos_sys_show_interface.h\
	include/ifxos_device_access.h\
	include/ifxos_event.h\
	include/ifxos_file_access.h\
	include/ifxos_linux_drv.h\
	include/ifxos_lock.h\
	include/ifxos_memory_map.h\
	include/ifxos_misc.h\
	include/ifxos_pipe.h\
	include/ifxos_print.h\
	include/ifxos_select.h\
	include/ifxos_socket.h\
	include/ifxos_termios.h\
	include/ifxos_thread.h\
	include/ifxos_time.h\
	include/ifxos_memory_alloc.h\
	include/ifxos_copy_user_space.h\
	include/ifxos_device_io.h\
	include/ifxos_device_access.h\
	include/ifxos_print_io.h\
	include/ifxos_mutex.h\
	include/ifxos_interrupt.h

lib_ifxos_extra_libraries = \
	common/ifx_fifo.c\
	include/ifx_fifo.h\
	common/ifx_crc.c\
	include/ifx_crc.h

lib_ifxos_ini_file_access_specific = \
	common/ifx_ini_access.c\
	include/ifx_ini_access.h

lib_ifxos_ecos = \
	common/ifx_getopt.c\
	include/ifx_getopt.h\
	common/ifx_getopt_ext.c\
	include/ifx_getopt_ext.h\
	ecos/ifxos_ecos_device_access.c\
	ecos/ifxos_ecos_event.c\
	ecos/ifxos_ecos_file_access.c\
	ecos/ifxos_ecos_lock.c\
	ecos/ifxos_ecos_memory_map.c\
	ecos/ifxos_ecos_misc.c\
	ecos/ifxos_ecos_pipe.c\
	ecos/ifxos_ecos_print.c\
	ecos/ifxos_ecos_select.c\
	ecos/ifxos_ecos_socket.c\
	ecos/ifxos_ecos_termios.c\
	ecos/ifxos_ecos_thread.c\
	ecos/ifxos_ecos_time.c\
	ecos/ifxos_ecos_copy_user_space.c\
	ecos/ifxos_ecos_memory_alloc.c\
	ecos/ifxos_ecos_mutex.c\
	ecos/ifxos_ecos_print_io.c\
	include/ecos/ifxos_ecos_common.h\
	include/ecos/ifxos_ecos_device_access.h\
	include/ecos/ifxos_ecos_event.h\
	include/ecos/ifxos_ecos_file_access.h\
	include/ecos/ifxos_ecos_print_io.h\
	include/ecos/ifxos_ecos_lock.h\
	include/ecos/ifxos_ecos_pipe.h\
	include/ecos/ifxos_ecos_print.h\
	include/ecos/ifxos_ecos_select.h\
	include/ecos/ifxos_ecos_socket.h\
	include/ecos/ifxos_ecos_misc.h\
	include/ecos/ifxos_ecos_termios.h\
	include/ecos/ifxos_ecos_thread.h\
	include/ecos/ifxos_ecos_time.h\
	include/ecos/ifxos_ecos_memory_alloc.h\
	include/ecos/ifxos_ecos_mutex.h \
	include/ecos/ifxos_ecos_std_defs.h\
	include/ecos/ifxos_ecos_interrupt.h

lib_ifxos_linux = \
	common/ifx_getopt_ext.c\
	include/ifx_getopt_ext.h\
	linux/ifxos_linux_device_access_appl.c\
	linux/ifxos_linux_file_access_appl.c\
	linux/ifxos_linux_lock_appl.c\
	linux/ifxos_linux_memory_alloc_appl.c\
	linux/ifxos_linux_misc_appl.c\
	linux/ifxos_linux_mutex_appl.c\
	linux/ifxos_linux_pipe_appl.c\
	linux/ifxos_linux_print_appl.c\
	linux/ifxos_linux_print_io_appl.c\
	linux/ifxos_linux_socket_appl.c\
	linux/ifxos_linux_termios_appl.c\
	linux/ifxos_linux_thread_appl.c\
	linux/ifxos_linux_time_appl.c\
	linux/ifxos_linux_event_appl.c\
	include/linux/ifxos_linux_common.h\
	include/linux/ifxos_linux_device_access.h\
	include/linux/ifxos_linux_event.h\
	include/linux/ifxos_linux_file_access.h\
	include/linux/ifxos_linux_print_io.h\
	include/linux/ifxos_linux_lock.h\
	include/linux/ifxos_linux_pipe.h\
	include/linux/ifxos_linux_print.h\
	include/linux/ifxos_linux_select.h\
	include/linux/ifxos_linux_socket.h\
	include/linux/ifxos_linux_termios.h\
	include/linux/ifxos_linux_thread.h\
	include/linux/ifxos_linux_time.h\
	include/linux/ifxos_linux_memory_alloc.h\
	include/linux/ifxos_linux_misc.h\
	include/linux/ifxos_linux_mutex.h\
	include/linux/ifxos_linux_std_defs.h\
	include/linux/ifxos_linux_interrupt.h

if WITH_KERNEL_MODULE

lib_ifxos_kernel_specific = \
	common/ifxos_version.c\
	common/ifxos_debug.c\
	common/ifxos_sys_show.c\
	common/ifx_fifo.c\
	linux/ifxos_linux_module_drv.c\
	linux/ifxos_linux_copy_user_space_drv.c\
	linux/ifxos_linux_memory_alloc_drv.c\
	linux/ifxos_linux_memory_map_drv.c\
	linux/ifxos_linux_event_drv.c\
	linux/ifxos_linux_lock_drv.c\
	linux/ifxos_linux_select_drv.c\
	linux/ifxos_linux_thread_drv.c\
	linux/ifxos_linux_mutex_drv.c\
	linux/ifxos_linux_time_drv.c\
	linux/ifxos_linux_socket_drv.c

else

lib_ifxos_linux += \
	linux/ifxos_linux_copy_user_space_appl.c\
	linux/ifxos_linux_memory_map_appl.c\
	linux/ifxos_linux_select_appl.c

endif

lib_ifxos_sun_os = \
	common/ifx_getopt_ext.c\
	common/ifx_ini_access.c\
	sun_os/ifxos_sun_os_file_access_appl.c\
	sun_os/ifxos_sun_os_memory_alloc_appl.c\
	sun_os/ifxos_sun_os_print_appl.c\
	sun_os/ifxos_sun_os_print_io_appl.c\
	sun_os/ifxos_sun_os_time_appl.c\
	include/ifx_getopt_ext.h\
	include/ifx_ini_access.h\
	include/sun_os/ifxos_sun_os_common.h\
	include/sun_os/ifxos_sun_os_file_access.h\
	include/sun_os/ifxos_sun_os_memory_alloc.h\
	include/sun_os/ifxos_sun_os_print_io.h\
	include/sun_os/ifxos_sun_os_print.h\
	include/sun_os/ifxos_sun_os_time.h\
	include/sun_os/ifxos_sun_os_std_defs.h


##   sun_os/ifxos_sun_os_device_access_appl.c\
##   sun_os/ifxos_sun_os_lock_appl.c\
##   sun_os/ifxos_sun_os_misc_appl.c\
##   sun_os/ifxos_sun_os_mutex_appl.c\
##   sun_os/ifxos_sun_os_pipe_appl.c\
##   sun_os/ifxos_sun_os_socket_appl.c\
##   sun_os/ifxos_sun_os_termios_appl.c\
##   sun_os/ifxos_sun_os_thread_appl.c\
##   include/sun_os/ifxos_sun_os_device_access.h\
##   include/sun_os/ifxos_sun_os_event.h\
##   include/sun_os/ifxos_sun_os_lock.h\
##   include/sun_os/ifxos_sun_os_pipe.h\
##   include/sun_os/ifxos_sun_os_select.h\
##   include/sun_os/ifxos_sun_os_socket.h\
##   include/sun_os/ifxos_sun_os_termios.h\
##   include/sun_os/ifxos_sun_os_thread.h\
##   include/sun_os/ifxos_sun_os_memory_alloc.h\
##   include/sun_os/ifxos_sun_os_misc.h\
##   include/sun_os/ifxos_sun_os_mutex.h\
##   include/sun_os/ifxos_sun_os_interrupt.h


lib_ifxos_nucleus = \
	common/ifx_getopt.c\
	include/ifx_getopt.h\
	common/ifx_getopt_ext.c\
	include/ifx_getopt_ext.h\
	nucleus/ifxos_nucleus_device_access.c\
	nucleus/ifxos_nucleus_event.c\
	nucleus/ifxos_nucleus_file_access.c\
	nucleus/ifxos_nucleus_lock.c\
	nucleus/ifxos_nucleus_memory_map.c\
	nucleus/ifxos_nucleus_misc.c\
	nucleus/ifxos_nucleus_pipe.c\
	nucleus/ifxos_nucleus_print.c\
	nucleus/ifxos_nucleus_select.c\
	nucleus/ifxos_nucleus_socket.c\
	nucleus/ifxos_nucleus_termios.c\
	nucleus/ifxos_nucleus_thread.c\
	nucleus/ifxos_nucleus_time.c\
	nucleus/ifxos_nucleus_copy_user_space.c\
	nucleus/ifxos_nucleus_memory_alloc.c\
	nucleus/ifxos_nucleus_mutex.c\
	nucleus/ifxos_nucleus_print_io.c\
	include/nucleus/ifxos_nucleus_common.h\
	include/nucleus/ifxos_nucleus_device_access.h\
	include/nucleus/ifxos_nucleus_event.h\
	include/nucleus/ifxos_nucleus_file_access.h\
	include/nucleus/ifxos_nucleus_print_io.h\
	include/nucleus/ifxos_nucleus_lock.h\
	include/nucleus/ifxos_nucleus_pipe.h\
	include/nucleus/ifxos_nucleus_print.h\
	include/nucleus/ifxos_nucleus_select.h\
	include/nucleus/ifxos_nucleus_socket.h\
	include/nucleus/ifxos_nucleus_termios.h\
	include/nucleus/ifxos_nucleus_thread.h\
	include/nucleus/ifxos_nucleus_time.h\
	include/nucleus/ifxos_nucleus_memory_alloc.h\
	include/nucleus/ifxos_nucleus_misc.h\
	include/nucleus/ifxos_nucleus_mutex.h \
	include/nucleus/ifxos_nucleus_std_defs.h\
	include/nucleus/ifxos_nucleus_interrupt.h

lib_ifxos_win32 = \
	common/ifx_getopt.c\
	include/ifx_getopt.h\
	common/ifx_getopt_ext.c\
	include/ifx_getopt_ext.h\
	win32/ifxos_win32_device_access.c\
	win32/ifxos_win32_event.c\
	win32/ifxos_win32_file_access.c\
	win32/ifxos_win32_lock.c\
	win32/ifxos_win32_memory_map.c\
	win32/ifxos_win32_misc.c\
	win32/ifxos_win32_pipe.c\
	win32/ifxos_win32_print.c\
	win32/ifxos_win32_select.c\
	win32/ifxos_win32_socket.c\
	win32/ifxos_win32_termios.c\
	win32/ifxos_win32_thread.c\
	win32/ifxos_win32_time.c\
	win32/ifxos_win32_copy_user_space.c\
	win32/ifxos_win32_memory_alloc.c\
	win32/ifxos_win32_mutex.c\
	win32/ifxos_win32_print_io.c\
	include/win32/ifxos_win32_common.h\
	include/win32/ifxos_win32_device_access.h\
	include/win32/ifxos_win32_event.h\
	include/win32/ifxos_win32_file_access.h\
	include/win32/ifxos_win32_print_io.h\
	include/win32/ifxos_win32_lock.h\
	include/win32/ifxos_win32_pipe.h\
	include/win32/ifxos_win32_print.h\
	include/win32/ifxos_win32_select.h\
	include/win32/ifxos_win32_socket.h\
	include/win32/ifxos_win32_termios.h\
	include/win32/ifxos_win32_thread.h\
	include/win32/ifxos_win32_time.h\
	include/win32/ifxos_win32_memory_alloc.h\
	include/win32/ifxos_win32_misc.h\
	include/win32/ifxos_win32_mutex.h \
	include/win32/ifxos_win32_std_defs.h\
	include/win32/ifxos_win32_interrupt.h

lib_ifxos_vxworks = \
	common/ifx_getopt.c\
	include/ifx_getopt.h\
	common/ifx_getopt_ext.c\
	include/ifx_getopt_ext.h\
	vxworks/ifxos_vxworks_device_access.c\
	vxworks/ifxos_vxworks_event.c\
	vxworks/ifxos_vxworks_file_access.c\
	vxworks/ifxos_vxworks_lock.c\
	vxworks/ifxos_vxworks_memory_map.c\
	vxworks/ifxos_vxworks_misc.c\
	vxworks/ifxos_vxworks_pipe.c\
	vxworks/ifxos_vxworks_print.c\
	vxworks/ifxos_vxworks_select.c\
	vxworks/ifxos_vxworks_socket.c\
	vxworks/ifxos_vxworks_termios.c\
	vxworks/ifxos_vxworks_thread.c\
	vxworks/ifxos_vxworks_time.c\
	vxworks/ifxos_vxworks_copy_user_space.c\
	vxworks/ifxos_vxworks_memory_alloc.c\
	vxworks/ifxos_vxworks_mutex.c\
	vxworks/ifxos_vxworks_print_io.c\
	include/vxworks/ifxos_vxworks_common.h\
	include/vxworks/ifxos_vxworks_device_access.h\
	include/vxworks/ifxos_vxworks_event.h\
	include/vxworks/ifxos_vxworks_file_access.h\
	include/vxworks/ifxos_vxworks_print_io.h\
	include/vxworks/ifxos_vxworks_lock.h\
	include/vxworks/ifxos_vxworks_pipe.h\
	include/vxworks/ifxos_vxworks_print.h\
	include/vxworks/ifxos_vxworks_select.h\
	include/vxworks/ifxos_vxworks_socket.h\
	include/vxworks/ifxos_vxworks_termios.h\
	include/vxworks/ifxos_vxworks_thread.h\
	include/vxworks/ifxos_vxworks_time.h\
	include/vxworks/ifxos_vxworks_memory_alloc.h\
	include/vxworks/ifxos_vxworks_misc.h\
	include/vxworks/ifxos_vxworks_mutex.h \
	include/vxworks/ifxos_vxworks_std_defs.h\
	include/vxworks/ifxos_vxworks_interrupt.h

lib_ifxos_generic_os = \
	common/ifx_getopt.c\
	include/ifx_getopt.h\
	common/ifx_getopt_ext.c\
	include/ifx_getopt_ext.h\
	generic_os/ifxos_generic_os_device_access.c\
	generic_os/ifxos_generic_os_event.c\
	generic_os/ifxos_generic_os_file_access.c\
	generic_os/ifxos_generic_os_lock.c\
	generic_os/ifxos_generic_os_memory_map.c\
	generic_os/ifxos_generic_os_misc.c\
	generic_os/ifxos_generic_os_pipe.c\
	generic_os/ifxos_generic_os_print.c\
	generic_os/ifxos_generic_os_select.c\
	generic_os/ifxos_generic_os_socket.c\
	generic_os/ifxos_generic_os_termios.c\
	generic_os/ifxos_generic_os_thread.c\
	generic_os/ifxos_generic_os_time.c\
	generic_os/ifxos_generic_os_copy_user_space.c\
	generic_os/ifxos_generic_os_memory_alloc.c\
	generic_os/ifxos_generic_os_mutex.c\
	generic_os/ifxos_generic_os_print_io.c\
	include/generic_os/ifxos_generic_os_common.h\
	include/generic_os/ifxos_generic_os_device_access.h\
	include/generic_os/ifxos_generic_os_event.h\
	include/generic_os/ifxos_generic_os_file_access.h\
	include/generic_os/ifxos_generic_os_print_io.h\
	include/generic_os/ifxos_generic_os_lock.h\
	include/generic_os/ifxos_generic_os_pipe.h\
	include/generic_os/ifxos_generic_os_print.h\
	include/generic_os/ifxos_generic_os_select.h\
	include/generic_os/ifxos_generic_os_socket.h\
	include/generic_os/ifxos_generic_os_termios.h\
	include/generic_os/ifxos_generic_os_thread.h\
	include/generic_os/ifxos_generic_os_time.h\
	include/generic_os/ifxos_generic_os_memory_alloc.h\
	include/generic_os/ifxos_generic_os_misc.h\
	include/generic_os/ifxos_generic_os_mutex.h \
	include/generic_os/ifxos_generic_os_std_defs.h\
	include/generic_os/ifxos_generic_os_interrupt.h

lib_ifxos_xapi = \
	common/ifx_getopt.c\
	include/ifx_getopt.h\
	common/ifx_getopt_ext.c\
	include/ifx_getopt_ext.h\
	xapi/ifxos_xapi_event.c\
	xapi/ifxos_xapi_lock.c\
	xapi/ifxos_xapi_select.c\
	xapi/ifxos_xapi_thread.c\
	xapi/ifxos_xapi_time.c\
	xapi/ifxos_xapi_memory_alloc.c\
	xapi/ifxos_xapi_mutex.c\
	xapi/ifxos_xapi_print.c\
	include/xapi/ifxos_xapi_common.h\
	include/xapi/ifxos_xapi_std_defs.h\
	include/xapi/ifxos_xapi_device_access.h\
	include/xapi/ifxos_xapi_event.h\
	include/xapi/ifxos_xapi_lock.h\
	include/xapi/ifxos_xapi_print.h\
	include/xapi/ifxos_xapi_select.h\
	include/xapi/ifxos_xapi_thread.h\
	include/xapi/ifxos_xapi_time.h\
	include/xapi/ifxos_xapi_memory_alloc.h\
	include/xapi/ifxos_xapi_mutex.h \
	include/xapi/ifxos_xapi_interrupt.h

lib_ifxos_rtems = \
	common/ifx_getopt.c\
	include/ifx_getopt.h\
	common/ifx_getopt_ext.c\
	include/ifx_getopt_ext.h\
	rtems/ifxos_rtems_copy_user_space.c\
	rtems/ifxos_rtems_device_access.c\
	rtems/ifxos_rtems_event.c\
	rtems/ifxos_rtems_file_access.c\
	rtems/ifxos_rtems_lock.c\
	rtems/ifxos_rtems_memory_alloc.c\
	rtems/ifxos_rtems_memory_map.c\
	rtems/ifxos_rtems_misc.c\
	rtems/ifxos_rtems_mutex.c\
	rtems/ifxos_rtems_pipe.c\
	rtems/ifxos_rtems_print.c\
	rtems/ifxos_rtems_print_io.c\
	rtems/ifxos_rtems_select.c\
	rtems/ifxos_rtems_socket.c\
	rtems/ifxos_rtems_termios.c\
	rtems/ifxos_rtems_thread.c\
	rtems/ifxos_rtems_time.c\
	include/rtems/ifxos_rtems_common.h\
	include/rtems/ifxos_rtems_device_access.h\
	include/rtems/ifxos_rtems_event.h\
	include/rtems/ifxos_rtems_file_access.h\
	include/rtems/ifxos_rtems_interrupt.h\
	include/rtems/ifxos_rtems_lock.h\
	include/rtems/ifxos_rtems_memory_alloc.h\
	include/rtems/ifxos_rtems_misc.h\
	include/rtems/ifxos_rtems_mutex.h\
	include/rtems/ifxos_rtems_pipe.h\
	include/rtems/ifxos_rtems_print.h\
	include/rtems/ifxos_rtems_print_io.h\
	include/rtems/ifxos_rtems_select.h\
	include/rtems/ifxos_rtems_socket.h\
	include/rtems/ifxos_rtems_termios.h\
	include/rtems/ifxos_rtems_thread.h\
	include/rtems/ifxos_rtems_time.h

lib_ifxos_lint = \
	include/lint/ifxos_lint_std_defs.h

if ENABLE_ECOS
lib_ifxos_specific=\
	$(lib_ifxos_ecos)\
	$(lib_ifxos_ini_file_access_specific)
endif

if ENABLE_LINUX
lib_ifxos_specific=\
	$(lib_ifxos_linux)\
	$(lib_ifxos_ini_file_access_specific)
endif

if ENABLE_SUN_OS
lib_ifxos_specific=\
	$(lib_ifxos_sun_os)
endif

if ENABLE_NUCLEUS
lib_ifxos_specific=\
	$(lib_ifxos_nucleus)\
	$(lib_ifxos_ini_file_access_specific)
endif

if ENABLE_RTEMS
lib_ifxos_specific=\
	$(lib_ifxos_rtems)\
	$(lib_ifxos_ini_file_access_specific)
endif

if ENABLE_GENERIC
lib_ifxos_specific=\
	$(lib_ifxos_generic_os)\
	$(lib_ifxos_ini_file_access_specific)
endif

libifxos_a_CFLAGS = \
	$(AM_CFLAGS) \
	$(libifxos_additional_cflags)

libifxos_a_SOURCES = \
	$(lib_ifxos_specific) \
	$(lib_ifxos_common)\
	$(lib_ifxos_extra_libraries)

if ENABLE_LINUX
if WITH_KERNEL_MODULE
drv_ifxos_CFLAGS = \
	$(AM_CFLAGS) \
	$(drvifxos_additional_cflags)

drv_ifxos_SOURCES = \
	$(lib_ifxos_kernel_specific)

# linux 2.6 kernel object - dummy to force dependencies
drv_ifxos_ko_SOURCES =

# Extra rule for linux-2.6 kernel object

if KERNEL_2_6
drv_ifxos_OBJS = "$(subst .c,.o,$(filter %.c,$(drv_ifxos_SOURCES)))"

drv_ifxos.ko: $(drv_ifxos_SOURCES)
	@echo "drv_ifxos: Making Linux 2.6.x kernel object"
	if test ! -e common/ifxos_debug.c ; then \
		echo "copy source files (as links only!)"; \
		for f in $(filter %.c,$(drv_ifxos_SOURCES)); do \
			mkdir -p $(PWD)/`dirname $$f`/ ; \
			cp -s $(addprefix @abs_srcdir@/,$$f) $(PWD)/`dirname $$f`/ ; \
		done \
	fi
	@echo "# drv_ifxos: Generated to build Linux 2.6.x kernel object" > $(PWD)/Kbuild
	@echo "obj-m := $(subst .ko,.o,$@)"			>> $(PWD)/Kbuild
	@echo "$(subst .ko,,$@)-y := $(drv_ifxos_OBJS)"	>> $(PWD)/Kbuild
	@echo "EXTRA_CFLAGS := -DHAVE_CONFIG_H $(drv_ifxos_CFLAGS) $(DSL_DRIVER_INCL_PATH) -I@abs_srcdir@/include -I$(PWD)/include"	>> $(PWD)/Kbuild
	$(MAKE) ARCH=@KERNEL_ARCH@ -C @KERNEL_BUILD_PATH@ O=@KERNEL_BUILD_PATH@ M=$(PWD) modules

clean-generic:
		@echo "drv_ifxos: Cleanup Linux 2.6.x kernel object build"
		@- find . -name ".*.cmd" | xargs rm -f
		@- find . -name "*.o" | xargs rm -f
		@- rm -f Module.symvers Kbuild
		@- rm -rf .tmp_versions *.mod.c *.order

endif KERNEL_2_6
endif WITH_KERNEL_MODULE
endif ENABLE_LINUX

EXTRA_DIST = \
	$(lib_ifxos_common) \
	$(lib_ifxos_ecos) \
	$(lib_ifxos_kernel_specific) \
	$(lib_ifxos_linux) \
	$(lib_ifxos_nucleus) \
	$(lib_ifxos_vxworks) \
	$(lib_ifxos_win32) \
	$(lib_ifxos_generic_os) \
	$(lib_ifxos_xapi) \
	$(lib_ifxos_rtems) \
	$(lib_ifxos_sun_os) \
	$(lib_ifxos_lint)

if ENABLE_LINT

noinst_PROGRAMS = lint
lint_SOURCES = ../README

endif

install-exec-hook: $(bin_PROGRAMS)
	@for p in $(bin_PROGRAMS); do \
		$(STRIP) --strip-debug $(DESTDIR)$(bindir)/$$p; \
		echo "  $(STRIP) --strip-debug $(DESTDIR)$(bindir)/$$p"; \
	done

lint:
	flint +b -vm \
	$(AM_CPPFLAGS) $(CPPFLAGS) \
	-i@top_srcdir@ -i@srcdir@/include -i@srcdir@ std_generic.lnt \
	$(filter %.c,$(lib_ifxos_generic_os))
