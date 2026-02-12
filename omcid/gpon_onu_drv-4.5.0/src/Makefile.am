## Process this file with automake to produce Makefile.in

libonu_sources= \
   drv_onu_base.c \
   drv_onu_cli.c \
   drv_onu_cli_core.c \
   drv_onu_cli_dump.c \
   drv_onu_cli_dump_misc.c \
   drv_onu_cli_misc.c \
   drv_onu_common.c \
   drv_onu_devio.c \
   drv_onu_gpe.c \
   drv_onu_gpe_tables.c \
   drv_onu_gtc.c \
   drv_onu_lan.c \
   drv_onu_linux.c \
   drv_onu_ll_cop.c \
   drv_onu_ll_eim.c \
   drv_onu_ll_fsqm.c \
   drv_onu_ll_gpearb.c \
   drv_onu_ll_gtc.c \
   drv_onu_ll_ictrlg.c \
   drv_onu_ll_ictrll.c \
   drv_onu_ll_iqm.c \
   drv_onu_ll_octrlg.c \
   drv_onu_ll_octrll.c \
   drv_onu_ll_sce.c \
   drv_onu_ll_ssb.c \
   drv_onu_ll_sys.c \
   drv_onu_ll_tbm.c \
   drv_onu_ll_tmu.c \
   drv_onu_ll_tod.c \
   drv_onu_ll_tod_asc.c \
   drv_onu_notifier.c \
   drv_onu_ploam.c \
   drv_onu_simulator.c \
   drv_onu_tse_config.c \
   drv_onu_tse.c

libonu_interface_headers= \
   include/drv_onu_devio.h \
   include/drv_onu_default.h \
   include/drv_onu_error.h \
   include/drv_onu_std_defs.h \
   include/drv_onu_types.h \
   include/drv_onu_gpe_tables.h \
   include/drv_onu_common_interface.h \
   include/drv_onu_event_interface.h \
   include/drv_onu_ethertypes.h \
   include/drv_onu_gpe_interface.h \
   include/drv_onu_gpe_tables_interface.h \
   include/drv_onu_gtc_interface.h \
   include/drv_onu_interface.h \
   include/drv_onu_lan_interface.h \
   include/drv_onu_ploam_interface.h \
   include/drv_onu_resource.h \
   include/drv_onu_resource_gpe_tables.h \
   include/drv_onu_resource_gpe.h

libonu_extra_headers= \
   drv_onu_api.h \
   drv_onu_cli_core.h \
   drv_onu_cli_dump.h \
   drv_onu_cli_dump_misc.h \
   drv_onu_debug.h \
   drv_onu_event_api.h \
   drv_onu_gpe_api.h \
   drv_onu_gpe_tables_api.h \
   drv_onu_gpe_tables.c \
   drv_onu_gtc_api.h \
   drv_onu_lan_api.h \
   drv_onu_lan_api_intern.h \
   drv_onu_ll_cop.h \
   drv_onu_ll_eim.h \
   drv_onu_ll_fsqm.h \
   drv_onu_ll_gpearb.h \
   drv_onu_ll_gtc.h \
   drv_onu_ll_ictrlg.h \
   drv_onu_ll_ictrll.h \
   drv_onu_ll_iqm.h \
   drv_onu_ll_octrlg.h \
   drv_onu_ll_octrll.h \
   drv_onu_ll_sce.h \
   drv_onu_ll_ssb.h \
   drv_onu_ll_sys.h \
   drv_onu_ll_tbm.h \
   drv_onu_ll_tmu.h \
   drv_onu_ll_tod.h \
   drv_onu_ll_tod_asc.h \
   drv_onu_notifier.h \
   drv_onu_ploam_api.h \
   drv_onu_reg_base.h \
   drv_onu_reg_coplink_cop.h \
   drv_onu_reg_disp.h \
   drv_onu_reg_eim.h \
   drv_onu_reg_sgmii.h \
   drv_onu_reg_sxgmii.h \
   drv_onu_reg_fsqm.h \
   drv_onu_reg_gpearb.h \
   drv_onu_reg_gtc.h \
   drv_onu_reg_ictrlc.h \
   drv_onu_reg_ictrlg.h \
   drv_onu_reg_ictrll.h \
   drv_onu_reg_iqm.h \
   drv_onu_reg_link.h \
   drv_onu_reg_merge.h \
   drv_onu_reg_octrlc.h \
   drv_onu_reg_octrlg.h \
   drv_onu_reg_octrll.h \
   drv_onu_reg_pctrl.h \
   drv_onu_reg_pe.h \
   drv_onu_reg_sbs0ctrl.h \
   drv_onu_reg_status.h \
   drv_onu_reg_sys_eth.h \
   drv_onu_reg_sys_gpe.h \
   drv_onu_reg_sys1.h \
   drv_onu_reg_tbm.h \
   drv_onu_reg_tmu.h \
   drv_onu_register.h \
   drv_onu_resource_device_psb98010.h \
   drv_onu_resource_device_psb98020.h \
   drv_onu_resource_device_psb98030.h \
   drv_onu_timer.h \
   drv_onu_reg_tod.h \
   drv_onu_tse_config.h \
   drv_onu_tse.h

AM_CFLAGS=

EXTRA_DIST = \
   $(libonu_sources) \
   $(libonu_interface_headers) \
   $(libonu_extra_headers)

if ENABLE_LINUX

if !INCLUDE_REMOTE_ONLY_ONU
bin_PROGRAMS = mod_onu.ko
endif

mod_onu_kodir = /include
mod_onu_ko_HEADERS = \
    $(libonu_interface_headers)

else !ENABLE_LINUX

AM_CFLAGS+= -Wall -Wno-unused-parameter -Wno-unused-variable -Os \
	-ffunction-sections -fdata-sections -funit-at-a-time 

lib_LIBRARIES = libonu.a
libonu_a_SOURCES = $(libonu_sources)
endif !ENABLE_LINUX

if !ONU_LIBRARY
AM_CFLAGS+= -DLINUX
endif

AM_CPPFLAGS = -Wall -Wextra \
   -I@srcdir@ \
   -I@srcdir@/include \
   -I@top_srcdir@/.. \
   @IFXOS_INCLUDE_PATH@

if EVENT_LOGGER_DEBUG
AM_CFLAGS += @EVENT_LOGGER_INCL_PATH@
endif

libonu_a_CFLAGS=$(AM_CFLAGS)

if ENABLE_LINUX

clean-generic:
	@echo "Cleanup Linux 2.6.x kernel object build"
	@- find . -name ".*.cmd" | xargs rm -f
	@- find . -name "*.o" | xargs rm -f
	@- rm -f Module.symvers Kbuild
	@- rm -rf .tmp_versions *.mod.c *.order

# linux 2.6 kernel object
# linux 2.6 kernel object - dummy to force dependencies
mod_onu_ko_SOURCES = ../ChangeLog

mod_onu_ko_OBJS = "$(subst .c,.o,$(filter %.c,$(libonu_sources)))"
mod_onu.ko: $(libonu_sources)
	@echo -e "mod_onu: Making Linux 2.6.x kernel object"
	if test ! -e drv_onu_common.c ; then \
		echo "copy source files (as links only!)"; \
		for f in $(filter %.c,$(libonu_sources)); do \
			mkdir -p $(PWD)/`dirname $$f`/ ; \
			cp -sf $(addprefix @abs_srcdir@/,$$f) $(PWD)/`dirname $$f`/ ; \
		done \
	fi
	@echo -e "# mod_onu: Generated to build Linux 2.6.x kernel object" > $(PWD)/Kbuild
	@echo -e "obj-m := $(subst .ko,.o,$@)"			>> $(PWD)/Kbuild
	@echo -e "$(subst .ko,,$@)-y := $(mod_onu_ko_OBJS)"	>> $(PWD)/Kbuild
	@echo -e "EXTRA_CFLAGS := $(libonu_a_CFLAGS) -DHAVE_CONFIG_H -I@abs_srcdir@ -I@abs_srcdir@/include $(IFXOS_INCLUDE_PATH)" >> $(PWD)/Kbuild

	$(MAKE) CONFIG_DEBUG_SECTION_MISMATCH=y ARCH=@KERNEL_ARCH@ -C @KERNEL_BUILD_PATH@ O=@KERNEL_BUILD_PATH@ M=$(PWD) modules

endif ENABLE_LINUX

lint:
	@flint -b -vm -cgnu \
	+libdir\(@KERNEL_INCL_PATH@/*\) \
	-i$(shell dirname `$(CC) -print-file-name=include`)/include \
	+libdir\($(shell dirname `$(CC) -print-file-name=include`)\) \
	-i /usr/include +libdir\(/usr/include\) \
	$(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) \
	-i@top_srcdir@ std_generic.lnt \
	$(filter %.c,$(libonu_sources))
