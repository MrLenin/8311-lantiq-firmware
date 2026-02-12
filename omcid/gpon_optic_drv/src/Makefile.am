## Process this file with automake to produce Makefile.in

liboptic_sources= \
   drv_optic_common.c \
   drv_optic_calc.c \
   drv_optic_goi.c \
   drv_optic_fcsi.c \
   drv_optic_mm.c \
   drv_optic_mpd.c \
   drv_optic_bert.c \
   drv_optic_tx.c \
   drv_optic_rx.c \
   drv_optic_omu.c \
   drv_optic_bosa.c \
   drv_optic_cal.c \
   drv_optic_dcdc_apd.c \
   drv_optic_dcdc_core.c \
   drv_optic_dcdc_ddr.c \
   drv_optic_ldo.c \
   drv_optic_ll_fcsi.c \
   drv_optic_ll_status.c \
   drv_optic_ll_sys_gpon.c \
   drv_optic_ll_octrlg.c \
   drv_optic_ll_gpio.c \
   drv_optic_ll_pll.c \
   drv_optic_ll_rx.c \
   drv_optic_ll_tx.c \
   drv_optic_ll_mm.c \
   drv_optic_ll_mpd.c \
   drv_optic_ll_bert.c \
   drv_optic_ll_gtc.c \
   drv_optic_ll_dcdc_apd.c \
   drv_optic_ll_dcdc_core.c \
   drv_optic_ll_dcdc_ddr.c \
   drv_optic_ll_sys1.c \
   drv_optic_ll_int.c \
   drv_optic_ll_simulator.c \
   drv_optic_linux.c \
   drv_optic_devio.c \
   drv_optic_base.c \
   drv_optic_cli.c \
   drv_optic_cli_misc.c \
   drv_optic_cli_core.c

liboptic_interface_headers= \
   include/drv_optic_std_defs.h \
   include/drv_optic_error.h \
   include/drv_optic_resource.h \
   include/drv_optic_interface.h \
   include/drv_optic_devio.h \
   include/drv_optic_base.h \
   include/drv_optic_goi_interface.h \
   include/drv_optic_fcsi_interface.h \
   include/drv_optic_mm_interface.h \
   include/drv_optic_mpd_interface.h \
   include/drv_optic_bert_interface.h \
   include/drv_optic_omu_interface.h \
   include/drv_optic_bosa_interface.h \
   include/drv_optic_cal_interface.h \
   include/drv_optic_event_interface.h \
   include/drv_optic_dcdc_apd_interface.h \
   include/drv_optic_dcdc_core_interface.h \
   include/drv_optic_dcdc_ddr_interface.h \
   include/drv_optic_ldo_interface.h

liboptic_extra_headers= \
   drv_optic_debug.h \
   drv_optic_api.h \
   drv_optic_common.h \
   drv_optic_fcsi.h \
   drv_optic_tx.h \
   drv_optic_rx.h \
   drv_optic_dcdc_apd.h \
   drv_optic_dcdc_core.h \
   drv_optic_dcdc_ddr.h \
   drv_optic_calc.h \
   drv_optic_mpd.h \
   drv_optic_mm.h \
   drv_optic_bosa.h \
   drv_optic_ll_fcsi.h \
   drv_optic_ll_status.h \
   drv_optic_ll_sys_gpon.h \
   drv_optic_ll_octrlg.h \
   drv_optic_ll_gpio.h \
   drv_optic_ll_pll.h \
   drv_optic_ll_rx.h \
   drv_optic_ll_tx.h \
   drv_optic_ll_mm.h \
   drv_optic_ll_bert.h \
   drv_optic_ll_gtc.h \
   drv_optic_ll_mpd.h \
   drv_optic_ll_dcdc_apd.h \
   drv_optic_ll_dcdc_core.h \
   drv_optic_ll_dcdc_ddr.h \
   drv_optic_ll_sys1.h \
   drv_optic_ll_int.h \
   drv_optic_ll_simulator.h \
   drv_optic_timer.h \
   drv_optic_cli_core.h \
   drv_optic_register.h \
   drv_optic_reg_base.h \
   drv_optic_reg_pma.h \
   drv_optic_reg_pma_int200.h \
   drv_optic_reg_pma_intrx.h \
   drv_optic_reg_pma_inttx.h \
   drv_optic_reg_status.h \
   drv_optic_reg_sys_gpon.h \
   drv_optic_reg_octrlg.h \
   drv_optic_reg_gtc.h \
   drv_optic_reg_gtc_pma.h \
   drv_optic_reg_dcdc.h \
   drv_optic_reg_sys1.h \
   drv_optic_reg_fcsic.h \
   drv_optic_reg_fcsi_base.h \
   drv_optic_reg_fcsi_txbosa.h \
   drv_optic_reg_fcsi_txomu.h \
   drv_optic_reg_fcsi_rxbosa.h \
   drv_optic_reg_fcsi_rxomu.h \
   drv_optic_reg_fcsi_mm.h \
   drv_optic_reg_fcsi_vdac.h \
   drv_optic_reg_fcsi_bfd.h \
   drv_optic_reg_fcsi_cbias.h \
   drv_optic_reg_fcsi_vdll.h

bin_PROGRAMS = 

EXTRA_DIST = \
   $(liboptic_sources) \
   $(liboptic_interface_headers) \
   $(liboptic_extra_headers) \
   $(optic_headers)

if ENABLE_LINUX

if !INCLUDE_REMOTE_ONLY_ONU
bin_PROGRAMS += mod_optic.ko
endif

#mod_optic_SOURCES = $(liboptic_sources)
mod_optic_kodir = /include
mod_optic_ko_HEADERS = $(liboptic_interface_headers)
else !ENABLE_LINUX
lib_LIBRARIES = liboptic.a
liboptic_a_SOURCES = $(liboptic_sources)
endif !ENABLE_LINUX

if !OPTIC_LIBRARY
AM_CFLAGS= -DLINUX
else
AM_CFLAGS= -Wall -Wno-unused-parameter -Wno-unused-variable -Os \
	-ffunction-sections -fdata-sections -funit-at-a-time 
endif

AM_CPPFLAGS = -Wall -Wextra  \
   -I@srcdir@ \
   -I@top_srcdir@/.. \
   @IFXOS_INCLUDE_PATH@ \
   -I@srcdir@/include

if EVENT_LOGGER_DEBUG
AM_CFLAGS += @EVENT_LOGGER_INCL_PATH@
endif

liboptic_a_CFLAGS=$(AM_CFLAGS)

if ENABLE_LINUX

clean-generic:
	@echo "Cleanup Linux 2.6.x kernel object build"
	@- find . -name ".*.cmd" | xargs rm -f
	@- find . -name "*.o" | xargs rm -f
	@- rm -f Module.symvers Kbuild
	@- rm -rf .tmp_versions *.mod.c *.order

# linux 2.6 kernel object
# linux 2.6 kernel object - dummy to force dependencies
mod_optic_ko_SOURCES = ../ChangeLog

mod_optic_ko_OBJS = "$(subst .c,.o,$(filter %.c,$(liboptic_sources)))"
mod_optic.ko: $(liboptic_sources)
	@echo -e "mod_optic: Making Linux 2.6.x kernel object"
	if test ! -e drv_optic_common.c ; then \
		echo "copy source files (as links only!)"; \
		for f in $(filter %.c,$(liboptic_sources)); do \
			mkdir -p $(PWD)/`dirname $$f`/ ; \
			cp -sf $(addprefix @abs_srcdir@/,$$f) $(PWD)/`dirname $$f`/ ; \
		done \
	fi
	@echo -e "# mod_optic: Generated to build Linux 2.6.x kernel object" > $(PWD)/Kbuild
	@echo -e "obj-m := $(subst .ko,.o,$@)"			>> $(PWD)/Kbuild
	@echo -e "$(subst .ko,,$@)-y := $(mod_optic_ko_OBJS)"	>> $(PWD)/Kbuild
	@echo -e "EXTRA_CFLAGS := $(liboptic_a_CFLAGS) -DHAVE_CONFIG_H -I@abs_srcdir@ -I@abs_srcdir@/include $(IFXOS_INCLUDE_PATH)" >> $(PWD)/Kbuild

	$(MAKE) ARCH=@KERNEL_ARCH@ -C @KERNEL_BUILD_PATH@ O=@KERNEL_BUILD_PATH@ M=$(PWD) modules

endif ENABLE_LINUX

lint:
	@flint -vm \
	+libdir\(@KERNEL_INCL_PATH@/*\) \
	-i$(shell dirname `$(CC) -print-file-name=include`)/include \
	-i@top_srcdir@ std_lx.lnt env-cw6.lnt $(AM_CPPFLAGS)\
	$(AM_CFLAGS) -D__KERNEL__ -DMODULE $(liboptic_sources)
