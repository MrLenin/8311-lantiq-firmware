## Process this file with automake to produce Makefile.in

mod_onu_led_trigger_SOURCES = drv_onu_led_trigger.c

EXTRA_DIST = \
   $(mod_onu_led_trigger_SOURCES) \
   drv_onu_led_trigger.h

if ONU_SIMULATION

else

bin_PROGRAMS = mod_onu_led_trigger.ko



AM_CFLAGS= -DLINUX

mod_onu_led_trigger_CFLAGS=$(AM_CFLAGS)

clean-generic:
	@echo "Cleanup Linux 2.6.x kernel object build"
	@- find . -name ".*.cmd" | xargs rm -f
	@- find . -name "*.o" | xargs rm -f
	@- rm -f Module.symvers Kbuild
	@- rm -rf .tmp_versions *.mod.c *.order

# linux 2.6 kernel object
# linux 2.6 kernel object - dummy to force dependencies
mod_onu_led_trigger_ko_SOURCES = ./ChangeLog

mod_onu_led_trigger_ko_OBJS = "$(subst .c,.o,$(filter %.c,$(mod_onu_led_trigger_SOURCES)))"
mod_onu_led_trigger.ko: $(mod_onu_led_trigger_SOURCES)
	@echo -e "mod_onu_led_trigger: Making Linux 2.6.x kernel object"
	if test ! -e drv_onu_led_trigger.c ; then \
		echo "copy source files (as links only!)"; \
		for f in $(filter %.c,$(mod_onu_led_trigger_SOURCES)); do \
			mkdir -p $(PWD)/`dirname $$f`/ ; \
			cp -sf $(addprefix @abs_srcdir@/,$$f) $(PWD)/`dirname $$f`/ ; \
		done \
	fi
	@echo -e "# mod_onu_led_trigger: Generated to build Linux 2.6.x kernel object" > $(PWD)/Kbuild
	@echo -e "obj-m := $(subst .ko,.o,$@)"			>> $(PWD)/Kbuild
	@echo -e "$(subst .ko,,$@)-y := $(mod_onu_led_trigger_ko_OBJS)"	>> $(PWD)/Kbuild
	@echo -e "EXTRA_CFLAGS := $(mod_onu_led_trigger_CFLAGS) -DHAVE_CONFIG_H -I@abs_srcdir@  -I@abs_top_srcdir@/src -I@abs_top_srcdir@/src/include" >> $(PWD)/Kbuild

	$(MAKE) CONFIG_DEBUG_SECTION_MISMATCH=y ARCH=@KERNEL_ARCH@ -C @KERNEL_BUILD_PATH@ O=@KERNEL_BUILD_PATH@ M=$(PWD) modules

endif

