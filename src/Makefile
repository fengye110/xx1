# When the make command line has the goal 'all' or no goal specified (i.e.
# when compiling the driver) a sub-make of the kernel's Makefile includes
# the kernel configuration (include/config/auto.conf), but if any other
# goal is specified (e.g. install) the kernel configuration does not get
# included.  Set a variable and export it to track over sub-makes.
ifeq ($(MAKELEVEL),0)
  ifeq ($(filter-out all, $(MAKECMDGOALS)),)
    export KERNEL_CONFIG_INCLUDED=1
  endif
endif

# Explicitly set shell to bash, to avoid issues on distros with a different
# default shell. Looking at you, Ubuntu.
SHELL=/bin/bash
KBUILD_CFLAGS += -g
KBUILD_EXTRA_SYMBOLS += $(src)/mucse_auxiliary/Module.symvers
COMMON_MK ?= $(wildcard $(src)/common.mk)
ifeq (${COMMON_MK},)
  override src = .
  COMMON_MK = $(wildcard $(src)/common.mk)
endif
ifeq (${COMMON_MK},)
  $(error Cannot find common.mk build rules)
else
  include ${COMMON_MK}
endif

ifneq ($(KERNELRELEASE),)

# object files to build
obj-m += mcepf.o
mcepf-y += mce_main.o
mcepf-y += mce_n20/mce_hw_n20.o
mcepf-y += mce_n20/mce_hw_debugfs.o
mcepf-y += mce_n20/mce_hw_dcb.o
mcepf-y += mce_n20/mce_hw_npu.o
mcepf-y += mce_n20/mce_hw_fdir.o
mcepf-$(CONFIG_PTP_1588_CLOCK:m=y) += mce_n20/mce_hw_ptp.o
mcepf-y += mce_fltr.o
mcepf-y += mce_lib.o
mcepf-y += mce_irq.o
mcepf-y += mce_base.o
mcepf-y += mce_txrx_lib.o
mcepf-y += mce_tc_lib.o
mcepf-y += mce_txrx.o
mcepf-y += mce_netdev.o
mcepf-y += mce_ethtool.o
mcepf-y += mce_fdir.o
mcepf-y += mce_fdir_flow.o
mcepf-y += mce_profile_mask.o
mcepf-y += mce_ethtool_fdir.o
mcepf-y += mce_idc.o
mcepf-y += mce_parse.o
mcepf-y += mce_mbx.o
mcepf-y += mce_sriov.o
mcepf-${CONFIG_SYSFS} += mce_sysfs.o
mcepf-$(CONFIG_DEBUG_FS) += mce_debugfs.o
mcepf-y += mce_dcb.o
mcepf-$(CONFIG_DCB) += mce_dcbnl.o
mcepf-y += mce_npu.o
mcepf-y += mce_virtchnl.o
mcepf-y += mce_fwchnl.o
mcepf-y += mce_vf_lib.o
mcepf-y += compat/kcompat.o
mcepf-y += mce_devlink.o
mcepf-y += mce_eswitch.o
mcepf-$(CONFIG_PTP_1588_CLOCK:m=y) += mce_ptp.o
ifndef CONFIG_PLDMFW
mcepf-y += compat/kcompat_pldmfw.o
endif
# Use kcompat DIMLIB if kernel doesn't provide it
ifndef CONFIG_DIMLIB
mcepf-y += compat/kcompat_dim.o
mcepf-y += compat/kcompat_net_dim.o
endif

else # ifneq($(KERNELRELEASE),)

DRIVER := mce

ifeq (,$(wildcard .define.mk))
# $(error Cannot find define.mk, run do_build.sh first)
# in default we use this cflags 
  $(warning *** compile without define.mk.)
else
	-include $(PWD)/.define.mk
endif

# mce does not support building on kernels older than 3.10.0
$(call minimum_kver_check,3,10,0)

all:
	$(MAKE) -C mucse_auxiliary
	@+$(call kernelbuild,modules)

euler: all

EXTRA_CFLAGS += -g

# close ptp
ifeq ($(findstring -DMCE_DEBUG_XINSI_PCIE,$(EXTRA_CFLAGS)),-DMCE_DEBUG_XINSI_PCIE)
    EXTRA_CFLAGS += -DMCE_MAX_TC_CNT=2
else
    EXTRA_CFLAGS += -DMCE_MAX_TC_CNT=2 -DMCE_13P_DEBUG_MSIX
endif
# make for vf debug
vf: EXTRA_CFLAGS += -DMCE_DEBUG_VF
vf: 
	@echo "EXTRA_CFLAGS += -DMCE_DEBUG_VF " > $(PWD)/.define.mk
	$(MAKE) -C mucse_auxiliary
	@+$(call kernelbuild,modules)

# make for uos
uos: EXTRA_CFLAGS += -DUOS_OS
uos: 
	@echo "EXTRA_CFLAGS += -DUOS_OS " > $(PWD)/.define.mk
	$(MAKE) -C mucse_auxiliary
	@+$(call kernelbuild,modules)

# make for xinsi pcie
xinsi_pcie: EXTRA_CFLAGS += -DMCE_DEBUG_XINSI_PCIE
xinsi_pcie:
	$(eval EXTRA_CFLAGS := $(filter-out -DMCE_13P_DEBUG_MSIX, $(EXTRA_CFLAGS)))
	@echo "EXTRA_CFLAGS += -DMCE_DEBUG_XINSI_PCIE " > $(PWD)/.define.mk
	$(MAKE) -C mucse_auxiliary
	@+$(call kernelbuild,modules)

# make for soc vf
soc_vf: EXTRA_CFLAGS += -DMCE_DEBUG_XINSI_PCIE -DMCE_DEBUG_VF -DMCE_DEBUG_CM3
soc_vf:
	@echo "EXTRA_CFLAGS += -DMCE_DEBUG_XINSI_PCIE -DMCE_DEBUG_VF -DMCE_DEBUG_CM3" > $(PWD)/.define.mk
	$(MAKE) -C mucse_auxiliary
	@+$(call kernelbuild,modules)

# make for poll whih no interrupt
thread_poll: EXTRA_CFLAGS += -DTHREAD_POLL -DMCE_DEBUG_XINSI_PCIE
thread_poll: all

modules_install: all
	@install -D -m 644 ../pci.updates /usr/share/hwdata/pci.ids.d/mucse.ids
	$(MAKE) -C mucse_auxiliary install
	+$(call kernelbuild,modules_install)

install: modules_install
	$(call cmd_depmod)

modules_uninstall:
	$(MAKE) -C mucse_auxiliary uninstall
	rm -rf ${INSTALL_MOD_PATH}/lib/modules/${KVER}/${INSTALL_MOD_DIR}

uninstall: modules_uninstall
	$(call cmd_depmod)

clean:
	$(MAKE) -C mucse_auxiliary clean
	@-rm -rf *.${MANSECTION}.gz *.ko .define.mk
	@+$(call kernelbuild,clean)

.PHONY: all clean euler vf install modules_install_no_aux uninstall modules_uninstall
endif
