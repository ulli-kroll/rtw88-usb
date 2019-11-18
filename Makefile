# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD       := $(shell pwd)

CONFIG_RTW88_CORE=m
CONFIG_RTW88_PCI=m
CONFIG_RTW88_USB=m
CONFIG_RTW88_8822BE=y
CONFIG_RTW88_8822CE=y
ccflags-y += -DCONFIG_RTW88_8822BE=y
ccflags-y += -DCONFIG_RTW88_8822CE=y
ccflags-y += -DDEBUG
ccflags-y += -DCONFIG_RTW88_DEBUG=y
ccflags-y += -DCONFIG_RTW88_DEBUGFS=y

########### section below is for upstream kernel ###########

obj-$(CONFIG_RTW88_CORE)	+= rtw88.o
rtw88-y += main.o \
	   mac80211.o \
	   util.o \
	   debug.o \
	   tx.o \
	   rx.o \
	   mac.o \
	   phy.o \
	   coex.o \
	   efuse.o \
	   fw.o \
	   ps.o \
	   sec.o \
	   bf.o \
	   regd.o

rtw88-$(CONFIG_RTW88_8822BE)	+= rtw8822b.o rtw8822b_table.o
rtw88-$(CONFIG_RTW88_8822CE)	+= rtw8822c.o rtw8822c_table.o

obj-$(CONFIG_RTW88_PCI)		+= rtwpci.o
obj-$(CONFIG_RTW88_USB)		+= rtwusb.o
rtwpci-objs			:= pci.o
rtwusb-objs			:= usb.o

########### section above is for upstream kernel ###########

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD)

cscope:
	find ./ -name "*.[ch]" > cscope.files
	cscope -Rbq -i cscope.files
	ctags -R --exclude=.git

.PHONY: clean

clean:
	find ./ -name "*.o" -exec rm {} \;
	find ./ -name "*.ko" -exec rm {} \;
	find ./ -name "*.cmd" -exec rm {} \;
	find ./ -name "*.mod" -exec rm {} \;
	find ./ -name "*.mod.c" -exec rm {} \;
	find ./ -name "*.order" -exec rm {} \;
	find ./ -name "*.symvers" -exec rm {} \;
	find ./ -name ".tmp_versions" -exec rm {} \;
