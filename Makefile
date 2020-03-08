# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD       := $(shell pwd)

CONFIG_RTW88_CORE=m
CONFIG_RTW88_USB=m
CONFIG_RTW88_8822B=y
CONFIG_RTW88_8822C=y
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
	   wow.o \
	   regd.o

rtw88-$(CONFIG_RTW88_8822B)	+= rtw8822b.o rtw8822b_table.o
rtw88-$(CONFIG_RTW88_8822C)	+= rtw8822c.o rtw8822c_table.o

obj-$(CONFIG_RTW88_USB)		+= rtwusb.o
rtwusb-objs			:= usb.o

########### section above is for upstream kernel ###########

SUBARCH := $(shell uname -m | sed -e s/i.86/i386/)
ARCH ?= $(SUBARCH)

all:
	$(MAKE) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) -C $(KERNELDIR) M=$(PWD) C=2

cscope:
	find ./ -name "*.[ch]" > cscope.files
	cscope -Rbq -i cscope.files
	ctags -R --exclude=.git

.PHONY: clean

clean:
	find ./ -name "*.o" -exec rm {} \;
	find ./ -name "*.a" -exec rm {} \;
	find ./ -name "*.ko" -exec rm {} \;
	find ./ -name "*.cmd" -exec rm {} \;
	find ./ -name "*.mod" -exec rm {} \;
	find ./ -name "*.mod.c" -exec rm {} \;
	find ./ -name "*.order" -exec rm {} \;
	find ./ -name "*.symvers" -exec rm {} \;
	find ./ -name ".tmp_versions" -exec rm {} \;
