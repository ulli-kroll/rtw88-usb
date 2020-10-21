# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD       := $(shell pwd)

CONFIG_RTW88_CORE=m
CONFIG_RTW88_PCI=m
CONFIG_RTW88_USB=m
CONFIG_RTW88_8822BE=m
CONFIG_RTW88_8822BU=m
CONFIG_RTW88_8822B=m
CONFIG_RTW88_8821CE=m
CONFIG_RTW88_8821CU=m
CONFIG_RTW88_8821C=m
CONFIG_RTW88_8822CE=m
CONFIG_RTW88_8822CU=m
CONFIG_RTW88_8822C=m
CONFIG_RTW88_8723DE=m
CONFIG_RTW88_8723DU=m
CONFIG_RTW88_8723D=m

ifneq ($(CONFIG_RTW88_8822BE),m)
ccflags-y += -DCONFIG_RTW88_8822BE=y
endif
ifneq ($(CONFIG_RTW88_8822BU),m)
ccflags-y += -DCONFIG_RTW88_8822BU=y
endif
ifneq ($(CONFIG_RTW88_8822CE),m)
ccflags-y += -DCONFIG_RTW88_8822CE=y
endif
ifneq ($(CONFIG_RTW88_8822CU),m)
ccflags-y += -DCONFIG_RTW88_8822CU=y
endif
ifneq ($(CONFIG_RTW88_8723DE),m)
ccflags-y += -DCONFIG_RTW88_8723DE=y
endif
ifneq ($(CONFIG_RTW88_8723DU),m)
ccflags-y += -DCONFIG_RTW88_8723DE=y
endif
ifneq ($(CONFIG_RTW88_DEBUG),y)
ccflags-y += -DCONFIG_RTW88_DEBUG=y
endif
ifneq ($(CONFIG_RTW88_DEBUGFS),y)
ccflags-y += -DCONFIG_RTW88_DEBUGFS=y
endif
ccflags-y += -DDEBUG

########### section below is for upstream kernel ###########

obj-$(CONFIG_RTW88_CORE)	+= rtw88_core.o
rtw88_core-y += main.o \
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


obj-$(CONFIG_RTW88_8822B)	+= rtw88_8822b.o
rtw88_8822b-objs		:= rtw8822b.o rtw8822b_table.o

obj-$(CONFIG_RTW88_8822BE)	+= rtw88_8822be.o
rtw88_8822be-objs		:= rtw8822be.o

obj-$(CONFIG_RTW88_8822BU)	+= rtw88_8822bu.o
rtw88_8822bu-objs		:= rtw8822bu.o

obj-$(CONFIG_RTW88_8822C)	+= rtw88_8822c.o
rtw88_8822c-objs		:= rtw8822c.o rtw8822c_table.o

obj-$(CONFIG_RTW88_8822CE)	+= rtw88_8822ce.o
rtw88_8822ce-objs		:= rtw8822ce.o

obj-$(CONFIG_RTW88_8822CU)	+= rtw88_8822cu.o
rtw88_8822cu-objs		:= rtw8822cu.o

obj-$(CONFIG_RTW88_8723D)	+= rtw88_8723d.o
rtw88_8723d-objs		:= rtw8723d.o rtw8723d_table.o

obj-$(CONFIG_RTW88_8723DE)	+= rtw88_8723de.o
rtw88_8723de-objs		:= rtw8723de.o

obj-$(CONFIG_RTW88_8723DU)	+= rtw88_8723du.o
rtw88_8723du-objs		:= rtw8723du.o

obj-$(CONFIG_RTW88_8821C)	+= rtw88_8821c.o
rtw88_8821c-objs		:= rtw8821c.o rtw8821c_table.o

obj-$(CONFIG_RTW88_8821CE)	+= rtw88_8821ce.o
rtw88_8821ce-objs		:= rtw8821ce.o

obj-$(CONFIG_RTW88_8821CU)	+= rtw88_8821cu.o
rtw88_8821cu-objs		:= rtw8821cu.o

obj-$(CONFIG_RTW88_PCI)		+= rtw88_pci.o
obj-$(CONFIG_RTW88_USB)		+= rtw88_usb.o
rtw88_pci-objs			:= pci.o
rtw88_usb-objs			:= usb.o

########### section above is for upstream kernel ###########

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD)

load:
	echo "Unload upstream driver(s)"
	for m in rtw88_8723de rtw88_8723d rtw88_8822be rtw88_8822b \
		rtw88_8821ce rtw88_8821c rtw88_8822ce rtw88_8821c \
		rtw88_pci rtw88_core; \
		do rmmod "$$m" 2> /dev/null; done;
	echo "Load rtw88-usb driver(s)"
	for m in rtw88_core.ko rtw88_pci.ko rtw88_usb.ko \
		rtw88_8723d.ko rtw88_8723de.ko rtw88_8723du.ko \
		rtw88_8822b.ko rtw88_8822be.ko rtw88_8822bu.ko \
		rtw88_8821c.ko rtw88_8821ce.ko rtw88_8821cu.ko \
		rtw88_8822c.ko rtw88_8822ce.ko rtw88_8822cu.ko; \
		do insmod "$$m"; done;

firmware:
	@echo "WARNING:"
	@echo "=========================================="
	@echo "you are about to install rtw88-usb firmware"
	@echo "Wait 5 sec or CTRL-C"
	@sleep 5
	@mkdir -p /lib/firmware/rtw88
	@cp fw/* /lib/firmware/rtw88/
	@echo
	@echo "rtw88-usb firmware installed"

install:
	@echo "WARNING:"
	@echo "=========================================="
	@echo "you are about to install rtw88-usb drivers"
	@echo "Wait 5 sec or CTRL-C"
	@sleep 5
	@cp *.ko /lib/modules/$(shell uname -r)/kernel/drivers/net/wireless/realtek/rtw88 
	@depmod -a
	@echo
	@echo "rtw88-usb drivers installed"



cscope:
	find ./ -name "*.[ch]" > cscope.files
	cscope -Rbq -i cscope.files
	ctags -R --exclude=.git

.PHONY: clean

clean:
	rm -f *.o .*.d *.a *.ko .*.cmd *.mod* *.order *.symvers *.tmp_versions
