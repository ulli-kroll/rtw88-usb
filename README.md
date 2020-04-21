# rtw88-usb

It's unofficial release. Just for fun. 
And welcome to test and upstream to the Linux kernel. 

Driver for 802.11ac USB Adapter with chipset:
  RTL88x2BU / RTL88x2CU

supports at least managed (i.e. client) and monitor mode.

This driver is based on Realtek's [rtw88 driver](https://github.com/torvalds/linux/tree/master/drivers/net/wireless/realtek/rtw88) in Linux main trunk.

For a backport version (backport to kernel v4.15), please check [this branch](https://github.com/borting/rtw88-usb/tree/backport-cfc1291-v4.15.0).

A few known wireless cards that use this driver include 
* [Edimax EW-7822ULC](http://us.edimax.com/edimax/merchandise/merchandise_detail/data/edimax/us/wireless_adapters_ac1200_dual-band/ew-7822ulc/)
* [ASUS AC-53 NANO](https://www.asus.com/Networking/USB-AC53-Nano/)
* [TPLink Archer T4U v3](https://www.tp-link.com/tw/support/download/archer-t4u/)


## Build

```console
$ make clean
$ make
```

## Installation

Load driver for test:
```console
$ sudo mkdir -p /lib/firmware/rtw88
$ sudo cp fw/rtw8822* /lib/firmware/rtw88/
$ sudo insmod rtw88.ko
$ sudo insmod rtwusb.ko
```
Load driver at boot:
```console
$ sudo mkdir -p /lib/firmware/rtw88
$ sudo cp fw/rtw8822* /lib/firmware/rtw88/
$ sudo mkdir /lib/modules/`uname -r`/kernel/drivers/net/wireless/realtek/rtw88
$ sudo cp rtw88.ko /lib/modules/`uname -r`/kernel/drivers/net/wireless/realtek/rtw88
$ sudo cp rtwusb.ko /lib/modules/`uname -r`/kernel/drivers/net/wireless/realtek/rtw88
$ sudo depmod -a
$ sudo echo -e "rtw88\nrtwusb" > /etc/modules-load.d/rtwusb.conf
$ sudo systemctl start systemd-modules-load
```

## General Commands

Scan:
```console
$ sudo iw wlanX scan
```
Connect to the AP without security:
```console
$ sudo iw wlanX connect <AP name>
```

## Test
test ok with general commands with the latest kernel
ubuntu 18 + kernel v5.3 test with Network Manager ok. 

## Known Issues

* Currently, this driver is not upstreamed to Linux kernel driver rtw88 yet. That means, loading this module will cause unpredictable results to other working Realtek wifi pcie device, especially to those laptops with Realtek wifi IC running kernel > v5.2.
