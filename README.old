# rtw88-usb

It's under GPL license, and please feel free to use it.
Also welcome to upstream to the Linux kernel if you want, and please
refer to the branch, for_kernel_upstream, which meets the Linux coding
style, and may be easier to upstream.

Thank to many people's kind help on this project. 

Driver for 802.11ac USB Adapter with chipset:
  RTL88x2BU / RTL88x2CU

supports at least managed (i.e. client) and monitor mode.

This driver is based on Realtek's [rtw88 driver](https://github.com/torvalds/linux/tree/master/drivers/net/wireless/realtek/rtw88) in Linux main trunk.

For a backport version (backport to kernel v4.15), please check [this branch](https://github.com/borting/rtw88-usb/tree/backport-cfc1291-v4.15.0).

A few known wireless cards that use this driver include 
* [ASUS AC-53 NANO](https://www.asus.com/Networking/USB-AC53-Nano/)
* [ASUS AC-55 (B1) AC1300](https://www.asus.com/Networking/USB-AC55-B1/)
* [Edimax EW-7822ULC](http://us.edimax.com/edimax/merchandise/merchandise_detail/data/edimax/us/wireless_adapters_ac1200_dual-band/ew-7822ulc/)
* [Netgear AC6150](http:/netgear.com/support/product/A6150.aspx)
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
## Wifi Sniffer - monitor mode
```console
$ sudo ip link set wlanX down
$ sudo iw dev wlanX set type monitor
$ sudo rfkill unblock all
$ sudo ip link set wlanX up
```

Then you can use "iw <device> info" to check if the wireless mode is correct.
```console
e.g.
    wlan1    IEEE 802.11  Mode:Monitor ... 
```

And you can use the program like wireshark to sniffer wifi packets.
1. set up the sniffer channel
```console
$ sudo iw dev wlanX set channel xxx
```

2. run the program
```console
$ sudo wireshark
```

## Test
test ok with general commands with the latest kernel
ubuntu 18 + kernel v5.3 test with Network Manager ok. 

## Known Issues

* Currently, this driver is not upstreamed to Linux kernel driver rtw88 yet. That means, loading this module will cause unpredictable results to other working Realtek wifi pcie device, especially to those laptops with Realtek wifi IC running kernel > v5.2.
