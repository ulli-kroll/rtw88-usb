# rtw88-usb

mac80211 kernel driver

currently supported chipset's

8723du  
8822bu with variants  
8821cu  
8822cu  


It's under GPL license, and please feel free to use it.
Also welcome to upstream to the Linux kernel if you want, and please
refer to the branch, for_kernel_upstream, which meets the Linux coding
style, and may be easier to upstream.

Thank to many people's kind help on this project.  
BIG tanks to Ji-Pin Jou and Neo Jou, for the USB parts

supports at least managed (i.e. client) and monitor mode.

This driver is based on Realtek's rtw88 in Linux main trunk.

## Build

```console
$ make clean
$ make
```

## load drivers, preferred

```console
$ sudo make load
```

## install drivers
did you have run make load ?

```console
$ sudo make install
```

## install firmware

```console
$ sudo make firmware
```

## NOTE
This driver will naturally clash with upstream rtw88 drivers  
For PCI based device you need the drivers from this location  


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
