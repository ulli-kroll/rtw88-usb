# rtw88-usb

This is based on 
https://github.com/torvalds/linux/tree/master/drivers/net/wireless/realtek/rtw88

to add support for USB wifi IC - 88x2bu / 88x2cu

fw/rtw8822b_fw.bin can be put under /lib/firmware/rtw88/rtw8822b_fw.bin

load driver:
    sudo insmod rtw88.ko
    sudo insmod rtwusb.ko

Scan:
    sudo iw wlanX scan

Connect to the AP without security:
    sudo iw wlanX connect <AP name>

dynamic IP:
    can see IP address obtained by DHCP by using ifconfig

loopback test:
    cat /sys/kernel/debug/rtw88/usb_loopback_func
    pktsize: 2000, spend: 54 us, throughput=296Mbps

