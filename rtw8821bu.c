// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright(c) 2018-2019  Realtek Corporation
 */

#include <linux/module.h>
#include <linux/usb.h>
#include "rtw8821bu.h"

static const struct usb_device_id rtw_8821bu_id_table[] = {
	{USB_DEVICE(RTW_USB_VENDOR_ID_REALTEK, 0xc811),
	  .driver_info = (kernel_ulong_t)&(rtw8822b_hw_spec) },
	{},
};
MODULE_DEVICE_TABLE(usb, rtw_8821bu_id_table);

static struct usb_driver rtw_8821bu_driver = {
	.name = "rtw_8821bu",
	.id_table = rtw_8822bu_id_table,
	.probe = rtw_usb_probe,
	.disconnect = rtw_usb_disconnect,
};
module_usb_driver(rtw_8821bu_driver);

MODULE_AUTHOR("Hans Ulli Kroll <linux@ulli-kroll.de>");
MODULE_DESCRIPTION("Realtek 802.11ac wireless 8821bu driver");
MODULE_LICENSE("Dual BSD/GPL");
