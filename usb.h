/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/* Copyright(c) 2018-2019  Realtek Corporation
 */

#ifndef __RTW_USB_H_
#define __RTW_USB_H_

#define RTW_USB_CMD_READ		0xc0
#define RTW_USB_CMD_WRITE		0x40
#define RTW_USB_CMD_REQ			0x05

#define RTW_USB_IS_FULL_SPEED_USB(rtwusb) \
	((rtwusb)->usb_speed == RTW_USB_SPEED_1_1)
#define RTW_USB_IS_HIGH_SPEED(rtwusb)	((rtwusb)->usb_speed == RTW_USB_SPEED_2)
#define RTW_USB_IS_SUPER_SPEED(rtwusb)	((rtwusb)->usb_speed == RTW_USB_SPEED_3)

#define RTW_USB_SUPER_SPEED_BULK_SIZE	1024
#define RTW_USB_HIGH_SPEED_BULK_SIZE	512
#define RTW_USB_FULL_SPEED_BULK_SIZE	64

#define RTW_USB_TX_SEL_HQ		BIT(0)
#define RTW_USB_TX_SEL_LQ		BIT(1)
#define RTW_USB_TX_SEL_NQ		BIT(2)
#define RTW_USB_TX_SEL_EQ		BIT(3)

#define RTW_USB_BULK_IN_ADDR		0x80
#define RTW_USB_INT_IN_ADDR		0x81

#define RTW_USB_HW_QUEUE_ENTRY		8

#define RTW_USB_PACKET_OFFSET_SZ	8
#define RTW_USB_MAX_XMITBUF_SZ		(1592 * 3)
#define RTW_USB_MAX_RECVBUF_SZ		32768

#define RTW_USB_RECVBUFF_ALIGN_SZ	8

#define RTW_USB_RXAGG_SIZE		6
#define RTW_USB_RXAGG_TIMEOUT		10

#define RTW_USB_RXCB_NUM		4

#define rtw_get_usb_priv(rtwdev) (struct rtw_usb *)((rtwdev)->priv)

enum rtw_usb_burst_size {
	USB_BURST_SIZE_3_0 = 0x0,
	USB_BURST_SIZE_2_0_HS = 0x1,
	USB_BURST_SIZE_2_0_FS = 0x2,
	USB_BURST_SIZE_2_0_OTHERS = 0x3,
	USB_BURST_SIZE_UNDEFINE = 0x7F,
};

enum rtw_usb_speed {
	RTW_USB_SPEED_UNKNOWN	= 0,
	RTW_USB_SPEED_1_1	= 1,
	RTW_USB_SPEED_2		= 2,
	RTW_USB_SPEED_3		= 3,
};

struct rx_usb_ctrl_block {
	struct rtw_dev *rtwdev;
	struct urb *rx_urb;
	struct sk_buff *rx_skb;
};

struct rtw_usb_work_data {
	struct work_struct work;
	struct rtw_dev *rtwdev;
};

struct rtw_usb_tx_data {
	u8 sn;
};

struct rtw_usb {
	struct rtw_dev *rtwdev;
	struct usb_device *udev;

	u32 bulkout_size;
	u8 num_in_pipes;
	u8 num_out_pipes;
	u8 pipe_interrupt;
	u8 pipe_in;
	u8 out_ep[4];
	u8 out_ep_queue_sel;
	u8 queue_to_pipe[8];
	u8 usb_speed;
	u8 usb_txagg_num;

	struct workqueue_struct *txwq, *rxwq;

	struct sk_buff_head tx_queue[RTK_MAX_TX_QUEUE_NUM];
	struct rtw_usb_work_data *tx_handler_data;

	struct rx_usb_ctrl_block rx_cb[RTW_USB_RXCB_NUM];
	struct sk_buff_head rx_queue;
	struct rtw_usb_work_data *rx_handler_data;
};

static inline struct rtw_usb_tx_data *rtw_usb_get_tx_data(struct sk_buff *skb)
{
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);

	BUILD_BUG_ON(sizeof(struct rtw_usb_tx_data) >
		sizeof(info->status.status_driver_data));

	return (struct rtw_usb_tx_data *)info->status.status_driver_data;
}
#endif
