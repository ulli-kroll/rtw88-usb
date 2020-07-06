// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright(c) 2018-2019  Realtek Corporation
 */

#include <linux/module.h>
#include <linux/usb.h>
#include <linux/mutex.h>
#include "main.h"
#include "debug.h"
#include "tx.h"
#include "rx.h"
#include "fw.h"
#include "usb.h"

#define RTW_USB_CONTROL_MSG_TIMEOUT	30000 /* (us) */
#define RTW_USB_MSG_TIMEOUT	30000 /* (ms) */
#define RTW_USB_MAX_RXQ_LEN	128

struct rtw_usb_txcb_t {
	struct rtw_dev *rtwdev;
	struct sk_buff_head tx_ack_queue;
};

/* RTW queue / pipe functions */
static u8 rtw_usb_ac_to_hwq[] = {
	[IEEE80211_AC_VO] = RTW_TX_QUEUE_VO,
	[IEEE80211_AC_VI] = RTW_TX_QUEUE_VI,
	[IEEE80211_AC_BE] = RTW_TX_QUEUE_BE,
	[IEEE80211_AC_BK] = RTW_TX_QUEUE_BK,
};

static void rtw_usb_read_port(struct rtw_dev *rtwdev, u8 addr,
			      struct rx_usb_ctrl_block *rxcb);
static void rtw_usb_tx_agg(struct rtw_usb *rtwusb, struct sk_buff *skb);
static void rtw_usb_txcb_ack(struct rtw_usb_txcb_t *txcb);

static void rtw_usb_fill_tx_checksum(struct rtw_usb *rtwusb,
				     struct sk_buff *skb, int agg_num)
{
	struct rtw_dev *rtwdev = rtwusb->rtwdev;
	struct rtw_chip_info *chip = rtwdev->chip;
	struct rtw_tx_pkt_info pkt_info;

	SET_TX_DESC_DMA_TXAGG_NUM(skb->data, agg_num);
	pkt_info.pkt_offset = GET_TX_DESC_PKT_OFFSET(skb->data);
	chip->ops->fill_txdesc_checksum(rtwdev, &pkt_info, skb->data);
}

/*
 * usb read/write register functions
 */

static u8 rtw_usb_read8(struct rtw_dev *rtwdev, u32 addr)
{
	struct rtw_usb *rtwusb = (struct rtw_usb *)rtwdev->priv;
	struct usb_device *udev = rtwusb->udev;
	u8 *buf = NULL, data;

	buf = kmalloc(sizeof(*buf), GFP_ATOMIC);
	if (!buf)
		return 0;

	usb_control_msg(udev, usb_rcvctrlpipe(udev, 0),
			RTW_USB_CMD_REQ, RTW_USB_CMD_READ,
			addr, 0, buf, sizeof(*buf),
			RTW_USB_CONTROL_MSG_TIMEOUT);
	data = *buf;
	kfree(buf);

	return data;
}

static u16 rtw_usb_read16(struct rtw_dev *rtwdev, u32 addr)
{
	struct rtw_usb *rtwusb = (struct rtw_usb *)rtwdev->priv;
	struct usb_device *udev = rtwusb->udev;
	__le16 *buf = NULL;
	u16 data;

	buf = kmalloc(sizeof(*buf), GFP_ATOMIC);
	if (!buf)
		return 0;

	usb_control_msg(udev, usb_rcvctrlpipe(udev, 0),
			RTW_USB_CMD_REQ, RTW_USB_CMD_READ,
			addr, 0, buf, sizeof(*buf),
			RTW_USB_CONTROL_MSG_TIMEOUT);
	data = le16_to_cpu(*buf);
	kfree(buf);

	return data;
}

static u32 rtw_usb_read32(struct rtw_dev *rtwdev, u32 addr)
{
	struct rtw_usb *rtwusb = (struct rtw_usb *)rtwdev->priv;
	struct usb_device *udev = rtwusb->udev;
	__le32 *buf;
	u32 data;

	buf = kmalloc(sizeof(*buf), GFP_ATOMIC);
	if (!buf)
		return 0;

	usb_control_msg(udev, usb_rcvctrlpipe(udev, 0),
			RTW_USB_CMD_REQ, RTW_USB_CMD_READ,
			addr, 0, buf, sizeof(*buf),
			RTW_USB_CONTROL_MSG_TIMEOUT);

	data = le32_to_cpu(*buf);
	kfree(buf);

	return data;
}

static void rtw_usb_write8(struct rtw_dev *rtwdev, u32 addr, u8 val)
{
	struct rtw_usb *rtwusb = (struct rtw_usb *)rtwdev->priv;
	struct usb_device *udev = rtwusb->udev;
	u8 *buf;

	buf = kmalloc(sizeof(*buf), GFP_ATOMIC);
	if (!buf)
		return;

	*buf = val;
	usb_control_msg(udev, usb_sndctrlpipe(udev, 0),
			RTW_USB_CMD_REQ, RTW_USB_CMD_WRITE,
			addr, 0, buf, sizeof(*buf),
			RTW_USB_CONTROL_MSG_TIMEOUT);
	kfree(buf);
}

static void rtw_usb_write16(struct rtw_dev *rtwdev, u32 addr, u16 val)
{
	struct rtw_usb *rtwusb = (struct rtw_usb *)rtwdev->priv;
	struct usb_device *udev = rtwusb->udev;
	__le16 *buf;

	buf = kmalloc(sizeof(*buf), GFP_ATOMIC);
	if (!buf)
		return;

	*buf = cpu_to_le16(val);
	usb_control_msg(udev, usb_sndctrlpipe(udev, 0),
			RTW_USB_CMD_REQ, RTW_USB_CMD_WRITE,
			addr, 0, buf, sizeof(*buf),
			RTW_USB_CONTROL_MSG_TIMEOUT);
	kfree(buf);
}

static void rtw_usb_write32(struct rtw_dev *rtwdev, u32 addr, u32 val)
{
	struct rtw_usb *rtwusb = (struct rtw_usb *)rtwdev->priv;
	struct usb_device *udev = rtwusb->udev;
	__le32 *buf;

	buf = kmalloc(sizeof(*buf), GFP_ATOMIC);
	if (!buf)
		return;

	*buf = cpu_to_le32(val);
	usb_control_msg(udev, usb_sndctrlpipe(udev, 0),
			RTW_USB_CMD_REQ, RTW_USB_CMD_WRITE,
			addr, 0, buf, sizeof(*buf),
			RTW_USB_CONTROL_MSG_TIMEOUT);
	kfree(buf);
}

static int rtw_usb_parse(struct rtw_dev *rtwdev,
			 struct usb_interface *interface)
{
	struct rtw_usb *rtwusb;
	struct usb_interface_descriptor *interface_desc;
	struct usb_host_interface *host_interface;
	struct usb_endpoint_descriptor *endpoint;
	struct device *dev;
	struct usb_device *usbd;
	int i, j = 0, endpoints;
	u8 dir, xtype, num;
	int ret = 0;

	rtwusb = rtw_get_usb_priv(rtwdev);

	dev = &rtwusb->udev->dev;

	usbd = interface_to_usbdev(interface);
	host_interface = &interface->altsetting[0];
	interface_desc = &host_interface->desc;
	endpoints = interface_desc->bNumEndpoints;

	rtwusb->num_in_pipes = 0;
	rtwusb->num_out_pipes = 0;
	for (i = 0; i < endpoints; i++) {
		endpoint = &host_interface->endpoint[i].desc;
		dir = endpoint->bEndpointAddress & USB_ENDPOINT_DIR_MASK;
		num = usb_endpoint_num(endpoint);
		xtype = usb_endpoint_type(endpoint);
		rtw_info(rtwdev, "\nusb endpoint descriptor (%i):\n", i);
		rtw_info(rtwdev, "bLength=%x\n", endpoint->bLength);
		rtw_info(rtwdev, "bDescriptorType=%x\n",
			 endpoint->bDescriptorType);
		rtw_info(rtwdev, "bEndpointAddress=%x\n",
			 endpoint->bEndpointAddress);
		rtw_info(rtwdev, "wMaxPacketSize=%d\n",
			 le16_to_cpu(endpoint->wMaxPacketSize));
		rtw_info(rtwdev, "bInterval=%x\n", endpoint->bInterval);

		if (usb_endpoint_dir_in(endpoint) &&
		    usb_endpoint_xfer_bulk(endpoint)) {
			rtw_info(rtwdev, "USB: dir in endpoint num %i\n", num);

			if (rtwusb->pipe_in) {
				rtw_err(rtwdev,
					"failed to get many IN pipes\n");
				ret = -EINVAL;
				goto exit;
			}

			rtwusb->pipe_in = num;
			rtwusb->num_in_pipes++;
		}

		if (usb_endpoint_dir_in(endpoint) &&
		    usb_endpoint_xfer_int(endpoint)) {
			rtw_info(rtwdev, "USB: interrupt endpoint num %i\n",
				 num);

			if (rtwusb->pipe_interrupt) {
				rtw_err(rtwdev,
					"failed to get many INTERRUPT pipes\n");
				ret = -EINVAL;
				goto exit;
			}

			rtwusb->pipe_interrupt = num;
		}

		if (usb_endpoint_dir_out(endpoint) &&
		    usb_endpoint_xfer_bulk(endpoint)) {
			rtw_info(rtwdev, "USB: out endpoint num %i\n", num);
			if (j >= 4) {
				rtw_err(rtwdev,
					"failed to get many OUT pipes\n");
				ret = -EINVAL;
				goto exit;
			}

			/* for out enpoint, address == number */
			rtwusb->out_ep[j++] = num;
			rtwusb->num_out_pipes++;
		}
	}

	switch (usbd->speed) {
	case USB_SPEED_LOW:
		rtw_info(rtwdev, "USB_SPEED_LOW\n");
		rtwusb->usb_speed = RTW_USB_SPEED_1_1;
		break;
	case USB_SPEED_FULL:
		rtw_info(rtwdev, "USB_SPEED_FULL\n");
		rtwusb->usb_speed = RTW_USB_SPEED_1_1;
		break;
	case USB_SPEED_HIGH:
		rtw_info(rtwdev, "USB_SPEED_HIGH\n");
		rtwusb->usb_speed = RTW_USB_SPEED_2;
		break;
	case USB_SPEED_SUPER:
		rtw_info(rtwdev, "USB_SPEED_SUPER\n");
		rtwusb->usb_speed = RTW_USB_SPEED_3;
		break;
	default:
		rtw_err(rtwdev, "failed to get USB speed\n");
		break;
	}

exit:
	return ret;
}

/*
 * driver status relative functions
 */
static
bool rtw_usb_is_bus_ready(struct rtw_dev *rtwdev)
{
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);

	return (atomic_read(&rtwusb->is_bus_drv_ready) == true);
}

static
void rtw_usb_set_bus_ready(struct rtw_dev *rtwdev, bool ready)
{
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);

	atomic_set(&rtwusb->is_bus_drv_ready, ready);
}

static u8 rtw_usb_tx_queue_mapping(struct sk_buff *skb)
{
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)skb->data;
	__le16 fc = hdr->frame_control;
	u8 q_mapping = skb_get_queue_mapping(skb);
	u8 queue = RTW_TX_QUEUE_BCN;

	if (unlikely(ieee80211_is_mgmt(fc) || ieee80211_is_ctl(fc)))
		queue = RTW_TX_QUEUE_MGMT;
	else if (q_mapping <= IEEE80211_AC_BK)
		queue = rtw_usb_ac_to_hwq[q_mapping];

	return queue;
}

static unsigned int rtw_usb_get_pipe(struct rtw_usb *rtwusb, u32 addr)
{
	struct rtw_dev *rtwdev = rtwusb->rtwdev;
	struct usb_device *usbd = rtwusb->udev;
	unsigned int pipe = 0, ep_num = 0;

	if (addr == RTW_USB_BULK_IN_ADDR) {
		pipe = usb_rcvbulkpipe(usbd, rtwusb->pipe_in);
	} else if (addr == RTW_USB_INT_IN_ADDR) {
		pipe = usb_rcvintpipe(usbd, rtwusb->pipe_interrupt);
	} else if (addr < RTW_USB_HW_QUEUE_ENTRY) {
		ep_num = rtwusb->queue_to_pipe[addr];
		pipe = usb_sndbulkpipe(usbd, ep_num);
	} else {
		rtw_err(rtwdev, "failed to get pipe, addr error: %d\n", addr);
	}

	return pipe;
}

static void rtw_usb_one_outpipe_mapping(struct rtw_usb *rtwusb)
{
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_VO] = rtwusb->out_ep[0];/* VO */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_VI] = rtwusb->out_ep[0];/* VI */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_BE] = rtwusb->out_ep[0];/* BE */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_BK] = rtwusb->out_ep[0];/* BK */

	rtwusb->queue_to_pipe[RTW_TX_QUEUE_BCN] = rtwusb->out_ep[0];/* BCN */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_MGMT] = rtwusb->out_ep[0];/* MGT */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_HI0] = rtwusb->out_ep[0];/* HIGH */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_H2C] = rtwusb->out_ep[0];/* TXCMD */
}

static void rtw_usb_two_outpipe_mapping(struct rtw_usb *rtwusb)
{
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_VO] = rtwusb->out_ep[0];/* VO */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_VI] = rtwusb->out_ep[0];/* VI */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_BE] = rtwusb->out_ep[1];/* BE */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_BK] = rtwusb->out_ep[1];/* BK */

	rtwusb->queue_to_pipe[RTW_TX_QUEUE_BCN] = rtwusb->out_ep[0];/* BCN */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_MGMT] = rtwusb->out_ep[0];/* MGT */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_HI0] = rtwusb->out_ep[0];/* HIGH */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_H2C] = rtwusb->out_ep[0];/* TXCMD */
}

static void rtw_usb_three_outpipe_mapping(struct rtw_usb *rtwusb)
{
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_VO] = rtwusb->out_ep[0];/* VO */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_VI] = rtwusb->out_ep[1];/* VI */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_BE] = rtwusb->out_ep[2];/* BE */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_BK] = rtwusb->out_ep[2];/* BK */

	rtwusb->queue_to_pipe[RTW_TX_QUEUE_BCN] = rtwusb->out_ep[0];/* BCN */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_MGMT] = rtwusb->out_ep[0];/* MGT */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_HI0] = rtwusb->out_ep[0];/* HIGH */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_H2C] = rtwusb->out_ep[0];/* TXCMD */
}

static void rtw_usb_set_queue_pipe_mapping(struct rtw_dev *rtwdev, u8 in_pipes,
					   u8 out_pipes)
{
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);

	rtwusb->out_ep_queue_sel = 0;
	rtwdev->hci.bulkout_num = 0;

	switch (out_pipes) {
	case 4:
		rtwusb->out_ep_queue_sel = RTW_USB_TX_SEL_HQ |
					   RTW_USB_TX_SEL_LQ |
					   RTW_USB_TX_SEL_NQ;
		rtwdev->hci.bulkout_num = 4;
		break;
	case 3:
		rtwusb->out_ep_queue_sel = RTW_USB_TX_SEL_HQ |
					   RTW_USB_TX_SEL_LQ |
					   RTW_USB_TX_SEL_NQ;
		rtwdev->hci.bulkout_num = 3;
		break;
	case 2:
		rtwusb->out_ep_queue_sel = RTW_USB_TX_SEL_HQ |
					   RTW_USB_TX_SEL_NQ;
		rtwdev->hci.bulkout_num = 2;
		break;
	case 1:
		rtwusb->out_ep_queue_sel = RTW_USB_TX_SEL_HQ;
		rtwdev->hci.bulkout_num = 1;
		break;
	default:
		break;
	}

	switch (out_pipes) {
	case 2:
		rtw_usb_two_outpipe_mapping(rtwusb);
		break;
	case 3:
	case 4:
		rtw_usb_three_outpipe_mapping(rtwusb);
		break;
	case 1:
		rtw_usb_one_outpipe_mapping(rtwusb);
		break;
	default:
		rtw_err(rtwdev, "failed to get out_pipes(%d)\n", out_pipes);
	}
}

static void rtw_usb_interface_configure(struct rtw_dev *rtwdev)
{
	struct rtw_chip_info *chip = rtwdev->chip;
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);

	if (RTW_USB_IS_SUPER_SPEED(rtwusb))
		rtwusb->bulkout_size = RTW_USB_SUPER_SPEED_BULK_SIZE;
	else if (RTW_USB_IS_HIGH_SPEED(rtwusb))
		rtwusb->bulkout_size = RTW_USB_HIGH_SPEED_BULK_SIZE;
	else
		rtwusb->bulkout_size = RTW_USB_FULL_SPEED_BULK_SIZE;
	rtw_info(rtwdev, "USB: bulkout_size: %d\n", rtwusb->bulkout_size);

	rtwusb->usb_txagg_num = chip->usb_txagg_num;
	rtw_info(rtwdev, "USB: TX Agg desc num: %d\n", rtwusb->usb_txagg_num);

	rtw_usb_set_queue_pipe_mapping(rtwdev, rtwusb->num_in_pipes,
				       rtwusb->num_out_pipes);
	rtw_info(rtwdev, "USB: bulkout_num: %d\n", rtwdev->hci.bulkout_num);
}

static void rtw_usb_tx_handler(struct work_struct *work)
{
	struct rtw_usb_work_data *work_data = container_of(work,
					struct rtw_usb_work_data,
					work);
	struct rtw_dev *rtwdev = work_data->rtwdev;
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);
	struct sk_buff *skb;
	bool is_empty = true;
	int index;

	index = RTK_MAX_TX_QUEUE_NUM - 1;
	while (index >= 0) {
		skb = skb_dequeue(&rtwusb->tx_queue[index]);
		if (skb) {
			rtw_usb_tx_agg(rtwusb, skb);
			is_empty = false;
		} else {
			index--;
		}

		if (index < 0 && !is_empty) {
			index = RTK_MAX_TX_QUEUE_NUM - 1;
			is_empty = true;
		}
	}
}

static void rtw_usb_indicate_tx_status(struct rtw_dev *rtwdev,
				       struct sk_buff *skb)
{
	struct ieee80211_hw *hw = rtwdev->hw;
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);

	info->flags |= IEEE80211_TX_STAT_ACK;

	ieee80211_tx_info_clear_status(info);
	ieee80211_tx_status_irqsafe(hw, skb);
}

static void rtw_usb_write_port_complete(struct urb *urb)
{
	struct sk_buff *skb;

	skb = (struct sk_buff *)urb->context;
	dev_kfree_skb_any(skb);
}

static int rtw_usb_write_port(struct rtw_dev *rtwdev, u8 addr, u32 cnt,
			      struct sk_buff *skb,
			      usb_complete_t cb, void *context)
{
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);
	struct usb_device *usbd = rtwusb->udev;
	struct urb *urb;
	unsigned int pipe;
	int ret;

	pipe = rtw_usb_get_pipe(rtwusb, addr);
	urb = usb_alloc_urb(0, GFP_ATOMIC);
	if (!urb)
		return -ENOMEM;

	usb_fill_bulk_urb(urb, usbd, pipe, skb->data, (int)cnt,
			  cb, context);
	ret = usb_submit_urb(urb, GFP_ATOMIC);
	if (unlikely(ret))
		rtw_err(rtwdev, "failed to submit write urb, ret=%d\n", ret);
	usb_free_urb(urb);

	return ret;
}

static void rtw_usb_write_port_tx_complete(struct urb *urb)
{
	struct rtw_usb_txcb_t *txcb;

	if (!urb)
		return;

	txcb = urb->context;
	rtw_usb_txcb_ack(txcb);
	kfree(txcb);
}

static int rtw_usb_write_port_tx(struct rtw_dev *rtwdev, u8 addr, u32 cnt,
				 struct sk_buff *skb,
				 struct rtw_usb_txcb_t *txcb)
{
	return rtw_usb_write_port(rtwdev, addr, cnt, skb,
				  rtw_usb_write_port_tx_complete, txcb);
}

static void rtw_usb_tx_queue_init(struct rtw_usb *rtwusb)
{
	int i;

	for (i = 0; i < RTK_MAX_TX_QUEUE_NUM; i++)
		skb_queue_head_init(&rtwusb->tx_queue[i]);
}

static void rtw_usb_tx_queue_purge(struct rtw_usb *rtwusb)
{
	int i;

	for (i = 0; i < RTK_MAX_TX_QUEUE_NUM; i++)
		skb_queue_purge(&rtwusb->tx_queue[i]);
}

static void rtw_usb_rx_queue_purge(struct rtw_usb *rtwusb)
{
	skb_queue_purge(&rtwusb->rx_queue);
}

static struct rtw_usb_txcb_t *rtw_usb_txcb_init(struct rtw_dev *rtwdev)
{
	struct rtw_usb_txcb_t *txcb;

	txcb = kmalloc(sizeof(*txcb), GFP_ATOMIC);
	if (!txcb)
		return NULL;

	txcb->rtwdev = rtwdev;
	skb_queue_head_init(&txcb->tx_ack_queue);

	return txcb;
}

static void rtw_usb_txcb_enqueue(struct rtw_usb_txcb_t *txcb,
				 struct sk_buff *skb)
{
	skb_queue_tail(&txcb->tx_ack_queue, skb);
}

static void rtw_usb_txcb_ack(struct rtw_usb_txcb_t *txcb)
{
	struct rtw_dev *rtwdev = txcb->rtwdev;
	struct sk_buff *skb;

	while ((skb = skb_dequeue(&txcb->tx_ack_queue))) {
		u8 qsel, queue;

		qsel = GET_TX_DESC_QSEL(skb->data);
		queue = rtw_tx_qsel_to_queue(rtwdev, qsel);

		if (queue <= RTW_TX_QUEUE_VO)
			rtw_usb_indicate_tx_status(rtwdev, skb);
		else
			dev_kfree_skb_any(skb);
	}
}

static void rtw_usb_tx_agg_skb(struct rtw_usb *rtwusb,
			       struct sk_buff_head *list,
			       struct sk_buff *skb_head, struct sk_buff *skb,
			       struct rtw_usb_txcb_t *txcb)
{
	struct sk_buff *skb_iter;
	unsigned long flags;
	u8 *data_ptr;
	int agg_num = 0, len, max_len;

	data_ptr = skb_head->data;
	skb_iter = skb;
	while (skb_iter) {
		memcpy(data_ptr, skb_iter->data, skb_iter->len);
		len = ALIGN(skb_iter->len, 8);
		skb_put(skb_head, len);
		data_ptr += len;
		agg_num++;

		rtw_usb_txcb_enqueue(txcb, skb);

		spin_lock_irqsave(&list->lock, flags);
		skb_iter = skb_peek(list);
		max_len = RTW_USB_MAX_XMITBUF_SZ - skb_head->len;
		if (skb_iter && skb_iter->len < max_len)
			__skb_unlink(skb_iter, list);
		else
			skb_iter = NULL;
		spin_unlock_irqrestore(&list->lock, flags);
	}

	if (agg_num > 1)
		rtw_usb_fill_tx_checksum(rtwusb, skb_head, agg_num);
}

static struct sk_buff *rtw_usb_tx_agg_check(struct rtw_usb *rtwusb,
					    struct sk_buff *skb,
					    u8 queue,
					    struct rtw_usb_txcb_t *txcb)
{
	struct sk_buff_head *list;
	struct sk_buff *skb_head;

	if (queue != RTW_TX_QUEUE_VO)
		return NULL;

	list = &rtwusb->tx_queue[queue];
	if (skb_queue_empty(list))
		return NULL;

	skb_head = dev_alloc_skb(RTW_USB_MAX_XMITBUF_SZ);
	if (!skb_head)
		return NULL;

	rtw_usb_tx_agg_skb(rtwusb, list, skb_head, skb, txcb);
	return skb_head;
}

static void rtw_usb_tx_agg(struct rtw_usb *rtwusb, struct sk_buff *skb)
{
	struct rtw_dev *rtwdev = rtwusb->rtwdev;
	struct sk_buff *skb_head;
	struct rtw_usb_txcb_t *txcb;
	u8 queue, qsel;
	int ret;

	txcb = rtw_usb_txcb_init(rtwdev);
	if (!txcb)
		return;

	qsel = GET_TX_DESC_QSEL(skb->data);
	queue = rtw_tx_qsel_to_queue(rtwdev, qsel);

	skb_head = rtw_usb_tx_agg_check(rtwusb, skb, queue, txcb);
	if (!skb_head) {
		skb_head = skb;
		rtw_usb_txcb_enqueue(txcb, skb);
	}

	ret = rtw_usb_write_port_tx(rtwdev, queue, skb_head->len, skb_head,
				    txcb);
	if (ret)
		rtw_err(rtwdev, "failed to do USB write sync, ret=%d\n", ret);

	if (skb_head != skb)
		dev_kfree_skb(skb_head);
}

static int rtw_usb_write_data(struct rtw_dev *rtwdev,
			      struct rtw_tx_pkt_info *pkt_info,
			      u8 *buf)
{
	struct rtw_chip_info *chip = rtwdev->chip;
	struct sk_buff *skb;
	unsigned int desclen, len, headsize, size;
	u8 queue, qsel;
	int ret;

	size = pkt_info->tx_pkt_size;
	qsel = pkt_info->qsel;
	desclen = chip->tx_pkt_desc_sz;
	headsize = (pkt_info->offset) ? pkt_info->offset : desclen;
	len = headsize + size;

	skb = dev_alloc_skb(len);
	if (unlikely(!skb))
		return -ENOMEM;

	skb_reserve(skb, headsize);
	skb_put_data(skb, buf, size);
	skb_push(skb, headsize);
	memset(skb->data, 0, headsize);
	rtw_tx_fill_tx_desc(pkt_info, skb);
	chip->ops->fill_txdesc_checksum(rtwdev, pkt_info, skb->data);
	queue = rtw_tx_qsel_to_queue(rtwdev, qsel);
	ret = rtw_usb_write_port(rtwdev, queue, len, skb,
				 rtw_usb_write_port_complete, skb);
	if (unlikely(ret))
		rtw_err(rtwdev, "failed to do USB write, ret=%d\n", ret);

	return ret;
}

static int rtw_usb_write_data_rsvd_page(struct rtw_dev *rtwdev, u8 *buf,
					u32 size)
{
	struct rtw_chip_info *chip = rtwdev->chip;
	struct rtw_usb *rtwusb;
	struct rtw_tx_pkt_info pkt_info = {0};
	u32 len, desclen;
	u8 qsel = TX_DESC_QSEL_BEACON;

	if (unlikely(!rtwdev))
		return -EINVAL;

	rtwusb = rtw_get_usb_priv(rtwdev);
	if (unlikely(!rtwusb))
		return -EINVAL;

	pkt_info.tx_pkt_size = size;
	pkt_info.qsel = qsel;

	desclen = chip->tx_pkt_desc_sz;
	len = desclen + size;
	if (len % rtwusb->bulkout_size == 0) {
		len = len + RTW_USB_PACKET_OFFSET_SZ;
		pkt_info.offset = desclen + RTW_USB_PACKET_OFFSET_SZ;
		pkt_info.pkt_offset = 1;
	} else {
		pkt_info.offset = desclen;
	}

	return rtw_usb_write_data(rtwdev, &pkt_info, buf);
}

static int rtw_usb_write_data_h2c(struct rtw_dev *rtwdev, u8 *buf, u32 size)
{
	struct rtw_tx_pkt_info pkt_info = {0};
	u8 qsel = TX_DESC_QSEL_H2C;

	pkt_info.tx_pkt_size = size;
	pkt_info.qsel = qsel;

	return rtw_usb_write_data(rtwdev, &pkt_info, buf);
}

static int rtw_usb_tx_write(struct rtw_dev *rtwdev,
			    struct rtw_tx_pkt_info *pkt_info,
			    struct sk_buff *skb)
{
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);
	struct rtw_chip_info *chip = rtwdev->chip;
	struct rtw_usb_tx_data *tx_data;
	u8 *pkt_desc;
	u8 queue = rtw_usb_tx_queue_mapping(skb);

	if (!pkt_info)
		return -EINVAL;

	pkt_desc = skb_push(skb, chip->tx_pkt_desc_sz);
	memset(pkt_desc, 0, chip->tx_pkt_desc_sz);
	pkt_info->qsel = rtw_tx_queue_to_qsel(skb, queue);
	rtw_tx_fill_tx_desc(pkt_info, skb);
	chip->ops->fill_txdesc_checksum(rtwdev, pkt_info, skb->data);

	tx_data = rtw_usb_get_tx_data(skb);
	tx_data->sn = pkt_info->sn;
	skb_queue_tail(&rtwusb->tx_queue[queue], skb);
	return 0;
}

static void rtw_usb_tx_kick_off(struct rtw_dev *rtwdev)
{
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);

	queue_work(rtwusb->txwq, &rtwusb->tx_handler_data->work);
}

static void rtw_usb_rx_handler(struct work_struct *work)
{
	struct rtw_usb_work_data *work_data = container_of(work,
						struct rtw_usb_work_data,
						work);
	struct rtw_dev *rtwdev = work_data->rtwdev;
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);
	struct rtw_chip_info *chip = rtwdev->chip;
	struct rtw_rx_pkt_stat pkt_stat;
	struct ieee80211_rx_status rx_status;
	struct sk_buff *skb;
	u32 pkt_desc_sz = chip->rx_pkt_desc_sz;
	u32 pkt_offset;
	u8 *rx_desc;

	while ((skb = skb_dequeue(&rtwusb->rx_queue)) != NULL) {
		rx_desc = skb->data;
		chip->ops->query_rx_desc(rtwdev, rx_desc, &pkt_stat,
					 &rx_status);
		pkt_offset = pkt_desc_sz + pkt_stat.drv_info_sz +
			     pkt_stat.shift;

		if (pkt_stat.is_c2h) {
			skb_put(skb, pkt_stat.pkt_len + pkt_offset);
			*((u32 *)skb->cb) = pkt_offset;
			rtw_fw_c2h_cmd_handle(rtwdev, skb);
			dev_kfree_skb(skb);
			continue;
		}

		if (skb_queue_len(&rtwusb->rx_queue) >= RTW_USB_MAX_RXQ_LEN) {
			rtw_err(rtwdev, "failed to get rx_queue, overflow\n");
			dev_kfree_skb(skb);
			continue;
		}

		skb_put(skb, pkt_stat.pkt_len);
		skb_reserve(skb, pkt_offset);

		memcpy(skb->cb, &rx_status, sizeof(rx_status));
		ieee80211_rx_irqsafe(rtwdev->hw, skb);
	}
}

static void rtw_usb_read_port_complete(struct urb *urb)
{
	struct rx_usb_ctrl_block *rxcb = urb->context;
	struct rtw_dev *rtwdev = (struct rtw_dev *)rxcb->data;
	struct rtw_usb *rtwusb = (struct rtw_usb *)rtwdev->priv;
	struct sk_buff *skb = rxcb->rx_skb;

	rxcb->rx_urb = NULL;

	if (urb->status == 0) {
		if (urb->actual_length >= RTW_USB_MAX_RECVBUF_SZ ||
		    urb->actual_length < 24) {
			rtw_err(rtwdev, "failed to get urb length:%d\n",
				urb->actual_length);
			if (skb)
				dev_kfree_skb_any(skb);
		} else {
			skb_queue_tail(&rtwusb->rx_queue, skb);
			queue_work(rtwusb->rxwq,
				   &rtwusb->rx_handler_data->work);
		}

		rtw_usb_read_port(rtwdev, RTW_USB_BULK_IN_ADDR, rxcb);
	} else {
		switch (urb->status) {
		case -EINVAL:
		case -EPIPE:
		case -ENODEV:
		case -ESHUTDOWN:
		case -ENOENT:
			/* USB HW may not be available, e.g. unplugged */
			rtw_usb_set_bus_ready(rtwdev, false);
			break;
		case -EPROTO:
		case -EILSEQ:
		case -ETIME:
		case -ECOMM:
		case -EOVERFLOW:
			rtw_err(rtwdev, "failed to read at USB, SW\n");
			break;
		case -EINPROGRESS:
			rtw_err(rtwdev, "failed to read at USB, in process\n");
			break;
		default:
			rtw_err(rtwdev, "failed to read at USB, unknown: %d\n",
				urb->status);
			break;
		}
		if (skb)
			dev_kfree_skb_any(skb);
	}
}

static void rtw_usb_read_port(struct rtw_dev *rtwdev, u8 addr,
			      struct rx_usb_ctrl_block *rxcb)
{
	struct urb *urb = NULL;
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);
	struct usb_device *usbd = rtwusb->udev;
	struct sk_buff *skb;
	unsigned int pipe;
	size_t alignment;
	u32 len;
	int ret;

	urb = usb_alloc_urb(0, GFP_ATOMIC);
	if (!urb)
		return;

	rxcb->data = (void *)rtwdev;
	pipe = rtw_usb_get_pipe(rtwusb, RTW_USB_BULK_IN_ADDR);
	len = RTW_USB_MAX_RECVBUF_SZ + RTW_USB_RECVBUFF_ALIGN_SZ;
	skb = dev_alloc_skb(len);
	if (!skb) {
		usb_free_urb(urb);
		return;
	}

	alignment = (size_t)skb->data & (RTW_USB_RECVBUFF_ALIGN_SZ - 1);
	skb_reserve(skb, RTW_USB_RECVBUFF_ALIGN_SZ - alignment);
	urb->transfer_buffer = skb->data;
	rxcb->rx_urb = urb;
	rxcb->rx_skb = skb;
	usb_fill_bulk_urb(urb, usbd, pipe,
			  urb->transfer_buffer,
			  RTW_USB_MAX_RECVBUF_SZ,
			  rtw_usb_read_port_complete,
			  rxcb);
	ret = usb_submit_urb(urb, GFP_ATOMIC);
	if (ret)
		rtw_err(rtwdev, "failed to submit USB urb, ret=%d\n", ret);

	usb_free_urb(urb);
}

static void rtw_usb_inirp_init(struct rtw_dev *rtwdev)
{
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);
	struct rx_usb_ctrl_block *rxcb;
	int i;

	if (rtw_usb_is_bus_ready(rtwdev)) {
		rtw_err(rtwdev, "fail to do USB inirp init, bus is set\n");
		return;
	}

	for (i = 0; i < RTW_USB_RXCB_NUM; i++) {
		rxcb = &rtwusb->rx_cb[i];
		rxcb->rx_urb = NULL;
	}

	for (i = 0; i < RTW_USB_RXCB_NUM; i++) {
		rxcb = &rtwusb->rx_cb[i];
		rtw_usb_read_port(rtwdev, RTW_USB_BULK_IN_ADDR, rxcb);
	}

	rtw_usb_set_bus_ready(rtwdev, true);
}

static void rtw_usb_inirp_deinit(struct rtw_dev *rtwdev)
{
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);
	struct rx_usb_ctrl_block *rxcb;
	int i;

	rtw_usb_set_bus_ready(rtwdev, false);

	for (i = 0; i < RTW_USB_RXCB_NUM; i++) {
		rxcb = &rtwusb->rx_cb[i];
		if (rxcb->rx_urb) {
			usb_kill_urb(rxcb->rx_urb);
			usb_free_urb(rxcb->rx_urb);
		}
	}
}

static int rtw_usb_setup(struct rtw_dev *rtwdev)
{
	/* empty function for rtw_hci_ops */
	return 0;
}

static int rtw_usb_start(struct rtw_dev *rtwdev)
{
	rtw_usb_inirp_init(rtwdev);
	return 0;
}

static void rtw_usb_stop(struct rtw_dev *rtwdev)
{
	rtw_usb_inirp_deinit(rtwdev);
}

static void rtw_usb_deep_ps(struct rtw_dev *rtwdev, bool enter)
{
	rtw_info(rtwdev, "USB deep ps: %d\n", enter);
}

static void rtw_usb_link_ps(struct rtw_dev *rtwdev, bool enter)
{
	rtw_info(rtwdev, "USB link ps: %d\n", enter);
}

static void rtw_usb_interface_cfg(struct rtw_dev *rtwdev)
{
	/* empty function for rtw_hci_ops */
}

static struct rtw_hci_ops rtw_usb_ops = {
	.tx_write = rtw_usb_tx_write,
	.tx_kick_off = rtw_usb_tx_kick_off,
	.setup = rtw_usb_setup,
	.start = rtw_usb_start,
	.stop = rtw_usb_stop,
	.deep_ps = rtw_usb_deep_ps,
	.link_ps = rtw_usb_link_ps,
	.interface_cfg = rtw_usb_interface_cfg,

	.read8 = rtw_usb_read8,
	.read16 = rtw_usb_read16,
	.read32 = rtw_usb_read32,
	.write8 = rtw_usb_write8,
	.write16 = rtw_usb_write16,
	.write32 = rtw_usb_write32,

	.write_data_rsvd_page = rtw_usb_write_data_rsvd_page,
	.write_data_h2c = rtw_usb_write_data_h2c,
};

static int rtw_usb_init_rx(struct rtw_dev *rtwdev)
{
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);

	rtwusb->rxwq = create_singlethread_workqueue("rtw88_usb: rx wq");
	if (!rtwusb->rxwq) {
		rtw_err(rtwdev, "failed to create RX work queue\n");
		goto err_destroy_wq;
	}

	skb_queue_head_init(&rtwusb->rx_queue);
	rtwusb->rx_handler_data = kmalloc(sizeof(*rtwusb->rx_handler_data),
					  GFP_KERNEL);
	if (!rtwusb->rx_handler_data)
		goto err_destroy_wq;

	rtwusb->rx_handler_data->rtwdev = rtwdev;
	INIT_WORK(&rtwusb->rx_handler_data->work, rtw_usb_rx_handler);
	return 0;

err_destroy_wq:
	if (rtwusb->rxwq)
		destroy_workqueue(rtwusb->rxwq);
	return -ENOMEM;
}

static void rtw_usb_deinit_rx(struct rtw_dev *rtwdev)
{
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);

	rtw_usb_rx_queue_purge(rtwusb);
	flush_workqueue(rtwusb->rxwq);
	destroy_workqueue(rtwusb->rxwq);
	kfree(rtwusb->rx_handler_data);
}

static int rtw_usb_init_tx(struct rtw_dev *rtwdev)
{
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);

	rtwusb->txwq = create_singlethread_workqueue("rtw88_usb: tx wq");
	if (!rtwusb->txwq) {
		rtw_err(rtwdev, "failed to create TX work queue\n");
		goto err_destroy_wq;
	}

	rtw_usb_tx_queue_init(rtwusb);
	rtwusb->tx_handler_data = kmalloc(sizeof(*rtwusb->tx_handler_data),
					  GFP_KERNEL);
	if (!rtwusb->tx_handler_data)
		goto err_destroy_wq;

	rtwusb->tx_handler_data->rtwdev = rtwdev;
	INIT_WORK(&rtwusb->tx_handler_data->work, rtw_usb_tx_handler);
	return 0;

err_destroy_wq:
	if (rtwusb->txwq)
		destroy_workqueue(rtwusb->txwq);
	return -ENOMEM;
}

static void rtw_usb_deinit_tx(struct rtw_dev *rtwdev)
{
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);

	rtw_usb_tx_queue_purge(rtwusb);
	flush_workqueue(rtwusb->txwq);
	destroy_workqueue(rtwusb->txwq);
	kfree(rtwusb->tx_handler_data);
}

static int rtw_usb_intf_init(struct rtw_dev *rtwdev,
			     struct usb_interface *intf)
{
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);
	struct usb_device *udev = usb_get_dev(interface_to_usbdev(intf));
	int ret;

	rtwusb->udev = udev;
	rtwusb->rtwdev = rtwdev;
	ret = rtw_usb_parse(rtwdev, intf);
	if (ret) {
		rtw_err(rtwdev, "failed to check USB configuration, ret=%d\n",
			ret);
		return ret;
	}

	usb_set_intfdata(intf, rtwdev->hw);
	rtw_usb_interface_configure(rtwdev);
	SET_IEEE80211_DEV(rtwdev->hw, &intf->dev);

	return 0;
}

static void rtw_usb_intf_deinit(struct rtw_dev *rtwdev,
				struct usb_interface *intf)
{
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);

	usb_put_dev(rtwusb->udev);
	usb_set_intfdata(intf, NULL);
}

static int rtw_usb_probe(struct usb_interface *intf,
			 const struct usb_device_id *id)
{
	struct rtw_dev *rtwdev;
	struct ieee80211_hw *hw;
	int drv_data_size;
	int ret;

	drv_data_size = sizeof(struct rtw_dev) + sizeof(struct rtw_usb);
	hw = ieee80211_alloc_hw(drv_data_size, &rtw_ops);
	if (!hw)
		return -ENOMEM;

	rtwdev = hw->priv;
	rtwdev->hw = hw;
	rtwdev->dev = &intf->dev;
	rtwdev->chip = (struct rtw_chip_info *)id->driver_info;
	rtwdev->hci.ops = &rtw_usb_ops;
	rtwdev->hci.type = RTW_HCI_TYPE_USB;

	ret = rtw_core_init(rtwdev);
	if (ret)
		goto err_release_hw;

	ret = rtw_usb_intf_init(rtwdev, intf);
	if (ret) {
		rtw_err(rtwdev, "failed to init USB interface\n");
		goto err_deinit_core;
	}

	ret = rtw_usb_init_tx(rtwdev);
	if (ret) {
		rtw_err(rtwdev, "failed to init USB TX\n");
		goto err_destroy_usb;
	}

	ret = rtw_usb_init_rx(rtwdev);
	if (ret) {
		rtw_err(rtwdev, "failed to init USB RX\n");
		goto err_destroy_txwq;
	}

	ret = rtw_chip_info_setup(rtwdev);
	if (ret) {
		rtw_err(rtwdev, "failed to setup chip information\n");
		goto err_destroy_rxwq;
	}

	ret = rtw_register_hw(rtwdev, rtwdev->hw);
	if (ret) {
		rtw_err(rtwdev, "failed to register hw\n");
		goto err_destroy_rxwq;
	}

	return 0;

err_destroy_rxwq:
	rtw_usb_deinit_rx(rtwdev);

err_destroy_txwq:
	rtw_usb_deinit_tx(rtwdev);

err_destroy_usb:
	rtw_usb_intf_deinit(rtwdev, intf);

err_deinit_core:
	rtw_core_deinit(rtwdev);

err_release_hw:
	ieee80211_free_hw(hw);

	return ret;
}

static void rtw_usb_disconnect(struct usb_interface *intf)
{
	struct ieee80211_hw *hw = usb_get_intfdata(intf);
	struct rtw_dev *rtwdev;
	struct rtw_usb *rtwusb;

	if (!hw)
		return;
	rtwdev = hw->priv;
	rtwusb = rtw_get_usb_priv(rtwdev);

	rtw_unregister_hw(rtwdev, hw);
	rtw_usb_deinit_tx(rtwdev);
	rtw_usb_deinit_rx(rtwdev);

	if (rtwusb->udev->state != USB_STATE_NOTATTACHED)
		usb_reset_device(rtwusb->udev);

	rtw_usb_intf_deinit(rtwdev, intf);
	rtw_core_deinit(rtwdev);
	ieee80211_free_hw(hw);
}

static const struct usb_device_id rtw_usb_id_table[] = {
#ifdef CONFIG_RTW88_8822B
	{ RTK_USB_DEVICE(RTW_USB_VENDOR_ID_REALTEK,
			 RTW_USB_PRODUCT_ID_REALTEK_8812B,
			 rtw8822b_hw_spec) },
	{ RTK_USB_DEVICE(RTW_USB_VENDOR_ID_REALTEK,
			 RTW_USB_PRODUCT_ID_REALTEK_8822B,
			 rtw8822b_hw_spec) },
	{ RTK_USB_DEVICE(RTW_USB_VENDOR_ID_EDIMAX,
			 0xB822, rtw8822b_hw_spec) },	/* Edimax */
	{ RTK_USB_DEVICE(RTW_USB_VENDOR_ID_EDIMAX,
			 0xC822, rtw8822b_hw_spec) },	/* Edimax */
	{ RTK_USB_DEVICE(0x0b05, 0x184c,
			 rtw8822b_hw_spec) },	/* ASUS AC53 Nano */
	{ RTK_USB_DEVICE(0x0b05, 0x1841,
			 rtw8822b_hw_spec) },	/* ASUS AC55 B1 */
	{ RTK_USB_DEVICE(0x2001, 0x331c,
			 rtw8822b_hw_spec) },	/* D-Link DWA-182 rev D1 */
	{ RTK_USB_DEVICE(0x13b1, 0x0043,
			 rtw8822b_hw_spec) },	/* Linksys WUSB6400M */
	{ RTK_USB_DEVICE(0x2357, 0x0115,
			 rtw8822b_hw_spec) },	/* TP-LINK - T4Uv3 */
	{ RTK_USB_DEVICE(0x2357, 0x012d,
			 rtw8822b_hw_spec) },	/* TP-LINK - T3U */
	{ RTK_USB_DEVICE(RTW_USB_VENDOR_ID_NETGEAR,
			 0x9055, rtw8822b_hw_spec) }, /* Netgear - A6150 */
#endif
#ifdef CONFIG_RTW88_8822C
	{ RTK_USB_DEVICE(RTW_USB_VENDOR_ID_REALTEK,
			 RTW_USB_PRODUCT_ID_REALTEK_8822C,
			 rtw8822c_hw_spec) },
	{ RTK_USB_DEVICE(RTW_USB_VENDOR_ID_REALTEK,
			 0xb82b, rtw8822c_hw_spec) },
	{ RTK_USB_DEVICE(RTW_USB_VENDOR_ID_REALTEK,
			 0xb820, rtw8822c_hw_spec) },
	{ RTK_USB_DEVICE(RTW_USB_VENDOR_ID_REALTEK,
			 0xC821, rtw8822c_hw_spec) },
	{ RTK_USB_DEVICE(RTW_USB_VENDOR_ID_REALTEK,
			 0xC820, rtw8822c_hw_spec) },
	{ RTK_USB_DEVICE(RTW_USB_VENDOR_ID_REALTEK,
			 0xC82A, rtw8822c_hw_spec) },
	{ RTK_USB_DEVICE(RTW_USB_VENDOR_ID_REALTEK,
			 0xC82B, rtw8822c_hw_spec) },
#endif
	{},
};
MODULE_DEVICE_TABLE(usb, rtw_usb_id_table);

static struct usb_driver rtw_usb_driver = {
	.name = "rtwifi_usb",
	.id_table = rtw_usb_id_table,
	.probe = rtw_usb_probe,
	.disconnect = rtw_usb_disconnect,
};

module_usb_driver(rtw_usb_driver);

MODULE_AUTHOR("Realtek Corporation");
MODULE_DESCRIPTION("Realtek 802.11ac wireless USB driver");
MODULE_LICENSE("Dual BSD/GPL");
