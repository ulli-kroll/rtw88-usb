				
// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright(c) 2018-2019  Realtek Corporation
 */

#include <linux/module.h>
#include <linux/usb.h>
#include <linux/mutex.h>
#include "main.h"
#include "usb.h"
#include "tx.h"
#include "rx.h"
#include "fw.h"
#include "debug.h"

#define RTW_USB_CMD_READ		0xc0
#define RTW_USB_CMD_WRITE		0x40
#define RTW_USB_CMD_REQ			0x05
#define RTW_USB_CONTROL_MSG_TIMEOUT	500

#define RTW_USB_IS_FULL_SPEED_USB(rtwusb) \
	(rtwusb->usb_speed == RTW_USB_SPEED_1_1)
#define RTW_USB_IS_HIGH_SPEED(rtwusb)	(rtwusb->usb_speed == RTW_USB_SPEED_2)
#define RTW_USB_IS_SUPER_SPEED(rtwusb)	(rtwusb->usb_speed == RTW_USB_SPEED_3)

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
#define RTW_USB_MAX_RECVBUF_SZ		32768

#define RTW_USB_RECVBUFF_ALIGN_SZ	8

#define RTW_USB_RXAGG_SIZE		6
#define RTW_USB_RXAGG_TIMEOUT		10

/* work queue */
struct work_data {
	struct work_struct work;
	struct rtw_dev *rtwdev;
};

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

/*
 * usb read/write register functions
 */

static u8 rtw_usb_read8(struct rtw_dev *rtwdev, u32 addr)
{
	struct rtw_usb *rtwusb = (struct rtw_usb *)rtwdev->priv;
	struct usb_device *udev = rtwusb->udev;
	int len;
	u8 data;

	mutex_lock(&rtwusb->usb_buf_mutex);
	len = usb_control_msg(udev, usb_rcvctrlpipe(udev, 0),
			      RTW_USB_CMD_REQ, RTW_USB_CMD_READ,
			      addr, 0, &rtwusb->usb_buf.val8, sizeof(u8),
			      RTW_USB_CONTROL_MSG_TIMEOUT);
	data = rtwusb->usb_buf.val8;
	mutex_unlock(&rtwusb->usb_buf_mutex);

	return data;
}

static u16 rtw_usb_read16(struct rtw_dev *rtwdev, u32 addr)
{
	struct rtw_usb *rtwusb = (struct rtw_usb *)rtwdev->priv;
	struct usb_device *udev = rtwusb->udev;
	int len;
	u16 data;

	mutex_lock(&rtwusb->usb_buf_mutex);
	len = usb_control_msg(udev, usb_rcvctrlpipe(udev, 0),
			      RTW_USB_CMD_REQ, RTW_USB_CMD_READ,
			      addr, 0, &rtwusb->usb_buf.val16, sizeof(u16),
			      RTW_USB_CONTROL_MSG_TIMEOUT);
	data = le16_to_cpu(rtwusb->usb_buf.val16);
	mutex_unlock(&rtwusb->usb_buf_mutex);

	return data;
}

static u32 rtw_usb_read32(struct rtw_dev *rtwdev, u32 addr)
{
	struct rtw_usb *rtwusb = (struct rtw_usb *)rtwdev->priv;
	struct usb_device *udev = rtwusb->udev;
	int len;
	u32 data;

	mutex_lock(&rtwusb->usb_buf_mutex);
	len = usb_control_msg(udev, usb_rcvctrlpipe(udev, 0),
			      RTW_USB_CMD_REQ, RTW_USB_CMD_READ,
			      addr, 0, &rtwusb->usb_buf.val32, sizeof(u32),
			      RTW_USB_CONTROL_MSG_TIMEOUT);
	data = le32_to_cpu(rtwusb->usb_buf.val32);
	mutex_unlock(&rtwusb->usb_buf_mutex);

	return data;
}

static void rtw_usb_write8(struct rtw_dev *rtwdev, u32 addr, u8 val)
{
	struct rtw_usb *rtwusb = (struct rtw_usb *)rtwdev->priv;
	struct usb_device *udev = rtwusb->udev;
	int ret;

	mutex_lock(&rtwusb->usb_buf_mutex);
	rtwusb->usb_buf.val8 = val;
	ret = usb_control_msg(udev, usb_sndctrlpipe(udev, 0),
			      RTW_USB_CMD_REQ, RTW_USB_CMD_WRITE,
			      addr, 0, &rtwusb->usb_buf.val8, sizeof(u8),
			      RTW_USB_CONTROL_MSG_TIMEOUT);

	mutex_unlock(&rtwusb->usb_buf_mutex);
}

static void rtw_usb_write16(struct rtw_dev *rtwdev, u32 addr, u16 val)
{
	struct rtw_usb *rtwusb = (struct rtw_usb *)rtwdev->priv;
	struct usb_device *udev = rtwusb->udev;
	int ret;

	mutex_lock(&rtwusb->usb_buf_mutex);
	rtwusb->usb_buf.val16 = cpu_to_le16(val);
	ret = usb_control_msg(udev, usb_sndctrlpipe(udev, 0),
			      RTW_USB_CMD_REQ, RTW_USB_CMD_WRITE,
			      addr, 0, &rtwusb->usb_buf.val16, sizeof(u16),
			      RTW_USB_CONTROL_MSG_TIMEOUT);
	mutex_unlock(&rtwusb->usb_buf_mutex);
}

static void rtw_usb_write32(struct rtw_dev *rtwdev, u32 addr, u32 val)
{
	struct rtw_usb *rtwusb = (struct rtw_usb *)rtwdev->priv;
	struct usb_device *udev = rtwusb->udev;
	int ret;

	mutex_lock(&rtwusb->usb_buf_mutex);
	rtwusb->usb_buf.val32 = cpu_to_le32(val);
	ret = usb_control_msg(udev, usb_sndctrlpipe(udev, 0),
			      RTW_USB_CMD_REQ, RTW_USB_CMD_WRITE,
			      addr, 0, &rtwusb->usb_buf.val32, sizeof(u32),
			      RTW_USB_CONTROL_MSG_TIMEOUT);
	mutex_unlock(&rtwusb->usb_buf_mutex);
}

/* RTW queue / pipe functions */
static u8 rtw_usb_ac_to_hwq[] = {
	[IEEE80211_AC_VO] = RTW_TX_QUEUE_VO,
	[IEEE80211_AC_VI] = RTW_TX_QUEUE_VI,
	[IEEE80211_AC_BE] = RTW_TX_QUEUE_BE,
	[IEEE80211_AC_BK] = RTW_TX_QUEUE_BK,
};

static u8 rtw_tx_queue_mapping(struct sk_buff *skb)
{
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)skb->data;
	__le16 fc = hdr->frame_control;
	u8 q_mapping = skb_get_queue_mapping(skb);
	u8 queue;

	if (unlikely(ieee80211_is_beacon(fc)))
		queue = RTW_TX_QUEUE_BCN;
	else if (unlikely(ieee80211_is_mgmt(fc) || ieee80211_is_ctl(fc)))
		queue = RTW_TX_QUEUE_MGMT;
	else
		queue = rtw_usb_ac_to_hwq[q_mapping];

	return queue;
}

static u8 rtw_queue_to_qsel(struct sk_buff *skb, u8 queue)
{
	switch (queue) {
	case RTW_TX_QUEUE_BCN:
		return TX_DESC_QSEL_BEACON;
	case RTW_TX_QUEUE_H2C:
		return TX_DESC_QSEL_H2C;
	case RTW_TX_QUEUE_MGMT:
		return TX_DESC_QSEL_MGMT;
	case RTW_TX_QUEUE_HI0:
		return TX_DESC_QSEL_HIGH;
	default:
		return skb->priority;
	}
}

static u8 rtw_qsel_to_queue(u8 qsel)
{
	switch (qsel) {
	case TX_DESC_QSEL_BEACON:
		return RTW_TX_QUEUE_BCN;
	case TX_DESC_QSEL_H2C:
		return RTW_TX_QUEUE_H2C;
	case TX_DESC_QSEL_MGMT:
		return RTW_TX_QUEUE_MGMT;
	case TX_DESC_QSEL_HIGH:
		return RTW_TX_QUEUE_HI0;
	/* skb->priority */
	case TX_DESC_QSEL_TID6:
	case TX_DESC_QSEL_TID7:
		return RTW_TX_QUEUE_VO;
	case TX_DESC_QSEL_TID4:
	case TX_DESC_QSEL_TID5:
		return RTW_TX_QUEUE_VI;
	case TX_DESC_QSEL_TID0:
	case TX_DESC_QSEL_TID3:
		return RTW_TX_QUEUE_BE;
	case TX_DESC_QSEL_TID1:
	case TX_DESC_QSEL_TID2:
		return RTW_TX_QUEUE_BK;
	default:
		pr_err("%s: qsel(%d) is out of range\n", __func__, qsel);
		return -1;
	}
}

static unsigned int rtw_usb_get_pipe(struct rtw_usb *rtwusb, u32 addr)
{
	unsigned int pipe = 0, ep_num = 0;
	struct usb_device *usbd = rtwusb->udev;

	if (addr == RTW_USB_BULK_IN_ADDR) {
		pipe = usb_rcvbulkpipe(usbd, rtwusb->pipe_in);
	} else if (addr == RTW_USB_INT_IN_ADDR) {
		pipe = usb_rcvintpipe(usbd, rtwusb->pipe_interrupt);
	} else if (addr < RTW_USB_HW_QUEUE_ENTRY) {
		ep_num = rtwusb->queue_to_pipe[addr];
		pipe = usb_sndbulkpipe(usbd, ep_num);
	} else {
		pr_err("%s : addr error: %d\n", __func__, addr);
	}

	return pipe;
}

/* RTW Thread functions */

static int rtw_init_event(struct rtw_event *event)
{
	atomic_set(&event->event_condition, 1);
	init_waitqueue_head(&event->event_queue);
	return 0;
}

static int rtw_wait_event(struct rtw_event *event, u32 timeout)
{
	int status = 0;

	if (!timeout) 
		status = wait_event_interruptible(event->event_queue,
			  (atomic_read(&event->event_condition) == 0));
	else
		status = wait_event_interruptible_timeout(event->event_queue,
			  (atomic_read(&event->event_condition) == 0),
			  timeout);
	return status;
}

static void rtw_set_event(struct rtw_event *event)
{
	atomic_set(&event->event_condition, 0);
	wake_up_interruptible(&event->event_queue);
}

static void rtw_reset_event(struct rtw_event *event)
{
	atomic_set(&event->event_condition, 1);
}

static void rtw_create_handler(struct rtw_handler *handler)
{
	atomic_set(&handler->handler_done, 0);
}

static void rtw_kill_handler(struct rtw_handler *handler)
{
	atomic_inc(&handler->handler_done);
	rtw_set_event(&handler->event);
}

// TX functions
void rtw_tx_func(struct rtw_usb *rtwusb);
static void rtw_usb_tx_handler(struct work_struct *work)
{
	struct work_data *my_data = container_of(work, struct work_data,
						 work);
	struct rtw_dev *rtwdev = my_data->rtwdev;
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);
	u32 timeout = 0;

	do {
		rtw_wait_event(&rtwusb->tx_handler.event, timeout);
		rtw_reset_event(&rtwusb->tx_handler.event);

		if (rtwusb->init_done)
			rtw_tx_func(rtwusb);
	} while (atomic_read(&rtwusb->tx_handler.handler_done) == 0);
}

// RX functions
static u32 rtw_usb_read_port(struct rtw_dev *rtwdev, u8 addr);

static void rtw_usb_rx_handler(struct work_struct *work)
{
	struct work_data *my_data = container_of(work, struct work_data,
						 work);
	struct rtw_dev *rtwdev = my_data->rtwdev;
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);
	u32 timeout = 0;
	struct sk_buff *skb;


	do {
		rtw_wait_event(&rtwusb->rx_handler.event, timeout);
		rtw_reset_event(&rtwusb->rx_handler.event);

		while (true) {
			u8 *rx_desc;
			struct rtw_chip_info *chip = rtwdev->chip;
			struct ieee80211_rx_status rx_status;
			struct rtw_rx_pkt_stat pkt_stat;
			struct rtw_loopback *loopback = &rtwdev->loopback;
			u32 pkt_desc_sz = chip->rx_pkt_desc_sz;
			u32 pkt_offset;

			if (atomic_read(&rtwusb->rx_handler.handler_done))
				goto out;

			skb = skb_dequeue(&rtwusb->rx_queue);
			if (!skb)
				break;


			rx_desc = skb->data;
			chip->ops->query_rx_desc(rtwdev, rx_desc, &pkt_stat,
						 &rx_status);

			/* offset from rx_desc to payload */
			pkt_offset = pkt_desc_sz + pkt_stat.drv_info_sz + pkt_stat.shift;

			if (pkt_stat.is_c2h) {
				skb_put(skb, pkt_stat.pkt_len + pkt_offset);
				*((u32 *)skb->cb) = pkt_offset;
				rtw_fw_c2h_cmd_handle(rtwdev, skb);
				dev_kfree_skb_any(skb);	
			} else {
				if (skb_queue_len(&rtwusb->rx_queue) >= 64) {
					pr_err("%s: rx_queue overflow\n", __func__);
					dev_kfree_skb(skb);
				} else {
					skb_put(skb, pkt_stat.pkt_len);
					skb_reserve(skb, pkt_offset);
					if (loopback->start) {
						if (loopback->rx_buf && (skb->len > 24)) {
							memcpy(loopback->rx_buf, skb->data + 24, min(skb->len - 24, loopback->pktsize));
						}
					} else {
						memcpy(skb->cb, &rx_status, sizeof(rx_status));
						ieee80211_rx_irqsafe(rtwdev->hw, skb);
					}
				}
			}
		}
	
	} while (1);

out:
	skb_queue_purge(&rtwusb->rx_queue);
}

static void rtw_indicate_tx_status(struct rtw_dev *rtwdev, struct sk_buff *skb)
{
	struct ieee80211_hw *hw = rtwdev->hw;
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);

	ieee80211_tx_info_clear_status(info);
	info->flags |= IEEE80211_TX_STAT_ACK;
	ieee80211_tx_status_irqsafe(hw, skb);
}

static u32 rtw_usb_write_port(struct rtw_dev *rtwdev, u8 addr, u32 cnt,
			      struct sk_buff *skb)
{
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);
	struct usb_device *usbd = rtwusb->udev;
	struct rtw_loopback *loopback = &rtwdev->loopback;
	unsigned int pipe;
	int ret;
	int transfer;

	pipe = rtw_usb_get_pipe(rtwusb, addr);

	// 0 : MAX_SCHEDULE_TIMEOUT
	ret = usb_bulk_msg(usbd, pipe, (void *)skb->data, (int)cnt, &transfer, 0);
	if (ret < 0) {
		pr_err("usb_bulk_msg error, ret=%d\n", ret);
	}

	if (loopback->start) {
		loopback->cur++;
		if (loopback->cur >= loopback->total)
			up(&loopback->sema);
	}
	return ret;
}

void rtw_tx_func(struct rtw_usb *rtwusb)
{
	struct rtw_dev *rtwdev = rtwusb->rtwdev;
	struct rtw_loopback *loopback = &rtwdev->loopback;
	struct sk_buff *skb;
	u8 queue;
	int status;

	while (1) {
		mutex_lock(&rtwusb->tx_lock);

		skb = skb_dequeue(&rtwusb->tx_queue);
		if (skb == NULL) {
			mutex_unlock(&rtwusb->tx_lock);
			break;
		}

		queue = rtw_tx_queue_mapping(skb);

		status = rtw_usb_write_port(rtwdev, queue, skb->len, skb);
		if (status) {
			pr_err("%s, rtw_usb_write_xmit failed, ret=%d\n",
			       __func__, status);
		}

		if (likely(!loopback->start))
			rtw_indicate_tx_status(rtwdev, skb);
		else
			dev_kfree_skb(skb);

		mutex_unlock(&rtwusb->tx_lock);
	}
}

static int
rtw_usb_write_data(struct rtw_dev *rtwdev, u8 *buf, u32 size, u8 qsel)
{
	struct rtw_chip_info *chip = rtwdev->chip;
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);
	struct sk_buff *skb;
	struct rtw_tx_pkt_info pkt_info;
	u32 desclen, len, headsize;
	u8 ret = 0;
	u8 addr;
	int status;

	if (!rtwusb) {
		pr_err("%s: rtwusb is NULL\n", __func__);
		return -EINVAL;
	}

	desclen = rtwusb->txdesc_size;
	len = desclen + size;
	headsize = desclen;

	skb = NULL;
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.tx_pkt_size = size;
	pkt_info.qsel = qsel;
	if (qsel == TX_DESC_QSEL_BEACON) {
		if (rtwusb->bulkout_size == 0) {
			rtw_err(rtwdev, "%s: ERROR: bulkout_size is 0\n",
				__func__);
			return -EINVAL;
		}
		if (len % rtwusb->bulkout_size == 0) {
			len = len + RTW_USB_PACKET_OFFSET_SZ;
			headsize = desclen + RTW_USB_PACKET_OFFSET_SZ;
			pkt_info.offset = desclen + RTW_USB_PACKET_OFFSET_SZ;
			pkt_info.pkt_offset = 1;
		} else {
			pkt_info.offset = desclen;
		}
	} else if (qsel == TX_DESC_QSEL_H2C) {
		;
	} else {
		rtw_err(rtwdev, "%s: qsel may be error(%d)\n", __func__, qsel);
		return -EINVAL;
	}

	skb = dev_alloc_skb(len);
	if (!skb)
		return -ENOMEM;

	skb_reserve(skb, headsize);

	memcpy((u8 *)skb_put(skb, size), buf, size);

	skb_push(skb, headsize);
	memset(skb->data, 0, headsize);

	rtw_tx_fill_tx_desc(&pkt_info, skb);

	status = chip->ops->fill_txdesc_checksum(rtwdev, skb->data);
	if (status != 0) {
		pr_err("%s : halmac txdesc checksum failed, status = %d\n",
		       __func__, status);
		goto exit;
	}

	addr = rtw_qsel_to_queue(qsel);

	ret = rtw_usb_write_port(rtwdev, addr, len, skb);
	if (ret) {
		pr_err("%s ,rtw_usb_write_port failed, ret=%d\n",
		       __func__, ret);
		goto exit;
	}
	dev_kfree_skb(skb);

	return 0;

exit:
	dev_kfree_skb(skb);
	return -EIO;
}

static int rtw_usb_write_data_rsvd_page(struct rtw_dev *rtwdev, u8 *buf,
					u32 size)
{
	rtw_dbg(rtwdev, RTW_DBG_USB, "%s: enter\n", __func__);
	if (!rtwdev) {
		pr_err("%s: rtwdev is NULL\n", __func__);
		return -EINVAL;
	}
	return rtw_usb_write_data(rtwdev, buf, size, TX_DESC_QSEL_BEACON);
}

static int rtw_usb_write_data_h2c(struct rtw_dev *rtwdev, u8 *buf, u32 size)
{
	return rtw_usb_write_data(rtwdev, buf, size, TX_DESC_QSEL_H2C);
}

static void rtw_usb_read_port_complete(struct urb *urb)
{
	struct rx_usb_ctrl_block *rxcb = urb->context;
	struct rtw_dev *rtwdev = (struct rtw_dev *)rxcb->data;
	struct sk_buff *skb = rxcb->rx_skb;
	struct rtw_usb *rtwusb = (struct rtw_usb *)rtwdev->priv;

	if (urb->status == 0) {
		if (urb->actual_length >= RTW_USB_MAX_RECVBUF_SZ ||
		    urb->actual_length < 24) {
			pr_err("%s actual_size error:%d\n",
			       __func__, urb->actual_length);
			if (skb)
				dev_kfree_skb(skb);
		} else {
			skb_queue_tail(&rtwusb->rx_queue, skb);
			rtw_set_event(&rtwusb->rx_handler.event);
		}

		rtw_usb_read_port(rtwdev, RTW_USB_BULK_IN_ADDR);
	} else {
		pr_info("###=> %s status(%d)\n", __func__, urb->status);

		switch (urb->status) {
		case -EINVAL:
		case -EPIPE:
		case -ENODEV:
		case -ESHUTDOWN:
		case -ENOENT:
			rtw_usb_set_bus_ready(rtwdev, false);
			break;
		case -EPROTO:
		case -EILSEQ:
		case -ETIME:
		case -ECOMM:
		case -EOVERFLOW:
			break;
		case -EINPROGRESS:
			pr_debug("%s: Error USB is in progress\n", __func__);
			break;
		default:
			pr_err("%s: unknown : status=%d\n", __func__,
			       urb->status);
			break;
		}
		if (skb)
			dev_kfree_skb(skb);
	}
}

static u32 rtw_usb_read_port(struct rtw_dev *rtwdev, u8 addr)
{
	unsigned int pipe;
	int ret = -1;
	struct urb *urb = NULL;
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);
	struct usb_device *usbd = rtwusb->udev;
	struct sk_buff *skb;
	u32 len;
	size_t buf_addr;
	size_t alignment = 0;
	// Suppose only one read_port first 
	struct rx_usb_ctrl_block *rxcb = &(rtwusb->rx_cb[0]); 

	if (!rtw_usb_is_bus_ready(rtwdev)) {
		pr_info("%s: cannot read USB port\n", __func__);
		return 0;
	}

	urb = rxcb->rx_urb;
	rxcb->data = (u8*)rtwdev;

	pipe = rtw_usb_get_pipe(rtwusb, RTW_USB_BULK_IN_ADDR);

	len = RTW_USB_MAX_RECVBUF_SZ + RTW_USB_RECVBUFF_ALIGN_SZ;
	skb = dev_alloc_skb(len);
	if (!skb) {
		pr_err("%s : dev_alloc_skb failed\n", __func__);
		return -ENOMEM;
	}
	buf_addr = (size_t)skb->data;
	alignment = buf_addr & (RTW_USB_RECVBUFF_ALIGN_SZ - 1);
	skb_reserve(skb, RTW_USB_RECVBUFF_ALIGN_SZ - alignment);

	urb->transfer_buffer = skb->data;
	rxcb->rx_skb = skb;

	usb_fill_bulk_urb(urb, usbd, pipe,
			  urb->transfer_buffer,
			  RTW_USB_MAX_RECVBUF_SZ,
			  rtw_usb_read_port_complete,
			  rxcb);

	ret = usb_submit_urb(urb, GFP_ATOMIC);
	if (ret) {
		pr_err("%s: usb_submit_urb failed, ret=%d\n", __func__, ret);
	}

	return ret;
}

static void rtw_usb_inirp_init(struct rtw_dev *rtwdev)
{
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);
	struct rx_usb_ctrl_block *rxcb = &(rtwusb->rx_cb[0]); 

	pr_info("%s ===>\n", __func__);

	// TODO: will change to call 8 read port
	rtw_usb_set_bus_ready(rtwdev, true);

	rxcb->rx_urb = usb_alloc_urb(0, GFP_KERNEL);
	if (!rxcb->rx_urb) {
		pr_err("%s: usb_alloc_urb failed\n", __func__);
		return;
	}

	rtw_usb_read_port(rtwdev, RTW_USB_BULK_IN_ADDR);
}

static void rtw_usb_inirp_deinit(struct rtw_dev *rtwdev)
{
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);
	struct rx_usb_ctrl_block *rxcb = &(rtwusb->rx_cb[0]); 

	pr_debug("%s ===>\n", __func__);
	rtw_usb_set_bus_ready(rtwdev, false);
	usb_kill_urb(rxcb->rx_urb);
}


static int rtw_usb_tx(struct rtw_dev *rtwdev, struct rtw_tx_pkt_info *pkt_info,
		      struct sk_buff *skb)
{
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);
	struct rtw_chip_info *chip = rtwdev->chip;
	u8 *pkt_desc;
	u8 queue = rtw_tx_queue_mapping(skb);
	int ret;

	if (!pkt_info)
		return -EINVAL;

	pkt_desc = skb_push(skb, chip->tx_pkt_desc_sz);
	memset(pkt_desc, 0, chip->tx_pkt_desc_sz);
	pkt_info->qsel = rtw_queue_to_qsel(skb, queue);
	rtw_tx_fill_tx_desc(pkt_info, skb);

	ret = chip->ops->fill_txdesc_checksum(rtwdev, skb->data);
	if (ret) {
		pr_err("%s : halmac txdesc checksum failed, status = %d\n",
		       __func__, ret);
		return -EINVAL;
	}

	skb_queue_tail(&rtwusb->tx_queue, skb);
	rtw_set_event(&rtwusb->tx_handler.event);
	return 0;
}

static int rtw_usb_setup(struct rtw_dev *rtwdev)
{
	pr_debug("%s ===>\n", __func__);
	return 0;
}

enum usb_burst_size {
	USB_BURST_SIZE_3_0 = 0x0,
	USB_BURST_SIZE_2_0_HS = 0x1,
	USB_BURST_SIZE_2_0_FS = 0x2,
	USB_BURST_SIZE_2_0_OTHERS = 0x3,
	USB_BURST_SIZE_UNDEFINE = 0x7F,
};

#define REG_SYS_CFG2		0x00FC
#define REG_USB_USBSTAT		0xFE11
#define REG_RXDMA_MODE		0x785
#define REG_TXDMA_OFFSET_CHK	0x20C
#define BIT_DROP_DATA_EN	BIT(9)

static int rtw_usb_start(struct rtw_dev *rtwdev)
{
	//struct rtw_chip_info *chip = rtwdev->chip;
	//int ret;
	u8 val8;

	pr_debug("%s ===>\n", __func__);
	// init_usb_cfg_88xx
	val8 = BIT(1) |  (0x3 << 2);

	if (rtw_read8(rtwdev, REG_SYS_CFG2 + 3) == 0x20) {
		pr_info("%s: USB 3.0\n", __func__);
		val8 |= (USB_BURST_SIZE_3_0 << 4);
	} else {
		if ((rtw_read8(rtwdev, REG_USB_USBSTAT) & 0x3) == 0x1) {
			pr_info("%s: USB 2.0\n", __func__);
			val8 |= (USB_BURST_SIZE_2_0_HS << 4);
		} else {
			pr_info("%s: USB 1.1\n", __func__);
			val8 |= (USB_BURST_SIZE_2_0_FS << 4);
		}
	}

	rtw_write8(rtwdev, REG_RXDMA_MODE, val8);
	rtw_write16_set(rtwdev, REG_TXDMA_OFFSET_CHK, BIT_DROP_DATA_EN);

#if 0
	/* TODO: turn off rx agg switch first
	 * need to turn on after implementing USB RX Aggregation
	 */
	ret = chip->ops->set_rx_agg_switch(rtwdev, false, RTW_USB_RXAGG_SIZE,
					 RTW_USB_RXAGG_TIMEOUT);
	if (ret) {
		pr_err("%s: set_rx_agg_switch failed, ret=%d\n", __func__, ret);
		return ret;
	}
#endif
	rtw_usb_inirp_init(rtwdev);
	return 0;
}

static void rtw_usb_stop(struct rtw_dev *rtwdev)
{
	pr_debug("%s ===>\n", __func__);
	rtw_usb_inirp_deinit(rtwdev);
}

static void rtw_usb_deep_ps(struct rtw_dev *rtwdev, bool enter)
{
	pr_debug("%s ===>\n", __func__);
}

static struct rtw_hci_ops rtw_usb_ops = {
	.tx = rtw_usb_tx,
	.setup = rtw_usb_setup,
	.start = rtw_usb_start,
	.stop = rtw_usb_stop,
	.deep_ps = rtw_usb_deep_ps,

	.read8 = rtw_usb_read8,
	.read16 = rtw_usb_read16,
	.read32 = rtw_usb_read32,
	.write8 = rtw_usb_write8,
	.write16 = rtw_usb_write16,
	.write32 = rtw_usb_write32,

	.write_data_rsvd_page = rtw_usb_write_data_rsvd_page,
	.write_data_h2c = rtw_usb_write_data_h2c,
};

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
		//dev_dbg(dev,
		//		"%s: endpoint: dir %02x, # %02x, type %02x\n",
		//		__func__, dir, num, xtype);
		pr_debug("\nusb endpoint descriptor (%i):\n", i);
		pr_debug("bLength=%x\n", endpoint->bLength);
		pr_debug("bDescriptorType=%x\n", endpoint->bDescriptorType);
		pr_debug("bEndpointAddress=%x\n", endpoint->bEndpointAddress);
		pr_debug("wMaxPacketSize=%d\n",
			 le16_to_cpu(endpoint->wMaxPacketSize));
		pr_debug("bInterval=%x\n", endpoint->bInterval);

		if (usb_endpoint_dir_in(endpoint) &&
		    usb_endpoint_xfer_bulk(endpoint)) {
			dev_dbg(dev, "%s: in endpoint num %i\n", __func__, num);

			if (rtwusb->pipe_in) {
				dev_warn(dev, "%s: Too many IN pipes\n",
					 __func__);
				ret = -EINVAL;
				goto exit;
			}

			rtwusb->pipe_in = num;
			rtwusb->num_in_pipes++;
		}

		if (usb_endpoint_dir_in(endpoint) &&
		    usb_endpoint_xfer_int(endpoint)) {
			dev_dbg(dev, "%s: interrupt endpoint num %i\n",
				__func__, num);

			if (rtwusb->pipe_interrupt) {
				dev_warn(dev, "%s: Too many INTERRUPT pipes\n",
					 __func__);
				ret = -EINVAL;
				goto exit;
			}

			rtwusb->pipe_interrupt = num;
		}

		if (usb_endpoint_dir_out(endpoint) &&
		    usb_endpoint_xfer_bulk(endpoint)) {
			dev_dbg(dev, "%s: out endpoint num %i\n",
				__func__, num);
			if (j >= 4) {
				dev_warn(dev,
					 "%s: Too many OUT pipes\n", __func__);
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
		pr_debug("USB_SPEED_LOW\r\n");
		rtwusb->usb_speed = RTW_USB_SPEED_1_1;
		break;
	case USB_SPEED_FULL:
		pr_debug("USB_SPEED_FULL\r\n");
		rtwusb->usb_speed = RTW_USB_SPEED_1_1;
		break;
	case USB_SPEED_HIGH:
		pr_debug("USB_SPEED_HIGH\r\n");
		rtwusb->usb_speed = RTW_USB_SPEED_2;
		break;
	case USB_SPEED_SUPER:
		pr_debug("USB_SPEED_SUPER\r\n");
		rtwusb->usb_speed = RTW_USB_SPEED_3;
		break;
	default:
		pr_debug("USB speed unknown \r\n");
		break;
	}

exit:
	rtwusb->nr_out_eps = j;
	pr_debug("out eps num: %d \r\n", rtwusb->nr_out_eps);
	return ret;
}

static void rtw_usb_one_outpipe_mapping(struct rtw_usb *rtwusb)
{
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_VO] = rtwusb->out_ep[0];/* VO */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_VI] = rtwusb->out_ep[0];/* VI */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_BE] = rtwusb->out_ep[0];/* BE */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_BK] = rtwusb->out_ep[0];/* BK */

	rtwusb->queue_to_pipe[RTW_TX_QUEUE_BCN]	= rtwusb->out_ep[0];/* BCN */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_MGMT]= rtwusb->out_ep[0];/* MGT */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_HI0] = rtwusb->out_ep[0];/* HIGH */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_H2C] = rtwusb->out_ep[0];/* TXCMD */
}

static void rtw_usb_two_outpipe_mapping(struct rtw_usb *rtwusb)
{
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_VO] = rtwusb->out_ep[0];/* VO */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_VI] = rtwusb->out_ep[0];/* VI */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_BE] = rtwusb->out_ep[1];/* BE */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_BK] = rtwusb->out_ep[1];/* BK */

	rtwusb->queue_to_pipe[RTW_TX_QUEUE_BCN]	= rtwusb->out_ep[0];/* BCN */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_MGMT]= rtwusb->out_ep[0];/* MGT */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_HI0] = rtwusb->out_ep[0];/* HIGH */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_H2C] = rtwusb->out_ep[0];/* TXCMD */
}

static void rtw_usb_three_outpipe_mapping(struct rtw_usb *rtwusb)
{
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_VO] = rtwusb->out_ep[0];/* VO */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_VI] = rtwusb->out_ep[1];/* VI */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_BE] = rtwusb->out_ep[2];/* BE */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_BK] = rtwusb->out_ep[2];/* BK */

	rtwusb->queue_to_pipe[RTW_TX_QUEUE_BCN]	= rtwusb->out_ep[0];/* BCN */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_MGMT]= rtwusb->out_ep[0];/* MGT */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_HI0] = rtwusb->out_ep[0];/* HIGH */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_H2C] = rtwusb->out_ep[0];/* TXCMD */
}

static u8 rtw_usb_set_queue_pipe_mapping(struct rtw_dev *rtwdev, u8 in_pipes,
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

	pr_debug("RTW: %s OutEPQueueSel(0x%02x) OutEPNum(%d)\n",
		 __func__, rtwusb->out_ep_queue_sel, rtwdev->hci.bulkout_num);

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
		pr_debug("%s ERROR - out_pipes(%d) out of expect\n",
			 __func__, out_pipes);
		return -1;
	}

	return 0;
}

static void usb_interface_configure(struct rtw_dev *rtwdev)
{
	struct rtw_chip_info *chip = rtwdev->chip;
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);

	if (RTW_USB_IS_SUPER_SPEED(rtwusb))
		rtwusb->bulkout_size = RTW_USB_SUPER_SPEED_BULK_SIZE;
	else if (RTW_USB_IS_HIGH_SPEED(rtwusb))
		rtwusb->bulkout_size = RTW_USB_HIGH_SPEED_BULK_SIZE;
	else
		rtwusb->bulkout_size = RTW_USB_FULL_SPEED_BULK_SIZE;

	pr_debug("%s : bulkout_size: %d\r\n", __func__, rtwusb->bulkout_size);

	rtwusb->txagg_desc_num = chip->ops->get_tx_agg_num(rtwdev);

	pr_debug("%s : TX Agg desc num: %d \r\n", __func__,
		 rtwusb->txagg_desc_num);

	rtw_usb_set_queue_pipe_mapping(rtwdev, rtwusb->num_in_pipes,
				       rtwusb->num_out_pipes);

	// txdesc
	rtwusb->txdesc_size = chip->tx_pkt_desc_sz;
	rtwusb->txdesc_offset = rtwusb->txdesc_size + RTW_USB_PACKET_OFFSET_SZ;

	// setup bulkout num
	pr_debug("%s : bulkout_num: %d\r\n", __func__, rtwdev->hci.bulkout_num);
}


static int rtw_os_core_init(struct rtw_dev **prtwdev,
			    const struct usb_device_id *id)
{
	int drv_data_size;
	struct ieee80211_hw *hw;
	struct rtw_dev *rtwdev;
	struct rtw_usb *rtwusb;
	int ret;

	*prtwdev = NULL;

	drv_data_size = sizeof(struct rtw_dev) + sizeof(struct rtw_usb);
	hw = ieee80211_alloc_hw(drv_data_size, &rtw_ops);
	if (!hw) {
		pr_err("ieee80211_alloc_hw: No memory for device\n");
		ret = -ENOMEM;
		goto finish;
	}

	rtwdev = hw->priv;
	rtwdev->hw = hw;
	rtwdev->chip = (struct rtw_chip_info *)id->driver_info;

	pr_info("%s: rtw_core_init\n", __func__);
	ret = rtw_core_init(rtwdev);
	if (ret) {
		pr_err("%s : rtw_core_init: ret=%d\n", __func__, ret);
		goto err_release_hw;
	}

	rtwusb = rtw_get_usb_priv(rtwdev);
	rtwusb->rtwdev = rtwdev;

	*prtwdev = rtwdev;
	return 0;

err_release_hw:
	ieee80211_free_hw(hw);

finish:
	return ret;
}

static int rtw_usb_init_rx(struct rtw_dev *rtwdev)
{
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);

	rtwusb->rxwq = create_singlethread_workqueue("rtw88-usb : TX work queue");
	if (!rtwusb->rxwq) {
		pr_err("%s: create_singlethread_workqueue failed\n", __func__);
		goto err;
	}

	skb_queue_head_init(&rtwusb->rx_queue);
	rtw_create_handler(&rtwusb->rx_handler);
	rtw_init_event(&rtwusb->rx_handler.event);

	rtwusb->rx_handler_data = kmalloc(sizeof(struct work_data), GFP_KERNEL);
	if (!rtwusb->rx_handler_data) {
		pr_err("%s: rx_handler_data allocation failed\n", __func__);
		goto err_destroy_wq;
	}

	rtwusb->rx_handler_data->rtwdev = rtwdev; 

	INIT_WORK(&rtwusb->rx_handler_data->work, rtw_usb_rx_handler);
	queue_work(rtwusb->rxwq, &rtwusb->rx_handler_data->work);

	return 0;

err_destroy_wq:
	flush_workqueue(rtwusb->rxwq);
	destroy_workqueue(rtwusb->rxwq);

err:
	return -ENOMEM;

}

static int rtw_usb_init_tx(struct rtw_dev *rtwdev)
{
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);

	rtwusb->txwq = create_singlethread_workqueue("rtw88-usb : TX work queue");
	if (!rtwusb->txwq) {
		pr_err("%s: create_singlethread_workqueue failed\n", __func__);
		goto err;
	}

	skb_queue_head_init(&rtwusb->tx_queue);
	rtw_create_handler(&rtwusb->tx_handler);
	rtw_init_event(&rtwusb->tx_handler.event);

	rtwusb->tx_handler_data = kmalloc(sizeof(struct work_data), GFP_KERNEL);
	if (!rtwusb->tx_handler_data) {
		pr_err("%s: tx_handler_data allocation failed\n", __func__);
		goto err_destroy_wq;
	}

	rtwusb->tx_handler_data->rtwdev = rtwdev; 

	INIT_WORK(&rtwusb->tx_handler_data->work, rtw_usb_tx_handler);
	queue_work(rtwusb->txwq, &rtwusb->tx_handler_data->work);

	return 0;

err_destroy_wq:
	flush_workqueue(rtwusb->txwq);
	destroy_workqueue(rtwusb->txwq);

err:
	return -ENOMEM;

}

static int rtw_usb_probe(struct usb_interface *intf,
			 const struct usb_device_id *id)
{
	struct rtw_dev *rtwdev;
	struct usb_device *udev;
	struct rtw_usb *rtwusb;
	int ret = 0;

	pr_info("rtw_info: %s ===>\n", __func__);

	ret = rtw_os_core_init(&rtwdev, id);
	if (ret) {
		pr_err("rtw_os_core_init fail, ret=%d\n", ret);
		goto finish;
	}

	rtwdev->dev = &intf->dev;

	udev = usb_get_dev(interface_to_usbdev(intf));

	rtwdev->hci.ops = &rtw_usb_ops;
	rtwdev->hci.type = RTW_HCI_TYPE_USB;

	usb_set_intfdata(intf, rtwdev->hw);

	rtwusb = rtw_get_usb_priv(rtwdev);
	rtwusb->udev = udev;
	mutex_init(&rtwusb->usb_buf_mutex);

	mutex_init(&rtwusb->tx_lock);

	pr_info("%s: rtw_usb_parse\n", __func__);
	ret = rtw_usb_parse(rtwdev, intf);
	if (ret) {
		rtw_err(rtwdev, "rtw_usb_parse failed, ret=%d\n", ret);
		goto err_deinit_core;
	}

	pr_info("%s: usb_interface_configure\n", __func__);
	usb_interface_configure(rtwdev);

	ret = rtw_usb_init_rx(rtwdev);
	if (ret) {
		goto err_deinit_core;
	}

	ret = rtw_usb_init_tx(rtwdev);
	if (ret) {
		goto err_destroy_rxwq;
	}

	rtwusb->init_done = true;
	SET_IEEE80211_DEV(rtwdev->hw, &intf->dev);

	ret = rtw_chip_info_setup(rtwdev);
	if (ret) {
		rtw_err(rtwdev, "failed to setup chip information\n");
		goto err_destroy_usb;
	}

	ret = rtw_register_hw(rtwdev, rtwdev->hw);
	if (ret) {
		pr_err("%s : rtw_register_hw failed: ret=%d\n", __func__, ret);
		goto err_destroy_usb;
	}

	goto finish;

err_destroy_usb:
	usb_put_dev(rtwusb->udev);
	usb_set_intfdata(intf, NULL);

//err_destroy_txwq:
	flush_workqueue(rtwusb->txwq);
	destroy_workqueue(rtwusb->txwq);

err_destroy_rxwq:
	flush_workqueue(rtwusb->rxwq);
	destroy_workqueue(rtwusb->rxwq);

err_deinit_core:
	rtw_core_deinit(rtwdev);
	mutex_destroy(&rtwusb->usb_buf_mutex);
	mutex_destroy(&rtwusb->tx_lock);

finish:
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

	rtwusb->init_done = false;
	skb_queue_purge(&rtwusb->tx_queue);
	skb_queue_purge(&rtwusb->rx_queue);
	rtw_kill_handler(&rtwusb->tx_handler);
	rtw_kill_handler(&rtwusb->rx_handler);
	cancel_work_sync(&rtwusb->rx_handler_data->work);
	cancel_work_sync(&rtwusb->tx_handler_data->work);
	destroy_workqueue(rtwusb->rxwq);
	destroy_workqueue(rtwusb->txwq);

	kfree(rtwusb->tx_handler_data);
	kfree(rtwusb->rx_handler_data);

	rtw_unregister_hw(rtwdev, hw);

	if (rtwusb->udev->state != USB_STATE_NOTATTACHED) {
		pr_info("Device still attached, trying to reset\n");
		usb_reset_device(rtwusb->udev);
	}

	usb_put_dev(rtwusb->udev);
	usb_set_intfdata(intf, NULL);
	rtw_core_deinit(rtwdev);
	mutex_destroy(&rtwusb->usb_buf_mutex);
	mutex_destroy(&rtwusb->tx_lock);
	ieee80211_free_hw(hw);
}

#define RTW_USB_VENDOR_ID_REALTEK 		0x0bda
#define RTW_USB_PRODUCT_ID_REALTEK_8822B 	0xB82C
#define RTW_USB_PRODUCT_ID_REALTEK_8812B 	0xB812

static const struct usb_device_id rtw_usb_id_table[] = {
	{ USB_DEVICE_AND_INTERFACE_INFO(RTW_USB_VENDOR_ID_REALTEK,
					RTW_USB_PRODUCT_ID_REALTEK_8822B,
					0xff, 0xff, 0xff),
		.driver_info = (kernel_ulong_t)&rtw8822b_hw_spec },
	{ USB_DEVICE_AND_INTERFACE_INFO(RTW_USB_VENDOR_ID_REALTEK,
					RTW_USB_PRODUCT_ID_REALTEK_8812B,
					0xff, 0xff, 0xff),
		.driver_info = (kernel_ulong_t)&rtw8822b_hw_spec },
	{}
};

static struct usb_driver rtw_usb_driver = {
	.name = "rtwifi_usb",
	.id_table = rtw_usb_id_table,
	.probe = rtw_usb_probe,
	.disconnect = rtw_usb_disconnect,
};

module_usb_driver(rtw_usb_driver);

MODULE_LICENSE("GPL");
