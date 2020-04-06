#ifndef __RTW_USB_H_
#define __RTW_USB_H_

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
#define RTW_USB_MAX_XMITBUF_SZ		(1592 * 3)
#define RTW_USB_MAX_RECVBUF_SZ		32768

#define RTW_USB_RECVBUFF_ALIGN_SZ	8

#define RTW_USB_RXAGG_SIZE		6
#define RTW_USB_RXAGG_TIMEOUT		10

#define RTW_USB_RXCB_NUM		8

#define REG_SYS_CFG2		0x00FC
#define REG_USB_USBSTAT		0xFE11
#define REG_RXDMA_MODE		0x785
#define REG_TXDMA_OFFSET_CHK	0x20C
#define BIT_DROP_DATA_EN	BIT(9)

/* USB Vendor/Product IDs */
#define RTW_USB_VENDOR_ID_REALTEK		0x0bda
#define RTW_USB_VENDOR_ID_EDIMAX		0x7392
#define RTW_USB_PRODUCT_ID_REALTEK_8812B	0xB812
#define RTW_USB_PRODUCT_ID_REALTEK_8822B	0xB82C
#define RTW_USB_PRODUCT_ID_REALTEK_8822C	0xC82C

/* helper for USB Ids */

#define RTK_USB_DEVICE(vend, dev, hw_config)	\
	USB_DEVICE(vend, dev),			\
	.driver_info = (kernel_ulong_t) & (hw_config),

#define RTK_USB_DEVICE_AND_INTERFACE(vend, dev, cl, sc, pr, hw_config)	\
	USB_DEVICE_AND_INTERFACE_INFO(vend, dev, cl, sc, pr),		\
	.driver_info = (kernel_ulong_t) & (hw_config),

/* defined functions */
#define rtw_get_usb_priv(rtwdev) ((struct rtw_usb *)rtwdev->priv)

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

struct rtw_event {
	atomic_t event_condition;
	wait_queue_head_t event_queue;
};

struct rtw_handler {
	struct rtw_event event;
	atomic_t handler_done;
};

struct rx_usb_ctrl_block {
	u8 *data;
	struct urb *rx_urb;
	struct sk_buff *rx_skb;
	u8 ep_num;
};

struct rtw_work_data {
	struct work_struct work;
	struct rtw_dev *rtwdev;
};

struct rtw_usb_tx_data {
	u8 sn;
};

struct rtw_usb {
	struct rtw_dev *rtwdev;
	struct usb_device *udev;

	struct mutex usb_buf_mutex; /* mutex for usb_buf */
	union {
		__le32 val32;
		__le16 val16;
		u8 val8;
	} usb_buf;

	u8 num_in_pipes;
	u8 num_out_pipes;
	unsigned int pipe_interrupt;
	unsigned int pipe_in;
	unsigned int pipe_out[20];
	u8 out_ep[4];
	u8 out_ep_queue_sel;
	//u8 out_ep_num;
	int nr_out_eps;
	u8 queue_to_pipe[8];
	u32 bulkout_size;
	u8  usb_speed;

	//struct list_head urb_list;
	atomic_t is_bus_drv_ready;

	// workqueue
	struct workqueue_struct *txwq, *rxwq;

	// TX
	u8 usb_txagg_num;

	// TX - workqueue
	struct mutex tx_lock; /* mutex for tx */
	struct sk_buff_head tx_queue[RTK_MAX_TX_QUEUE_NUM];
	struct sk_buff_head tx_ack_queue;
	struct rtw_handler tx_handler;
	struct rtw_work_data *tx_handler_data;

	// RX
	// RX - workqueue
	struct rx_usb_ctrl_block rx_cb[RTW_USB_RXCB_NUM];
	struct sk_buff_head rx_queue;
	struct rtw_handler rx_handler;
	struct rtw_work_data *rx_handler_data;
};

static inline struct
rtw_usb_tx_data *rtw_usb_get_tx_data(struct sk_buff *skb)
{
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);

	BUILD_BUG_ON(sizeof(struct rtw_usb_tx_data) >
		sizeof(info->status.status_driver_data));

	return (struct rtw_usb_tx_data *)info->status.status_driver_data;
}

#endif
