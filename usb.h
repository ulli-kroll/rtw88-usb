#ifndef __RTW_USB_H_
#define __RTW_USB_H_

enum RTW_USB_SPEED {
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
	u8 txagg_desc_num;
	u32 txdesc_size;
	u32 txdesc_offset;
	// TX - workqueue
	bool init_done;
	struct mutex tx_lock;
	struct sk_buff_head tx_queue;
	struct rtw_handler tx_handler;
	struct work_data *tx_handler_data;

	// RX
	// RX - workqueue
	struct rx_usb_ctrl_block rx_cb[8];
	struct sk_buff_head rx_queue;
	struct rtw_handler rx_handler;
	struct work_data *rx_handler_data;
};

#define rtw_get_usb_priv(rtwdev) ((struct rtw_usb *)rtwdev->priv)

#endif
