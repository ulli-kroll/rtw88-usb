#ifndef __RTW_USB_H_
#define __RTW_USB_H_

enum RTW_USB_SPEED {
	RTW_USB_SPEED_UNKNOWN	= 0,
	RTW_USB_SPEED_1_1	= 1,
	RTW_USB_SPEED_2		= 2,
	RTW_USB_SPEED_3		= 3,
};

struct rtw_usb_urb {
	struct list_head list;
	bool urb_is_tx;
	struct urb *urb;
	struct sk_buff *skb;
};

struct rtw_usb {
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

	u8 txagg_desc_num;

	u32 txdesc_size;
	u32 txdesc_offset;

	struct list_head urb_list;

	atomic_t is_bus_drv_ready;
};

#define rtw_get_usb_priv(rtwdev) ((struct rtw_usb *)rtwdev->priv)

#endif
