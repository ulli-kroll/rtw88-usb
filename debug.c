// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright(c) 2018-2019  Realtek Corporation
 */

#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include "main.h"
#include "coex.h"
#include "sec.h"
#include "fw.h"
#include "debug.h"
#include "phy.h"
#include "mac.h"

#ifdef CONFIG_RTW88_DEBUGFS
struct rtw_debugfs_priv {
	struct rtw_dev *rtwdev;

	union {
		u32 result;
	};
};

/* do_tx_perf */

static int rtw_debugfs_do_tx_perf(struct seq_file *s, void *data)
{
	int i;
	struct rtw_debugfs_priv *priv = s->private;
	struct rtw_dev *rtwdev = priv->rtwdev;
	u64 start_time, delta;

	start_time = ktime_get_ns();

	for (i = 0; i < 1000; i++)
		rtw_fw_send_h2c2h_loopback(rtwdev);

	delta = ktime_get_ns() - start_time;
	seq_printf(s, "H2C loopback 1000, total time: %llu, average: %llu ns\n",
		   delta, delta / 1000);

	return 0;
}

static int rtw_debugfs_do_tx_perf_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, rtw_debugfs_do_tx_perf, inode->i_private);
}

static const struct file_operations file_ops_do_tx_perf = {
	.owner = THIS_MODULE,
	.open = rtw_debugfs_do_tx_perf_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

/* usb_loopback_func */

static int rtw_debugfs_usb_loopback_func(struct seq_file *s, void *data)
{
	struct rtw_debugfs_priv *priv = s->private;
	struct rtw_dev *rtwdev = priv->rtwdev;
	struct sk_buff *skb;
	struct rtw_chip_info *chip = rtwdev->chip;
	struct rtw_tx_pkt_info pkt_info = {0};
	struct rtw_loopback *loopback = &rtwdev->loopback;
	int size;
	int cnt = 100;
	u32 pktsize = 2000;
	ktime_t t1, spend;
	int ret = 0;
	int i;

	sema_init(&loopback->sema, 0);
	loopback->total = cnt;
	loopback->pktsize = pktsize;

	rtwdev->trx_mode = RTW_TRX_MODE_LOOPBACK;
	ret = rtw_mac_init(rtwdev);
	if (ret) {
		rtw_err(rtwdev, "failed to configure mac\n");
		goto exit;
	}

	size = pktsize + chip->tx_pkt_desc_sz + 24;
	skb = dev_alloc_skb(size);
	if (!skb) {
		ret = -ENOMEM;
		goto trxmode_deinit;
	}

	loopback->rx_buf = kmalloc(pktsize, GFP_KERNEL);
	if (!loopback->rx_buf) {
		ret = -ENOMEM;
		goto skb_deinit;
	}

	loopback->tx_buf = kmalloc(pktsize, GFP_KERNEL);
	if (!loopback->tx_buf) {
		ret = -ENOMEM;
		goto rxbuf_deinit;
	}

	skb_put(skb, pktsize + 24);
	memset(skb->data, 0x00, 24);
	skb->data[0] = 0x40;
	memset(skb->data + 4, 0xFF, ETH_ALEN);
	memcpy(skb->data + 4 + ETH_ALEN, rtwdev->efuse.addr, ETH_ALEN);
	memset(skb->data + 4 + 2 * ETH_ALEN, 0Xff, ETH_ALEN);

	get_random_bytes(skb->data + 24, pktsize);
	memcpy(loopback->tx_buf, skb->data + 24, pktsize);

	/* set pkt_info */
	pkt_info.sec_type = 0;
	pkt_info.tx_pkt_size = skb->len;
	pkt_info.offset = chip->tx_pkt_desc_sz;
	pkt_info.qsel = 0;
	pkt_info.ls = true;

	loopback->cur = 0;
	loopback->read_cnt = 0;
	loopback->start = true;

	t1 = ktime_get();

	for (i = 0; i < loopback->total; i++) {
		struct sk_buff *skb1;

		skb1 = skb_copy(skb, GFP_ATOMIC);
		if (!skb1) {
			rtw_err(rtwdev, "skb_copy failed\n");
			ret = -ENOMEM;
			goto txbuf_deinit;
		}

		ret = rtw_hci_tx_write(rtwdev, &pkt_info, skb1);
		if (ret) {
			rtw_err(rtwdev, "rtw_hci_tx() failed\n");
			goto txbuf_deinit;
		}

		rtw_hci_tx_kick_off(rtwdev);
	}

	down(&loopback->sema);

	cnt += loopback->read_cnt;
	spend = ktime_to_ns(ktime_sub(ktime_get(), t1)) / (cnt * 1000);
	seq_printf(s, "pktsize:%d, spend: %lldus, throughput=%lldMbps\n",
		   pktsize, spend, pktsize * 8 / spend);

	msleep(100);

	if (memcmp(loopback->tx_buf, loopback->rx_buf, pktsize) == 0)
		seq_printf(s, "loopback success, pktsize=%d\n", pktsize);
	else
		seq_printf(s, "loopback failed, pktsize=%d\n", pktsize);

	loopback->start = false;

txbuf_deinit:
	kfree(loopback->tx_buf);

rxbuf_deinit:
	kfree(loopback->rx_buf);

skb_deinit:
	dev_kfree_skb(skb);

trxmode_deinit:

	rtwdev->trx_mode = RTW_TRX_MODE_NORMAL;
	ret = rtw_mac_init(rtwdev);
	if (ret) {
		rtw_err(rtwdev, "failed to configure mac\n");
		return ret;
	}

exit:
	return ret;
}

static int rtw_debugfs_usb_loopback_func_open(struct inode *inode,
					      struct file *filp)
{
	return single_open(filp, rtw_debugfs_usb_loopback_func,
			   inode->i_private);
}

static const struct file_operations file_ops_usb_loopback_func = {
	.owner = THIS_MODULE,
	.open = rtw_debugfs_usb_loopback_func_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static struct rtw_debugfs_priv priv_data;
void rtw_debugfs_init(struct rtw_dev *rtwdev)
{
	struct dentry *debugfs_topdir;

	debugfs_topdir = debugfs_create_dir("rtw88", NULL);
	rtwdev->debugfs = debugfs_topdir;

	priv_data.rtwdev = rtwdev;
	if (!debugfs_create_file("do_tx_perf", S_IFREG | S_IRUGO,
				 debugfs_topdir, &priv_data,
				 &file_ops_do_tx_perf))
		pr_err("Unable to initialize debugfs-do_tx_perf\n");

	if (!debugfs_create_file("usb_loopback_func", S_IFREG | S_IRUGO,
				 debugfs_topdir, &priv_data,
				 &file_ops_usb_loopback_func))
		pr_err("Unable to initialize debugfs-usb_loopback_func\n");
}

void rtw_debugfs_deinit(struct rtw_dev *rtwdev)
{
	debugfs_remove_recursive(rtwdev->debugfs);
}
#endif /* CONFIG_RTW88_DEBUGFS */

#ifdef CONFIG_RTW88_DEBUG

void __rtw_dbg(struct rtw_dev *rtwdev, enum rtw_debug_mask mask,
	       const char *fmt, ...)
{
	struct va_format vaf = {
		.fmt = fmt,
	};
	va_list args;

	va_start(args, fmt);
	vaf.va = &args;

	if (rtw_debug_mask & mask)
		dev_dbg(rtwdev->dev, "%pV", &vaf);

	va_end(args);
}
EXPORT_SYMBOL(__rtw_dbg);

#endif /* CONFIG_RTW88_DEBUG */
