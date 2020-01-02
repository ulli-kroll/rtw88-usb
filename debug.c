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


struct rtw_debugfs_priv {
	struct rtw_dev *rtwdev;

	union {
		u32 result;
	};
};

static int rtw_debugfs_do_tx_perf(struct seq_file *s, void *data)
{
	int i;
	struct rtw_debugfs_priv *priv = s->private;
	struct rtw_dev *rtwdev = priv->rtwdev;
	u64 start_time, delta;

	start_time = ktime_get_ns();

	for (i=0; i<1000; i++)
		rtw_fw_send_h2c2h_loopback(rtwdev);

	delta = ktime_get_ns() - start_time;
	seq_printf(s, "H2C loopback 1000, total time: %llu, average: %llu ns\n",
		delta, delta/1000);

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


static struct rtw_debugfs_priv priv_data;
void rtw_debugfs_init(struct rtw_dev *rtwdev)
{
	struct dentry *debugfs_topdir;

	debugfs_topdir = debugfs_create_dir("rtw88", NULL);
	rtwdev->debugfs = debugfs_topdir;

	priv_data.rtwdev = rtwdev;
	if (!debugfs_create_file("do_tx_perf", S_IFREG| S_IRUGO, 
				 debugfs_topdir, &priv_data,
				 &file_ops_do_tx_perf))		
		pr_err("Unable to initialize debugfs-do_tx_perf\n");
}

void rtw_debugfs_deinit(struct rtw_dev *rtwdev)
{
	if (rtwdev->debugfs)
		debugfs_remove_recursive(rtwdev->debugfs);
}

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
		dev_printk(KERN_DEBUG, rtwdev->dev, "%pV", &vaf);

	va_end(args);
}
EXPORT_SYMBOL(__rtw_dbg);

#endif /* CONFIG_RTW88_DEBUG */
