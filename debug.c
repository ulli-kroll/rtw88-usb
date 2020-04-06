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
void rtw_debugfs_init(struct rtw_dev *rtwdev)
{
	struct dentry *debugfs_topdir;

	debugfs_topdir = debugfs_create_dir("rtw88", NULL);
	rtwdev->debugfs = debugfs_topdir;
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
