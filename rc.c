#include <net/mac80211.h>
#include "main.h"
#include "rc.h"

static void *rtw_rate_alloc(struct ieee80211_hw *hw, struct dentry *debugfsdir)
{
	struct rtw_dev *rtwdev = hw->priv;
	pr_info("%s: NEO TODO\n", __func__);
	return rtwdev;
}

static void rtw_rate_free(void *rtwdev)
{
	pr_info("%s: NEO TODO\n", __func__);
	return;
}

static void *rtw_rate_alloc_sta(void *priv, struct ieee80211_sta *sta,
				gfp_t gfp)
{
	struct rtw_dev *rtwdev = priv;
	struct rtw_rate_priv *rate_priv = &(rtwdev->rate_priv);
	pr_info("%s: NEO TODO\n", __func__);
	return rate_priv;
}

static void rtw_rate_free_sta(void *priv, struct ieee80211_sta *sta,
			      void *priv_sta)
{
	pr_info("%s: NEO TODO\n", __func__);
	return;
}

static void rtw_rate_init(void *priv, struct ieee80211_supported_band *sband,
			struct cfg80211_chan_def *chandef,
			struct ieee80211_sta *sta, void *priv_sta)
{
	pr_info("%s: NEO TODO\n", __func__);
	return;
}

static void rtw_tx_status(void *priv, struct ieee80211_supported_band *sband,
			struct ieee80211_sta *sta, void *priv_sta,
			struct sk_buff *skb)
{
	pr_info("%s: NEO TODO\n", __func__);
	return;
}

static void rtw_rc_rate_set_series(struct rtw_dev *rtwdev,
				   struct ieee80211_sta *sta,
				   struct ieee80211_tx_rate *rate,
				   struct ieee80211_tx_rate_control *txrc,
				   u8 tries, s8 rix, int rtsctsenable,
				   bool not_data)
{
	u8 sgi_20 = 0, sgi_40 = 0, sgi_80 = 0;

	rate->count = tries;
	rate->idx = (rix >= 0) ? rix : 0;

	if (not_data) return;
	if (!sta) return;

	sgi_20 = sta->ht_cap.cap & IEEE80211_HT_CAP_SGI_20;
	sgi_40 = sta->ht_cap.cap & IEEE80211_HT_CAP_SGI_40;
	sgi_80 = sta->vht_cap.cap & IEEE80211_VHT_CAP_SHORT_GI_80;

	if (sgi_20 || sgi_40 || sgi_80) {
		rate->flags |= IEEE80211_TX_RC_SHORT_GI;
	}

	if (sta->bandwidth == IEEE80211_STA_RX_BW_80)
		rate->flags |= IEEE80211_TX_RC_80_MHZ_WIDTH;
	else if (sta->bandwidth == IEEE80211_STA_RX_BW_40)
		rate->flags |= IEEE80211_TX_RC_40_MHZ_WIDTH;

	if (sta->ht_cap.ht_supported)
		rate->flags |= IEEE80211_TX_RC_MCS;
	
	if (sta->vht_cap.vht_supported)
		rate->flags |= IEEE80211_TX_RC_VHT_MCS;
}

static u8 rtw_rc_get_highest_rix(struct rtw_dev *rtwdev, struct ieee80211_sta *sta,
				 struct sk_buff *skb, bool not_data)
{
	struct rtw_hal *hal = &rtwdev->hal;
	struct ieee80211_tx_rate rate;
	u8 nss;

	if (not_data)
		return 0;

	if (!sta)
		return 0;

	switch (hal->rf_type) {
	case RF_4T4R:
		nss = 4;
		break;
	case RF_3T3R:
		nss = 3;
		break;
	case RF_2T2R:
		nss = 2;
		break;
	default:
		nss = 1;
		break;
	}

 	if (hal->current_band_type == RTW_BAND_2G) {
		if (sta->vht_cap.vht_supported) { /* ac mode */
			if (sta->bandwidth == IEEE80211_STA_RX_BW_20) {
				ieee80211_rate_set_vht(&rate,
						AC_MODE_MCS8_RIX,
						nss);
				goto out;
			} else {
				ieee80211_rate_set_vht(&rate,
						AC_MODE_MCS9_RIX,
						nss);
				goto out;
			}	
		} else if (sta->ht_cap.ht_supported) { /* n mode */
			if (nss == 1)
				return N_MODE_MCS7_RIX;
			else
				return N_MODE_MCS15_RIX;
		} else if (sta->supp_rates[0] <= 0xf) { /* b mode */
			return B_MODE_MAX_RIX;		
		} else { /* g mode */
			return G_MODE_MAX_RIX;
		}
	} else if (hal->current_band_type == RTW_BAND_5G) {
		if (sta->vht_cap.vht_supported) { /* ac mode */
			if (sta->bandwidth == IEEE80211_STA_RX_BW_20) {
				ieee80211_rate_set_vht(&rate,
						AC_MODE_MCS8_RIX,
						nss);
				goto out;
			} else {
				ieee80211_rate_set_vht(&rate,
						AC_MODE_MCS9_RIX,
						nss);
				goto out;
			}	
		} else if (sta->ht_cap.ht_supported) { /* n mode */
			if (nss == 1)
				return N_MODE_MCS7_RIX;
			else
				return N_MODE_MCS15_RIX;
		} else { /* a mode */
			return A_MODE_MAX_RIX;
		}
	} else {
		pr_err("%s: current_band_type:%d error\n",
		       __func__, hal->current_band_type);
		return 0;
	}

out:
	return rate.idx;
}

static void rtw_get_rate(void *priv, struct ieee80211_sta *sta, void *priv_sta,
			 struct ieee80211_tx_rate_control *txrc)
{
	struct rtw_dev *rtwdev = priv;
	struct sk_buff *skb = txrc->skb;
	struct ieee80211_tx_info *tx_info = IEEE80211_SKB_CB(skb);
	struct ieee80211_tx_rate *rates = tx_info->control.rates;
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)skb->data;
	__le16 fc = hdr->frame_control;
	bool not_data = !ieee80211_is_data(fc);
	u8 rix, i, try_per_rate;

	pr_info("%s: not_data:%d\n", __func__, not_data);

	rix = rtw_rc_get_highest_rix(rtwdev, sta, skb, not_data);
	pr_info("%s: rix:%u\n", __func__, rix);

	try_per_rate = 1;

	rtw_rc_rate_set_series(rtwdev, sta, &rates[0], txrc, try_per_rate, rix,
			       1, not_data);

	if (!not_data)
		for (i = 1; i < 4; i++)
			rtw_rc_rate_set_series(rtwdev, sta, &rates[i], txrc,
					i, rix - i, 1, not_data);

	return;
}

static void rtw_rate_update(void *priv, struct ieee80211_supported_band *sband,
			struct cfg80211_chan_def *channel, 
			struct ieee80211_sta *sta,
			void *priv_sta, u32 changed)
{
	pr_info("%s: NEO TODO\n", __func__);
	return;
}

static const struct rate_control_ops rtw_rate_ops = {
	.name = RTW_RC_NAME,
	.tx_status = rtw_tx_status,
	.get_rate = rtw_get_rate,
	.rate_init = rtw_rate_init,
	.alloc = rtw_rate_alloc,
	.free = rtw_rate_free,
	.alloc_sta = rtw_rate_alloc_sta,
	.free_sta = rtw_rate_free_sta,
	.rate_update = rtw_rate_update,
	.capa = RATE_CTRL_CAPA_VHT_EXT_NSS_BW,
};

int rtw_rate_control_register(void)
{
	pr_info("%s\n", __func__);
	return ieee80211_rate_control_register(&rtw_rate_ops);
}
EXPORT_SYMBOL(rtw_rate_control_register);

void rtw_rate_control_unregister(void)
{
	pr_info("%s\n", __func__);
	ieee80211_rate_control_unregister(&rtw_rate_ops);
}
EXPORT_SYMBOL(rtw_rate_control_unregister);


