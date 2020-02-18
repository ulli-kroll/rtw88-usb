#ifndef __RC_H__
#define __RC_H__

#define RTW_RC_NAME	"rtw88-rc"

#define B_MODE_MAX_RIX		3
#define G_MODE_MAX_RIX		11
#define A_MODE_MAX_RIX		7

#define N_MODE_MCS7_RIX		7
#define N_MODE_MCS15_RIX	15

#define AC_MODE_MCS7_RIX	7
#define AC_MODE_MCS8_RIX	8
#define AC_MODE_MCS9_RIX	9


struct rtw_rate_priv {
	u8 ht_cap;
};

int rtw_rate_control_register(void);
void rtw_rate_control_unregister(void);


#endif
