#ifndef _MCE_DCB_H_
#define _MCE_DCB_H_

#ifdef CONFIG_DCB
bool is_default_etscfg(struct mce_ets_cfg *etscfg);
bool is_default_pfccfg(struct mce_pfc_cfg *pfccfg);
int mce_dcb_update_swetscfg(struct mce_dcb *dcb);
void mce_dcb_update_hwetscfg(struct mce_dcb *dcb);
void mce_dcb_update_swpfccfg(struct mce_dcb *dcb);
void mce_dcb_update_hwpfccfg(struct mce_dcb *dcb);
#endif /* CONFIG_DCB */

void mce_dcb_tc_default(struct mce_tc_cfg *tccfg);
void mce_dcb_ets_default(struct mce_ets_cfg *etscfg);
void mce_dcb_pfc_default(struct mce_pfc_cfg *pfccfg);

#endif /* _MCE_DCB_H_ */
