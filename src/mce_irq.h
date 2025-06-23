#ifndef _MCE_IRQ_H_
#define _MCE_IRQ_H_

int mce_napi_poll(struct napi_struct *napi, int budget);
void mce_napi_add(struct mce_vsi *vsi);
int mce_get_irq_num(struct mce_pf *pf, int idx);
int mce_init_interrupt_scheme(struct mce_pf *pf);
void mce_clear_interrupt_scheme(struct mce_pf *pf);
int mce_vsi_req_irq_msix(struct mce_vsi *vsi, char *basename);

#endif /* _MCE_IRQ_H_ */
