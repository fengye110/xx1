#include "mce.h"
#include "mce_lib.h"
#include "./mucse_auxiliary/mce_idc.h"

struct iidc_core_dev_info my_cdev_info;
struct iidc_auxiliary_dev my_aux_dev;

static void mce_adev_release_cb(struct device *dev)
{
	struct iidc_auxiliary_dev *iadev;

	iadev = container_of(dev, struct iidc_auxiliary_dev, adev.dev);
	kfree(iadev);
}

static void idc_dev_event(struct iidc_core_dev_info *cdev_info,
		          struct iidc_event *event)
{
	struct net_device *netdev = cdev_info->netdev;
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;

	// detect mrdma insmod or rmmod 
	if (test_bit(IIDC_EVENT_INSMOD, event->type))
		pf->m_status = MRDMA_INSMOD;
	if (test_bit(IIDC_EVENT_RMMOD, event->type))
		pf->m_status = MRDMA_REMOVE;

	set_bit(MCE_FLAG_MRDMA_CHANGED,	pf->flags);
	//printk("mrdma status changed\n");

}

int mce_plug_aux_devs(struct mce_pf *pf, const char *name)
{
	struct iidc_core_dev_info *cdev_info = NULL;
	struct iidc_auxiliary_dev *iadev = NULL;
	struct auxiliary_device *adev = NULL;
	struct mce_dcb *dcb = pf->dcb;
	struct mce_ets_cfg *etscfg = &(dcb->cur_etscfg);
	int ret = 0;
	struct iidc_qos_params *qos_info;
	int i;

	if (pf->vsi[0] == NULL)
		return -EFAULT;

	if (pf->vsi[0]->netdev == NULL)
		return -EFAULT;

	cdev_info = kzalloc(sizeof(*cdev_info), GFP_KERNEL);
	if (!cdev_info)
		return -ENOMEM;

	qos_info = &cdev_info->qos_info;

	pf->cdev_infos = cdev_info;
	memset(cdev_info, 0, sizeof(*cdev_info));

	cdev_info->ver.major = IIDC_MAJOR_VER;
	cdev_info->ver.minor = IIDC_MINOR_VER;
	cdev_info->pdev = pf->pdev;
	cdev_info->netdev = pf->vsi[0]->netdev;
	cdev_info->eth_bar_base  = pf->hw.eth_bar_base;
	cdev_info->rdma_bar_base = pf->hw.rdma_bar_base;
	cdev_info->ftype = IIDC_FUNCTION_TYPE_PF;
	cdev_info->rdma_protocol = IIDC_RDMA_PROTOCOL_ROCEV2;
	cdev_info->pname = pf->vsi[0]->netdev->name;
	cdev_info->num_q_vectors = pf->vsi[0]->num_q_vectors;
	pf->rdma_irq_base = 5;
	cdev_info->msix_count = 1;
	cdev_info->msix_entries = &pf->msix_entries[pf->rdma_irq_base];
	cdev_info->func_num = 0;
	cdev_info->valid_prio = 0;
	// update qos info
	for (i = 0; i < IIDC_MAX_USER_PRIORITY; i++) {
		qos_info->up2tc[i] = etscfg->prio_table[i];
	}
	/* mode is dscp or pcp */
	if (test_bit(MCE_DSCP_EN, dcb->flags))
		qos_info->map_mode = IIDC_DSCP_PFC_MODE;
	else
		qos_info->map_mode = IIDC_VLAN_PFC_MODE;

	if (test_bit(MCE_PFC_EN, dcb->flags))
		qos_info->pfc_en = IIDC_PFC_ON;
	else
		qos_info->pfc_en = IIDC_PFC_OFF;

	memcpy(qos_info->dscp_map, dcb->dscp_map, MCE_MAX_DSCP);

	qos_info->valid_prio = cdev_info->valid_prio;

	iadev = kzalloc(sizeof(*iadev), GFP_KERNEL);
	if (!iadev) {
		ret = -ENOMEM;
		goto err_alloc_iadev;
	}

	adev = &iadev->adev;

	mutex_lock(&pf->adev_mutex);
	cdev_info->adev = adev;
	iadev->cdev_info = cdev_info;
	iadev->event_handler = idc_dev_event;
	mutex_unlock(&pf->adev_mutex);
#define ASSIGN_BUS_NUM(x) (x << 8)
	adev->id = ASSIGN_BUS_NUM(pf->pdev->bus->number) | (pf->pdev->devfn & 0xff);
	// unsigned char number
	adev->dev.release = mce_adev_release_cb;
	adev->dev.parent = &(pf->pdev->dev);
	adev->name = name;

	ret = auxiliary_device_init(adev);
	if (ret)
		goto err_init_aux_dev;

	ret = auxiliary_device_add(adev);
	if (ret)
		goto err_add_aux_dev;

	return 0;
err_add_aux_dev:
	auxiliary_device_uninit(adev);
err_init_aux_dev:
	kfree(iadev);
err_alloc_iadev:
	kfree(cdev_info);

	return ret;
}

/* mce_unplug_aux_devs - unregister and free aux devs
 * @pf: pointer to pf struct
 */
void mce_unplug_aux_devs(struct mce_pf *pf)
{
	struct iidc_core_dev_info *cdev_info = pf->cdev_infos;

	if (!cdev_info)
		return;

	/* if this aux dev has already been unplugged move on */
	mutex_lock(&pf->adev_mutex);
	if (!cdev_info->adev) {
		mutex_unlock(&pf->adev_mutex);
		return;
	}

	auxiliary_device_delete(cdev_info->adev);
	auxiliary_device_uninit(cdev_info->adev);
	cdev_info->adev = NULL;
	mutex_unlock(&pf->adev_mutex);

	kfree(cdev_info);
	pf->cdev_infos = NULL;
}

/**
 * mce_get_auxiliary_drv - retrieve iidc_auxiliary_drv struct
 * @cdev_info: pointer to iidc_core_dev_info struct
 *
 * This function has to be called with a device_lock on the
 * cdev_info->adev.dev to avoid race conditions for auxiliary
 * driver unload, and the mutex pf->adev_mutex locked to avoid
 * plug/unplug race conditions..
 */
struct iidc_auxiliary_drv
*mce_get_auxiliary_drv(struct iidc_core_dev_info *cdev_info)
{
        struct auxiliary_device *adev;
        struct mce_pf *pf;

        if (!cdev_info)
                return NULL;
        pf = pci_get_drvdata(cdev_info->pdev);

        lockdep_assert_held(&pf->adev_mutex);

        adev = cdev_info->adev;
        if (!adev || !adev->dev.driver)
                return NULL;

        return container_of(adev->dev.driver, struct iidc_auxiliary_drv,
                            adrv.driver);
}



/**
 * mce_send_event_to_aux - send event to a specific aux driver
 * @cdev_info: pointer to iidc_core_dev_info struct for this aux
 * @data: opaque pointer used to pass event struct
 */
static int
mce_send_event_to_aux(struct iidc_core_dev_info *cdev_info, void *data)
{
        struct iidc_event *event = data;
        struct iidc_auxiliary_drv *iadrv;
        struct mce_pf *pf;

        if (WARN_ON_ONCE(!in_task()))
                return -EINVAL;

        if (!cdev_info)
                return -EINVAL;

        pf = pci_get_drvdata(cdev_info->pdev);
        if (!pf)
                return -EINVAL;

        //if (test_bit(ICE_SET_CHANNELS, pf->state))
        //        return 0;

        mutex_lock(&pf->adev_mutex);

        if (!cdev_info->adev || !event) {
                mutex_unlock(&pf->adev_mutex);
                return 0;
        }

        device_lock(&cdev_info->adev->dev);
        iadrv = mce_get_auxiliary_drv(cdev_info);
        if (iadrv && iadrv->event_handler)
                iadrv->event_handler(cdev_info, event);
	else
		printk("no driver or handler \n");

        device_unlock(&cdev_info->adev->dev);
        mutex_unlock(&pf->adev_mutex);

        return 0;
}

//static void debug_qos_info(struct iidc_qos_params *qos_info)
//{
//	int i;
//
//	for (i = 0; i < IIDC_MAX_USER_PRIORITY; i++) 
//		printk("up2tc[%d]: 0x%x\n", i, qos_info->up2tc[i]);
//	
//	for (i = 0; i < IIDC_MAX_DSCP_MAPPING; i++)
//		printk("dscp_map[%d]: 0x%x\n", i, qos_info->dscp_map[i]);
//	
//	printk("pfc_mode is %x\n", qos_info->pfc_mode);
//	printk("num_tc is %d\n", qos_info->num_tc);
//
//}

/**
 * mce_send_event_to_auxs - send event to all auxiliary drivers
 * @pf: pointer to PF struct
 * @event: pointer to iidc_event to propagate
 *
 * event struct to be populated by caller
 */
void mce_send_event_to_auxs(struct mce_pf *pf, struct iidc_event *event)
{
	struct iidc_core_dev_info *cdev_info = pf->cdev_infos;
	struct iidc_qos_params *qos_info = &cdev_info->qos_info;
	struct mce_dcb *dcb = pf->dcb;
	struct mce_ets_cfg *etscfg = &(dcb->cur_etscfg);

	if (test_bit(IIDC_EVENT_PRIO_MODE_CHNG, event->type)) {
		if (test_bit(MCE_DSCP_EN, dcb->flags))
			qos_info->map_mode = IIDC_DSCP_PFC_MODE;
		else
			qos_info->map_mode = IIDC_VLAN_PFC_MODE;
	}
	//if (test_bit(IIDC_EVENT_PRIO_CHNG, event->type)) {
	qos_info->valid_prio = cdev_info->valid_prio;
	/* if dcb change update qos */
	if (test_bit(IIDC_EVENT_AFTER_TC_CHANGE, event->type)) {
		int i;

		for (i = 0; i < IIDC_MAX_USER_PRIORITY; i++) {
			qos_info->up2tc[i] = etscfg->prio_table[i];
		}
		//if (test_bit(MCE_DSCP_EN, dcb->flags))
		//	qos_info->map_mode = IIDC_DSCP_PFC_MODE;
		//else
		//	qos_info->map_mode = IIDC_VLAN_PFC_MODE;
		/* mode is dscp or pcp */
		if (test_bit(MCE_PFC_EN, dcb->flags))
			qos_info->pfc_en = IIDC_PFC_ON;
		else
			qos_info->pfc_en = IIDC_PFC_OFF;

		qos_info->num_tc = etscfg->curtcs;
		memcpy(qos_info->dscp_map, dcb->dscp_map, MCE_MAX_DSCP);
		//debug_qos_info(qos_info);
	}
	// copy to info
	event->info.port_qos = cdev_info->qos_info;

	//}

	/* if mrdma insmod ,sento mrdma */
        if (!event || !pf)
                return;

        if (bitmap_weight(event->type, IIDC_EVENT_NBITS) != 1) {
                dev_warn(mce_pf_to_dev(pf), "Event with not exactly one type bit set\n");
                return;
        }


	mce_send_event_to_aux(cdev_info, event);

}

