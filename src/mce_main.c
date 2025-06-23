#include <linux/module.h>
#include "mce.h"
#include "mce_irq.h"
#include "mce_lib.h"
#include "mce_base.h"
#include "mce_netdev.h"
#include "mce_fltr.h"
#include "mce_fdir.h"
#include "mce_sriov.h"
#include "mce_fwchnl.h"
#include "mce_virtchnl.h"
#include "mce_devlink.h"
#include "mce_dcb.h"
#include "mce_fdir_flow.h"
#include "mce_tc_lib.h"
#include "mce_version.h"
#include "mce_npu.h"

/* Device IDs */
#define PCI_VENDOR_ID_MUCSE 0x8848
#define PCI_DEVICE_ID_N20 0x903f
#define PCI_DEVICE_ID_N20_25G 0x8500
#define PCI_DEVICE_ID_N20_100G 0x8501

#define MCE_NPU_BAR_N20 0
#ifndef MCE_DEBUG_XINSI_PCIE
/* bar number */
#define MCE_NIC_BAR_N20 2
#define MCE_RDMA_BAR_N20 4
#else
/* bar number */
#define MCE_NIC_BAR_N20 2
#define MCE_RDMA_BAR_N20 4
#endif

MODULE_AUTHOR("Mucse Corporation, <mucse@mucse.com>");
MODULE_DESCRIPTION(
	"Mucse(R) 10/25/50/100 Gigabit PCI Express Network Driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_VERSION);

static int debug = -1;
module_param(debug, int, 0644);
MODULE_PARM_DESC(debug, "netif level (0=none,...,16=all)");

static int pcie_irq_mode = MCE_PCIE_IRQ_MODE_NONE;
module_param(pcie_irq_mode, int, 0644);
MODULE_PARM_DESC(
	pcie_irq_mode,
	"pcie interrupt mode (1:msix, 2:msi, 3:legency, default:1)");

static struct pci_device_id mce_pci_tbl[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_MUCSE, PCI_DEVICE_ID_N20),
	  .driver_data = board_n20 }, // n20
	{ PCI_DEVICE(PCI_VENDOR_ID_MUCSE, PCI_DEVICE_ID_N20_25G),
	  .driver_data = board_n20 }, // n20
#ifndef MCE_DEBUG_XINSI_PCIE
	{ PCI_DEVICE(PCI_VENDOR_ID_MUCSE, PCI_DEVICE_ID_N20_100G),
	  .driver_data = board_n20 }, // n20
#endif
	/* required last entry */
	{ 0 }
};
MODULE_DEVICE_TABLE(pci, mce_pci_tbl);

static unsigned int tun_inner;
module_param(tun_inner, uint, 0000);
MODULE_PARM_DESC(tun_inner, "parse tunnel packet by inner layer");

static unsigned int fdir_mode;
module_param(fdir_mode, uint, 0000);
MODULE_PARM_DESC(fdir_mode,
		 "fdir mode (0:exact, 1:sign, 2:macvlan, default: 0)");

struct workqueue_struct *mce_wq;

/**
 * mce_service_task_schedule - schedule the service task to wake up
 * @pf: board private structure
 *
 * If not already scheduled, this puts the task into the work queue.
 */
void mce_service_task_schedule(struct mce_pf *pf)
{
	if (!test_bit(MCE_SERVICE_DIS, pf->state) &&
	    !test_and_set_bit(MCE_SERVICE_SCHED, pf->state) &&
	    !test_bit(MCE_NEEDS_RESTART, pf->state))
		queue_work(mce_wq, &pf->serv_task);
}

/**
 * mce_service_task_complete - finish up the service task
 * @pf: board private structure
 */
static void mce_service_task_complete(struct mce_pf *pf)
{
	/* force memory (pf->state) to sync before next service task */
	smp_mb__before_atomic();
	clear_bit(MCE_SERVICE_SCHED, pf->state);
}

/**
 * mce_service_task_stop - stop service task and cancel works
 * @pf: board private structure
 *
 * Return 0 if the ICE_SERVICE_DIS bit was not already set,
 * 1 otherwise.
 */
static int mce_service_task_stop(struct mce_pf *pf)
{
	int ret;

	ret = test_and_set_bit(MCE_SERVICE_DIS, pf->state);

	if (pf->serv_tmr.function)
		del_timer_sync(&pf->serv_tmr);
	if (pf->serv_task.func)
		cancel_work_sync(&pf->serv_task);
	if (pf->tx_hwtstamp_work.func)
		cancel_work_sync(&pf->tx_hwtstamp_work);

	clear_bit(MCE_SERVICE_SCHED, pf->state);
	return ret;
}

static void mce_monitor_msix_vector(struct mce_pf *pf)
{
	struct mce_hw *hw = &pf->hw;
	u32 val, i;
	struct mce_vsi *vsi = pf->vsi[0];
	struct mce_q_vector *q_vector;
	int base = vsi->base_vector;
	u32 base_off = hw->vector_offset;
	int v_idx;
	struct mce_ring *ring;

	if (test_bit(MCE_VSI_DOWN, vsi->state))
		return;

	for ((i) = 0; (i) < (vsi)->num_q_vectors; (i)++) {
		q_vector = vsi->q_vectors[i];
		v_idx = q_vector->v_idx + base;
		val = vector_rd(hw, base_off + 0xc + 0x10 * v_idx);
		if (val & BIT(0)) {
			printk("vidx %d mask detected\n", v_idx);
			vector_wr(hw, base_off + 0xc + 0x10 * v_idx, 0);
			mce_rc_for_each_ring(ring, q_vector->tx) {

				hw->ops->set_txring_trig_intr(ring);
			}
		}
	}
}

/**
 * mce_service_timer - timer callback to schedule service task
 * @t: pointer to timer_list
 */
static void mce_service_timer(struct timer_list *t)
{
	struct mce_pf *pf = from_timer(pf, t, serv_tmr);

	mod_timer(&pf->serv_tmr,
		  round_jiffies(pf->serv_tmr_period + jiffies));
	mce_service_task_schedule(pf);
}

/**
 * mce_vsi_fltr_changed - check if filter state changed
 * @vsi: VSI to be checked
 *
 * returns true if filter state has changed, false otherwise.
 */
static bool mce_vsi_fltr_changed(struct mce_vsi *vsi)
{
	return test_bit(MCE_VSI_UMAC_FLTR_CHANGED, vsi->state) ||
	       test_bit(MCE_VSI_MMAC_FLTR_CHANGED, vsi->state);
}

/**
 * mce_vsi_sync_fltr - Update the VSI filter list to the HW
 * @vsi: ptr to the VSI
 *
 * Push any outstanding VSI filter changes through the AdminQ.
 */
static int mce_vsi_sync_fltr(struct mce_vsi *vsi)
{
	struct net_device *netdev = vsi->netdev;
	struct mce_pf *pf = vsi->back;
	struct mce_hw *hw = &pf->hw;
	u32 changed_flags = 0;

	if (!vsi->netdev)
		return -EINVAL;
	changed_flags = vsi->current_netdev_flags ^ vsi->netdev->flags;
	vsi->current_netdev_flags = vsi->netdev->flags;

	if (mce_vsi_fltr_changed(vsi)) {
		clear_bit(MCE_VSI_UMAC_FLTR_CHANGED, vsi->state);
		clear_bit(MCE_VSI_MMAC_FLTR_CHANGED, vsi->state);
		/* grab the netdev's addr_list_lock */
		netif_addr_lock_bh(netdev);
		__dev_uc_sync(netdev, mce_add_uc_filter,
			      mce_del_uc_filter);
		__dev_mc_sync(netdev, mce_add_mc_filter,
			      mce_del_mc_filter);
		/* our temp lists are populated. release lock */
		netif_addr_unlock_bh(netdev);
	}

	/* check for changes in promiscuous modes */
	if (changed_flags & IFF_ALLMULTI) {
		if (vsi->current_netdev_flags & IFF_ALLMULTI) {
			hw->ops->set_mc_promisc(hw, true);
		} else {
			hw->ops->set_mc_promisc(hw, false);
		}
	}

	if (changed_flags & IFF_PROMISC) {
		if (vsi->current_netdev_flags & IFF_PROMISC) {
			hw->ops->set_rx_promisc(hw, true);
			/* we should set mc promisc too */
			hw->ops->set_mc_promisc(hw, true);
			hw->vf.ops->set_vf_set_vlan_promisc(hw, PFINFO_IDX,
							    true);
		} else {
			hw->ops->set_rx_promisc(hw, false);
			/* maybe in mc promisc */
			if (vsi->current_netdev_flags & IFF_PROMISC) {
				hw->ops->set_mc_promisc(hw, true);
			} else {
				hw->ops->set_mc_promisc(hw, false);
			}
			if (test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
				hw->vf.ops->set_vf_set_vlan_promisc(
					hw, PFINFO_IDX, false);
			else
				hw->vf.ops->set_vf_set_vlan_promisc(
					hw, PFINFO_IDX, true);
		}
	}

	return 0;
}

/**
 * mce_sync_fltr_subtask - Sync the VSI filter list with HW
 * @pf: board private structure
 */
static void mce_sync_fltr_subtask(struct mce_pf *pf)
{
	int v;

	if (!pf || !(test_bit(MCE_FLAG_FLTR_SYNC, pf->flags)))
		return;

	clear_bit(MCE_FLAG_FLTR_SYNC, pf->flags);

	mce_for_each_vsi(pf, v) {
		if (pf->vsi[v] && mce_vsi_fltr_changed(pf->vsi[v]) &&
		    mce_vsi_sync_fltr(pf->vsi[v])) {
			/* come back and try again later */
			set_bit(MCE_FLAG_FLTR_SYNC, pf->flags);
			break;
		}
	}
}

static void mce_process_pcs_link_event(struct mce_pf *pf)
{
	struct mce_hw *hw = &pf->hw;
	u32 val = 0;
	int ret = 0;

	if (!test_and_clear_bit(MCE_FLAG_MISC_IRQ_PCS_LINK_PENDING,
				pf->flags))
		return;
	ret = hw->ops->get_misc_irq_st(hw, MCE_MAC_MISC_IRQ_PCS_LINK,
				       &val);
	if (ret)
		dev_err(mce_pf_to_dev(pf), "pcs link intrrupt error!\n");
	else
		dev_info(mce_pf_to_dev(pf),
			 "pcs link intrrupt, val:0x%x\n", val);
	hw->ops->clear_misc_irq_evt(hw, MCE_MAC_MISC_IRQ_PCS_LINK,
				    MCE_MISC_IRQ_CLEAR_ALL);
}

static void mce_process_ptp_event(struct mce_pf *pf)
{
	struct mce_hw *hw = &pf->hw;
	u32 val = 0;
	int ret = 0;

	if (!test_and_clear_bit(MCE_FLAG_MISC_IRQ_PTP_PENDING, pf->flags))
		return;
	ret = hw->ops->get_misc_irq_st(hw, MCE_MAC_MISC_IRQ_PTP, &val);
	if (ret)
		dev_err(mce_pf_to_dev(pf), "ptp  intrrupt error!\n");
	else
		dev_info(mce_pf_to_dev(pf), "ptp intrrupt, val:0x%x\n",
			 val);
	hw->ops->clear_misc_irq_evt(hw, MCE_MAC_MISC_IRQ_PTP,
				    MCE_MISC_IRQ_CLEAR_ALL);
}

static void mce_process_vflr_event(struct mce_pf *pf)
{
	struct mce_hw *hw = &pf->hw;
	u32 val = 0, v_clr;
	int i = 0;

	if (!test_and_clear_bit(MCE_FLAG_MISC_IRQ_FLR_PENDING, pf->flags))
		return;
	for (i = MCE_MISC_IRQ_FLR_NONE; i < MCE_MISC_IRQ_FLR_MAX; i++) {
		val = i;
		hw->ops->get_misc_irq_st(hw, MCE_MAC_MISC_IRQ_FLR, &val);
		dev_info(mce_pf_to_dev(pf),
			 "mce process vflr group:%d val:0x%x!\n", i, val);
		/* TODO: handle each vf flr event */
		// mce_handle_each_vf_flr(hw, vfid);
		if (val) {
			v_clr = i;
			hw->ops->clear_misc_irq_evt(
				hw, MCE_MAC_MISC_IRQ_FLR, v_clr);
		}
	}
}

static void mce_sync_mrdma_subtask(struct mce_pf *pf)
{
	bool mrdma_true = false;
	struct mce_hw *hw = &pf->hw;
	struct iidc_core_dev_info *cdev_info = pf->cdev_infos;
	int i;
	// it mrdma status changed, setup mrdma 
	if (!test_and_clear_bit(MCE_FLAG_MRDMA_CHANGED,
				pf->flags))
		return;
	
	// if mrdma in
	if (pf->m_status == MRDMA_INSMOD) {
		mrdma_true = true;
		// for each vsi, reset valid_prio
		mce_for_each_vsi(pf, i) {
			if (!pf->vsi[i])
				continue;
			// if mrdam on, force prio 7 to mrdma
			pf->vsi[i]->valid_prio &= 0x7f;
		}
		printk("mrdma insmode\n");
	} else {
		/* if mrdma removed, nic use all prio */
		mce_for_each_vsi(pf, i) {
			if (!pf->vsi[i])
				continue;
			pf->vsi[i]->valid_prio = 0xff;
		}
		// rdma use null valid_prio
		// should echo again
		if (cdev_info)
			cdev_info->valid_prio = 0;
	}


	if (hw->ops->update_rdma_status)
		hw->ops->update_rdma_status(hw, mrdma_true);

}

static void mce_pf_reset_subtask(struct mce_pf *pf)
{
	struct net_device *netdev = pf->vsi[0]->netdev;
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;

	if (!pf || !(test_bit(MCE_FLAG_PF_RESET_ENA, pf->flags)))
		return;

	clear_bit(MCE_FLAG_PF_RESET_ENA, pf->flags);
	rtnl_lock();
	mce_vsi_close(vsi);
	netdev_info(netdev, "mce_pf_reset_subtask\n");
	mce_vsi_open(vsi);
	rtnl_unlock();
}

void mce_link_state_subtask(struct mce_pf *pf)
{
	struct mce_vsi *vsi = pf->vsi[0];
	struct mce_hw *hw = &pf->hw;
	u32 value;
	struct net_device *netdev = vsi->netdev;
	struct device *dev = &hw->pdev->dev;

	if (hw->func_caps.common_cap.num_txq != 8)
		return ;

	if (test_bit(MCE_VSI_DOWN, vsi->state))
		return;

	value = mce_rd32(hw, 0x60004);

	if ((!vsi->link) && (value & 0x3)) {
		if (!netif_carrier_ok(netdev)) {
			netif_carrier_on(netdev);
			dev_info(dev, "link is up\n");
			vsi->link = 1;
		}

	} else if ((vsi->link) && (!(value & 0x3))) {
		if (netif_carrier_ok(netdev)) {
			netif_carrier_off(netdev);
			dev_info(dev, "link is down\n");
			vsi->link = 0;
		}
	}
}

/**
 * mce_service_task - manage and run subtasks
 * @work: pointer to work_struct contained by the PF struct
 */
static void mce_service_task(struct work_struct *work)
{
	struct mce_pf *pf = container_of(work, struct mce_pf, serv_task);
	unsigned long start_time = jiffies;

	mce_sync_fltr_subtask(pf);
	mce_process_pcs_link_event(pf);
	mce_process_ptp_event(pf);
	mce_process_vflr_event(pf);
	mce_sync_mrdma_subtask(pf);
	mce_monitor_msix_vector(pf);
	mce_pf_reset_subtask(pf);
	mce_link_state_subtask(pf);
	/* Clear ICE_SERVICE_SCHED flag to allow scheduling next event */
	mce_service_task_complete(pf);

	/* If the tasks have taken longer than one service timer period
	 * or there is more work to be done, reset the service timer to
	 * schedule the service task now.
	 */
	if (time_after(jiffies, (start_time + pf->serv_tmr_period)))
		mod_timer(&pf->serv_tmr, jiffies);
}

void get_msix_vector(struct mce_hw *hw)
{
	struct pci_dev *dev = hw->pdev;
	u32 table_offset;

	pci_read_config_dword(dev, dev->msix_cap + PCI_MSIX_TABLE,
			&table_offset);
	hw->msix_vector_bar = (u8)(table_offset & PCI_MSIX_TABLE_BIR);
	hw->vector_offset = table_offset;
}

struct self_test {
	u32 reg;
	u32 value;
	u8 *string;
	u32 mask;
};

struct self_test eth_test[] = {
	{0x70000, 0x20250612, "nic version      "},
	{0x40014, 0x0000000f, "nic bus status   "},
	{0x86408, 0x00000000, "nic t-fifo status"},
	{0x8641c, 0x00000000, "nic r-fifo status"}
};

struct self_test rdma_test[] = {
	{0x00000, 0x20250508, "rdma version     ", 0xffffffff},
	{0x1e030, 0x00000000, "rdma qp status   ", 0x3f},
	{0x1e0b0, 0x00000000, "rdma cq status   ", 0x1f},
	{0x1e010, 0x00000000, "rdma dma status  ", 0xf}
};

static int mce_self_test(struct mce_hw *hw)
{
	int i;
	u32 value;
	struct device *dev = hw->dev;
	int ret = 0;

	// no chengjian skip self_test
	if (hw->func_caps.common_cap.num_txq != 8)
		return 0;
	// test only
	//return 0;
	// check eth status
	for (i = 0; i < (sizeof(eth_test) / sizeof(struct self_test)); i++) {
		value = mce_rd32(hw, eth_test[i].reg);
		if (value != eth_test[i].value) {
			dev_info(dev, "self-test '%s' \tfailed\n", eth_test[i].string);
			dev_info(dev, "expect %x, true %x\n", eth_test[i].value, value);
			ret = 1;
		} else {
			
			dev_info(dev, "self-test '%s' \tpass\n", eth_test[i].string);
		}

	}

	// check eth status
	for (i = 0; i < (sizeof(rdma_test) / sizeof(struct self_test)); i++) {
		value = rdma_rd32(hw, rdma_test[i].reg);
		if ((value & rdma_test[i].mask) != (rdma_test[i].value & rdma_test[i].mask)) {
			dev_info(dev, "self-test '%s' \tfailed\n", rdma_test[i].string);
			dev_info(dev, "expect %x, true %x\n", rdma_test[i].value, value);
			ret = 1;
		} else {
			
			dev_info(dev, "self-test '%s' \tpass\n", rdma_test[i].string);
		}

	}
	// temp close
	//ret = 0;
	return ret;
}

static int mce_init_hw(struct mce_hw *hw)
{
	struct device *dev = hw->dev;
	int err = 0;
	int bar_id = 0;

	switch (hw->hw_type) {
	case board_n20:
		bar_id = MCE_NIC_BAR_N20;
		hw->eth_bar_base =
			ioremap(pci_resource_start(hw->pdev, bar_id),
				pci_resource_len(hw->pdev, bar_id));
		if (!(hw->eth_bar_base)) {
			dev_err(dev, "pcim_iomap bar%u faild!\n", bar_id);
			err = -EIO;
			goto err_ioremap_eth;
		}
		dev_info(dev,
			 "BAR%u PA:%016llx,SIZE:0x%08llu, VA=0x%016llx",
			 bar_id, pci_resource_start(hw->pdev, bar_id),
			 pci_resource_len(hw->pdev, bar_id),
			 (uint64_t)(hw->eth_bar_base));

//#ifndef MCE_DEBUG_XINSI_PCIE
		// ioremap RDMA bar
		bar_id = MCE_RDMA_BAR_N20;
		hw->rdma_bar_base =
			ioremap(pci_resource_start(hw->pdev, bar_id),
				pci_resource_len(hw->pdev, bar_id));
		if (!(hw->rdma_bar_base)) {
			dev_err(dev, "pcim_iomap bar%u faild!\n", bar_id);
			err = -EIO;
			goto err_ioremap_rdma;
		}
		dev_info(dev,
			 "BAR%u PA:%016llx,SIZE:0x%08llu, VA=0x%016llx",
			 bar_id, pci_resource_start(hw->pdev, bar_id),
			 pci_resource_len(hw->pdev, bar_id),
			 (uint64_t)(hw->rdma_bar_base));
//#endif
		if (mce_get_n20_caps(hw) < 0) {
			dev_err(dev, "Failed to mce_get_n20_caps\n");
			err = -EIO;
			goto err_hw_type;
		}

		if (hw->nic_version == 0xffffffff ||
		    hw->dma_version == 0xffffffff) {
			dev_err(dev, "Failed to get hw version\n");
			err = -EIO;
			goto err_hw_type;
		}

		get_msix_vector(hw);
		if (hw->msix_vector_bar == MCE_NIC_BAR_N20)
			hw->vector_bar_base = hw->eth_bar_base;

		if ((!hw->func_caps.common_cap.npu_capable) &&
		    (hw->msix_vector_bar != MCE_NPU_BAR_N20))
			break;
		bar_id = MCE_NPU_BAR_N20;
		hw->npu_bar_base =
			ioremap(pci_resource_start(hw->pdev, bar_id),
				pci_resource_len(hw->pdev, bar_id));
		if (!hw->npu_bar_base) {
			dev_err(dev, "pcim_iomap bar%u faild!\n", bar_id);
			err = -EIO;
			goto err_ioremap_npu;
		}
		if (hw->func_caps.common_cap.npu_capable)
			hw->func_caps.common_cap.npu_en = true;
		if (hw->msix_vector_bar == MCE_NPU_BAR_N20)
			hw->vector_bar_base = hw->npu_bar_base;
		if (!hw->vector_bar_base) {
			dev_err(dev, "no vector_bar_base!\n");
			err = -EIO;
			goto err_ioremap_npu;
		}
		break;
	default:
		dev_err(dev, "Sorry this device not supported!");
		err = -EINVAL;
		goto err_hw_type;
	}

	if (!hw->port_info) {
		hw->port_info = devm_kzalloc(dev, sizeof(*hw->port_info),
					     GFP_KERNEL);
		if (!hw->port_info) {
			err = -ENOMEM;
			goto err_hw_type;
		}
	}


	/* TODO:setup ptp , this only test for ptp intrrupt, 
	 * remove in future.
	 */
	if (hw->func_caps.common_cap.mac_misc_irq &
	    BIT(MCE_MAC_MISC_IRQ_PTP))
		hw->ops->set_init_ptp(hw);
	hw->ops->reset_hw(hw);
	// added self-test for chengjian
	if (mce_self_test(hw)) {
		
		dev_info(dev, "self-test failed\n");
		err = -EIO;
		goto err_hw_type;
	}

	dev_info(dev, "self-test pass\n");
	hw->ops->init_hw(hw);
	hw->vf.ops->set_vf_rebase_ring_base(hw);
	hw->ops->enable_proc_old(hw);

	mutex_init(&hw->fdir_fltr_lock);
	INIT_LIST_HEAD(&hw->fdir_list_head);
	INIT_LIST_HEAD(&hw->vlan_list_head);

	mutex_init(&hw->tnl_lock);
	memset(&hw->tnl, 0x0, sizeof(hw->tnl));

	return err;
err_ioremap_npu:
	if (hw->npu_bar_base)
		iounmap(hw->npu_bar_base);
	hw->npu_bar_base = NULL;
err_hw_type:
//#ifndef MCE_DEBUG_XINSI_PCIE
	if (hw->rdma_bar_base)
		iounmap(hw->rdma_bar_base);
	hw->rdma_bar_base = NULL;
err_ioremap_rdma:
//#endif
	if (hw->eth_bar_base)
		iounmap(hw->eth_bar_base);
	hw->eth_bar_base = NULL;
err_ioremap_eth:
	return err;
}

static void mce_set_pf_caps(struct mce_pf *pf)
{
	struct mce_hw_func_caps *func_caps = &(pf->hw.func_caps);

	clear_bit(MCE_FLAG_RSS_ENA, pf->flags);
	if (func_caps->common_cap.rss_table_size)
		set_bit(MCE_FLAG_RSS_ENA, pf->flags);
	clear_bit(MCE_FLAG_SRIOV_CAPABLE, pf->flags);
	if (func_caps->common_cap.sr_iov)
		set_bit(MCE_FLAG_SRIOV_CAPABLE, pf->flags);

	pf->pcie_irq_mode = pcie_irq_mode;
	pf->max_pf_txqs = func_caps->common_cap.num_txq;
	pf->max_pf_rxqs = func_caps->common_cap.num_rxq;
	pf->num_msix_cnt = func_caps->common_cap.max_irq_cnts;
	pf->max_vfs = func_caps->common_cap.max_vfs;
	pf->mbox_irq_base = func_caps->common_cap.mbox_irq_base;
	pf->num_mbox_irqs = func_caps->common_cap.num_mbox_irqs;
	pf->rdma_irq_base = func_caps->common_cap.rdma_irq_base;
	pf->num_rdma_irqs = func_caps->common_cap.num_rdma_irqs;
	if (pf->pcie_irq_mode == MCE_PCIE_IRQ_MODE_MSIX)
		pf->qvec_irq_base = func_caps->common_cap.qvec_irq_base;
	else {
		/* no pcie msix mode, we only support 1 pcie vector */
		pf->qvec_irq_base = 0;
	}
	pf->vlan_strip_cnt = func_caps->common_cap.vlan_strip_cnt;
	pf->num_max_tc = func_caps->common_cap.max_tc;
	pf->num_q_for_tc = func_caps->common_cap.queue_for_tc;
	pf->mac_misc_irq = func_caps->common_cap.mac_misc_irq;
	pf->mac_misc_irq_retry = func_caps->common_cap.mac_misc_irq_retry;
	pf->npu_capable = func_caps->common_cap.npu_capable;
	pf->npu_en = func_caps->common_cap.npu_en;

	if (func_caps->common_cap.pcie_irq_capable &
	    BIT(MCE_PCIE_IRQ_MODE_MSIX))
		set_bit(MCE_FLAG_IRQ_MSIX_CAPABLE, pf->flags);
	if (func_caps->common_cap.pcie_irq_capable &
	    BIT(MCE_PCIE_IRQ_MODE_MSI))
		set_bit(MCE_FLAG_IRQ_MSI_CAPABLE, pf->flags);
	if (func_caps->common_cap.pcie_irq_capable &
	    BIT(MCE_FLAG_IRQ_LEGENCY_CAPABLE))
		set_bit(MCE_FLAG_SRIOV_CAPABLE, pf->flags);
}
static int mce_init_devlink(struct mce_pf *pf)
{
#ifndef HAVE_DEVLINK_PARAMS_PUBLISH
#if IS_ENABLED(CONFIG_NET_DEVLINK)
	struct devlink *devlink = priv_to_devlink(pf);
#endif /* CONFIG_NET_DEVLINK */
	bool need_register = true;
#endif /* !HAVE_DEVLINK_PARAMS_PUBLISH */

#ifndef HAVE_DEVLINK_PARAMS_PUBLISH
#if IS_ENABLED(CONFIG_NET_DEVLINK)
	/* for old kernels, prior to auto-publish of devlink params, API has
	 * required a call to devlink_register() prior to registering params.
	 * API has changed to be the other way around at the same moment that
	 * explicit param publishing was deprecated.
	 * Some older kernels have backported the removal of param publishing
	 * but not the reversing of register order. Because of that, we need
	 * to check if devlink->dev was properly allocated before registering
	 * params to avoid segfaults.
	 */
	if (!devlink_to_dev(devlink)) {
		mce_devlink_register(pf);
		need_register = false;
	}
#endif /* CONFIG_NET_DEVLINK */
#else
	mce_devlink_register(pf);
#endif /* !HAVE_DEVLINK_PARAMS_PUBLISH */
	mce_devlink_init_regions(pf);
#ifndef HAVE_DEVLINK_PARAMS_PUBLISH

	if (need_register)
		mce_devlink_register(pf);
#endif /* !HAVE_DEVLINK_PARAMS_PUBLISH */
	return 0;
}

static void mce_deinit_devlink(struct mce_pf *pf)
{
	mce_devlink_unregister(pf);
	mce_devlink_destroy_regions(pf);
}

static int mce_pf_init_dcb(struct mce_pf *pf)
{
	struct mce_dcb *dcb = NULL;
	dcb = devm_kzalloc(mce_pf_to_dev(pf), sizeof(*pf->dcb),
			   GFP_KERNEL);
	if (!dcb)
		return -ENOMEM;

	clear_bit(MCE_DSCP_EN, dcb->flags);
	clear_bit(MCE_ETS_EN, dcb->flags);
	clear_bit(MCE_DCB_EN, dcb->flags);
	clear_bit(MCE_PFC_EN, dcb->flags);

	mce_dcb_tc_default(&(dcb->cur_tccfg));
	mce_dcb_tc_default(&(dcb->new_tccfg));
	mce_dcb_ets_default(&(dcb->cur_etscfg));
	mce_dcb_ets_default(&(dcb->new_etscfg));
	mce_dcb_pfc_default(&(dcb->cur_pfccfg));
	mce_dcb_pfc_default(&(dcb->new_pfccfg));

	dcb->back = pf;
	pf->dcb = dcb;

	mutex_init(&(dcb->dcb_mutex));

	return 0;
}

static void mce_pf_deinit_dcb(struct mce_pf *pf)
{
	struct mce_dcb *dcb = pf->dcb;

	if (dcb) {
		mutex_destroy(&(dcb->dcb_mutex));
		devm_kfree(mce_pf_to_dev(pf), dcb);
		pf->dcb = NULL;
	}
}

static int mce_init_pf(struct mce_pf *pf)
{
	struct mce_hw *hw = &pf->hw;
	int err = 0;

	mce_set_pf_caps(pf);

	mutex_init(&pf->sw_mutex);
	mutex_init(&pf->adev_mutex);
#ifdef HAVE_PTP_1588_CLOCK
	/* setup ptp address */
	INIT_WORK(&pf->tx_hwtstamp_work, mce_tx_hwtstamp_work);
#endif
	//pf->ptp_addr = pf->hw.eth_bar_base + 0x64000;
	pf->tx_timeout_factor = 10; // 10s for ptp timeout

	/* setup service timer and periodic service task */
	timer_setup(&pf->serv_tmr, mce_service_timer, 0);
	pf->serv_tmr_period = HZ;
	INIT_WORK(&pf->serv_task, mce_service_task);
	clear_bit(MCE_SERVICE_SCHED, pf->state);
	//clear_bit(MCE_FLAG_SW_DIM_ENA, pf->flags);
	set_bit(MCE_FLAG_HW_DIM_ENA, pf->flags);

	memset(&(pf->fc), 0x0, sizeof(struct mce_flow_control));

	mce_debugfs_pf_init(pf);

	err = mce_pf_init_dcb(pf);
	if (err) {
		dev_err(mce_pf_to_dev(pf), "init dcb failed\n");
		return err;
	}
	mce_realloc_and_fill_pfinfo(pf, false, false);
	/* setup tunnel inner layer */
	if (pf->tun_inner)
		set_bit(TNL_INNER_EN, hw->l2_fltr_flags);
	hw->ops->set_tun_select_inner(hw, pf->tun_inner);
	/* init fdir */
	mce_init_flow_engine(pf, fdir_mode);

	// add for chengjian
	if (hw->func_caps.common_cap.num_txq == 8) {
		pf->ptp_addr = hw->eth_bar_base + 0x50000 + 0x700;
		pf->gmac4 = 0;
	}
	return 0;
}

/**
 * mce_deinit_pf - Unrolls initialziations done by mce_init_pf
 * @pf: board private structure to initialize
 */
static void mce_deinit_pf(struct mce_pf *pf)
{
	mce_service_task_stop(pf);
	mutex_destroy(&pf->sw_mutex);
	mutex_destroy(&pf->adev_mutex);

	mce_debugfs_pf_exit(pf);
	mce_pf_deinit_dcb(pf);
}

/**
 * mce_pf_vsi_setup - Set up a PF VSI
 * @pf: board private structure
 * @pi: pointer to the port_info instance
 *
 * Returns pointer to the successfully allocated VSI software struct
 * on success, otherwise returns NULL on failure.
 */
static struct mce_vsi *mce_pf_vsi_setup(struct mce_pf *pf)
{
	return mce_vsi_setup(pf, MCE_VSI_PF);
}

static void mce_setup_fc_status(struct mce_pf *pf)
{
	struct mce_flow_control *fc = &(pf->fc);

	fc->req_mode = MCE_FC_FULL;
}

/**
 * mce_setup_pf_sw - Setup the HW switch on startup or after reset
 * @pf: board private structure
 *
 * Returns 0 on success, negative value on failure
 */
static int mce_setup_pf_sw(struct mce_pf *pf)
{
	struct mce_vsi *vsi;
	int status = 0;

	vsi = mce_pf_vsi_setup(pf);
	if (!vsi) {
		dev_err(&(pf->pdev->dev), "pf vsi setup failed!\n");
		return -ENOMEM;
	}

	mce_setup_fc_status(pf);
	status = mce_cfg_netdev(vsi);
	if (status) {
		dev_err(&(pf->pdev->dev), "cfg netdev failed!\n");
		goto unroll_vsi_setup;
	}

	/* registering the NAPI handler requires both the queues and
	 * netdev to be created, which are done in mce_pf_vsi_setup()
	 * and mce_cfg_netdev() respectively
	 */
	mce_napi_add(vsi);

	/* set pcie max vfs drv limit */
	if (test_bit(MCE_FLAG_SRIOV_CAPABLE, pf->flags))
		pci_sriov_set_totalvfs(pf->pdev, pf->max_vfs);

	return status;

unroll_vsi_setup:
	mce_vsi_release(vsi);

	return status;
}

#ifdef MCE_DEBUG_VF
/**
 * __mce_clean_ctrlq - helper function to clean controlq rings
 * @pf: ptr to struct mce_pf
 * @q_type: specific Control queue type
 */
static int __mce_clean_ctrlq(struct mce_pf *pf, enum mce_ctl_q q_type)
{
	struct device *dev = mce_pf_to_dev(pf);
	const char *qtype;
	int vfid = 0;

	/* Do not clean control queue if/when PF reset fails */
	if (test_bit(MCE_RESET_FAILED, pf->state))
		return 0;

	switch (q_type) {
	case MCE_CTL_Q_MAILBOX:
		qtype = "Mailbox";
		break;
	default:
		dev_warn(dev, "Unknown control queue type 0x%x\n", q_type);
		return 0;
	}

	/* Notify any thread that might be waiting for this event */
	// mce_aq_check_events(pf, opcode, &event);

	/* handle mailbox message for CM3 */
	vfid = MBX_FW;
	do {
		mce_fw_process_mailbox_msg(pf, vfid);
	} while (0);

	/* handle mailbox message for VF */
	vfid = 0;
	do {
		mce_vc_process_mailbox_msg(pf, vfid);
	} while (++vfid < pf->num_vfs);

	return 0;
}

/**
 * mce_clean_mailboxq_subtask - clean the MailboxQ rings
 * @pf: board private structure
 */
void mce_clean_mailboxq_subtask(struct mce_pf *pf)
{
	// struct mce_hw *hw = &(pf->hw);
	set_bit(MCE_MAILBOXQ_EVENT_PENDING, pf->state);

	if (!test_bit(MCE_MAILBOXQ_EVENT_PENDING, pf->state))
		return;

	if (__mce_clean_ctrlq(pf, MCE_CTL_Q_MAILBOX))
		return;

	clear_bit(MCE_MAILBOXQ_EVENT_PENDING, pf->state);

	// if (mce_ctrlq_pending(hw, &hw->mailboxq))
	// __mce_clean_ctrlq(pf, MCE_CTL_Q_MAILBOX);
}

/**
 * mce_misc_intr - misc interrupt handler
 * @irq: interrupt number
 * @data: pointer to a q_vector
 */
static irqreturn_t mce_misc_intr(int __always_unused irq, void *data)
{
	struct mce_pf *pf = data;
	struct mce_hw *hw = &pf->hw;
	int type_idx = 0, misc_irq_pending = 0;

	mce_clean_mailboxq_subtask(pf);
	mce_for_each_misc_irq(type_idx) {
		if (mce_get_misc_irq_evt(hw, type_idx)) {
			misc_irq_pending = 1;
			mce_pre_handle_misc_irq(hw, type_idx);
		}
	}
	if (misc_irq_pending)
		mce_service_task_schedule(pf);

	return IRQ_WAKE_THREAD;
}

/**
 * mce_misc_intr_thread_fn - misc interrupt thread function
 * @irq: interrupt number
 * @data: pointer to a q_vector
 */
static irqreturn_t mce_misc_intr_thread_fn(int __always_unused irq,
					   void *data)
{
	// struct mce_pf *pf = data;
	//mce_clean_mailboxq_subtask(pf);
	return IRQ_HANDLED;
}

/**
 * mce_req_irq_msix_misc - Setup the misc vector to handle non queue events
 * @pf: board private structure
 *
 * This sets up the handler for MSIX 0, which is used to manage the
 * non-queue interrupts, e.g. AdminQ and errors. This is not used
 * when in MSI or Legacy interrupt mode.
 */
static int mce_req_irq_msix_misc(struct mce_pf *pf)
{
	struct device *dev = mce_pf_to_dev(pf);
	struct mce_hw *hw = &(pf->hw);
	int err = 0, nr_vec;

	if (pf->pcie_irq_mode != MCE_PCIE_IRQ_MODE_MSIX) {
		pf->mbox_irq_base = MCE_MBOX_IRQ_NO_MSIX_BASE;
		goto misc_share_ring_irq;
	}

	err = mce_get_irq_res(pf, pf->irq_tracker, pf->num_mbox_irqs,
			      pf->mbox_irq_base);
	if (err) {
		dev_err(dev, "No irq rem for mbox\n");
		return err;
	}
	nr_vec = pf->mbox_irq_base;
	if (!pf->int_name[0])
		snprintf(pf->int_name, sizeof(pf->int_name) - 1,
			 "%s-%s:misc", dev_driver_string(dev),
			 dev_name(dev));

	err = devm_request_threaded_irq(
		dev, mce_get_irq_num(pf, pf->mbox_irq_base), mce_misc_intr,
		mce_misc_intr_thread_fn, 0, pf->int_name, pf);
	if (err) {
		dev_err(dev, "devm_request_threaded_irq for %s failed",
			pf->int_name);
		mce_free_irq_res(pf->irq_tracker, pf->num_mbox_irqs,
				 pf->mbox_irq_base);
		goto out;
	}

	/* TODO: must test other irq in mis/legency mode */
	mce_setup_misc_irq(hw, true, nr_vec);
misc_share_ring_irq:
	hw->mbx.other_irq_enabled = true;
	hw->mbx.ops->configure(hw, pf->mbox_irq_base, true);
out:
	return 0;
}
#endif /* MCE_DEBUG_VF */

/**
 * mce_probe - Device initialization routine
 * @pdev: PCI device information struct
 * @ent: entry in mce_pci_tbl
 *
 * Returns 0 on success, negative on failure
 */
static int mce_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct device *dev = &pdev->dev;
	struct mce_pf *pf = NULL;
	struct mce_hw *hw = NULL;
	int err = 0;

	if (pdev->is_virtfn) {
		dev_err(dev, "can't probe a virtual function\n");
		return -EINVAL;
	}

	dev_info(dev, DRIVER_NAME " PCI probe");

	err = pci_enable_device(pdev);
	if (err)
		return err;

	pf = mce_allocate_pf(dev);
	if (!pf)
		return -ENOMEM;
	/* set up for high or low DMA */
	err = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64));
	if (err) {
		dev_err(dev, "DMA configuration failed: 0x%x\n", err);
		return err;
	}

#ifdef HAVE_PCI_ENABLE_PCIE_ERROR_REPORTING
	pci_enable_pcie_error_reporting(pdev);
#endif /* HAVE_PCI_ENABLE_PCIE_ERROR_REPORTING */
	pci_set_master(pdev);

	pf->pdev = pdev;
	pci_set_drvdata(pdev, pf);
	set_bit(MCE_DOWN, pf->state);

	hw = &pf->hw;

	pci_save_state(pdev);

	hw->back = pf;
	hw->dev = dev;
	hw->pdev = pdev;
	hw->vendor_id = pdev->vendor;
	hw->device_id = pdev->device;
	pci_read_config_byte(pdev, PCI_REVISION_ID, &hw->revision_id);
	hw->subsystem_vendor_id = pdev->subsystem_vendor;
	hw->subsystem_device_id = pdev->subsystem_device;
	hw->bus.bus_num = pdev->bus->number;
	hw->bus.device = PCI_SLOT(pdev->devfn);
	hw->bus.func = PCI_FUNC(pdev->devfn);
	hw->hw_type = id->driver_data;

	/* init module params */
	pf->msg_enable = netif_msg_init(debug, MCE_DFLT_NETIF_M);
	if (pcie_irq_mode == MCE_PCIE_IRQ_MODE_NONE)
		pcie_irq_mode = MCE_PCIE_IRQ_MODE_MSIX;
	err = pci_request_mem_regions(pdev, dev_driver_string(dev));
	if (err) {
		dev_err(dev, "pci_request_selected_regions failed 0x%x\n",
			err);
		goto err_regions;
	}

	pci_save_state(pdev);

	err = mce_init_hw(hw);
	if (err) {
		dev_err(dev, "mce_init_hw failed: %d", err);
		goto err_init_hw;
	}
	/* setup tunnel inner layer */
	pf->tun_inner = tun_inner;
	err = mce_init_pf(pf);
	if (err) {
		dev_err(dev, "mce_init_hw failed: %d", err);
		goto err_init_pf;
	}

	err = mce_init_devlink(pf);
	if (err)
		goto err_init_pf;

#ifdef HAVE_UDP_TUNNEL_NIC_INFO
	mce_udp_tunnel_prepare(pf);
#endif /* HAVE_UDP_TUNNEL_NIC_INFO */
	hw->ops->set_fd_fltr_guar(hw);
	pf->num_alloc_vsi = hw->func_caps.guar_num_vsi;
	if (!pf->num_alloc_vsi) {
		err = -EIO;
		goto err_init_pf;
	}

	pf->vsi = devm_kcalloc(dev, pf->num_alloc_vsi, sizeof(*pf->vsi),
			       GFP_KERNEL);
	if (!pf->vsi) {
		err = -ENOMEM;
		goto err_init_pf;
	}

	pf->vsi_stats = devm_kcalloc(dev, pf->num_alloc_vsi,
				     sizeof(*pf->vsi_stats), GFP_KERNEL);

	if (!pf->vsi_stats) {
		err = -ENOMEM;
		goto err_init_vsi_stats;
	}

	err = mce_init_interrupt_scheme(pf);
	if (err) {
		dev_err(dev, "mce_init_interrupt_scheme failed: %d", err);
		err = -EIO;
		goto err_init_interrupt_scheme;
	}

	err = mce_setup_pf_sw(pf);
	if (err) {
		dev_err(dev, "probe failed due to setup PF switch");
		goto err_setup_pf_sw;
	}

	/* In case of MSIX we are going to setup the misc vector right here
	 * to handle admin queue events etc. In case of legacy and MSI
	 * the misc functionality and queue processing is combined in
	 * the same vector and that gets setup at open.
	 */
#ifdef MCE_DEBUG_VF
	err = mce_req_irq_msix_misc(pf);
	if (err) {
		dev_err(dev, "setup of misc vector failed: %d", err);
		goto err_setup_pf_sw;
	}
#endif

	/* ready to go, so clear down state bit */
	clear_bit(MCE_DOWN, pf->state);
	clear_bit(MCE_SERVICE_DIS, pf->state);

	/* since everything is good, start the service timer */
	mod_timer(&pf->serv_tmr,
		  round_jiffies(jiffies + pf->serv_tmr_period));

	err = mce_register_netdev(pf);
	if (err) {
		dev_err(dev, "failed to register netdev!\n");
		goto err_netdev_reg;
	}

	err = mce_plug_aux_devs(pf, "mrdma_roce");
	if (err)
		dev_err(dev, "failed to register auxdev!\n");

#ifdef MCE_SYSFS
	if (mce_sysfs_init(pf))
		dev_err(dev, "failed to init sysfs!\n");
#endif
	if (pf->npu_en)
		mce_npu_download_firmware(hw);
	return 0;

err_netdev_reg:
	mce_vsi_release_all(pf);
err_setup_pf_sw:
	set_bit(MCE_DOWN, pf->state);
	mce_clear_interrupt_scheme(pf);
err_init_interrupt_scheme:
	devm_kfree(dev, pf->vsi_stats);
	pf->vsi_stats = NULL;
err_init_vsi_stats:
	mce_deinit_devlink(pf);
	devm_kfree(dev, pf->vsi);
	pf->vsi = NULL;
err_init_pf:
	mce_deinit_pf(pf);
err_init_hw:
	pci_clear_master(pdev);
	pci_release_mem_regions(pdev);
err_regions:
	pci_disable_device(pdev);
	return err;
}

/**
 * mce_unmap_all_hw_addr - Release device register memory maps
 * @pf: pointer to the PF structure
 *
 * Release all PCI memory maps and regions.
 */
static void mce_unmap_all_hw_addr(struct mce_pf *pf)
{
	struct mce_hw *hw = &(pf->hw);
	struct pci_dev *pdev = pf->pdev;

	if (hw->eth_bar_base)
		iounmap(hw->eth_bar_base);
	hw->eth_bar_base = NULL;
	if (hw->rdma_bar_base)
		iounmap(hw->rdma_bar_base);
	hw->rdma_bar_base = NULL;
	if (hw->npu_bar_base)
		iounmap(hw->npu_bar_base);
	hw->npu_bar_base = NULL;
	pci_clear_master(pdev);
	pci_release_mem_regions(pdev);
}
#ifdef MCE_DEBUG_VF
/**
 * mce_free_irq_msix_misc - Unroll misc vector setup
 * @pf: board private structure
 */
static void mce_free_irq_msix_misc(struct mce_pf *pf)
{
	int irq_num = mce_get_irq_num(pf, pf->mbox_irq_base);
	struct mce_hw *hw = &(pf->hw);
	int nr_vec = 0;

	if (pf->pcie_irq_mode != MCE_PCIE_IRQ_MODE_MSIX) {
		pf->mbox_irq_base = MCE_MBOX_IRQ_NO_MSIX_BASE;
		goto misc_share_ring_irq;
	}
	nr_vec = pf->mbox_irq_base;
	synchronize_irq(irq_num);
	devm_free_irq(mce_pf_to_dev(pf), irq_num, pf);

	mce_free_irq_res(pf->irq_tracker, pf->num_mbox_irqs,
			 pf->mbox_irq_base);
	mce_setup_misc_irq(hw, false, 0);
misc_share_ring_irq:
	hw->mbx.ops->configure(hw, pf->mbox_irq_base, false);
	hw->mbx.other_irq_enabled = false;
}
#endif

/**
 * mce_deinit_hw - Release device register memory maps
 * @pf: pointer to the PF structure
 *
 */
static void mce_deinit_hw(struct mce_pf *pf)
{
	struct mce_hw *hw = &(pf->hw);
	struct mce_fdir_fltr *f_rule, *f_tmp;
	struct mce_vlan_list_entry *vlan_l, *v_tmp;
	mutex_lock(&hw->fdir_fltr_lock);
	list_for_each_entry_safe(f_rule, f_tmp, &hw->fdir_list_head,
				 fltr_node) {
		list_del(&f_rule->fltr_node);
		devm_kfree(hw->dev, f_rule);
	}
	mutex_unlock(&hw->fdir_fltr_lock);

	list_for_each_entry_safe(vlan_l, v_tmp, &hw->vlan_list_head,
				 vlan_node) {
		list_del(&f_rule->fltr_node);
		devm_kfree(hw->dev, vlan_l);
	}

	mutex_destroy(&hw->fdir_fltr_lock);

	mutex_destroy(&hw->tnl_lock);

	if (hw->port_info) {
		devm_kfree(hw->dev, hw->port_info);
		hw->port_info = NULL;
	}

	hw->ops->reset_hw(hw);

	mce_unmap_all_hw_addr(pf);
}

/**
 * mce_remove - Device removal routine
 * @pdev: PCI device information struct
 */
static void mce_remove(struct pci_dev *pdev)
{
	struct mce_pf *pf = pci_get_drvdata(pdev);
	int i = 0;

	if (!pf)
		return;
#ifdef MCE_DEBUG_VF
	mce_free_irq_msix_misc(pf);
#endif
#ifdef CONFIG_PCI_IOV
	mce_disable_sriov(pf);
#endif
#ifdef MCE_SYSFS
	mce_sysfs_exit(pf);
#endif
	set_bit(MCE_SHUTTING_DOWN, pf->state);

	/* clean all mrdma event first */
	clear_bit(MCE_FLAG_MRDMA_CHANGED, pf->flags);
	mce_unplug_aux_devs(pf);
	mce_vsi_release_all(pf);

	mce_for_each_vsi(pf, i) {
		if (!pf->vsi[i])
			continue;
		mce_vsi_free_q_vectors(pf->vsi[i]);
	}

	devm_kfree(&pdev->dev, pf->vsi_stats);
	pf->vsi_stats = NULL;
	mce_deinit_devlink(pf);
	mce_deinit_pf(pf);

	mce_clear_interrupt_scheme(pf);

	pci_wait_for_pending_transaction(pdev);
	mce_deinit_hw(pf);
#ifdef HAVE_PCI_ENABLE_PCIE_ERROR_REPORTING
	pci_disable_pcie_error_reporting(pdev);
#endif /* HAVE_PCI_ENABLE_PCIE_ERROR_REPORTING */
	pci_disable_device(pdev);

	dev_info(&(pdev->dev), DRIVER_NAME " PCI remove");
}

static struct pci_driver mce_driver = {
	.name = DRIVER_NAME,
	.id_table = mce_pci_tbl,
	.probe = mce_probe,
	.remove = mce_remove,
//.shutdown = mce_shutdown,
#if defined(HAVE_SRIOV_CONFIGURE)
	.sriov_configure = mce_sriov_configure,
#endif
};

static int __init mce_init_module(void)
{
	int status;

	mce_wq = alloc_workqueue("%s", 0, 0, KBUILD_MODNAME);
	if (!mce_wq) {
		pr_err("Failed to create workqueue\n");
		return -ENOMEM;
	}

	mce_debugfs_init();

	status = pci_register_driver(&mce_driver);
	if (status) {
		pr_err("failed to register PCI driver, err %d\n", status);
		destroy_workqueue(mce_wq);
		mce_debugfs_exit();
	}

	return status;
}

static void __exit mce_exit_module(void)
{
	pci_unregister_driver(&mce_driver);
	destroy_workqueue(mce_wq);
	mce_debugfs_exit();
	pr_info("module unloaded\n");
}

module_init(mce_init_module);
module_exit(mce_exit_module);
