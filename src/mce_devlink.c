/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2023 Intel Corporation */

#include "mce.h"
#include "mce_lib.h"
#include "mce_devlink.h"
#include "mce_eswitch.h"
#include "./mucse_auxiliary/mce_idc.h"

#define MCE_PORT_OPT_DESC_LEN	50
#ifdef HAVE_DEVLINK_INFO_GET
enum ice_version_type {
	MCE_VERSION_FIXED,
	MCE_VERSION_RUNNING,
	MCE_VERSION_STORED,
};

/* context for devlink info version reporting */
struct mce_info_ctx {
	char buf[128];
	struct mce_orom_info pending_orom;
	struct mce_nvm_info pending_nvm;
	struct mce_netlist_info pending_netlist;
	struct mce_hw_dev_caps dev_caps;
};

#define fixed(key, getter) { MCE_VERSION_FIXED, key, getter, NULL }
#define running(key, getter) { MCE_VERSION_RUNNING, key, getter, NULL }
#define stored(key, getter, fallback) \
	{ MCE_VERSION_STORED, key, getter, fallback }

/* The combined() macro inserts both the running entry as well as a stored
 * entry. The running entry will always report the version from the active
 * handler. The stored entry will first try the pending handler, and fallback
 * to the active handler if the pending function does not report a version.
 * The pending handler should check the status of a pending update for the
 * relevant flash component. It should only fill in the buffer in the case
 * where a valid pending version is available. This ensures that the related
 * stored and running versions remain in sync, and that stored versions are
 * correctly reported as expected.
 */
#define combined(key, active, pending) \
	running(key, active), \
	stored(key, pending, active)

static void mce_info_fw_api(struct mce_pf *pf, struct mce_info_ctx *ctx)
{
	snprintf(ctx->buf, sizeof(ctx->buf), "%u.%u.%u", 1, 1, 1);
}

static const struct mce_devlink_version {
	enum ice_version_type type;
	const char *key;
	void (*getter)(struct mce_pf * pf, struct mce_info_ctx * ctx);
	void (*fallback)(struct mce_pf * pf, struct mce_info_ctx * ctx);
} mce_devlink_versions[] = {
	running("fw.mgmt.api", mce_info_fw_api),
};

/**
 * mce_devlink_info_get - .info_get devlink handler
 * @devlink: devlink instance structure
 * @req: the devlink info request
 * @extack: extended netdev ack structure
 *
 * Callback for the devlink .info_get operation. Reports information about the
 * device.
 *
 * Return: zero on success or an error code on failure.
 */
static int mce_devlink_info_get(struct devlink *devlink,
				  struct devlink_info_req *req,
				  struct netlink_ext_ack *extack)
{
	struct mce_pf *pf = devlink_priv(devlink);
	struct mce_info_ctx *ctx;
	u32 i;
	int err;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;
	for (i = 0; i < ARRAY_SIZE(mce_devlink_versions); i++) {
		enum ice_version_type type = mce_devlink_versions[i].type;
		const char *key = mce_devlink_versions[i].key;

		memset(ctx->buf, 0, sizeof(ctx->buf));

		mce_devlink_versions[i].getter(pf, ctx);
		/* If the default getter doesn't report a version, use the
		 * fallback function. This is primarily useful in the case of
		 * "stored" versions that want to report the same value as the
		 * running version in the normal case of no pending update.
		 */
		if (ctx->buf[0] == '\0' && mce_devlink_versions[i].fallback)
			mce_devlink_versions[i].fallback(pf, ctx);

		/* Do not report missing versions */
		if (ctx->buf[0] == '\0')
			continue;

		switch (type) {
		case MCE_VERSION_FIXED:
			err =
			    devlink_info_version_fixed_put(req, key, ctx->buf);
			if (err) {
				NL_SET_ERR_MSG_MOD(extack,
						   "Unable to set fixed version");
				goto out_free_ctx;
			}
			break;
		case MCE_VERSION_RUNNING:
			err =
			    devlink_info_version_running_put(req, key,
							     ctx->buf);
			if (err) {
				NL_SET_ERR_MSG_MOD(extack,
						   "Unable to set running version");
				goto out_free_ctx;
			}
			break;
		case MCE_VERSION_STORED:
			err =
			    devlink_info_version_stored_put(req, key, ctx->buf);
			if (err) {
				NL_SET_ERR_MSG_MOD(extack,
						   "Unable to set stored version");
				goto out_free_ctx;
			}
			break;
		}
	}
 out_free_ctx:
	kfree(ctx);
	return err;

}
#endif	/* HAVE_DEVLINK_INFO_GET */

static const struct devlink_ops mce_devlink_ops = {
#ifdef HAVE_DEVLINK_FLASH_UPDATE_PARAMS
	.supported_flash_update_params =
	    DEVLINK_SUPPORT_FLASH_UPDATE_OVERWRITE_MASK,
#endif				/* HAVE_DEVLINK_FLASH_UPDATE_PARAMS */

	.eswitch_mode_get = mce_eswitch_mode_get,
	.eswitch_mode_set = mce_eswitch_mode_set,
#ifdef HAVE_DEVLINK_INFO_GET
	.info_get = mce_devlink_info_get,
#endif				/* HAVE_DEVLINK_INFO_GET */

};

static void mce_devlink_free(void *devlink_ptr)
{
	devlink_free((struct devlink *)devlink_ptr);
}

/**
 * mce_allocate_pf - Allocate devlink and return PF structure pointer
 * @dev: the device to allocate for
 *
 * Allocate a devlink instance for this device and return the private area as
 * the PF structure. The devlink memory is kept track of through devres by
 * adding an action to remove it when unwinding.
 */
struct mce_pf *mce_allocate_pf(struct device *dev)
{
	struct devlink *devlink;

	devlink =
	    devlink_alloc(&mce_devlink_ops, sizeof(struct mce_pf), dev);
	if (!devlink)
		return NULL;

	/* Add an action to teardown the devlink when unwinding the driver */
	if (devm_add_action(dev, mce_devlink_free, devlink)) {
		devlink_free(devlink);
		return NULL;
	}

	return (struct mce_pf *)devlink_priv(devlink);
}

/**
 * mce_devlink_register - Register devlink interface for this PF
 * @pf: the PF to register the devlink for.
 *
 * Register the devlink instance associated with this physical function.
 *
 * Return: zero on success or an error code on failure.
 */
void mce_devlink_register(struct mce_pf *pf)
{
	struct devlink *devlink = priv_to_devlink(pf);

#ifdef HAVE_DEVLINK_SET_FEATURES
	devlink_set_features(devlink, DEVLINK_F_RELOAD);
#endif				/* HAVE_DEVLINK_SET_FEATURES */
#ifdef HAVE_DEVLINK_REGISTER_SETS_DEV
	devlink_register(devlink, mce_pf_to_dev(pf));
#else
	devlink_register(devlink);
#endif

#ifdef HAVE_DEVLINK_RELOAD_ACTION_AND_LIMIT
#ifndef HAVE_DEVLINK_SET_FEATURES
#ifdef HAVE_DEVLINK_RELOAD_ENABLE_DISABLE
	devlink_reload_enable(devlink);
#endif				/* HAVE_DEVLINK_RELOAD_ENABLE_DISABLE */
#endif				/* !HAVE_DEVLINK_SET_FEATURES */
#endif				/* HAVE_DEVLINK_RELOAD_ACTION_AND_LIMIT */
}

/**
 * mce_devlink_unregister - Unregister devlink resources for this PF.
 * @pf: the PF structure to cleanup
 *
 * Releases resources used by devlink and cleans up associated memory.
 */
void mce_devlink_unregister(struct mce_pf *pf)
{
	struct devlink *devlink = priv_to_devlink(pf);

#ifdef HAVE_DEVLINK_RELOAD_ACTION_AND_LIMIT
#ifndef HAVE_DEVLINK_SET_FEATURES
#ifdef HAVE_DEVLINK_RELOAD_ENABLE_DISABLE
	devlink_reload_disable(devlink);
#endif				/* HAVE_DEVLINK_RELOAD_ENABLE_DISABLE */
#endif				/* !HAVE_DEVLINK_SET_FEATURES */
#endif				/* HAVE_DEVLINK_RELOAD_ACTION_AND_LIMIT */

	devlink_unregister(devlink);
}

#ifdef HAVE_DEVLINK_REGIONS
#ifdef HAVE_DEVLINK_REGION_OPS_SNAPSHOT
#define MCE_DEVLINK_READ_BLK_SIZE (1024 * 1024)

#ifdef HAVE_DEVLINK_REGION_OPS_SNAPSHOT_OPS

/**
 * mce_devlink_nvm_snapshot - Capture a snapshot of the NVM flash contents
 * @devlink: the devlink instance
 * @ops: the devlink region being snapshotted
 * @extack: extended ACK response structure
 * @data: on exit points to snapshot data buffer
 *
 * This function is called in response to the DEVLINK_CMD_REGION_TRIGGER for
 * the nvm-flash devlink region. It captures a snapshot of the full NVM flash
 * contents, including both banks of flash. This snapshot can later be viewed
 * via the devlink-region interface.
 *
 * It captures the flash using the FLASH_ONLY bit set when reading via
 * firmware, so it does not read the current Shadow RAM contents. For that,
 * use the shadow-ram region.
 *
 * @returns zero on success, and updates the data pointer. Returns a non-zero
 * error code on failure.
 */
#endif				/* HAVE_DEVLINK_REGION_OPS_SNAPSHOT_OPS */
static int mce_devlink_nvm_snapshot(struct devlink *devlink,
#ifdef HAVE_DEVLINK_REGION_OPS_SNAPSHOT_OPS
				      const struct devlink_region_ops
				      __always_unused * ops,
#endif				/* HAVE_DEVLINK_REGION_OPS_SNAPSHOT_OPS */
				      struct netlink_ext_ack *extack,
				      u8 ** data)
{
	u8 *nvm_data;
	u32 nvm_size, i = 0;
	nvm_size = 1024;
	nvm_data = vzalloc(nvm_size);
	if (!nvm_data)
		return -ENOMEM;

	for (i = 0; i < 1024; i++) {
		nvm_data[i] = i;
	}
	*data = nvm_data;

	return 0;
}

#ifdef HAVE_DEVLINK_REGION_OPS_SNAPSHOT_OPS
/**
 * mce_devlink_sram_snapshot - Capture a snapshot of the Shadow RAM contents
 * @devlink: the devlink instance
 * @ops: the devlink region being snapshotted
 * @extack: extended ACK response structure
 * @data: on exit points to snapshot data buffer
 *
 * This function is called in response to the DEVLINK_CMD_REGION_TRIGGER for
 * the shadow-ram devlink region. It captures a snapshot of the shadow ram
 * contents. This snapshot can later be viewed via the devlink-region
 * interface.
 *
 * @returns zero on success, and updates the data pointer. Returns a non-zero
 * error code on failure.
 */
#endif				/* HAVE_DEVLINK_REGION_OPS_SNAPSHOT_OPS */
static int mce_devlink_sram_snapshot(struct devlink *devlink,
#ifdef HAVE_DEVLINK_REGION_OPS_SNAPSHOT_OPS
				       const struct devlink_region_ops
				       __always_unused * ops,
#endif				/* HAVE_DEVLINK_REGION_OPS_SNAPSHOT_OPS */
				       struct netlink_ext_ack *extack,
				       u8 ** data)
{

	return 0;
}

#ifdef HAVE_DEVLINK_REGION_OPS_SNAPSHOT_OPS
/**
 * mce_devlink_devcaps_snapshot - Capture snapshot of device capabilities
 * @devlink: the devlink instance
 * @ops: the devlink region being snapshotted
 * @extack: extended ACK response structure
 * @data: on exit points to snapshot data buffer
 *
 * This function is called in response to the DEVLINK_CMD_REGION_TRIGGER for
 * the device-caps devlink region. It captures a snapshot of the device
 * capabilities reported by firmware.
 *
 * @returns zero on success, and updates the data pointer. Returns a non-zero
 * error code on failure.
 */
#endif				/* HAVE_DEVLINK_REGION_OPS_SNAPSHOT_OPS */
static int mce_devlink_devcaps_snapshot(struct devlink *devlink,
#ifdef HAVE_DEVLINK_REGION_OPS_SNAPSHOT_OPS
					  const struct devlink_region_ops
					  __always_unused * ops,
#endif				/* HAVE_DEVLINK_REGION_OPS_SNAPSHOT_OPS */
					  struct netlink_ext_ack *extack,
					  u8 ** data)
{
	return 0;
}
#endif				/* HAVE_DEVLINK_REGION_OPS_SNAPSHOT */

static const struct devlink_region_ops mce_nvm_region_ops = {
	.name = "nvm-flash",
	.destructor = vfree,
#ifdef HAVE_DEVLINK_REGION_OPS_SNAPSHOT
	.snapshot = mce_devlink_nvm_snapshot,
#endif
};

static const struct devlink_region_ops mce_sram_region_ops = {
	.name = "shadow-ram",
	.destructor = vfree,
#ifdef HAVE_DEVLINK_REGION_OPS_SNAPSHOT
	.snapshot = mce_devlink_sram_snapshot,
#endif
};

static const struct devlink_region_ops mce_devcaps_region_ops = {
	.name = "device-caps",
	.destructor = vfree,
#ifdef HAVE_DEVLINK_REGION_OPS_SNAPSHOT
	.snapshot = mce_devlink_devcaps_snapshot,
#endif
};

/**
 * mce_devlink_init_regions - Initialize devlink regions
 * @pf: the PF device structure
 *
 * Create devlink regions used to enable access to dump the contents of the
 * flash memory on the device.
 */
void mce_devlink_init_regions(struct mce_pf *pf)
{
	struct devlink *devlink = priv_to_devlink(pf);
	u64 nvm_size, sram_size;

	nvm_size = 1024;
	pf->nvm_region =
	    devlink_region_create(devlink, &mce_nvm_region_ops, 1, nvm_size);
	if (IS_ERR(pf->nvm_region)) {

		pf->nvm_region = NULL;
	}

	sram_size = pf->hw.flash.sr_words * 2u;
	pf->sram_region = devlink_region_create(devlink, &mce_sram_region_ops,
						1, sram_size);
	if (IS_ERR(pf->sram_region)) {

		pf->sram_region = NULL;
	}
#define MCE_AQ_MAX_BUF_LEN 4096

	pf->devcaps_region = devlink_region_create(devlink,
						   &mce_devcaps_region_ops,
						   10, MCE_AQ_MAX_BUF_LEN);
	if (IS_ERR(pf->devcaps_region)) {

		pf->devcaps_region = NULL;
	}
}

/**
 * mce_devlink_destroy_regions - Destroy devlink regions
 * @pf: the PF device structure
 *
 * Remove previously created regions for this PF.
 */
void mce_devlink_destroy_regions(struct mce_pf *pf)
{
	if (pf->nvm_region)
		devlink_region_destroy(pf->nvm_region);

	if (pf->sram_region)
		devlink_region_destroy(pf->sram_region);

	if (pf->devcaps_region)
		devlink_region_destroy(pf->devcaps_region);
}
#endif				/* HAVE_DEVLINK_REGIONS */
