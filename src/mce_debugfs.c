#include <linux/fs.h>
#include <linux/debugfs.h>
#include "mce.h"

static struct dentry *mce_debugfs_root;

static void debugfs_command_help(struct device *dev, char *cmd_buf)
{
	dev_info(dev, "unknown or invalid command '%s'\n", cmd_buf);
	dev_info(dev, "available commands\n");
	dev_info(dev, "\t dump all\n");
	dev_info(dev, "\t dump ring\n");
	dev_info(dev, "\t dump dma\n");
	dev_info(dev, "\t dump mux\n");
	dev_info(dev, "\t dump parser\n");
	dev_info(dev, "\t dump fwd_proc\n");
	dev_info(dev, "\t dump editor\n");
	dev_info(dev, "\t dump fwd_attr\n");
	dev_info(dev, "\t dump oop\n");
	dev_info(dev, "\t dump tc\n");
	dev_info(dev, "\t dump hwpfc\n");
}

/**
 * mce_debugfs_command_write - write into command datum
 * @filp: the opened file
 * @buf: where to find the user's data
 * @count: the length of the user's data
 * @ppos: file position offset
 */
static ssize_t
mce_debugfs_command_write(struct file *filp, const char __user *buf,
			    size_t count, loff_t *ppos)
{
	struct mce_pf *pf = filp->private_data;
	struct device *dev = mce_pf_to_dev(pf);
	struct mce_hw *hw = &(pf->hw);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;

	/* don't allow partial writes */
	if (*ppos != 0)
		return 0;

	cmd_buf = memdup_user(buf, count + 1);
	if (IS_ERR(cmd_buf))
		return PTR_ERR(cmd_buf);
	cmd_buf[count] = '\0';

	cmd_buf_tmp = strchr(cmd_buf, '\n');
	if (cmd_buf_tmp) {
		*cmd_buf_tmp = '\0';
		count = (size_t)cmd_buf_tmp - (size_t)cmd_buf + 1;
	}

	argv = argv_split(GFP_KERNEL, cmd_buf, &argc);
	if (!argv) {
		ret = -ENOMEM;
		goto err_copy_from_user;
	}

	if (argc == 2 && !strncmp(argv[0], "dump", 4)) {
		ret = hw->ops->dump_debug_regs(hw, argv[1]);
		if (ret) {
			debugfs_command_help(dev, cmd_buf);
			ret = -EINVAL;
			goto command_write_error;
		}
	} else {
		debugfs_command_help(dev, cmd_buf);
		ret = -EINVAL;
		goto command_write_error;
	}

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_error:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);

	/* This function always consumes all of the written input, or produces
	 * an error. Check and enforce this. Otherwise, the write operation
	 * won't complete properly.
	 */
	if (WARN_ON(ret != (ssize_t)count && ret >= 0))
		ret = -EIO;

	return ret;
}

static const struct file_operations mce_debugfs_command_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = mce_debugfs_command_write,
};

/**
 * mce_debugfs_pf_init - setup the debugfs directory
 * @pf: the ice that is starting up
 */
void mce_debugfs_pf_init(struct mce_pf *pf)
{
	const char *name = pci_name(pf->pdev);

	pf->mce_debugfs_hw = debugfs_create_dir(name, mce_debugfs_root);
	if (IS_ERR(pf->mce_debugfs_hw))
		return;

	if (!debugfs_create_file("command", 0600, pf->mce_debugfs_hw,
			pf, &mce_debugfs_command_fops)){
		dev_err(mce_pf_to_dev(pf),
			"debugfs dir/file for %s failed\n", name);
		debugfs_remove_recursive(pf->mce_debugfs_hw);
	}
}

/**
 * mce_debugfs_pf_exit - clear out the ices debugfs entries
 * @pf: the ice that is stopping
 */
void mce_debugfs_pf_exit(struct mce_pf *pf)
{
	debugfs_remove_recursive(pf->mce_debugfs_hw);
	pf->mce_debugfs_hw = NULL;
}

/**
 * mce_debugfs_init - create root directory for debugfs entries
 */
void mce_debugfs_init(void)
{
	mce_debugfs_root = debugfs_create_dir(KBUILD_MODNAME, NULL);
	if (IS_ERR(mce_debugfs_root))
		pr_info("init of debugfs failed\n");
}

/**
 * mce_debugfs_exit - remove debugfs entries
 */
void mce_debugfs_exit(void)
{
	debugfs_remove_recursive(mce_debugfs_root);
	mce_debugfs_root = NULL;
}
