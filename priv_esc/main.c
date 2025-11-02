#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/namei.h>
#include <linux/version.h>

// Module Init function - executed on module load (insmod)
static int __init load(void)
{
	int ret = 0;

	pr_info("rootkits are cool!\n");

	return ret;
}

// Module Exit function - executed on module unload (rmmod)
static void __exit unload(void)
{
	pr_info("Goodbye cruel world ;(\n");
}

module_init(load);
module_exit(unload);

// Licensing and other required shenanigans
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Oreomeister");
MODULE_DESCRIPTION("Totally not sus");
MODULE_VERSION("1.0");