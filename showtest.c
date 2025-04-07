#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/delay.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("TheodoreC");
MODULE_DESCRIPTION("Test");
MODULE_VERSION("0.01");

static struct list_head *prev_module;
static short hidden = 0;

void showme(void){
	list_add(&THIS_MODULE->list, prev_module);
	hidden = 0;
}
void hideme(void){
	prev_module = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
	hidden = 1;
}
static int __init myinit(void){
	printk(KERN_INFO "Hiding breadboard\n");
	hideme();
	printk(KERN_INFO "Sleeping\n");
	ssleep(10);
	printk(KERN_INFO "Showing\n");
	showme();
	return 0;
}
static void __exit myexit(void){
	printk(KERN_INFO "Unloading\n");
}

module_init(myinit);
module_exit(myexit);
