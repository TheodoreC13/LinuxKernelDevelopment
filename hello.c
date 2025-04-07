#include <linux/module.h>
#include <linux/init.h>

static int __init my_init(void){
	printk("Hello Kernel!\n");
	return 0;
}
static void __exit my_exit(void){
	printk("Goodbye Kernel!\n");
}

module_init(my_init);
module_exit(my_exit);

MODULE_AUTHOR("Heapheaus");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("A basic linux kernel driver written for personal development");
