/*
 * @Author: Gitai<i@gitai.me>
 * @Date: 2020-06-05 15:00:08
 * @LastEditors: Gitai
 * @LastEditTime: 2020-06-08 12:23:08
 * @FilePath: /stacktest/main.c
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/binfmts.h>
#include <linux/proc_fs.h>
#include <linux/lru_cache.h>
#include <crypto/public_key.h>
#include <linux/types.h>
#include <linux/cred.h>
#include <crypto/hash.h>
#include <crypto/sha.h>
#include <crypto/algapi.h>
#include <asm/ptrace.h>

MODULE_LICENSE("GPL");

int testcount = 0;

//typedef void (*sys_call_ptr_t)(void);
//sys_call_ptr_t *_sys_call_table = NULL;
unsigned long sys_call_table_addr = 0;
typedef asmlinkage long (*orig_execve)(const char __user *filename, const char __user *const __user *argv, const char __user *const __user *envp);
orig_execve SyS_execve = NULL;

// hooked mkdir function
asmlinkage long hooked_execve(const char __user *filename, const char __user *const __user *argv, const char __user *const __user *envp)
{
	long ret = -1;
	size_t exec_line_size;
	char *exec_str = NULL;
	char **p_argv = (char **)argv;
	static char *msg = "hooked sys_execve(): ";
	exec_line_size = (strlen(filename) + 1);

	/* Iterate through the execution arguments, to determine the final
	size of the execution string. */
	while (NULL != *p_argv)
	{
		exec_line_size += (strlen(*p_argv) + 1);
		(char **)p_argv++;
	}

	/* Allocate enough memory for the execution string */
	exec_str = vmalloc(exec_line_size);
	if (NULL != exec_str)
	{
		snprintf(exec_str, exec_line_size, "%s", filename);

		/* Iterate through the execution arguments */
		p_argv = (char **)argv;
		while (NULL != *p_argv)
		{
			/* Concatenate each argument with our execution line */
			snprintf(exec_str, exec_line_size,
					 "%s %s", exec_str, *p_argv);
			(char **)p_argv++;
		}

		/* Send execution line to the user app */
		//COMM_nl_send_exec_msg(exec_str);
		printk("%s,%s\n", msg, exec_str);
	}
	// printk("%s%s---%s:%s\n", msg, filename, argv[0], envp[0]);
	
	// ???
	ret = SyS_execve(filename, argv, envp);
	if (ret == -ENOEXEC)
		return -EACCES;
	return ret;
}

/*******************************************************************
* Name: 	obtain_sys_call_table_addr
* Description:	Obtains the address of the `sys_call_table` in the
*		system.
*******************************************************************/
static int obtain_sys_call_table_addr(unsigned long *sys_call_table_addr)
{
	int ret = 1;
	unsigned long temp_sys_call_table_addr;

	temp_sys_call_table_addr = kallsyms_lookup_name("sys_call_table");

	/* Return error if the symbol doesn't exist */
	if (0 == sys_call_table_addr)
	{
		ret = -1;
		goto cleanup;
	}

	printk("Found sys_call_table: %p", (void *)temp_sys_call_table_addr);
	*sys_call_table_addr = temp_sys_call_table_addr;

cleanup:
	return ret;
}

// memory protection shinanigans
unsigned int level;
pte_t *pte;

static int hooked_execve_init(void)
{
	int ret = -1;
	printk("+ Loading hook_mkdir module\n");
	ret = obtain_sys_call_table_addr(&sys_call_table_addr);
	if (ret != 1)
	{
		printk("- unable to locate sys_call_table\n");
		return 0;
	}

	// print out sys_call_table address
	printk("+ found sys_call_table at %08lx!\n", sys_call_table_addr);

	// now we can hook syscalls ...such as uname
	// first, save the old gate (fptr)
	SyS_execve = ((unsigned long *)(sys_call_table_addr))[__NR_execve];

	// unprotect sys_call_table memory page
	pte = lookup_address((unsigned long)sys_call_table_addr, &level);

	// change PTE to allow writing
	set_pte_atomic(pte, pte_mkwrite(*pte));

	printk("+ unprotected kernel memory page containing sys_call_table\n");

	// now overwrite the __NR_uname entry with address to our uname
	((unsigned long *)(sys_call_table_addr))[__NR_execve] = (unsigned long)hooked_execve;

	printk("+ sys_execve hooked!\n");

	return 0;
}

static void hooked_execve_exit(void)
{
	if (SyS_execve != NULL)
	{
		// restore sys_call_table to original state
		((unsigned long *)(sys_call_table_addr))[__NR_execve] = (unsigned long)SyS_execve;

		// reprotect page
		set_pte_atomic(pte, pte_clear_flags(*pte, _PAGE_RW));
	}

	printk("+ Unloading hook_execve module\n");
}

static int entry_handler(struct kprobe *ri, struct pt_regs *regs)
{
	printk("kprobe entry_handler\n");
	testcount++;
	if (testcount < 3)
	{
		struct linux_binprm *bprm = (struct linux_binprm *)regs->di;
		bprm->buf[3] = 0;
		struct elfhdr elf_ex = *((struct elfhdr *)bprm->buf);
		printk("kprobe elf_ex.e_ident before changed %d\n", memcmp(elf_ex.e_ident, ELFMAG, SELFMAG));
	}
	return 0;

}

static struct kprobe kp = {
	.pre_handler = entry_handler,
	// .post_handler = return_handler,
	.symbol_name = "load_elf_binary"
};

static int kprobe_init(void)
{
	int ret;

	ret = register_kprobe(&kp);
	if (ret < 0)
	{
		pr_err("register_kretprobe returned %d\n", ret);
		return ret;
	}
	printk(KERN_INFO "kprobe at registered\n");
	return 0;
}

static void kprobe_exit(void)
{
	unregister_kprobe(&kp);
	printk(KERN_INFO "kprobe at unregistered\n");
}


static int __init mod_init(void)
{
	hooked_execve_init();
	kprobe_init();
}

static void __exit mod_exit(void)
{
	kprobe_exit();
	hooked_execve_exit();
}

module_init(mod_init);
module_exit(mod_exit);

MODULE_AUTHOR("Gitai");
MODULE_DESCRIPTION("ELF!\n");