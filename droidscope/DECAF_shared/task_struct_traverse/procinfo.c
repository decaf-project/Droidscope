

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/security.h>
#include <linux/kprobes.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/dcache.h>

// UTS_RELEASE may be defined in different files for different release versions
//#include <generated/utsrelease.h>

#define OFFSET_OF(type, field) (  (unsigned long)&( ((struct type *)0)->field ) )

static int linuxdrv_init(void)
{

    printk("starting module\n");
    printk("pid\ttask_name\tstate\n");

    struct task_struct *task;
    struct list_head *list;


    printk("%10d%20s%10li\n",init_task.pid,init_task.comm,init_task.state);


    list_for_each(list,&(init_task.children)){
        task=list_entry(list,struct task_struct,sibling);
        printk("%10d%20s%10li\n",task->pid,task->comm,task->state);
    }

    return -1;
}

static void linuxdrv_exit(void)
{
    printk(KERN_INFO "linuxdrv: module removed.\n");
}

module_init(linuxdrv_init);
module_exit(linuxdrv_exit);

MODULE_DESCRIPTION("Provide task information to temu.");
MODULE_LICENSE("GPL");

