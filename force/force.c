/*
cat /proc/kallsyms |grep kddns
ffffffffa0023240 d __this_module	[kddns]

*/
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>


int __init rm_init(void)   
{   
        complete((struct completion *)0xffffffffa0023240);   
        return 0;   
}   
void __exit rm_exit(void)   
{   
}   
module_init(rm_init);   
module_exit(rm_exit);   
MODULE_LICENSE("GPL");  
