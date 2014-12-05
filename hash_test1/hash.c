//http://blog.chinaunix.net/uid-27878639-id-3370734.html
#include <linux/types.h>

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include "hash.h"
static int __init lkp_init(void)
{
        int i;
        int addr;
        struct hash_term *p;
        struct hash_term *tpos;
        struct hlist_node *pos;

        for(i=0; i<NR_HASH; i++)
        {
                INIT_HLIST_HEAD( &hash[i] ); /*初始化哈希表*/
        }

        for(i=0; i<NR_KEYS; i++)
        {
                addr = hashfn(keys[i]); /*由哈希函数获得地址*/

                p = (struct hash_term *)kmalloc(sizeof(struct hash_term), GFP_KERNEL); /*动态申请内核内存*/
                p->key = keys[i];
                hlist_add_head(&p->list, &hash[addr]); /*头插法存放关键字节点*/
        }
        
        for(i=0; i<NR_HASH; i++) /*输出哈希表*/
        {
                printk("print hash table:\n");
                printk("%d\t",i);
                hlist_for_each_entry(tpos, pos, &hash[i], list){
                        printk("%d\t",tpos->key);
                }
                printk("^\n");
}

        return 0;
}

static void __exit lkp_cleanup(void)
{
        struct hlist_node *pos;
        struct hlist_node *n;
        int i;

        printk("destroy hash table...."); /*释放内存*/
        for(i=0; i<NR_HASH; i++)
        {
                hlist_for_each_safe(pos, n, &hash[i]){
                        kfree(pos);
                }
        }
}
module_init(lkp_init);
module_exit(lkp_cleanup);
MODULE_LICENSE("GPL");
