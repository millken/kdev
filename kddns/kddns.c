#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <net/ip.h>

#define KFDNS_PERIOD_MAX 1000
#define KFDNS_PROCFS_STAT "kfdns"
#define DNS_HEADER_SIZE 12

static int kddns_init(void)
{
	printk(KERN_INFO "Starting kddns module\n");
	return 0;
}

static void kddns_exit(void)
{
	printk(KERN_INFO "Stoping kddns module\n");
}

module_init(kddns_init);
module_exit(kddns_exit);


MODULE_AUTHOR("Millken <millken@gmail.com>");
MODULE_DESCRIPTION("anti-ddos DNS query");
MODULE_LICENSE("GPL");
