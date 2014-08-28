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

static struct nf_hook_ops nfho; //net filter hook option struct


unsigned int kddns_packet_hook(unsigned int hooknum,
						struct sk_buff *skb,
						const struct net_device *in,
						const struct net_device *out,
						int (*okfn)(struct sk_buff *))
	{
	struct sock *sk = skb->sk;
	printk("Hello packet!");
	return NF_ACCEPT;
}

static int init_filter_if(void)
{
	nfho.hook = kddns_packet_hook;
	nfho.hooknum = 0 ; //NF_IP_PRE_ROUTING;
	nfho.pf = PF_INET;
	nfho.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&nfho);
	return 0;
}

static int __init kddns_init(void)
{
	printk(KERN_INFO "Starting kddns module\n");
	init_filter_if();
	return 0; // Non-zero return means that the module couldn't be loaded.
}

static void __exit kddns_exit(void)
{
	nf_unregister_hook(&nfho);
	printk(KERN_INFO "Stoping kddns module\n");
}

module_init(kddns_init);
module_exit(kddns_exit);


MODULE_AUTHOR("Millken <millken@gmail.com>");
MODULE_DESCRIPTION("anti-ddos DNS query");
MODULE_LICENSE("GPL");
