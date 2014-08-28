#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/kthread.h>
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

struct dns_stats {
	atomic_t count;
	atomic64_t data_used;
};

static struct task_struct *counter_thread;
struct kmem_cache *packet_node_cache;
struct dns_stats *stats; 

static int kfdns_check_dns_header(unsigned char *data, uint len)
{
	if (len < DNS_HEADER_SIZE)
		return -1;
	if (*(data + sizeof(u16)) & 0x80)
		return 0;	/* response */
	return 1;		/* request */
}

unsigned int kddns_packet_hook(unsigned int hooknum,
						struct sk_buff *skb,
						const struct net_device *in,
						const struct net_device *out,
						int (*okfn)(struct sk_buff *))
{
	struct dns_stats *temp = stats;
	struct iphdr *ip;
	struct udphdr *udp;
	unsigned char *data;
	unsigned int datalen;
	int query;
	if (skb->protocol == htons(ETH_P_IP)) {
		ip = (struct iphdr *)skb_network_header(skb);
		if (ip->version == 4 && ip->protocol == IPPROTO_UDP) {
			skb_set_transport_header(skb, ip->ihl * 4);
			udp = (struct udphdr *)skb_transport_header(skb);
			if (udp->dest == htons(53)) {
				datalen =
				    skb->len - sizeof(struct iphdr) -
				    sizeof(struct udphdr);
				data =
				    skb->data + sizeof(struct udphdr) +
				    sizeof(struct iphdr);
				/* Drop packet if it hasn`t got
				 * valid dns query header */
				query = kfdns_check_dns_header(data, datalen);
				if (query < 0) return NF_DROP;
				atomic_inc(&(temp->count));
				printk(KERN_INFO "query = %d, ip->saddr=%pI4(%d), num=%d\n", query, &ip->saddr, ip->saddr, atomic_read(&(temp->count)));
			}
		}
	}
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

static int counter_fn(void *data)
{
	for (;;) {
		msleep(1000);
		atomic_set(&(stats->count), 0);
	}
	return 0;
}

static int __init kddns_init(void)
{
	printk(KERN_INFO "Starting kddns module\n");
	packet_node_cache = kmem_cache_create("kmem_packet_cache", sizeof(struct
	dns_stats), 0, SLAB_HWCACHE_ALIGN, NULL);
	pr_info("%pS\n", __builtin_return_address(1));	
	stats = (struct dns_stats *)kmem_cache_alloc(packet_node_cache, GFP_KERNEL);
	atomic_set(&(stats->count), 0);
	atomic64_set(&(stats->data_used), 0);

	counter_thread = kthread_run(counter_fn, NULL, "counter_thread");
	if (IS_ERR(counter_thread)) {
		printk(KERN_ERR "kddns: creating thread failed, err: %li \n",
		       PTR_ERR(counter_thread));
		return -ENOMEM;
	}
			
	init_filter_if();
	return 0; // Non-zero return means that the module couldn't be loaded.
}

static void __exit kddns_exit(void)
{
	kthread_stop(counter_thread);
	nf_unregister_hook(&nfho);

	kmem_cache_free(packet_node_cache, stats);
	kmem_cache_destroy(packet_node_cache);
	printk(KERN_INFO "Stoping kddns module\n");
}

module_init(kddns_init);
module_exit(kddns_exit);


MODULE_AUTHOR("Millken <millken@gmail.com>");
MODULE_DESCRIPTION("anti-ddos DNS query");
MODULE_LICENSE("GPL");
