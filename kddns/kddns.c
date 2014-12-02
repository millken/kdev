#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/list.h>
#include <linux/kthread.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <net/ip.h>

/*
 * http://www.roman10.net/how-to-filter-network-packets-using-netfilterpart-2-implement-the-hook-function/
 */

#define KDDNS_PERIOD_MAX 1000
#define DNS_HEADER_SIZE 12

static struct nf_hook_ops nfho; //net filter hook option struct

struct dns_stats {
	atomic_t count;
	atomic64_t data_used;
};

struct query_stats {
	char topdomain[70]; //http://www.baike.com/wiki/%E5%9B%BD%E9%99%85%E5%9F%9F%E5%90%8D
	atomic_t count;
	struct list_head list;
};

static struct query_stats qs_list;

static struct task_struct *counter_thread;
struct kmem_cache *packet_node_cache;
struct dns_stats *stats; 
static int threshold = 1000;
static int period = 1000;
static bool forward;

#ifdef CONFIG_SYSFS
static ssize_t kddns_threshold_show(struct kobject *kobj,
				    struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%u\n", threshold);
}

static ssize_t kddns_period_show(struct kobject *kobj,
				 struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%u\n", period);
}

static ssize_t kddns_threshold_store(struct kobject *kobj,
				     struct kobj_attribute *attr,
				     const char *buf, size_t count)
{
	int err;
	unsigned long tmp;

	err = kstrtoul(buf, 10, &tmp);
	if (err || !tmp)
		return -EINVAL;

	threshold = tmp;

	return count;
}

static ssize_t kddns_period_store(struct kobject *kobj,
				  struct kobj_attribute *attr,
				  const char *buf, size_t count)
{
	int err;
	unsigned long tmp;

	err = kstrtoul(buf, 10, &tmp);
	if (err || !tmp || tmp > KDDNS_PERIOD_MAX)
		return -EINVAL;

	period = tmp;

	return count;
}


static struct kobj_attribute kddns_threshold_attr =
__ATTR(threshold, 0644, kddns_threshold_show,
       kddns_threshold_store);

static struct kobj_attribute kddns_period_attr =
__ATTR(period, 0644, kddns_period_show,
       kddns_period_store);

static struct attribute *kddns_attrs[] = {
	&kddns_threshold_attr.attr,
	&kddns_period_attr.attr,
	NULL,
};

static struct attribute_group kddns_attr_group = {
	.attrs = kddns_attrs,
	.name = "kddns",
};

#endif
/*  
 *  DNS HEADER:
 *
 *  0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                        ID                     |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |QR|   Opcode  |AA|TC|RD|RA|    Z   |   RCODE   |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                     QDCOUNT                   |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                     ANCOUNT                   |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                     NSCOUNT                   |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                     ARCOUNT                   |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */

static void send_tc_packet(struct sk_buff *in_skb, uint dst_ip,
				 uint dst_port, uint src_ip,
				 const unsigned char *data)
{
	unsigned char *ndata;
	struct sk_buff *nskb;
	struct iphdr *iph;
	struct udphdr *udph;
	int udp_len;

	udp_len = sizeof(struct udphdr) + DNS_HEADER_SIZE;
	nskb = alloc_skb(sizeof(struct iphdr) + udp_len +
			 LL_MAX_HEADER, GFP_ATOMIC);
	if (!nskb) {
		printk(KERN_ERR
		       "kddns: Error, can`t allocate memory to DNS reply\n");
		return;
	}
	skb_reserve(nskb, LL_MAX_HEADER);
	skb_reset_network_header(nskb);

	iph = (struct iphdr *)skb_put(nskb, sizeof(struct iphdr));
	iph->version = 4;
	iph->ihl = sizeof(struct iphdr) / 4;
	iph->ttl = 64;
	iph->tos = 0;
	iph->id = 0;
	iph->frag_off = htons(IP_DF);
	iph->protocol = IPPROTO_UDP;
	iph->saddr = src_ip;
	iph->daddr = dst_ip;
	iph->tot_len = htons(sizeof(struct iphdr) + udp_len);
	iph->check = 0;
	iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);

	udph = (struct udphdr *)skb_put(nskb, sizeof(struct udphdr));
	memset(udph, 0, sizeof(*udph));
	udph->source = htons(53);
	udph->dest = dst_port;
	udph->len = htons(udp_len);
	skb_dst_set(nskb, dst_clone(skb_dst(in_skb)));
	nskb->protocol = htons(ETH_P_IP);
	ndata = (char *)skb_put(nskb, DNS_HEADER_SIZE);
	memcpy(ndata, data, DNS_HEADER_SIZE);	//copy header from query
	*(ndata + 2) |= 0x82;	//set responce and tc bits
	*(u16 *) (ndata + 4) = 0;	//set questions = 0 to prevent warning on client side
	udph->check = 0;
	udph->check = csum_tcpudp_magic(src_ip, dst_ip,
					udp_len, IPPROTO_UDP,
					csum_partial(udph, udp_len, 0));
	if (ip_route_me_harder(nskb, RTN_UNSPEC))
		goto free_nskb;
	ip_local_out(nskb);
	return;

free_nskb:
	printk(KERN_ERR "Not good\n");
	kfree_skb(nskb);
}

static int check_dns_header(unsigned char *data, uint len)
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
	char domain[70];
	int i,j, query;
	unsigned int p=0;
	unsigned int is_find = 0;
	
   struct list_head *ch;

   struct query_stats *qs, *newQS;	
   
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
				query = check_dns_header(data, datalen);
				if (query < 0) return NF_DROP;
				atomic_inc(&(temp->count));
				if (forward) {
					send_tc_packet(skb, ip->saddr,
							     udp->source,
							     ip->daddr, data);
					return NF_DROP;				
				}
				//http://elinux.org/Debugging_by_printing
				print_hex_dump_bytes("", DUMP_PREFIX_NONE, data, datalen);
				memcpy(domain, data + 12, datalen - 14);
				//http://www.binarytides.com/dns-query-code-in-c-with-linux-sockets/
				for(i=0;i<(int)strlen((const char*)domain);i++) 
					{
						p=domain[i];
						for(j=0;j<(int)p;j++) 
						{
							domain[i]=domain[i+1];
							i=i+1;
						}
						domain[i]='.';
					}
					domain[i-1]='\0'; //remove the last dot
i = 0;
is_find = 0;
list_for_each(ch, &qs_list.list) {
	i++;
	qs = list_entry(ch, struct query_stats, list);
	printk(KERN_INFO "domain %d: qs->topdomain = %s; qs->count = %d;\n", i, qs->topdomain, atomic_read(&(qs->count)) ); 
	if(strcmp(domain, qs->topdomain) == 0) {
		is_find = 1;
	 	atomic_inc(&(qs->count));
	}

}
if (is_find == 0) {
		newQS = kmalloc(sizeof(*newQS), GFP_ATOMIC);
		strcpy(newQS->topdomain, domain);
		atomic_set(&(newQS->count), 1);
    	INIT_LIST_HEAD(&(newQS->list));
    	list_add_tail(&(newQS->list), &(qs_list.list));
    	printk(KERN_INFO "Insert Domain : newQS->topdomain = %s; newQS->count = %d;\n", newQS->topdomain, atomic_read(&(newQS->count)) ); 		

}
				
				printk(KERN_INFO "forward= %d, query = %d, ip->saddr=%pI4(%d), num=%d, domain=‘%s’\n", forward, query, &ip->saddr, ip->saddr, atomic_read(&(temp->count)), domain);
			}
		}
	}
	return NF_ACCEPT;
}


static int init_filter_if(void)
{
	nfho.hook = kddns_packet_hook;
	nfho.owner = THIS_MODULE;
	nfho.hooknum = NF_INET_LOCAL_IN ; //NF_IP_PRE_ROUTING;
	nfho.pf = PF_INET;
	nfho.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&nfho);
	return 0;
}

static int counter_fn(void *data)
{
	int qps = 0;
	for (;;) {
		msleep(period);
		if (kthread_should_stop())
			break;
		qps = atomic_read(&(stats->count));
		forward = qps > threshold ? true : false;
		pr_info("qps=%d, forward=%d\n", qps, forward);
		atomic_set(&(stats->count), 0);
	}
	return 0;
}

static int __init kddns_init(void)
{
	int err;
	printk(KERN_INFO "Starting kddns module\n");
	if (period <= 0 || period > KDDNS_PERIOD_MAX) {
		printk(KERN_INFO
		       "kddns: period should be in range 1 ... %u, forcing default value 1000 \n",
		       KDDNS_PERIOD_MAX);
		period = 1000;
	}
	if (threshold <= 0) {
		printk(KERN_INFO
		       "kddns: threshold should be >0, forcing default value 1000 \n");
		threshold = 1000;	
	}
	
#ifdef CONFIG_SYSFS
	if ((err = sysfs_create_group(kernel_kobj, &kddns_attr_group)))
		goto out_err;
#endif

	INIT_LIST_HEAD(&(qs_list.list));
		
	packet_node_cache = kmem_cache_create("kmem_packet_cache", sizeof(struct
		dns_stats), 0, SLAB_HWCACHE_ALIGN, NULL);
	pr_info("%pS\n", __builtin_return_address(1));	
	stats = (struct dns_stats *)kmem_cache_alloc(packet_node_cache, GFP_KERNEL);
	atomic_set(&(stats->count), 0);
	atomic64_set(&(stats->data_used), 0);
	forward = false;

	counter_thread = kthread_run(counter_fn, NULL, "counter_thread");
	if (IS_ERR(counter_thread)) {
		printk(KERN_ERR "kddns: creating thread failed, err: %li \n",
		PTR_ERR(counter_thread));
		goto out_err_free3;
	}
			
	init_filter_if();
	return 0; // Non-zero return means that the module couldn't be loaded.
out_err_free3:
#ifdef CONFIG_SYSFS
	sysfs_remove_group(kernel_kobj, &kddns_attr_group);
#endif
out_err:
	return -ENOMEM;
		
}

static void __exit kddns_exit(void)
{
	kthread_stop(counter_thread);
	nf_unregister_hook(&nfho);
#ifdef CONFIG_SYSFS
	sysfs_remove_group(kernel_kobj, &kddns_attr_group);
#endif
	kmem_cache_free(packet_node_cache, stats);
	kmem_cache_destroy(packet_node_cache);
	printk(KERN_INFO "Stoping kddns module\n");
}

module_init(kddns_init);
module_exit(kddns_exit);

module_param(threshold, int, 0);
MODULE_PARM_DESC(threshold,
		 "Number of reuests from one IP passed to dns per one period");
module_param(period, int, 0);
MODULE_PARM_DESC(period, "Time between counting collected stats, ms");

MODULE_AUTHOR("Millken <millken@gmail.com>");
MODULE_DESCRIPTION("anti-ddos DNS query");
MODULE_LICENSE("GPL");
