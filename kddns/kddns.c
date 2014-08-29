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

#define DNS_HEADER_SIZE 12

static struct nf_hook_ops nfho; //net filter hook option struct

struct dns_stats {
	atomic_t count;
	atomic64_t data_used;
};

static struct task_struct *counter_thread;
struct kmem_cache *packet_node_cache;
struct dns_stats *stats; 
static bool forward;
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
				query = check_dns_header(data, datalen);
				if (query < 0) return NF_DROP;
				atomic_inc(&(temp->count));
				if (forward) {
					send_tc_packet(skb, ip->saddr,
							     udp->source,
							     ip->daddr, data);
					return NF_DROP;				
				}
				//printk(KERN_INFO "forward= %d, query = %d, ip->saddr=%pI4(%d), num=%d\n", forward, query, &ip->saddr, ip->saddr, atomic_read(&(temp->count)));
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
		msleep(1000);
		if (kthread_should_stop())
			break;
		qps = atomic_read(&(stats->count));
		forward = qps > 1000 ? true : false;
		pr_info("qps=%d, forward=%d\n", qps, forward);
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
	forward = false;

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
