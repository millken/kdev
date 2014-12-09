#ifndef MAIN_H
#define MAIN_H

#define NETLINK_CHANNEL 24
#define MAX_MSGSIZE 1024

#define KDDNS_PERIOD_MAX 1000
#define DNS_HEADER_SIZE 12

struct dns_stats {
	atomic_t count;
	atomic64_t data_used;
};
struct item_t /*哈希表项*/
{
        char key[70];
        struct hlist_node list;
};
struct query_stats {
	char topdomain[70]; //http://www.baike.com/wiki/%E5%9B%BD%E9%99%85%E5%9F%9F%E5%90%8D
	atomic_t count;
	struct list_head list;
};

static struct query_stats qs_list;
struct sock *netlink_socket = NULL;

struct nl_msg {
    int op;
};

#endif
