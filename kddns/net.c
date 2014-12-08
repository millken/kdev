#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>

#include "net.h"

#define NETLINK_CHANNEL 31

struct sock *netlink_socket = NULL;


int net_init(void)
{
	//struct netlink_kernel_cfg netlink_config = {
	//	.input = net_server,
	//};
	//create Netlink Socket So We Can receive updates from Go Lang :D
	netlink_socket = netlink_kernel_create(&init_net, NETLINK_CHANNEL, 0, net_server, 0, THIS_MODULE);
	if(!netlink_socket)
	{
		printk(KERN_INFO "Error creating Netlink Socket.\n");
		return 591;
	}
	return 0;
}

int net_exit(void)
{
	netlink_kernel_release(netlink_socket);
	return 0;
}

void net_server(struct sk_buff *netfilter_socket_buffer)
{
    struct nlmsghdr *netlink_header;
    int senders_pid;
    int res;
    char *message;
    
    struct sk_buff *response;
    
    netlink_header = (struct nlmsghdr*)netfilter_socket_buffer->data;
    senders_pid = netlink_header->nlmsg_pid; /*pid of sending process */
    
    message = kmalloc(strlen((char*)nlmsg_data(netlink_header)) + 1,GFP_KERNEL);
        
    strncpy(message,(char*)nlmsg_data(netlink_header),strlen((char*)nlmsg_data(netlink_header)));
    message[strlen((char*)nlmsg_data(netlink_header))] = '\0';
    
    printk(KERN_INFO "Echoing: %s\n", message);
       
    response = nlmsg_new(strlen(message),GFP_KERNEL);
    netlink_header = nlmsg_put(response,0,0,NLMSG_DONE,strlen(message),0);
    NETLINK_CB(response).dst_group = 0; /* not in mcast group */
    strncpy(nlmsg_data(netlink_header),message,strlen(message));
    
    
    res=nlmsg_unicast(netlink_socket, response, senders_pid);
    if(res < 0) {
        printk(KERN_ERR "Error while Sending ECHO.\n");
    }
    
    kfree(message);
}