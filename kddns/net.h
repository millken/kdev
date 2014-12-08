#ifndef NET_H
#define	NET_H

int net_init(void);
int net_exit(void);
void net_server(struct sk_buff*);

#endif