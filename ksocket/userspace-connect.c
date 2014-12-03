//http://blog.chinaunix.net/uid-20662820-id-3787086.html

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#define MAXLINE 100
struct thread_info {
    unsigned long long packet;
    unsigned long long bytes;
};
void err_quit(char * fmt,...)
{
    char buf[MAXLINE+1];
    va_list ap;
    va_start(ap,fmt);
    vsnprintf(buf,sizeof(buf),fmt,ap);
    va_end(ap);
    fputs(buf,stdout);
    fputs("\n",stdout);
    exit(1);
}
void dg_cli(int sockfd,const struct sockaddr *servaddr,socklen_t serlen)
{
    int n;
    int pret;
    pthread_t id;
    struct thread_info info;
    char sendline[MAXLINE],recvline[MAXLINE];
    info.packet=0;
    info.bytes=0;
    bzero(sendline,MAXLINE);
    strcpy(sendline,"TEST BOY\n");
restart:
    connect(sockfd, servaddr, serlen);
    while(1) {
        sleep(10);
    }
    while(1){
        pret = send(sockfd,sendline,strlen(sendline),0);
        if(pret < 0){
            //printf("errno=%d, errstr=%s\n", errno, strerror(errno));
            if(errno == 111){
                printf("I received udp port unreachable packet\n");
                sleep(1);
                goto restart;
            }
        }else{
            printf("OK\n");
        }
        sleep(1);
    }
}
int main(int argc,char **argv)
{
    int sockfd;
    struct sockaddr_in servaddr;
    if(argc!=3)
        err_quit("usage:client <IP address> <UDP port>");
    bzero(&servaddr,sizeof(servaddr));;
    servaddr.sin_family=AF_INET;
    servaddr.sin_port=htons(atoi(argv[2]));
    inet_pton(AF_INET,argv[1],&servaddr.sin_addr);
    if((sockfd=socket(AF_INET,SOCK_DGRAM,0))<0)
        err_quit("socket error");
    dg_cli(sockfd,(struct sockaddr*)&servaddr,sizeof(servaddr));
    exit(0);
}


