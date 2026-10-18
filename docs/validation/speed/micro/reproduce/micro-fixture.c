#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
static volatile sig_atomic_t running = 1;
static void stop(int sig) { (void)sig; running = 0; }
static void fail(const char *s) { perror(s); exit(1); }
static uint16_t checksum(const unsigned char *b, size_t n) {
    unsigned sum=0;
    for(size_t i=0;i<n;i+=2) sum += ((unsigned)b[i]<<8) | (i+1<n?b[i+1]:0);
    while(sum>>16)sum=(sum&65535)+(sum>>16);
    return (uint16_t)~sum;
}
static void mixed_reply(int fd, struct sockaddr_ll *a, const unsigned char *packet, size_t length) {
    if(length<54 || packet[12]!=8 || packet[13]!=0)return;
    const unsigned char *ip=packet+14;unsigned h=(ip[0]&15)*4;
    if(ip[9]!=6 || length<14+h+20 || ip[h+13]!=2)return;
    const unsigned char *tcp=ip+h;
    unsigned char out[54]={0}, pseudo[32]={0};
    memcpy(out,packet+6,6);memcpy(out+6,packet,6);out[12]=8;
    unsigned char *reply=out+14;
    reply[0]=0x45;reply[3]=40;reply[5]=1;reply[8]=64;reply[9]=6;
    memcpy(reply+12,ip+16,4);memcpy(reply+16,ip+12,4);
    uint16_t check=checksum(reply,20);reply[10]=check>>8;reply[11]=check;
    unsigned char *rt=reply+20;
    memcpy(rt,tcp+2,2);memcpy(rt+2,tcp,2);rt[7]=42;
    uint32_t sequence;memcpy(&sequence,tcp+4,4);sequence=htonl(ntohl(sequence)+1);memcpy(rt+8,&sequence,4);
    rt[12]=0x50;rt[13]=0x16;rt[14]=4;
    memcpy(pseudo,reply+12,8);pseudo[9]=6;pseudo[11]=20;memcpy(pseudo+12,rt,20);
    check=checksum(pseudo,sizeof(pseudo));rt[16]=check>>8;rt[17]=check;
    a->sll_protocol=htons(ETH_P_IP);a->sll_halen=6;memcpy(a->sll_addr,out,6);
    if(sendto(fd,out,sizeof(out),0,(void*)a,sizeof(*a))!=sizeof(out))fail("mixed reply");
}
int main(int argc, char **argv) {
    signal(SIGTERM, stop); signal(SIGINT, stop);
    if (argc == 2 && !strcmp(argv[1], "serve")) {
        int fd=socket(AF_INET,SOCK_STREAM,0), one=1;
        struct sockaddr_in a={.sin_family=AF_INET,.sin_port=htons(8080)};
        setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));
        if(bind(fd,(void*)&a,sizeof(a)) || listen(fd,128)) fail("listen");
        while(running) { struct pollfd p={fd,POLLIN,0}; if(poll(&p,1,100)>0) {int c=accept(fd,0,0); if(c>=0)close(c);} }
        close(fd); return 0;
    }
    if (argc!=4 || (strcmp(argv[1],"capture") && strcmp(argv[1],"mixed"))) return 2;
    int fd=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
    if(fd<0)fail("socket");
    int sendfd=strcmp(argv[1],"mixed") ? -1 : socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
    if(!strcmp(argv[1],"mixed") && sendfd<0)fail("send socket");
    struct sockaddr_ll a={.sll_family=AF_PACKET,.sll_protocol=htons(ETH_P_ALL),.sll_ifindex=if_nametoindex(argv[2])};
    if(bind(fd,(void*)&a,sizeof(a)))fail("bind");
    int size=16*1024*1024; setsockopt(fd,SOL_SOCKET,SO_RCVBUF,&size,sizeof(size));
    FILE*f=fopen(argv[3],"wb");if(!f)fail("pcap");
    uint32_t h[]={0xa1b2c3d4,0x00040002,0,0,65535,1};fwrite(h,sizeof(h),1,f);
    unsigned char b[65535]; unsigned long packets=0;
    while(running) { struct pollfd p={fd,POLLIN,0};if(poll(&p,1,100)<=0)continue;
        ssize_t n=recv(fd,b,sizeof(b),0);if(n<0){if(errno==EINTR)continue;fail("recv");}
        struct timeval t;gettimeofday(&t,0); uint32_t r[]={t.tv_sec,t.tv_usec,n,n};
        if(fwrite(r,sizeof(r),1,f)!=1 || fwrite(b,n,1,f)!=1)fail("write");
        packets++;
        if(!strcmp(argv[1],"mixed"))mixed_reply(sendfd,&a,b,n);
    }
    struct tpacket_stats stats; socklen_t len=sizeof(stats);
    if(getsockopt(fd,SOL_PACKET,PACKET_STATISTICS,&stats,&len))fail("statistics");
    if(fclose(f))fail("close");
    close(fd);
    printf("captured=%lu kernel_packets=%u kernel_drops=%u\n",packets,stats.tp_packets,stats.tp_drops);
    return stats.tp_drops?3:0;
}
