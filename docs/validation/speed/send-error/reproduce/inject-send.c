#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
static unsigned calls, failures, forwarded;
static unsigned char first[2048];
static size_t first_length;
static struct timespec first_time;
static int selected(int fd,const void *buffer,size_t length) {
    struct sockaddr_ll address; socklen_t size=sizeof(address);
    const unsigned char *b=buffer; unsigned h;
    const char *iface=getenv("SEND_INJECT_INTERFACE");
    if(!iface || getsockname(fd,(void*)&address,&size) || address.sll_family!=AF_PACKET || address.sll_ifindex!=(int)if_nametoindex(iface))return 0;
    if(length<54 || b[12]!=8 || b[13]!=0 || b[23]!=6)return 0;
    if(memcmp(b+26,"\xc6\x12\x00\x03",4) || memcmp(b+30,"\xc6\x12\x00\x02",4))return 0;
    h=14+(b[14]&15)*4;
    return length>=h+20 && b[h+13]==2;
}
static int inject(int fd,const void *buffer,size_t length) {
    const char *mode=getenv("SEND_INJECT_MODE");
    if(!mode || !selected(fd,buffer,length))return 0;
    calls++;
    if(calls==1){clock_gettime(CLOCK_MONOTONIC,&first_time);first_length=length;memcpy(first,buffer,length<sizeof(first)?length:sizeof(first));}
    if(calls<=8)fprintf(stderr,"send_inject: call=%u same_as_first=%d length=%zu\n",calls,length==first_length && length<=sizeof(first) && memcmp(first,buffer,length)==0,length);
    struct timespec now;clock_gettime(CLOCK_MONOTONIC,&now);
    long long elapsed_ns=(now.tv_sec-first_time.tv_sec)*1000000000LL+now.tv_nsec-first_time.tv_nsec;
    if(!strcmp(mode,"persistent") || (!strcmp(mode,"transient") && elapsed_ns<40000000LL)) {
        failures++;
        errno=!strcmp(mode,"persistent")?ENOBUFS:EAGAIN;
        return 1;
    }
    return 0;
}
ssize_t send(int fd,const void *buffer,size_t length,int flags) {
    static ssize_t (*next)(int,const void*,size_t,int);
    int chosen=selected(fd,buffer,length);
    if(inject(fd,buffer,length))return -1;
    if(!next)next=dlsym(RTLD_NEXT,"send");
    ssize_t result=next(fd,buffer,length,flags);
    if(chosen && result>=0)forwarded++;
    return result;
}
ssize_t sendto(int fd,const void *buffer,size_t length,int flags,const struct sockaddr *dest,socklen_t size) {
    static ssize_t (*next)(int,const void*,size_t,int,const struct sockaddr*,socklen_t);
    int chosen=selected(fd,buffer,length);
    if(inject(fd,buffer,length))return -1;
    if(!next)next=dlsym(RTLD_NEXT,"sendto");
    ssize_t result=next(fd,buffer,length,flags,dest,size);
    if(chosen && result>=0)forwarded++;
    return result;
}
__attribute__((destructor)) static void summary(void) {
    fprintf(stderr,"send_inject: summary selected_calls=%u injected_failures=%u forwarded_successes=%u transient_block_ms=40\n",calls,failures,forwarded);
}
