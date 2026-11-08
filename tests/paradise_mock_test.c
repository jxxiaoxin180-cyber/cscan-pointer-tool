#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "ahwbp/paradise.h"
static int scenario, syscall_count, socket_count, closed, ioctl_count, mode_read, retry, checks;
static uint32_t magics[8];
static DIR* mock_opendir(const char*p){(void)p;errno=ENOENT;return NULL;}
static int mock_fcntl(int fd,int cmd,...){(void)fd;return cmd==F_DUPFD_CLOEXEC?9:0;}
static int mock_close(int fd){closed=fd;return 0;}
static ssize_t mock_readlink(const char*p,char*b,size_t n){(void)p;const char*s=scenario==7?"not-driver":"anon_inode:[paradise_driver]";size_t len=strlen(s);if(len>n)len=n;memcpy(b,s,len);return (ssize_t)len;}
static long mock_syscall(long nr,...){(void)nr;va_list ap;va_start(ap,nr);unsigned long one=va_arg(ap,unsigned long);unsigned long two=va_arg(ap,unsigned long);(void)va_arg(ap,unsigned long);int*fd=va_arg(ap,int*);va_end(ap);if(one!=0xDEADBEEFUL)abort();magics[syscall_count++]=(uint32_t)two;if((scenario==1||scenario==5)&&two==0xF00DCAFEUL){*fd=scenario==5?0:7;return 0;}if(scenario==2&&two==0xCAFEBABEUL){*fd=8;return 0;}errno=ENODEV;return -1;}
static int mock_socket(int family,int type,int protocol){(void)family;(void)type;(void)protocol;++socket_count;if(scenario==3)return 10;errno=EAFNOSUPPORT;return -1;}
static long mock_sysconf(int name){(void)name;return scenario==8?-1:4096;}
static int mock_ioctl(int fd,unsigned long request,...);
#define opendir mock_opendir
#define fcntl mock_fcntl
#define close mock_close
#define readlink mock_readlink
#define syscall mock_syscall
#define socket mock_socket
#define sysconf mock_sysconf
#define ioctl mock_ioctl
#include "../vendor/ahwbp/paradise.c"
#undef opendir
#undef fcntl
#undef close
#undef readlink
#undef syscall
#undef socket
#undef sysconf
#undef ioctl
static int mock_ioctl(int fd,unsigned long request,...){(void)fd;va_list ap;va_start(ap,request);void*raw=va_arg(ap,void*);va_end(ap);++ioctl_count;if(retry){retry=0;errno=EINTR;return -1;}if(mode_read==1&&ioctl_count==2){errno=EFAULT;return -1;}if(mode_read==2){errno=0;return 1;}
 uintptr_t address,dst;size_t size;if(_IOC_NR(request)==16){struct paradise_memory_ioremap_cmd*p=raw;address=p->src_va;dst=p->dst_va;size=p->size;if(p->prot!=0||p->phy_addr!=0)abort();}else if(_IOC_NR(request)==9){struct paradise_memory_cmd*p=raw;address=p->src_va;dst=p->dst_va;size=p->size;}else abort();if(size>4096-address%4096)abort();memset((void*)dst,0x5a,size);return 0;}
#define CHECK(x) do {++checks;if(!(x)){fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x);return 1;}} while(0)
static void reset(int sc){scenario=sc;syscall_count=socket_count=ioctl_count=mode_read=retry=0;closed=-2;memset(magics,0,sizeof magics);errno=0;}
int main(void){struct ahwb_paradise d;struct ahwb_paradise_read_result r;unsigned char buf[8192];
 reset(1);CHECK(ahwb_paradise_open(&d)==0);CHECK(d.acquisition==2);CHECK(syscall_count==1&&magics[0]==0xF00DCAFEU);CHECK(socket_count==0);ahwb_paradise_close(&d);CHECK(closed==7);
 reset(2);CHECK(ahwb_paradise_open(&d)==0);CHECK(d.acquisition==3);CHECK(syscall_count==2&&magics[1]==0xCAFEBABEU);CHECK(ahwb_paradise_ioctl_request(d.transport)==_IOWR('W',16,struct paradise_memory_ioremap_cmd));
 reset(3);CHECK(ahwb_paradise_open(&d)==0);CHECK(d.acquisition==4&&d.transport==AHWBP_PARADISE_TRANSPORT_DECNET_HOOK);CHECK(syscall_count==2&&socket_count==1);CHECK(_IOC_SIZE(ahwb_paradise_ioctl_request(d.transport))==40);
 reset(3);CHECK(ahwb_paradise_open_mode(&d,1,-1)==-1);CHECK(socket_count==0);CHECK(d.open_errors[1]!=0&&d.open_errors[2]!=0);
 reset(3);CHECK(ahwb_paradise_open_mode(&d,2,-1)==0);CHECK(syscall_count==0&&socket_count==1);
 reset(4);CHECK(ahwb_paradise_open(&d)==-1);CHECK(d.fd==-1);CHECK(errno!=0);
 reset(5);CHECK(ahwb_paradise_open(&d)==0);CHECK(d.fd==0);ahwb_paradise_close(&d);CHECK(closed==0);
 reset(1);CHECK(ahwb_paradise_open_mode(&d,0,3)==0);CHECK(d.fd==9&&d.acquisition==5);CHECK(syscall_count==0);
 reset(7);CHECK(ahwb_paradise_open_mode(&d,0,3)==-1&&errno==ENODEV);
 reset(1);CHECK(ahwb_paradise_open(&d)==0);CHECK(ahwb_paradise_read(&d,1,0x1003,buf,6000,&r)==0);CHECK(r.transferred==6000&&r.ioctl_calls==2);CHECK(buf[5999]==0x5a);
 ioctl_count=0;mode_read=1;memset(buf,0,8192);CHECK(ahwb_paradise_read(&d,1,0x1003,buf,6000,&r)==-1);CHECK(r.transferred==4093&&r.ioctl_calls==2);CHECK(errno==EFAULT&&buf[4093]==0);
 ioctl_count=0;mode_read=0;retry=1;CHECK(ahwb_paradise_read(&d,1,0x1003,buf,6000,&r)==0);CHECK(r.ioctl_calls==3&&r.transferred==6000);
 ioctl_count=0;mode_read=2;CHECK(ahwb_paradise_read(&d,1,0x1000,buf,8,&r)==-1);CHECK(errno==EIO&&r.transferred==0);
 mode_read=0;CHECK(ahwb_paradise_read(&d,1,UINT64_MAX-3,buf,8,&r)==-1&&errno==EINVAL);CHECK(ahwb_paradise_read(&d,1,0x1000,NULL,8,&r)==-1);CHECK(ahwb_paradise_read(&d,0,0x1000,buf,8,&r)==-1);
 scenario=8;CHECK(ahwb_paradise_read(&d,1,0x1000,buf,8,&r)==-1&&errno==EINVAL);
 CHECK(ahwb_paradise_chunk_size(0x1003,16384,16384)==12285);CHECK(_IOC_SIZE(ahwb_paradise_ioctl_request(AHWBP_PARADISE_TRANSPORT_FD_IOREMAP))==48);
 printf("PASS %d Paradise ABI/handshake/page/read-error checks (mock transport, no real driver calls)\n",checks);return 0;}
