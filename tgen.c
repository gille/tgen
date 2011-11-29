#include <stdint.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/sockios.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>

#define _USE_GNU
#define __USE_GNU
#include <sched.h>
#include <pthread.h>


#if !defined(LITTLE_ENDIAN) && !defined(BIG_ENDIAN)
#error no endian!
#endif
#ifdef LITTLE_ENDIAN
#define IP(a,b,c,d) htonl(((a)<<24)|((b)<<16)|((c)<<8)|(d))
#else
#define IP(a,b,c,d) ((a)<<24)|((b)<<16)|((c)<<8)|(d)
#endif

#define SIZEOF_ETHERNET 14
#define SIZEOF_IP       20
#define SIZEOF_UDP      8

struct state {
    int intf;
    int next_expected;
    int rx_ok;
    int ooo; /* out of order */
    int dropped;
    union {
	struct sockaddr_ll *sll;
	struct sockaddr *saddr; 
	struct sockaddr_in *sin;
    } u;
    unsigned char mac[6];
    unsigned char me[6];
};

int verbose=0; 
#define printv(fmt, args...) do { if(verbose) {printf(fmt, ##args); } } while(0)
#define printvv(fmt, args...) do { if(verbose > 1) {printf(fmt, ##args); } } while(0)

const char eth_broadcast[]={0xff,0xff,0xff,0xff,0xff,0xff};
static pthread_barrier_t start_barrier;

static void * fill_ethernet(char *p, const char *him, const char *me, uint16_t proto) {
    int i, j=0; 
    for(i=0; i < 6; i++) {
	p[j++] = him[i];
    }
    for(i=0; i < 6; i++) {
	p[j++] = me[i];
    }

    p[j++] = proto>>8;
    p[j++] = proto&0xFF;
    
    return &p[j];
}

static unsigned short csum(unsigned short *buf, int nwords)

{       //

        unsigned long sum;
        for(sum=0; nwords>0; nwords--)
                sum += *buf++;
        sum = (sum >> 16) + (sum &0xffff);
        sum += (sum >> 16);
        return (unsigned short)(~sum);

}
struct state rx_state;
struct state tx_state;

#define on_error(x,y) do {if((x) < 0) { perror (y); exit(-1); }} while(0)

void do_arp(struct state *tx, uint32_t src, uint32_t dst) {
    //, unsigned char *my_eth, char *my_ip) {
    int n;
    int i;
    struct arphdr *arp;
    int size;

    char buf[128];
    char *p;
    /* I want to send real RAW packets */
    p = fill_ethernet(buf, eth_broadcast, tx->me, (0x806));
    arp = (struct arphdr*)p;
    arp->ar_hrd=htons(1);
    arp->ar_pro=htons(0x800);
    arp->ar_hln = 6;
    arp->ar_pln = 4;
    arp->ar_op = htons(ARPOP_REQUEST); 
    p = (char*)++arp;
    i=0;
    for(i=0; i < 6; i++) {
	p[i]=tx->me[i]; 
    }
    memcpy(&p[i], &src, 4);
    i+=4;
    memset(&p[i], 0, 6);
    i+=6;
    memcpy(&p[i], &dst, 4);
    i+=4;
    size = &p[i]-&buf[0];
    n = sendto(tx->intf, buf, size, 0, (struct sockaddr*)tx->u.sll, sizeof(*(tx->u.sll)));
    on_error(n, "sendto");
}

int recv_arp(struct state *rx, uint32_t src, uint32_t dst) {
    struct arphdr *arp;
    struct ethhdr *eth;
    char buf[128];
    char *p;
    socklen_t sll;
    uint32_t a,b;
    int n;

    sll = sizeof(*rx->u.sll);
    n = recvfrom(rx->intf, buf, sizeof(buf), 0, (struct sockaddr*)rx->u.sll, &sll); 
    on_error(n,"recvfrom");
    eth = (struct ethhdr*)buf; 

    arp = (struct arphdr*)++eth;
    if(arp->ar_op == htons(ARPOP_REPLY)) {
	arp++;
	p = (char*)arp;
	memcpy(&a, &p[6], 4);
	memcpy(&b, &p[16], 4);
	if(src ==  b && dst == a) {
	    memcpy(rx->mac, p, 6);
	    return 1;
	}
    }

    
    return 0;
}

static int id = 0;

static void * fill_ip(void *p, uint32_t me, uint32_t him, uint16_t proto, int size) {
    struct iphdr *ip = p;
    ip->ihl=5;
    ip->version=4;
    ip->tos = 0;
    ip->tot_len = htons(size);
    ip->id = id++;
    ip->frag_off = 0;
    ip->ttl=0xFF;
    ip->protocol = proto;
    ip->check = 0;
    ip->saddr = me;
    ip->daddr = him;
    
    ip->check = csum((uint16_t*)ip, 20/sizeof(short));
    return ++ip;
}

static void * fill_udp(void *p, uint16_t src, uint16_t dst, uint16_t size) {
    struct udphdr *udp = p;
    udp->source = htons(src);
    udp->dest = htons(dst);
    udp->len = htons(size);
    udp->check = 0; 
    return ++udp;
}

void do_tx_udp(struct state *tx, uint32_t src, uint32_t dst, uint16_t sprt, uint16_t dprt, uint16_t size) {
    void *p;
    char *buf;
    int n;

    buf = malloc(size);

    p = fill_ethernet(buf, tx->mac, tx->me, 0x0800);
    p = fill_ip(p, src, dst, IPPROTO_UDP, (size-SIZEOF_ETHERNET));
    p = fill_udp(p, sprt, dprt, size-SIZEOF_ETHERNET-SIZEOF_IP);
    n = sendto(tx->intf, buf, size, 0, (struct sockaddr*)tx->u.sll, sizeof(*(tx->u.sll)));
    on_error(n, "sendto");
    
}

void *prepare_tx_udp(struct state *tx, void *p, uint32_t src_ip, uint32_t dst_ip, uint16_t sprt, uint16_t dprt, uint16_t size) {
    p = fill_ethernet(p, tx->mac, tx->me, 0x0800);
    p = fill_ip(p, src_ip, dst_ip, IPPROTO_UDP, (size-SIZEOF_ETHERNET));
    p = fill_udp(p, sprt, dprt, size-SIZEOF_ETHERNET-SIZEOF_IP);
    return p;
}

void send_pkt(struct state *tx, void *p, int size) {
    int n;
    int restart;
    do { 
	restart = 0;
	n = sendto(tx->intf, p, size, 0, (struct sockaddr*)tx->u.sll, sizeof(*(tx->u.sll)));
	if(n == -1 && errno == ENOBUFS) { 
	    usleep(10);
	    restart = 1;
	}
	
    } while((restart == 1)); 

    on_error(n, "sendto");
}

void * tx_thread(void *arg) {
    struct state *tx = (struct state*)arg;
    char *p = malloc(128);
    char *p2;
    int i;
    p2 = prepare_tx_udp(tx, p, IP(192,168,1,21), IP(172,16,1,20), 1234, 1234, 128);
    (void)p2;
    pthread_barrier_wait(&start_barrier);
    for(i = 0; i < 4; i++) {	
	for(i=0; i < 10000000;i++) {	    
	    send_pkt(tx, p, 64);
	}
	return 0;
    }

    return NULL;
}

static void usage(void) {
}

int main(int argc, char **argv) {
    struct state tx; 
    struct state *tx_th;
    struct state rx; 
    struct sockaddr_ll tx_sll;
    struct sockaddr_in rx_sin;
    char me[]={0x00, 0x50, 0x43, 0x00, 0xd7, 0xAA};
    int i;
    int tx_threads=4, rx_threads = 0;
    pthread_t *threads;
    cpu_set_t cpu;
    char *intf0=NULL;
    char optstr[]="o:r:R:t:T:i:S:v";
    int o;
    int ifindex;
    struct ifreq ifr;
    uint32_t rx_ip=0, tx_ip=0, my_ip=0;
    int die = 0;

    while((o=getopt(argc, argv, optstr)) != -1) {
	switch(o) {
	case 'i':
	    intf0 = optarg;
	    break;
	case 'o':
	    break;
	case 'r':
	    rx_threads = atoi(optarg);
	    break;
	case 'R':
	    i = inet_pton(AF_INET, optarg, &rx_ip);
	    on_error(i, "inet_pton");
	    break;
	case 'S':
	    i = inet_pton(AF_INET, optarg, &my_ip);
	    on_error(i, "inet_pton");
	    break;

	case 'T':
	    i = inet_pton(AF_INET, optarg, &tx_ip);
	    on_error(i, "inet_pton");
	    break;

	case 't':
	    tx_threads = atoi(optarg);
	    break;
	case 'v':
	    verbose++;
	    break;
	case 'h':
	default:
	    usage();
	    exit(0);
	}
    }
	
    if(rx_threads <= 0) {
	printf("Error: rx_threads must be > 0\n");
	die = 1;
    }

    if(tx_threads <= 0) {
	printf("Error: tx_threads must be > 0\n");
	die = 1;
    }

    if(intf0 == NULL) {
	printf("Error: TX interface not set\n");
	die  = 1;
    }
    
    if(rx_ip == 0) {
	printf("Error: RX_ip == 0\n");
	die = 1;
    }

    if(my_ip == 0) {
	printf("Error: my_ip == 0\n");
	die = 1;
    }

    if(tx_ip == 0) {
	printf("Error: TX_ip == 0\n");
	die = 1;
    }

    if(die)
	exit(die);

    printf("Configuration: \n"
	   "\trx_threads: %d\n"
	   "\ttx_threads: %d\n"
	   "\ttx_interface: %s\n"
	   "\trx_ip: %d.%d.%d.%d\n"
	   "\ttx_ip: %d.%d.%d.%d\n"
	   "\tmy_ip: %d.%d.%d.%d\n",

	   rx_threads, tx_threads, intf0,
	   htonl(rx_ip)>>24, (htonl(rx_ip)>>16)&0xFF, (htonl(rx_ip)>>8)&0xFF, htonl(rx_ip)&0xFF,
	   htonl(tx_ip)>>24, (htonl(tx_ip)>>16)&0xFF, (htonl(tx_ip)>>8)&0xFF, htonl(tx_ip)&0xFF,
	   htonl(my_ip)>>24, (htonl(my_ip)>>16)&0xFF, (htonl(my_ip)>>8)&0xFF, htonl(my_ip)&0xFF
	   );
    i = socket(AF_INET, SOCK_STREAM, 0);
    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, intf0); 
    o = ioctl(i, SIOCGIFHWADDR, &ifr);
    on_error(o, "SIOCGIFHWADDR"); 

    o = ioctl(i, SIOCGIFINDEX, &ifr);
    ifindex = ifr.ifr_ifindex;
    on_error(o, "SIOCGIFINDEX");    
    close(i);

    /* I want to send real RAW packets */
    tx.intf = socket(PF_PACKET, SOCK_RAW, htons(0x806));
    tx.u.sll = &tx_sll;
    on_error(tx.intf, "socket");

    tx.u.sll->sll_family = PF_PACKET;
    tx.u.sll->sll_protocol = htons(0x806);
    tx.u.sll->sll_ifindex = ifindex;
    tx.u.sll->sll_hatype = 0;
    tx.u.sll->sll_pkttype = PACKET_OUTGOING;
    tx.u.sll->sll_halen = ETH_ALEN;

    rx.intf = socket(PF_INET, SOCK_DGRAM, 0);
    rx.u.sin = &rx_sin;
    on_error(rx.intf, "socket");


    for(i=0; i < 6; i++) {
	tx.me[i]=me[i];
    }
    /* step one arp */
    i = 0;

    threads = malloc(sizeof(pthread_t)*tx_threads);
    pthread_barrier_init(&start_barrier, NULL, tx_threads+1);

    do {
	printv("arp for %d.%d.%d.%d from %d.%d.%d.%d\n",
	       htonl(tx_ip)>>24, (htonl(tx_ip)>>16)&0xFF, 
	       (htonl(tx_ip)>>8)&0xFF, htonl(tx_ip)&0xFF,
	       htonl(my_ip)>>24, (htonl(my_ip)>>16)&0xFF, 
	       (htonl(my_ip)>>8)&0xFF, htonl(my_ip)&0xFF);
	do_arp(&tx, my_ip, tx_ip); 
	tx.u.sll->sll_pkttype = PACKET_HOST;
	i = recv_arp(&tx, my_ip, tx_ip); 
	tx.u.sll->sll_pkttype = PACKET_OUTGOING;
    } while(!i);
    printvv("got arp response from %.2x:%.2x:%.2x:%.2x:%.2x\n",
	    tx.mac[0], tx.mac[1], tx.mac[2], tx.mac[3], tx.mac[4], tx.mac[5]);
    for(i=0; i < rx_threads; i++) {
	
    }
    
    for (i=0; i < tx_threads; i++) { 
	pthread_attr_t attr;
	int cpus = 4;
	CPU_ZERO(&cpu);
	CPU_SET(i%cpus, &cpu);
	pthread_attr_init(&attr);
	tx_th = malloc(sizeof(*tx_th));
	memcpy(tx_th, &tx, sizeof(*tx_th));
	tx_th->intf = socket(PF_PACKET, SOCK_RAW, htons(0x806));
	pthread_attr_setaffinity_np(&attr, cpus, &cpu); 

	printf("Spawning thread %d on processor %d\n", 
	       i, i%cpus);
	pthread_create(&threads[i], &attr, tx_thread, tx_th);
    }
    pthread_barrier_wait(&start_barrier);
    for(i=0; i < 4; i++) {
	pthread_join(threads[i], NULL);
	printv("thread %d died\n", i);

    }
    return 0;
}

