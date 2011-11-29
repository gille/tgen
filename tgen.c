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
#include <sys/time.h>
#define __USE_GNU
#include <sched.h>
#include <pthread.h>


#define printv(fmt, args...) do { if(unlikely(verbose)) {printf(fmt, ##args); } } while(0)
#define printvv(fmt, args...) do { if(unlikely(verbose > 1)) {printf(fmt, ##args); } } while(0)
#define printvvv(fmt, args...) do { if(unlikely(verbose > 2)) {printf(fmt, ##args); } } while(0)

/* FIXME */
#ifndef likely
#define likely(x) (__builtin_expect(!!(x), 1))
#define unlikely(x) (__builtin_expect(!!(x), 0))
#endif

#if !defined(LITTLE_ENDIAN) && !defined(BIG_ENDIAN)
#error no endian!
#endif
#ifdef LITTLE_ENDIAN
#define IP(a,b,c,d) htonl(((a)<<24)|((b)<<16)|((c)<<8)|(d))
#else
#define IP(a,b,c,d) ((a)<<24)|((b)<<16)|((c)<<8)|(d)
#endif

#define on_error(x,y) do {if(unlikely((x) < 0)) { fprintf(stderr, "Error in %s:%d [%s %s]\n", __FILE__, __LINE__, y, strerror(errno)); exit(-1); }} while(0)
#define on_error_zero(x,y) do {if(unlikely((x) != 0)) { fprintf(stderr, "Error in %s:%d [%s %s]\n", __FILE__, __LINE__, y, strerror(errno)); exit(-1); }} while(0)
#define on_error_ptr(x,y) do {if(unlikely((x) == NULL)) { fprintf(stderr, "Error in %s:%d [%s %s]\n", __FILE__, __LINE__, y, strerror(errno)); exit(-1); }} while(0)

#define SIZEOF_ETHERNET (14)
#define SIZEOF_IP       (20)
#define SIZEOF_UDP      (8)

struct state {
    int intf;
    int next_expected;
    int rx_ok;
    int ooo; /* out of order */
    int dropped;
    int packets; 
    int size;
    int sleep_period;

    union {
	struct sockaddr_ll *sll;
	struct sockaddr *saddr; 
	struct sockaddr_in *sin;
    } ;
    uint32_t tx_ip;
    uint32_t sender_ip;
    unsigned short port;
    unsigned char mac[6];
    unsigned char me[6];
};

static int verbose=0; 
static int id = 0;
static const unsigned char eth_broadcast[]={0xff,0xff,0xff,0xff,0xff,0xff};
static pthread_barrier_t start_barrier;

static void * fill_ethernet(unsigned char *p, const unsigned char *him, const unsigned char *me, 
			    uint16_t proto) 
{
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
{
        unsigned long sum;
        for(sum=0; nwords > 0; nwords--)
                sum += *buf++;
        sum = (sum >> 16) + (sum &0xffff);
        sum += (sum >> 16);
        return (unsigned short)(~sum);
}

static void do_arp(struct state *tx, uint32_t src, uint32_t dst) {
    //, unsigned char *my_eth, char *my_ip) {
    int n;
    int i;
    struct arphdr *arp;
    int size;

    unsigned char buf[128];
    unsigned char *p;
    /* I want to send real RAW packets */
    p = fill_ethernet(buf, eth_broadcast, tx->me, (0x806));
    arp = (struct arphdr*)p;
    arp->ar_hrd=htons(1);
    arp->ar_pro=htons(0x800);
    arp->ar_hln = 6;
    arp->ar_pln = 4;
    arp->ar_op = htons(ARPOP_REQUEST); 
    p = (unsigned char*)++arp;

    for(i=0; i < 6; i++) {
	p[i]=tx->me[i]; 
    }
    *(uint32_t*)&p[i] = *(uint32_t*)&src; 
    i+=4;
    memset(&p[i], 0, 6);
    i+=6;
    *(uint32_t*)&p[i] = *(uint32_t*)&dst; 
    i+=4;
    size = &p[i]-&buf[0];
    n = sendto(tx->intf, buf, size, 0, (struct sockaddr*)tx->sll, sizeof(*(tx->sll)));
    on_error(n, "sendto");
}

static int recv_arp(struct state *rx, uint32_t src, uint32_t dst) {
    struct arphdr *arp;
    struct ethhdr *eth;
    char buf[128];
    char *p;
    socklen_t sll;
    uint32_t a,b;
    int n;

    sll = sizeof(*rx->sll);
    n = recvfrom(rx->intf, buf, sizeof(buf), 0, (struct sockaddr*)rx->sll, &sll); 
    on_error(n,"recvfrom");
    eth = (struct ethhdr*)buf; 

    arp = (struct arphdr*)++eth;
    if(likely(arp->ar_op == htons(ARPOP_REPLY))) {
	arp++;
	p = (char*)arp;
	*(unsigned int*)&a=*(unsigned int*)&p[6];
	*(unsigned int*)&b=*(unsigned int*)&p[16];
	if(src ==  b && dst == a) {
	    memcpy(rx->mac, p, 6);
	    return 1;
	}
    }

    
    return 0;
}

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

#if 0
static void do_tx_udp(struct state *tx, uint32_t src, uint32_t dst, uint16_t sprt, uint16_t dprt, uint16_t size) {
    void *p;
    unsigned char *buf;
    int n;

    buf = (unsigned char*)malloc(size);
    on_error_ptr(buf, "malloc");
    p = fill_ethernet(buf, tx->mac, tx->me, 0x0800);
    p = fill_ip(p, src, dst, IPPROTO_UDP, (size-SIZEOF_ETHERNET));
    p = fill_udp(p, sprt, dprt, size-SIZEOF_ETHERNET-SIZEOF_IP);
    n = sendto(tx->intf, buf, size, 0, (struct sockaddr*)tx->sll, sizeof(*(tx->sll)));
    on_error(n, "sendto");
}
#endif

static void *prepare_tx_udp(struct state *tx, void *p, uint32_t src_ip, uint32_t dst_ip, uint16_t sprt, uint16_t dprt, uint16_t size) {
    p = fill_ethernet(p, tx->mac, tx->me, 0x0800);
    p = fill_ip(p, src_ip, dst_ip, IPPROTO_UDP, (size-SIZEOF_ETHERNET));
    p = fill_udp(p, sprt, dprt, size-SIZEOF_ETHERNET-SIZEOF_IP);
    return p;
}

static void send_pkt(struct state *tx, void *p, int size) {
    int n;
    int restart;

    do { 
	restart = 0;
	n = sendto(tx->intf, p, size, 0, (struct sockaddr*)tx->sll, sizeof(*(tx->sll)));
	if(n == -1 && errno == ENOBUFS) { 
	    restart = 1;
	} else {
	    on_error(n, "sendto");
	}
	
    } while((restart == 1)); 

    on_error(n, "sendto");
}

static void * rx_thread(void *arg) {
    char buf[65535];
    int packets;
    struct state *rx = arg;
    fd_set r; 
    struct timeval t;
    int n;
    packets = 0;

    FD_ZERO(&r);
    FD_SET(rx->intf, &r);

    while(1) {
	t.tv_sec = 1;
	t.tv_usec = 0; 
	n = select(rx->intf+1, &r, 0, 0, &t); 
	if(n == 1) {
	    recv(rx->intf, buf, sizeof(buf), 0); 
	    packets++;
	} else {
	    /* No traffic received for 1s */
	    return (void*)packets;
	}
    }
    return NULL;
}

static void * tx_thread(void *arg) {
    struct state *tx = (struct state*)arg;
    char *p = malloc(tx->size);
    char *p2;
    int i;
    on_error_ptr(p, "malloc");
    p2 = prepare_tx_udp(tx, p, tx->sender_ip, tx->tx_ip, tx->port, tx->port, tx->size);
    (void)p2;
    pthread_barrier_wait(&start_barrier);
    for(i = 0; i < 4; i++) {	
	for(i=0; i < tx->packets;i++) {	    
	    send_pkt(tx, p, tx->size);
	    usleep(tx->sleep_period);
	}
	return 0;
    }

    return NULL;
}

static void usage(void) {
    printf("usage: \n");
}

static void print_time(struct timeval *t0, struct timeval *t1, int tx_packets, int rx_packets, int size, int tx_threads) {
    struct timeval t;
    uint64_t usec;
    uint64_t tx_bw, rx_bw;

    if(t1->tv_usec < t0->tv_usec) {
	t1->tv_usec += 1000000;
	t1->tv_sec--;
    }
    t.tv_sec = t1->tv_sec - t0->tv_sec;
    t.tv_usec = t1->tv_usec - t0->tv_usec;
    printvv("time elapsed: %d:%d\n", (int)t.tv_sec, (int)t.tv_usec/1000);
    usec = 1000000*t.tv_sec;
    usec += t.tv_usec;
    size += 12 + 4; /* inter frame gap + crc */
    tx_bw = size;
    tx_bw *= 8;
    rx_bw = tx_bw;
    tx_bw *= tx_packets;
    tx_bw *= tx_threads;
    rx_bw *= rx_packets;
    rx_bw /= usec;
    tx_bw /= usec;

    printv("tx bandwidth: %lldMb/s rx bandwidth %lldMb/s rx packets lost: %d\n", tx_bw, rx_bw, tx_packets*tx_threads-rx_packets);
}

int do_udp_bmark(struct state * tx, struct state * rx, int tx_threads, int rx_threads);


int main(int argc, char **argv) {
    struct state tx; 

    struct state rx; 
    struct sockaddr_ll tx_sll;
    struct sockaddr_in rx_sin;
    const char optstr[]="p:o:r:R:t:T:i:S:vn:s:u:B";

    int i, o, ifindex, n;

    int binary_search = 0;
    struct ifreq ifr;

    int tx_threads = 1, rx_threads = 1, packets = 0, size = 0, die = 0;
    uint32_t rx_ip = 0, tx_ip = 0, my_ip = 0;
    char *intf0 = NULL;
    unsigned short port = 0;

    int current_sleep, delta; 

    while((o=getopt(argc, argv, optstr)) != -1) {
	switch(o) {
	case 'i':
	    intf0 = optarg;
	    break;
	case 'n':
	    packets = atoi(optarg);
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
	case 's':
	    size = atoi(optarg);
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
	case 'p':
	    port = atoi(optarg);
	    break;
	case 'u':
	    break;
	case 'B':
	    binary_search = 1;
	    /* Binary search for max bandwidth */
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

    if(port == 0) {
	printf("Error: port == 0\n");
	die = 1;
    }

    if(packets == 0) {
	printf("Error: packets == 0\n");
	die = 1;
    }

    if(size < 64 || size > 1514) {
	printf("Error: size < 64 or size > 1514\n");
	die = 1;
    }

    if(die)
	exit(die);

    printv("Configuration: \n"
	   "\trx_threads: %d\n"
	   "\ttx_threads: %d\n"
	   "\ttx_interface: %s\n"
	   "\trx_ip: %d.%d.%d.%d\n"
	   "\ttx_ip: %d.%d.%d.%d\n"
	   "\tmy_ip: %d.%d.%d.%d\n"
	   "\tport: %d\n"
	   "\tpackets %d\n"
	   "\tsize: %db\n\n"
	   ,
	   rx_threads, tx_threads, intf0,
	   htonl(rx_ip)>>24, (htonl(rx_ip)>>16)&0xFF, (htonl(rx_ip)>>8)&0xFF, htonl(rx_ip)&0xFF,
	   htonl(tx_ip)>>24, (htonl(tx_ip)>>16)&0xFF, (htonl(tx_ip)>>8)&0xFF, htonl(tx_ip)&0xFF,
	   htonl(my_ip)>>24, (htonl(my_ip)>>16)&0xFF, (htonl(my_ip)>>8)&0xFF, htonl(my_ip)&0xFF,
	   port, packets, size
	   );
    printvv("size: "
	    "\t14b\tethernet\n"
	    "\t20b\tIP\n"
	    "\t8b\tUDP header\n"
	    "\t%db\tUDP payload\n"
	    "\t--------------------\n"
	    "\t%db\n\n",
	    size-SIZEOF_ETHERNET-SIZEOF_IP-SIZEOF_UDP, size);

    i = socket(AF_INET, SOCK_STREAM, 0);
    on_error(i, "socket");

    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, intf0); 
    o = ioctl(i, SIOCGIFHWADDR, &ifr);
    on_error(o, "SIOCGIFHWADDR"); 
    memcpy(tx.me, ifr.ifr_hwaddr.sa_data, 6);

    o = ioctl(i, SIOCGIFINDEX, &ifr);
    on_error(o, "SIOCGIFINDEX");
    ifindex = ifr.ifr_ifindex;
    close(i);

    /* I want to send real RAW packets */
    tx.intf = socket(PF_PACKET, SOCK_RAW, htons(0x806));
    on_error(tx.intf, "socket");

    tx.sll = &tx_sll;
    tx.sll->sll_family = PF_PACKET;
    tx.sll->sll_protocol = htons(0x806);
    tx.sll->sll_ifindex = ifindex;
    tx.sll->sll_hatype = 0;
    tx.sll->sll_pkttype = PACKET_OUTGOING;
    tx.sll->sll_halen = ETH_ALEN;
    tx.port = port;
    tx.tx_ip = rx_ip;
    tx.sender_ip = my_ip;
    tx.packets = packets;
    tx.sleep_period = 0;
    tx.size = size;

    rx.intf = socket(PF_INET, SOCK_DGRAM, 0);
    on_error(rx.intf, "socket");
    rx.packets = (tx_threads * packets)/rx_threads;
    rx.sin = &rx_sin;
    rx.sin->sin_family = AF_INET;
    rx.sin->sin_addr.s_addr = (rx_ip); 
    rx.sin->sin_port = htons(port);
    i = bind(rx.intf, rx.saddr, sizeof(*rx.saddr)); 
    on_error_zero(i, "bind"); 

    do {
	printv("arp for %d.%d.%d.%d from %d.%d.%d.%d\n",
	       htonl(tx_ip)>>24, (htonl(tx_ip)>>16)&0xFF, 
	       (htonl(tx_ip)>>8)&0xFF, htonl(tx_ip)&0xFF,
	       htonl(my_ip)>>24, (htonl(my_ip)>>16)&0xFF, 
	       (htonl(my_ip)>>8)&0xFF, htonl(my_ip)&0xFF);
	do_arp(&tx, my_ip, tx_ip); 
	tx.sll->sll_pkttype = PACKET_HOST;
	i = recv_arp(&tx, my_ip, tx_ip); 
	tx.sll->sll_pkttype = PACKET_OUTGOING;
    } while(!i);
    printvv("got arp response from %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
	    tx.mac[0], tx.mac[1], tx.mac[2], tx.mac[3], tx.mac[4], tx.mac[5]);
   

    if(binary_search) {
	current_sleep = 64; 
	do { 
	    tx.sleep_period = current_sleep;
	    n = do_udp_bmark(&tx, &rx, tx_threads, rx_threads); 
	    current_sleep *= 2; /* *= 4? */
	} while (n != 0); 
	delta = current_sleep/2;
	current_sleep -= delta;
	do { 
	    delta /= 2;
	    tx.sleep_period = current_sleep;
	    n = do_udp_bmark(&tx, &rx, tx_threads, rx_threads); 
	    if(n == 0) { 
		/* current_sleep too high! */		
		current_sleep -= delta;
	    } else {
		current_sleep += delta; 
	    }
	} while(delta);
    } else {
	do_udp_bmark(&tx, &rx, tx_threads, rx_threads); 
    }
    return 0;
}

int do_udp_bmark(struct state * tx, struct state * rx, int tx_threads, int rx_threads) {
    int i; 
    int o;
    int cpus = 8; 
    pthread_attr_t attr;
    struct timeval t0, t1;
    struct state *tx_th;
    pthread_t *tx_pthreads;
    pthread_t *rx_pthreads;
    cpu_set_t cpu;
    int rx_packets = 0; 

    tx_pthreads = malloc(sizeof(pthread_t)*tx_threads);
    on_error_ptr(tx_pthreads, "malloc");

    rx_pthreads = malloc(sizeof(pthread_t)*rx_threads);
    on_error_ptr(rx_pthreads, "malloc");

    i = pthread_barrier_init(&start_barrier, NULL, tx_threads+1);
    on_error_zero(i, "pthread_barrier_init");

    for(i=0; i < rx_threads; i++) {
	CPU_ZERO(&cpu);
	CPU_SET((i+cpus/2)%cpus, &cpu);
	o = pthread_attr_init(&attr);
	on_error_zero(o, "pthread_attr_init");
	o = pthread_attr_setaffinity_np(&attr, cpus, &cpu); 
	on_error_zero(o, "pthread_attr_setaffinity_np");
	printvvv("Spawning rx thread %d on processor %d\n", 
	       i, (i+cpus/2)%cpus);
	o = pthread_create(&rx_pthreads[i], &attr, rx_thread, rx);
	on_error_zero(o, "pthread_create");
    }

    for (i=0; i < tx_threads; i++) { 
	CPU_ZERO(&cpu);
	CPU_SET(i%cpus, &cpu);
	o = pthread_attr_init(&attr);
	on_error_zero(o, "pthread_attr_init");
	tx_th = malloc(sizeof(*tx_th));
	on_error_ptr(tx_th, "malloc");
	memcpy(tx_th, tx, sizeof(*tx_th));
	tx_th->intf = socket(PF_PACKET, SOCK_RAW, htons(0x806));
	o = pthread_attr_setaffinity_np(&attr, cpus, &cpu); 
	on_error_zero(o, "pthread_attr_setaffinity_np");
	printvvv("Spawning tx thread %d on processor %d\n", 
	       i, i%cpus);
	o = pthread_create(&tx_pthreads[i], &attr, tx_thread, tx_th);
	on_error_zero(o, "pthread_create");
    }
    gettimeofday(&t0, NULL);
    o = pthread_barrier_wait(&start_barrier);
    on_error_zero(o, "pthread_barrier_wait");
    for(i=0; i < tx_threads; i++) {
	o = pthread_join(tx_pthreads[i], NULL);
	on_error_zero(o, "pthread_join");
	printvv("tx thread %d died\n", i);
    }
    gettimeofday(&t1, NULL);    
    for(i=0; i < rx_threads; i++) {
	unsigned int *p;
	o = pthread_join(rx_pthreads[i], (void**)&p);
	on_error_zero(o, "pthread_join");
	printvv("rx thread %d died\n", i);
	rx_packets += (unsigned int)p;
    }

    free(tx_pthreads);
    free(rx_pthreads);
    print_time(&t0, &t1, tx->packets, rx_packets, tx->size, tx_threads);

    return tx->packets*tx_threads-rx_packets;
}
