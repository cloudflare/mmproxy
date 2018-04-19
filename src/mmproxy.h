#define ERRORF(x...) fprintf(stderr, x)

#define FATAL(x...)                                                            \
	do {                                                                   \
		ERRORF("[-] PROGRAM ABORT : " x);                              \
		ERRORF("\n\tLocation : %s(), %s:%u\n\n", __FUNCTION__,         \
		       __FILE__, __LINE__);                                    \
		exit(EXIT_FAILURE);                                            \
	} while (0)

#define PFATAL(x...)                                                           \
	do {                                                                   \
		ERRORF("[-] SYSTEM ERROR : " x);                               \
		ERRORF("\n\tLocation : %s(), %s:%u\n", __FUNCTION__, __FILE__, \
		       __LINE__);                                              \
		perror("      OS message ");                                   \
		ERRORF("\n");                                                  \
		exit(EXIT_FAILURE);                                            \
	} while (0)


#define TIMESPEC_NSEC(ts) ((ts)->tv_sec * 1000000000ULL + (ts)->tv_nsec)
#define TIMEVAL_NSEC(ts)                                                       \
	((ts)->tv_sec * 1000000000ULL + (ts)->tv_usec * 1000ULL)
#define NSEC_TIMESPEC(ns)                                                      \
	(struct timespec) { (ns) / 1000000000ULL, (ns) % 1000000000ULL }
#define NSEC_TIMEVAL(ns)                                                       \
	(struct timeval)                                                       \
	{                                                                      \
		(ns) / 1000000000ULL, ((ns) % 1000000000ULL) / 1000ULL         \
	}
#define MSEC_NSEC(ms) ((ms)*1000000ULL)
#define NSEC_MSEC(ns) ((ns) / 1000000UL)

#define MIN(a, b) ((a) < (b) ? (a) : (b))

typedef struct { uint8_t data[16]; } sixteen;
typedef struct { sixteen addr; sixteen mask; } network;

/* utils.c */
const char *optstring_from_long_options(const struct option *opt);
int check_ip_route_get_local(ipaddr target_addr);
int check_direct_connect(ipaddr target_addr);
int check_spoofed_connect(ipaddr fake_source_addr, ipaddr target_addr, uint32_t mark);
int tcpconnect_spoofed(ipaddr source_addr, ipaddr target_addr, int64_t deadline, uint32_t mark);
const char **parse_argv(const char *str, char delim);
int check_iptables(const char *rule);
int check_ip_rule(int ipv6, uint32_t mark, uint32_t table);
int check_ip_route(int ipv6, uint32_t table);
int set_nofile_max();
int read_subnets(const char *fname, network **ptr_networks, int *ptr_networks_len);

/* net.c */
ipaddr ipaddr_parse(const char *addr, int noport);
int ipfamily(ipaddr addr);
ipaddr peername(int fd);
const char* ipaddrstr_noport(ipaddr addr, char *ipstr);
const char* ipaddrstr_port(ipaddr addr, char *ipstr);
size_t tcprecvpkt(int fd, char *buf, size_t buf_len, int64_t deadline, int *more);
size_t tcpsendpkt(int fd, char *buf, size_t buf_len, int64_t deadline, int more);
void tcp_tune(int s);
int tcpsock_fd(tcpsock a);
network net_make(ipaddr addr, int prefix_len);
const char *net_str(network net);
int net_find_match(network *networks, int networks_len, ipaddr addr);
int ipport(ipaddr addr);



#ifndef IP_TRANSPARENT
# define IP_TRANSPARENT 19
#endif

#ifndef IP_BIND_ADDRESS_NO_PORT
# define IP_BIND_ADDRESS_NO_PORT 24
#endif
