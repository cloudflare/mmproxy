#include <arpa/inet.h>
#include <fcntl.h>
#include <getopt.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>

#include <libmill.h>
#include "mmproxy.h"

// Parse host:port.
ipaddr ipaddr_parse(const char *addr, int noport)
{
	long port = 0;
	int addr_len = strlen(addr);
	if (noport) {
		goto afterport;
	}
	const char *colon = strrchr(addr, ':');
	if (colon == NULL || colon[1] == '\0') {
		goto parse_error;
	}

	char *endptr;
	port = strtol(&colon[1], &endptr, 10);
	if (port < 0 || port > 65535 || *endptr != '\0') {
		goto parse_error;
	}
	addr_len = colon - addr > 254 ? 254 : colon - addr;

afterport:
	;
	char host[255];
	strncpy(host, addr, addr_len);
	host[addr_len] = '\0';
	if (strlen(host) > 0 && host[0] == '[' &&
	    host[strlen(host) - 1] == ']') {
		host[strlen(host) - 1] = '\0';
		return iplocal(host + 1, port, 0);
	}
	return iplocal(host, port, 0);

parse_error:
	errno = EINVAL;
	ipaddr a;
	((struct sockaddr *)&a)->sa_family = AF_UNSPEC;
	return a;
}

int ipfamily(ipaddr addr) { return ((struct sockaddr *)&addr)->sa_family; }

int ipport(ipaddr addr)
{
	switch (ipfamily(addr)) {
	case AF_INET:
		return ntohs(((struct sockaddr_in *)&addr)->sin_port);
	case AF_INET6:
		return ntohs(((struct sockaddr_in6 *)&addr)->sin6_port);
	}
	return -1;
}

// "127.0.0.1" for ipv4 "::1" for ipv6
const char *ipaddrstr_noport(ipaddr addr, char *ipstr)
{
	if (ipstr == NULL) {
		static char ipstr_static[IPADDR_MAXSTRLEN];
		ipstr = ipstr_static;
	}
	int err = errno;
	const char *r = NULL;
	switch (ipfamily(addr)) {
	case AF_INET:
		r = inet_ntop(AF_INET,
			      &(((struct sockaddr_in *)&addr)->sin_addr), ipstr,
			      IPADDR_MAXSTRLEN);
		break;
	case AF_INET6:
		r = inet_ntop(AF_INET6,
			      &(((struct sockaddr_in6 *)&addr)->sin6_addr),
			      ipstr, IPADDR_MAXSTRLEN);
		break;
	}
	errno = err;
	return r;
}

// "127.0.0.1:1234" or "[::1]:1234"
const char *ipaddrstr_port(ipaddr addr, char *ipstr)
{
	int err = errno;
	const char *r = NULL;
	if (ipstr == NULL) {
		static char ipstr_static[IPADDR_MAXSTRLEN];
		ipstr = ipstr_static;
	}

	char buf[IPADDR_MAXSTRLEN];
	const char *str = ipaddrstr_noport(addr, buf);

	switch (ipfamily(addr)) {
	case AF_INET:
		snprintf(ipstr, IPADDR_MAXSTRLEN, "%s:%d", str, ipport(addr));
		r = ipstr;
		break;

	case AF_INET6:
		snprintf(ipstr, IPADDR_MAXSTRLEN, "[%s]:%d", str, ipport(addr));
		r = ipstr;
		break;
	}
	errno = err;
	return r;
}

size_t tcprecvpkt(int fd, char *buf, size_t buf_len, int64_t deadline,
		  int *more)
{
	int events = fdwait(fd, FDW_IN, deadline);
	if ((events & (FDW_IN | FDW_ERR)) != 0) {
		errno = 0;
		int r = recv(fd, buf, buf_len, MSG_DONTWAIT);
		if (r < 0) {
			if (errno == EAGAIN)
				errno = 0;
			return 0;
		} else if (r == 0) {
			errno = ECONNRESET;
			return 0;
		} else {
			/* On good read, which fills the buffer check for more.
			 */
			if (r == (int)buf_len && more != NULL) {
				/* Ignore error */
				ioctl(fd, FIONREAD, more);
			}
			errno = 0;
			return r;
		}
	}

	errno = ETIMEDOUT;
	return 0;
}

size_t tcpsendpkt(int fd, char *buf, size_t buf_len, int64_t deadline, int more)
{
	/* Opportunistic write */
	int more_flag = more ? MSG_MORE : 0;
	int r = send(fd, buf, buf_len, MSG_DONTWAIT | MSG_NOSIGNAL | more_flag);
	if (r < 0) {
		if (errno != EAGAIN) {
			return -1;
		}
	} else if (r == 0) {
		errno = ECONNRESET;
		return 0;
	} else {
		errno = 0;
		return r;
	}

	int events = fdwait(fd, FDW_OUT, deadline);
	if ((events & (FDW_OUT | FDW_ERR)) != 0) {
		int r = send(fd, buf, buf_len,
			     MSG_DONTWAIT | MSG_NOSIGNAL | more_flag);
		if (r < 0) {
			if (errno == EAGAIN) {
				errno = 0;
			}
			return 0;
		} else if (r == 0) {
			errno = ECONNRESET;
			return 0;
		} else {
			errno = 0;
			return r;
		}
	}

	errno = ETIMEDOUT;
	return 0;
}

void tcp_tune(int s)
{
	int opt = fcntl(s, F_GETFL, 0);
	if (opt == -1) {
		opt = 0;
	}
	int r = fcntl(s, F_SETFL, opt | O_NONBLOCK);
	if (r == -1) {
		PFATAL("fcntl");
	}

	/* Non fatal errors */
	opt = 1;
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	opt = 1;
	setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

	/* Set keepalives */
	opt = 1;
	setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));
	opt = 9; // default is 9 probes, I don't mind
	setsockopt(s, IPPROTO_TCP, TCP_KEEPCNT, &opt, sizeof(opt));
	opt = 29; // 29 seconds to first probe
	setsockopt(s, IPPROTO_TCP, TCP_KEEPIDLE, &opt, sizeof(opt));
	opt = 29; // 29 seconds between probes
	setsockopt(s, IPPROTO_TCP, TCP_KEEPINTVL, &opt, sizeof(opt));
}

ipaddr peername(int sd)
{
	ipaddr addr = {{0}};
	socklen_t addr_len = sizeof(ipaddr);
	int r = getpeername(sd, (struct sockaddr *)&addr, &addr_len);
	if (r < 0) {
		((struct sockaddr *)&addr)->sa_family = AF_UNSPEC;
	}
	return addr;
}

int tcpsock_fd(tcpsock a)
{
	int *b = (int *)a;
	return b[1];
}

sixteen to_16(ipaddr addr)
{
	sixteen a = {{0}};
	switch (ipfamily(addr)) {
	case AF_INET:
		a.data[10] = '\xff';
		a.data[11] = '\xff';
		memcpy(&a.data[12],
		       &((struct sockaddr_in *)&addr)->sin_addr.s_addr, 4);
		break;

	case AF_INET6:
		memcpy(a.data,
		       &((struct sockaddr_in6 *)&addr)->sin6_addr.s6_addr, 16);
		break;
	}
	return a;
}

void print_16(sixteen a)
{
	int i;
	for (i = 0; i < 8; i++) {
		printf("%02x%02x%s", a.data[i * 2], a.data[i * 2 + 1],
		       i == 7 ? ":" : "");
	}
}

network net_make(ipaddr addr, int prefix_len)
{
	network net = {{{0}}, {{0}}};
	net.addr = to_16(addr);

	if (ipfamily(addr) == AF_INET) {
		prefix_len += 96;
	}

	int i;
	for (i = 0; i < prefix_len; i++) {
		net.mask.data[i / 8] |= (1 << (7 - i % 8));
	}
	for (i = prefix_len; i < 128; i++) {
		net.mask.data[i / 8] &= ~(1 << (7 - i % 8));
	}
	return net;
}

int net_cmp(network net, ipaddr addr)
{
	sixteen ip = to_16(addr);

	int i;
	for (i = 0; i < 16; i++) {
		if ((ip.data[i] & net.mask.data[i]) != net.addr.data[i]) {
			return 1;
		}
	}
	return 0;
}

const char *net_str(network net)
{
	int i;
	for (i = 0; i < 128; i++) {
		if (FD_ISSET(i, (fd_set *)net.mask.data) == 0) {
			break;
		}
	}
	char dst[128];
	static char buf[128];
	int prefix_len = i;
	const char *v4pref = "\0\0\0\0\0\0\0\0\0\0\xff\xff";
	if (memcmp(v4pref, net.addr.data, 12) == 0) {
		inet_ntop(AF_INET, &net.addr.data[12], dst, sizeof(dst));
		snprintf(buf, sizeof(buf), "%s/%d", dst, prefix_len - 96);
	} else {
		inet_ntop(AF_INET6, net.addr.data, dst, sizeof(dst));
		snprintf(buf, sizeof(buf), "%s/%d", dst, prefix_len);
	}

	return buf;
}

int net_find_match(network *networks, int networks_len, ipaddr addr)
{
	int i;
	for (i = 0; i < networks_len; i++) {
		if (net_cmp(networks[i], addr) == 0) {
			return 1;
		}
	}
	return 0;
}
