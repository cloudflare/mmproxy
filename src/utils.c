#include <getopt.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <fcntl.h>

#include <libmill.h>
#include "mmproxy.h"

int iplen(ipaddr addr)
{
	return ipfamily(addr) == AF_INET ? sizeof(struct sockaddr_in)
					 : sizeof(struct sockaddr_in6);
}

const char *optstring_from_long_options(const struct option *opt)
{
	static char optstring[256] = {0};
	char *osp = optstring;

	for (; opt->name != NULL; opt++) {
		if (opt->flag == 0 && opt->val > 0 && opt->val < 256) {
			*osp++ = opt->val;
			switch (opt->has_arg) {
			case optional_argument:
				*osp++ = ':';
				*osp++ = ':';
				break;
			case required_argument:
				*osp++ = ':';
				break;
			}
		}
	}
	*osp++ = '\0';

	if (osp - optstring >= (int)sizeof(optstring)) {
		abort();
	}

	return optstring;
}

int check_ip_route_get_local(ipaddr target_addr)
{
	/* Reset the ENV before system(). */
	clearenv();

	char cmd[1024];
	snprintf(cmd, sizeof(cmd),
		 "/sbin/ip route get %s | /bin/fgrep -q local",
		 ipaddrstr_noport(target_addr, NULL));
	int r = system(cmd);
	if (WIFEXITED(r)) {
		return WEXITSTATUS(r);
	}
	return -1;
}

int check_direct_connect(ipaddr target_addr)
{
	int s = socket(ipfamily(target_addr), SOCK_STREAM, 0);
	if (s < 0) {
		PFATAL("socket()");
	}

	struct timeval tv = NSEC_TIMEVAL(MSEC_NSEC(300));
	int r = setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	if (r < 0) {
		PFATAL("setsockopt()");
	}

	// make sure it will fail fast. There is no packet loss on loopback.
	int opt = 1;
	r = setsockopt(s, IPPROTO_TCP, TCP_SYNCNT, &opt, sizeof(opt));
	if (r < 0) {
		PFATAL("setsockopt()");
	}

	// Blocking connect.
	r = connect(s, (struct sockaddr *)&target_addr, iplen(target_addr));
	int err = errno;
	close(s);
	errno = err;
	return r;
}

int check_spoofed_connect(ipaddr fake_source_addr, ipaddr target_addr,
			  uint32_t mark)
{
	int s = socket(ipfamily(target_addr), SOCK_STREAM, 0);
	if (s < 0) {
		PFATAL("socket()");
	}

	struct timeval tv = NSEC_TIMEVAL(MSEC_NSEC(300));
	int r = setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	if (r < 0) {
		PFATAL("setsockopt()");
	}

	// make sure it will fail fast. There is no packet loss on loopback.
	int opt = 1;
	r = setsockopt(s, IPPROTO_TCP, TCP_SYNCNT, &opt, sizeof(opt));
	if (r < 0) {
		PFATAL("setsockopt()");
	}

	r = setsockopt(s, IPPROTO_IP, IP_TRANSPARENT, &opt, sizeof(opt));
	if (r < 0) {
		close(s);
		return -2;
	}

	// IP_BIND_ADDRESS_NO_PORT is opportunistic, ignore the error
	opt = 1;
	setsockopt(s, IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT, &opt, sizeof(opt));

	r = setsockopt(s, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
	if (r < 0) {
		PFATAL("setsockopt(SOL_SOCKET, SO_MARK)");
	}

	// Bind-before-connect to select source IP.
	r = bind(s, (struct sockaddr *)&fake_source_addr,
		 iplen(fake_source_addr));
	if (r < 0) {
		PFATAL("bind()");
	}

	r = connect(s, (struct sockaddr *)&target_addr, iplen(target_addr));
	int err = errno;
	close(s);
	errno = err;
	return r < 0 ? -1 : r;
}

int tcpconnect_spoofed(ipaddr source_addr, ipaddr target_addr, int64_t deadline,
		       uint32_t mark)
{
	if (ipfamily(source_addr) != ipfamily(target_addr)) {
		errno = EPROTOTYPE;
		return -1;
	}

	int s = socket(ipfamily(target_addr), SOCK_STREAM, 0);
	if (s < 0) {
		return -1;
	}

	// make sure it will fail fast. There is no packet loss on loopback.
	int opt = 2;
	int r = setsockopt(s, IPPROTO_TCP, TCP_SYNCNT, &opt, sizeof(opt));
	if (r < 0) {
		PFATAL("setsockopt()");
	}

	opt = 1;
	r = setsockopt(s, IPPROTO_IP, IP_TRANSPARENT, &opt, sizeof(opt));
	if (r < 0) {
		goto error;
	}

	/* We can live without SO_REUSEADDR. But, since we are doing
	 * bind-before-connect, the 5-tuple will go into  */
	r = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	if (r < 0) {
		goto error;
	}

	if (ipport(source_addr) == 0) {
		// IP_BIND_ADDRESS_NO_PORT is opportunistic, ignore the error
		opt = 1;
		setsockopt(s, IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT, &opt,
			   sizeof(opt));
	}

	r = setsockopt(s, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
	if (r < 0) {
		goto error;
	}

	if (ipfamily(target_addr) == AF_INET6) {
		opt = 0;
		setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt));
	}

	// Bind-before-connect to select source IP.
	r = bind(s, (struct sockaddr *)&source_addr, iplen(source_addr));
	if (r < 0) {
		goto error;
	}

	tcp_tune(s);

	r = connect(s, (struct sockaddr *)&target_addr, iplen(target_addr));
	if (r == 0 || errno != EINPROGRESS) {
		goto error;
	}

	r = fdwait(s, FDW_OUT, deadline);
	if (r == 0) {
		errno = ETIMEDOUT;
		goto fdclean_error;
	}

	int err;
	socklen_t errsz = sizeof(err);
	r = getsockopt(s, SOL_SOCKET, SO_ERROR, (void *)&err, &errsz);
	if (r != 0) {
		goto fdclean_error;
	}

	if (err != 0) {
		errno = err;
		goto fdclean_error;
	}

	return s;

fdclean_error:
	err = errno;
	fdclean(s);
	close(s);
	errno = err;
	return -1;

error:
	;
	err = errno;
	close(s);
	errno = err;
	return -1;
}

const char **parse_argv(const char *str, char delim)
{
	int str_len = strlen(str);
	int i, items = 1;
	for (i = 0; i < str_len; i++) {
		if (str[i] == delim) {
			items += 1;
		}
	}

	char **argv = malloc(sizeof(char *) * (items + 1) + str_len + 1);
	char *nstr = (char *)&argv[items + 1];
	memcpy(nstr, str, str_len + 1);

	char delim_s[2] = {delim, '\x00'};
	char *s = nstr, *saveptr = NULL, **a = argv;

	for (;; s = NULL) {
		char *token = strtok_r(s, delim_s, &saveptr);
		if (token == NULL)
			break;

		a[0] = token;
		a += 1;
	}
	*a = NULL;

	return (const char **)argv;
}

unsigned argv_len(const char **argv)
{
	int i;
	for (i = 0; argv[i]; i++)
		;
	return i;
}

int check_iptables(const char *rule)
{
	/* Reset the ENV before system() */
	clearenv();

	char cmd[1024];
	snprintf(cmd, sizeof(cmd), "/sbin/%s 2>/dev/null", rule);

	// assuming rules are INSERT ' -I '. Replace with " -C " check.
	char *p = strstr(cmd, " -I ");
	if (p == NULL) {
		return -1;
	}
	memcpy(p, " -C ", 4);

	int r = system(cmd);
	if (WIFEXITED(r)) {
		return WEXITSTATUS(r);
	}
	return -1;
}

int check_ip_rule(int ipv6, uint32_t mark, uint32_t table)
{
	/* Reset the ENV before system() */
	clearenv();

	char cmd[1024];
	snprintf(cmd, sizeof(cmd),
		 "/sbin/ip %srule list | fgrep -q 'fwmark 0x%x lookup %d'",
		 ipv6 ? "-6 " : "", mark, table);

	int r = system(cmd);
	if (WIFEXITED(r)) {
		return WEXITSTATUS(r);
	}
	return -1;
}

int check_ip_route(int ipv6, uint32_t table)
{
	/* Reset the ENV before system() */
	clearenv();

	char cmd[1024];
	snprintf(cmd, sizeof(cmd),
		 "/sbin/ip %sroute show table %d | fgrep -q default",
		 ipv6 ? "-6 " : "", table);

	int r = system(cmd);
	if (WIFEXITED(r)) {
		return WEXITSTATUS(r);
	}
	return -1;
}

int set_nofile_max()
{
	struct rlimit limit;
	int r = getrlimit(RLIMIT_NOFILE, &limit);
	if (r != 0) {
		return -1;
	}
	limit.rlim_cur = limit.rlim_max;
	r = setrlimit(RLIMIT_NOFILE, &limit);
	if (r == 0) {
		return limit.rlim_cur;
	}
	return -1;
}

char *read_text_file(const char *fname, int extra_bytes)
{
	int fd = open(fname, O_RDONLY);
	if (fd < 0) {
		PFATAL("open(%s)", fname);
	}

	struct stat stat;
	int r = fstat(fd, &stat);
	if (r < 0) {
		PFATAL("fstat(%s)", fname);
	}
	if (!S_ISREG(stat.st_mode)) {
		FATAL("fstat(%s): not a regular file", fname);
	}

	char *buf = malloc(stat.st_size + extra_bytes + 1);

	int n = read(fd, buf, stat.st_size + extra_bytes);
	if (n < 0) {
		PFATAL("read(%s, %lu) is %u", fname, stat.st_size, n);
	}
	close(fd);

	buf[n] = '\x00';

	return buf;
}

int read_subnets(const char *fname, network **ptr_networks,
		 int *ptr_networks_len)
{
	char *data = read_text_file(fname, 0);
	if (data == NULL) {
		return -1;
	}
	const char **lines = parse_argv(data, '\n');

	int lines_len = argv_len(lines);

	network *networks = calloc(sizeof(network), lines_len + 1);
	int networks_len = 0;
	char *reason = "";
	int i;
	for (i = 0; i < lines_len; i++) {
		char *line = (char *)lines[i];
		while (line[0] == ' ' || line[0] == '\t') {
			line++;
		}
		if (line[0] == '\x00' || line[0] == ';' || line[0] == '#') {
			continue;
		}
		char *slash = strchr(line, '/');
		if (slash == NULL) {
			reason = "Subnet like /32 not found";
			goto ignoreline;
		}
		*slash = '\x00';
		ipaddr addr = ipaddr_parse(line, 1);
		if (ipfamily(addr) == AF_UNSPEC) {
			char buf[256];
			snprintf(buf, sizeof(buf),
				 "Failed to parse IP address %s", line);
			reason = buf;
			goto ignoreline;
		}

		char *endptr;
		unsigned long prefix_len = strtoul(slash + 1, &endptr, 10);
		if (*endptr != '\x00' && *endptr != ' ' && *endptr != '\t' &&
		    *endptr != '\r') {
			reason = "Unknown character after subnet";
			goto ignoreline;
		}

		if ((ipfamily(addr) == AF_INET && prefix_len > 32) ||
		    (ipfamily(addr) == AF_INET6 && prefix_len > 128)) {
			reason = "Subnet value seems off";
			goto ignoreline;
		}

		networks[networks_len++] = net_make(addr, prefix_len);
		continue;
	ignoreline:
		fprintf(stderr,
			"[!] Parsing %s: line %d unrecognized, ingoring. %s\n",
			fname, i + 1, reason);
		continue;
	}

	free(data);
	free(lines);
	*ptr_networks = networks;
	*ptr_networks_len = networks_len;
	return 0;
}
