#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <seccomp.h>
#include <libmill.h>

#include "mmproxy.h"

struct state
{
	int verbose;
	int quiet;
	int do_not_sandbox;
	int force_real_client_port;

	ipaddr remote_v4_addr;
	ipaddr remote_v6_addr;

	uint32_t mark;
	uint32_t table;

	network *allowed_networks;
	int allowed_networks_len;
};

#define BUF_SIZE 8192
coroutine void do_proxy_half_duplex(int a, int b, chan ch)
{
	int err = 0;
	while (1) {
		char buf[BUF_SIZE];
		int more = 0;
		size_t nbytes = tcprecvpkt(a, buf, sizeof(buf), -1, &more);
		if (errno != 0) {
			err = errno;
			goto out;
		}

		size_t p = 0;
		while (p < nbytes) {
			size_t r = tcpsendpkt(b, &buf[p], nbytes - p, -1, more);
			if (errno != 0) {
				err = errno;
				goto out;
			}
			p += r;
		}
	}
out:
	if (err == ECONNRESET) {
		shutdown(a, SHUT_RDWR);
		shutdown(b, SHUT_RDWR);
	} else {
		shutdown(a, SHUT_RD);
		shutdown(b, SHUT_WR);
	}
	chs(ch, int, err);
}

coroutine void new_connection(int cd, struct state *state)
{
	char lstr[IPADDR_MAXSTRLEN + 7];
	ipaddrstr_port(peername(cd), lstr);

	if (net_find_match(state->allowed_networks, state->allowed_networks_len,
			   peername(cd)) == 0) {
		printf("[?] %s is not allowed to connect\n", lstr);
		fdclean(cd);
		close(cd);
		return;
	}

	char buf[256];
	size_t rbytes = tcprecvpkt(cd, buf, sizeof(buf), -1, NULL);
	if (errno != 0) {
		printf("[?] %s broke without proxy-protocol header\n", lstr);
		fdclean(cd);
		close(cd);
		return;
	}

	/* Chop buf on \r\n. */

	char *nl = memchr(buf, '\n', rbytes);
	if (nl == NULL) {
		goto parseerror;
	}

	size_t nbytes = nl - buf;
	if (nbytes == 0 || buf[nbytes - 1] != '\r' || buf[nbytes] != '\n') {
		goto parseerror;
	}

	buf[nbytes - 1] = '\0';
	buf[nbytes] = '\0';

	const char **words = parse_argv(buf, ' ');
	if (strcasecmp(words[0], "PROXY") != 0) {
		goto parseerror;
	}

	const char *port = "0";
	if (state->force_real_client_port) {
		port = words[4];
	}

	char addr_buf[256];
	ipaddr remote_addr;
	if (strcasecmp(words[1], "TCP4") == 0) {
		remote_addr = state->remote_v4_addr;
		if (ipfamily(remote_addr) == AF_INET) {
			snprintf(addr_buf, sizeof(addr_buf), "%s:%s", words[2],
				 port);
		} else {
			snprintf(addr_buf, sizeof(addr_buf), "[::ffff:%s]:%s",
				 words[2], port);
		}
	} else if (strcasecmp(words[1], "TCP6") == 0) {
		remote_addr = state->remote_v6_addr;
		snprintf(addr_buf, sizeof(addr_buf), "[%s]:%s", words[2], port);
	} else {
		goto parseerror;
	}

	char rstr[IPADDR_MAXSTRLEN + 7];
	ipaddrstr_port(remote_addr, rstr);

	ipaddr client_addr = ipaddr_parse(addr_buf, 0);
	if (errno != 0) {
		goto parseerror;
	}

	printf("[+] %s connected, proxy protocol source %s, local destination "
	       "%s\n",
	       lstr, ipaddrstr_port(client_addr, NULL), rstr);
	int rs = tcpconnect_spoofed(client_addr, remote_addr, -1, state->mark);
	if (rs < 0) {
		printf("[-] %s to %s failed %s\n", lstr, rstr, strerror(errno));
		fdclean(cd);
		close(cd);
		return;
	}
	int err = 0;
	if (nbytes + 1 < rbytes) {
		/* Some bytes left */
		/* TODO: potentially blocking */
		size_t r = send(rs, &buf[nbytes + 1], rbytes - (nbytes + 1),
				MSG_WAITALL);
		if (r != rbytes - (nbytes + 1)) {
			err = errno;
			goto disconnected;
		}
	}

	chan ch = chmake(int, 2);
	go(do_proxy_half_duplex(cd, rs, ch));
	do_proxy_half_duplex(rs, cd, ch);
	err = chr(ch, int);
	chr(ch, int);

disconnected:
	fdclean(cd);
	close(cd);
	fdclean(rs);
	close(rs);
	printf("[-] %s disconnected: %s\n", lstr, strerror(err));
	return;

parseerror:
	printf("[?] %s broke with bad proxy-protocol header\n", lstr);
	fdclean(cd);
	close(cd);
	return;
}

void do_accept(tcpsock sd, struct state *state)
{
	while (1) {
		tcpsock cd = tcpaccept(sd, -1);
		if (errno != 0) {
			if (errno == EMFILE) {
				msleep(now() + 200);
				continue;
			}
			break;
		}

		go(new_connection(tcpsock_fd(cd), state));
	}
}

static void usage()
{
	char *fmt =
		"Usage:\n"
		"\n"
		"    mmproxy [ options ] --allowed-networks FILE -l "
		"LISTEN_ADDR "
		"-4 TARGET_V4_ADDR -6 TARGET_V6_ADDR\n"
		"\n"
		"mmproxy binds to given TCP LISTEN_ADDR (default [::]:8080) "
		"and accepts\n"
		"inbound TCP connections. The inbound connections MUST have a "
		"proxy-protocol\n"
		"version 1 header, and MUST be originated from set of given "
		"source IP's.\n"
		"The traffic will be magically spoofed to look like it came "
		"from real client IP.\n"
		""
		" LISTEN_ADDR      Address to bind to. In form like [::]:8080\n"
		" TARGET_ADDR      Address to forward traffic to. In form like "
		"[::]:80\n"
		" --allowed-networks FILE Load allowed IP subnets from given "
		"file.\n"
		" --mark MARK      Set specific MARK on outbound packets. "
		"Needed to play with iptables.\n"
		" --table TABLE    Use specific routing table number in "
		"printed suggestion\n."
		" --quiet          Don't print the iptables, routing and "
		"system tuning suggestions.\n"
		" --verbose        Print detailed logs on stdout.\n"
		"\n"
		"This runs mmproxy on port 2222, unpacks the proxy-protocol "
		"header\n"
		"and forwards the traffic to 127.0.0.1:22 on TCP:\n"
		"\n"
		"    echo \"0.0.0.0/0\" > allowed-networks.txt\n"
		"    mmproxy --allowed-networks allowed-networks.txt "
		"-l 0.0.0.0:2222 -4 127.0.0.1:22 -6 [::1]:22\n"
		"\n";
	fprintf(stderr, "%s", fmt);
	exit(-1);
}

int main(int argc, char *argv[])
{
	/* Reset the ENV since we call system() later. We don't use environment
	 * vars anyway. */
	clearenv();

	static struct option long_options[] = {
		{"allowed-networks", required_argument, 0, 'a'},
		{"mark", required_argument, 0, 'm'},
		{"table", required_argument, 0, 't'},
		{"quiet", no_argument, 0, 'q'},
		{"verbose", no_argument, 0, 'v'},
		{"do-not-sandbox", no_argument, 0, 'N'},
		{"force-real-client-port", no_argument, 0, 'P'},
		{"help", no_argument, 0, 'h'},
		{"listen", required_argument, 0, 'l'},
		{"target-v4", required_argument, 0, '4'},
		{"target-v6", required_argument, 0, '6'},
		{NULL, 0, 0, 0}};

	const char *optstring = optstring_from_long_options(long_options);

	struct state *state = calloc(1, sizeof(struct state));
	state->mark = 123;
	state->table = 100;
	ipaddr listen_addr = {{0}};
	const char *networks_fname = NULL;

	while (1) {
		char *endptr = NULL;

		int arg =
			getopt_long(argc, argv, optstring, long_options, NULL);
		if (arg == -1) {
			break;
		}

		switch (arg) {
		default:
		case 0:
			FATAL("Unknown option %c: \"%s\"", arg, argv[optind]);
			break;

		case '?':
			exit(-1);
			break;

		case 'h':
			usage();
			break;

		case 'a':
			networks_fname = optarg;
			break;

		case 'q':
			state->quiet++;
			break;

		case 'N':
			state->do_not_sandbox++;
			break;

		case 'P':
			state->force_real_client_port++;
			break;

		case 'v':
			state->verbose++;
			break;

		case 'm':
			state->mark = (uint32_t)strtol(optarg, &endptr, 10);
			break;

		case 't':
			state->table = (uint32_t)strtol(optarg, &endptr, 10);
			break;

		case 'l':
			listen_addr = ipaddr_parse(optarg, 0);
			if (errno != 0) {
				FATAL("%s is not a valid listen address",
				      optarg);
			}
			break;

		case '4':
			state->remote_v4_addr = ipaddr_parse(optarg, 0);
			if (errno != 0) {
				FATAL("%s is not a valid target address",
				      optarg);
			}
			break;

		case '6':
			state->remote_v6_addr = ipaddr_parse(optarg, 0);
			if (errno != 0) {
				FATAL("%s is not a valid target address",
				      optarg);
			}
			break;
		}
	}

	if (optind != argc) {
		FATAL("No extra parameters allowed.");
	}

	ipaddr zero = {{0}};
	if (memcmp(&listen_addr, &zero, sizeof(zero)) == 0) {
		FATAL("Please specify -l listen address. Like: -l "
		      "0.0.0.0:1234");
	}
	if (memcmp(&state->remote_v4_addr, &zero, sizeof(zero)) == 0) {
		FATAL("Please specify -4 target ipv4 address. Like: -4 "
		      "127.0.0.1:22");
	}
	if (memcmp(&state->remote_v6_addr, &zero, sizeof(zero)) == 0) {
		FATAL("Please specify -6 target address. Like: -6 [::1]:22");
	}

	if (networks_fname == NULL) {
		FATAL("Please specify --allowed-networks filename, like:\n"
		      "\techo \"0.0.0.0/0\" > allowed-networks.txt\n"
		      "\t%s --allowed-networks allowed-networks.txt ...\n",
		      argv[0]);
	}

	int r = read_subnets(networks_fname, &state->allowed_networks,
			     &state->allowed_networks_len);
	if (r != 0) {
		FATAL("Failed to load --allowed-networks file %s",
		      networks_fname);
	}

	set_nofile_max();

	if (state->quiet == 0) {
		fprintf(stderr,
			"[ ] Remember to set the reverse routing rules "
			"correctly:\n");
		char rules[][256] = {
			"iptables -t mangle -I PREROUTING -m mark --mark %u -m "
			"comment --comment mmproxy -j CONNMARK --save-mark",
			"iptables -t mangle -I OUTPUT -m connmark --mark %u -m "
			"comment --comment mmproxy -j CONNMARK --restore-mark",
			"ip6tables -t mangle -I PREROUTING -m mark --mark %u "
			"-m comment --comment mmproxy -j CONNMARK --save-mark",
			"ip6tables -t mangle -I OUTPUT -m connmark --mark %u "
			"-m comment --comment mmproxy -j CONNMARK "
			"--restore-mark",
		};
		int i;
		for (i = 0; i < 4; i++) {
			char rule[1024];
			snprintf(rule, sizeof(rule), rules[i], state->mark);
			fprintf(stderr, "%s\t# %s\n", rule,
				check_iptables(rule) == 0 ? "[+] VERIFIED"
							  : "[!] CHECK FAILED");
		}

		fprintf(stderr, "ip rule add fwmark %d lookup %d\t\t# %s\n",
			state->mark, state->table,
			check_ip_rule(0, state->mark, state->table) == 0
				? "[+] VERIFIED"
				: "[!] CHECK FAILED");
		fprintf(stderr,
			"ip route add local 0.0.0.0/0 dev lo table %u\t# %s\n",
			state->table, check_ip_route(0, state->table) == 0
					      ? "[+] VERIFIED"
					      : "[!] CHECK FAILED");

		fprintf(stderr, "ip -6 rule add fwmark %d lookup %d\t\t# %s\n",
			state->mark, state->table,
			check_ip_rule(1, state->mark, state->table) == 0
				? "[+] VERIFIED"
				: "[!] CHECK FAILED");
		fprintf(stderr,
			"ip -6 route add local ::/0 dev lo table %u\t# %s\n",
			state->table, check_ip_route(1, state->table) == 0
					      ? "[+] VERIFIED"
					      : "[!] CHECK FAILED");
	}

	ipaddr targets[2];
	int targets_len = 1;
	targets[0] = state->remote_v4_addr;

	if (memcmp(&state->remote_v4_addr, &state->remote_v6_addr,
		   sizeof(ipaddr)) != 0) {
		targets_len = 2;
		targets[1] = state->remote_v6_addr;
	}

	int t;
	for (t = 0; t < targets_len; t++) {
		ipaddr target_addr = targets[t];
		int r = check_ip_route_get_local(target_addr);
		if (r != 0) {
			fprintf(stderr,
				"[!] FAILED: Target %s isn't on a local "
				"machine. This "
				"program will likely NOT WORK.\n",
				ipaddrstr_noport(target_addr, NULL));
		} else {
			fprintf(stderr,
				"[+] OK. Routing to %s points to a local "
				"machine.\n",
				ipaddrstr_noport(target_addr, NULL));
		}

		r = check_direct_connect(target_addr);
		if (r < 0 && errno == ECONNREFUSED) {
			fprintf(stderr,
				"[!] FAILED: Target server %s seems to be "
				"down. This "
				"program will likely NOT WORK.\n",
				ipaddrstr_port(target_addr, NULL));
		} else if (r < 0) {
			fprintf(stderr,
				"[!] FAILED: Unable to connect() to target "
				"server %s. "
				"Error: %s. This program will likely NOT "
				"WORK.\n",
				ipaddrstr_port(target_addr, NULL),
				strerror(errno));
		} else {
			fprintf(stderr,
				"[+] OK. Target server %s is up and reachable "
				"using "
				"conventional connection.\n",
				ipaddrstr_port(target_addr, NULL));
		}

		ipaddr fake_source_addr;
		if (ipfamily(target_addr) == AF_INET) {
			fake_source_addr = ipaddr_parse("192.0.2.1", 1);
		} else {
			fake_source_addr = ipaddr_parse("[2001:0db8::1]", 1);
		}

		r = check_spoofed_connect(fake_source_addr, target_addr,
					  state->mark);
		if (r == -2) {
			PFATAL("Can't set IP_TRANSPARENT socket flag.\n"
			       "\tPerhaps it's a permissions problem. Are you "
			       "root or "
			       "have CAP_NET_ADMIN capability?\n");
		} else if (r < 0 && errno == ECONNREFUSED) {
			fprintf(stderr,
				"[!] FAILED: Target server %s seems to be "
				"down. This "
				"program will likely NOT WORK.\n",
				ipaddrstr_port(target_addr, NULL));
		} else if (r < 0) {
			fprintf(stderr,
				"[!] FAILED: Unable to do spoofed connect() to "
				"target "
				"server %s. This program will likely NOT "
				"WORK.\n",
				ipaddrstr_port(target_addr, NULL));
			fprintf(stderr,
				"[!] FAILED: Check if iptables and routing are "
				"set "
				"correctly!\n");
			if (ipfamily(target_addr) == AF_INET) {
				fprintf(stderr,
					"[!] FAILED: Also make sure you have a "
					"\"route_localhost\" "
					"set on outbound interface, like:\n");
				fprintf(stderr,
					"echo 1 | sudo tee "
					"/proc/sys/net/ipv4/conf/eth0/"
					"route_localnet\n");
			} else {
				fprintf(stderr,
					"[!] FAILED: Also make sure you have a "
					"valid "
					"IPv6 default route set!\n");
			}
		} else {
			fprintf(stderr,
				"[+] OK. Target server %s is up and reachable "
				"using "
				"spoofed connection.\n",
				ipaddrstr_port(target_addr, NULL));
		}
	}

	if (state->allowed_networks_len == 0) {
		fprintf(stderr,
			"[ ] No allowed networks. All inbound traffic "
			"dropped.\n");
	} else {
		fprintf(stderr,
			"[ ] Allowing only proxy-protocol enabled traffic from "
			"these subnets:\n");
		int i;
		for (i = 0; i < state->allowed_networks_len; i++) {
			fprintf(stderr, "%s\n",
				net_str(state->allowed_networks[i]));
		}
	}

	fprintf(stderr, "[+] Listening on %s\n",
		ipaddrstr_port(listen_addr, NULL));
	tcpsock sd = tcplisten(listen_addr, 1024);
	if (errno != 0) {
		PFATAL("Failed to bind to %s\n",
		       ipaddrstr_port(listen_addr, NULL));
	}

	/* Setup seccomp */
	if (state->do_not_sandbox == 0) {
		scmp_filter_ctx ctx;
		ctx = seccomp_init(SCMP_ACT_KILL);

#define ALLOW(syscall)                                                         \
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(syscall), 0)

		ALLOW(rt_sigreturn);
		ALLOW(rt_sigaction);
		ALLOW(exit);
		ALLOW(exit_group);
		ALLOW(read);
		ALLOW(write);
		ALLOW(close);

		ALLOW(clock_gettime);
		ALLOW(getsockopt);
		ALLOW(setsockopt);
		ALLOW(ioctl);
		ALLOW(fcntl);
		ALLOW(fstat);

		ALLOW(getrlimit);
		ALLOW(prlimit64);
		ALLOW(mmap);
		ALLOW(brk);
		ALLOW(mprotect);
		ALLOW(munmap);

		ALLOW(send);
		ALLOW(sendto);
		ALLOW(recv);
		ALLOW(recvfrom);

		ALLOW(epoll_create);
		ALLOW(epoll_ctl);
		ALLOW(epoll_wait);
		ALLOW(epoll_pwait);
		ALLOW(accept);
		ALLOW(accept4);
		ALLOW(getpeername);
		ALLOW(bind);
		ALLOW(socket);
		ALLOW(connect);
		ALLOW(shutdown);
#undef ALLOW
		seccomp_load(ctx);
	} else {
		fprintf(stderr, "[!] Seccomp sandbox is disabled\n");
	}

	/* Forever */
	do_accept(sd, state);

	return 0;
}
