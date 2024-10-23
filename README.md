MMPROXY
-------

mmproxy is a lightweight TCP proxy that serves exactly one purpose:
to smooth the transition of TCP servers to use proxy-protocol.

Usually, introducing TCP level load balancing introduces a significant
problem - the client source IP gets lost. From the application point
of view the inbound TCP connection is originated by load-balancer, not
the real client.

Proxy-protocol is an invention from Haproxy, that aims to solve this:

  - https://www.haproxy.com/blog/haproxy/proxy-protocol/

Proxy-protocol defines an exchange in which the first bytes
transmitted from the load balancer will describe the Client Source
IP. This is great, but applications must explicitly support
proxy-protocol to use it.

For many mature applications introducing proxy-protocol support is
hard. "mmproxy" is a workaround to help in this case.

mmproxy sits near the application, receives the proxy-protocol enabled
connections from the load balancer, spoofs the client IP addresses,
and sends traffic directly to the application. From application point
of view the traffic look identically like it would have originated
from the remote client.


Nomenclature
------------

In normal case the TCP client directly connects to application:

    Client --> Application

Here, application can use Client IP directly, without any
problem. Introducing proxy-protocol TCP load balancer breaks it
though. In such architecture application must support proxy-protocol:

    Client --> PP-enabled Load Balancer --> PP-enabled Application

mmproxy can remove the need of supporting proxy-protocol directly on
the TCP application:

    Client --> PP-enabled Load Balancer --> mmproxy --> Application

It's worth emphasizing that the traffic in last link (mmproxy -->
Application) will be source IP spoofed and MUST be delivered over
loopback.  In effect - mmproxy MUST run on the same machine as the
application.

Requirements
------------

mmproxy requires:

  - To be run on the very server which runs the
    application. Communication between mmproxy and the application
    must happen over loopback interface.
  - Root permissions. Alternatively - `CAP_NET_ADMIN` capability.
  - Linux Kernel at least 2.6.28.
  - Relatively unsophisticated iptables / routing setup.

How mmproxy works?
------------------

mmproxy uses two tricks to perform the source IP spoofing. First, it
uses an obscure Linux `IP_TRANSPARENT` socket option.  Originally was
designed to help building transparent proxies with Linux. We reuse
this feature to spoof source IPs. With it we can create sockets that
will send from arbitrary IP addresses.

Second, we must fix the outbound routing. By default Linux will route
the response packets to the default route (internet). To work around
we deploy a custom routing table, which forces the return traffic to
be routed to loopback.

1) If traffic is forwarded to the "lo" interface (127.0.0.1 / ::1 for example):

       # 1. Route packets from lo address and lo interface to table 100
       ip -4 rule add from 127.0.0.1/8 iif lo table 100
       ip -6 rule add from ::1/128 iif lo table 100

       # 2. In routing table=100 treat all IP addresses as bound to
       # loopback, and pass them to network stack for processing:
       ip route add local 0.0.0.0/0 dev lo table 100
       ip -6 route add local ::/0 dev lo table 100

2) Or, if traffic is forwarded to any other interface:

       # 1. Check if you have a default route for ipv4 / ipv6
       # if you don't have any default route response will be dropped before #4 & #5

       # 2. Enable route_localnet on your default interface
       # substitute "eth0" in the path below, if needed
       echo 1 > /proc/sys/net/ipv4/conf/eth0/route_localnet

       # 3. Save conntrack CONNMARK on packets sent with MARK 123.
       iptables -t mangle -I PREROUTING -m mark --mark 123 -m comment --comment mmproxy -j CONNMARK --save-mark
       ip6tables -t mangle -I PREROUTING -m mark --mark 123 -m comment --comment mmproxy -j CONNMARK --save-mark

       # 4. Restore MARK on packets belonging to connections with conntrack CONNMARK 123.
       iptables -t mangle -I OUTPUT -m connmark --mark 123 -m comment --comment mmproxy -j CONNMARK --restore-mark
       ip6tables -t mangle -I OUTPUT -m connmark --mark 123 -m comment --comment mmproxy -j CONNMARK --restore-mark

       # 5. Route packets with MARK 123 to routing table 100
       ip rule add fwmark 123 lookup 100
       ip -6 rule add fwmark 123 lookup 100

       # 6. In routing table=100 treat all IP addresses as bound to
       # loopback, and pass them to network stack for processing:
       ip route add local 0.0.0.0/0 dev lo table 100
       ip -6 route add local ::/0 dev lo table 100


Development
-----------


    git clone https://github.com/cloudflare/mmproxy.git
    cd mmproxy
    git submodule update --init
    make


Usage
-----

Help message:

```
./mmproxy  --help
Usage:

    mmproxy [ options ] --allowed-networks FILE -l LISTEN_ADDR -4 TARGET_V4_ADDR -6 TARGET_V6_ADDR

mmproxy binds to given TCP LISTEN_ADDR (default [::]:8080) and accepts
inbound TCP connections. The inbound connections MUST have a proxy-protocol
version 1 header, and MUST be originated from set of given source IP's.
The traffic will be magically spoofed to look like it came from real client IP.
 LISTEN_ADDR      Address to bind to. In form like [::]:8080
 TARGET_ADDR      Address to forward traffic to. In form like [::]:80
 --allowed-networks FILE Load allowed IP subnets from given file.
 --mark MARK      Set specific MARK on outbound packets. Needed to play with iptables.
 --table TABLE    Use specific routing table number in printed suggestion.
. --quiet          Don't print the iptables, routing and system tuning suggestions.
 --verbose        Print detailed logs on stdout.

This runs mmproxy on port 2222, unpacks the proxy-protocol header
and forwards the traffic to 127.0.0.1:22 on TCP:

    echo "0.0.0.0/0" > allowed-networks.txt
    mmproxy --allowed-networks allowed-networks.txt -l 0.0.0.0:2222 -4 127.0.0.1:22 -6 [::1]:22
```

Example run:
```
$ curl -s https://www.cloudflare.com/ips-v4 https://www.cloudflare.com/ips-v6 > networks.txt
$ sudo mmproxy -a networks.txt -l 0.0.0.0:2222 -4 127.0.0.1:22 -6 '[::1]:22'
[ ] Remember to set the reverse routing rules correctly:
iptables -t mangle -I PREROUTING -m mark --mark 123 -m comment --comment mmproxy -j CONNMARK --save-mark        # [+] VERIFIED
iptables -t mangle -I OUTPUT -m connmark --mark 123 -m comment --comment mmproxy -j CONNMARK --restore-mark     # [+] VERIFIED
ip6tables -t mangle -I PREROUTING -m mark --mark 123 -m comment --comment mmproxy -j CONNMARK --save-mark       # [+] VERIFIED
ip6tables -t mangle -I OUTPUT -m connmark --mark 123 -m comment --comment mmproxy -j CONNMARK --restore-mark    # [+] VERIFIED
ip rule add fwmark 123 lookup 100               # [+] VERIFIED
ip route add local 0.0.0.0/0 dev lo table 100   # [+] VERIFIED
ip -6 rule add fwmark 123 lookup 100            # [+] VERIFIED
ip -6 route add local ::/0 dev lo table 100     # [+] VERIFIED
[+] OK. Routing to 127.0.0.1 points to a local machine.
[+] OK. Target server 127.0.0.1:22 is up and reachable using conventional connection.
[+] OK. Target server 127.0.0.1:22 is up and reachable using spoofed connection.
[+] OK. Routing to ::1 points to a local machine.
[+] OK. Target server [::1]:22 is up and reachable using conventional connection.
[+] OK. Target server [::1]:22 is up and reachable using spoofed connection.
[+] Listening on 0.0.0.0:2222
```

Then you can locally test it with:

```
$ echo -en "PROXY TCP4 1.2.3.4 1.2.3.4 11 11\r\nHello World!" | nc -q3 -v 127.0.0.1 2222
```
