FROM gcc:7

RUN mkdir /mmproxy
WORKDIR /mmproxy

COPY ./ .

RUN make
RUN make cloudflare-ip-ranges.txt


FROM alpine:3
RUN apk add iptables ip6tables
COPY --from=0 /mmproxy/mmproxy .
COPY --from=0 /mmproxy/cloudflare-ip-ranges.txt .
RUN echo -e '0.0.0.0/0\n::/0' > all-networks.txt

ENTRYPOINT ["./mmproxy"]
