FROM alpine:3.20
RUN apk add --no-cache iptables iproute2 tcpdump
COPY acl.sh /acl.sh
RUN chmod +x /acl.sh
ENTRYPOINT ["/acl.sh"]
