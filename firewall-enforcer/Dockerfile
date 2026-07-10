FROM alpine:3.20

RUN apk add --no-cache curl ipset iptables jq

COPY firewall-enforcer/enforce-ip-bans.sh /usr/local/bin/enforce-ip-bans.sh
RUN chmod +x /usr/local/bin/enforce-ip-bans.sh

ENTRYPOINT ["/usr/local/bin/enforce-ip-bans.sh"]
