#!/bin/bash

## Truncates log files ##

truncate -s 0 /var/ossec/logs/custom-active-response/Cloudflare-Ban-IP6.log
truncate -s 0 /var/ossec/logs/custom-active-response/Cloudflare-Ban-IP4.log

## Parses out ipv6 and ipv4 addresses then runs a curl command to post a block request to Cloudflare while reading each address ##

ip6tables -S | egrep -o '(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]).){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]).){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))' | while read address ; do curl -iv --raw -s -X POST "https://api.cloudflare.com/client/v4/user/firewall/access_rules/rules" -H "X-Auth-Email: <email>" -H "X-Auth-Key: <api>" -H "Content-Type: application/json" --data "{\"mode\":\"block\",\"configuration\":{\"target\":\"ip\",\"value\":\"$address\"},\"notes\":\"Wazuh Active Response - IoC found in Threat Intel\"}" | echo "Cloudflare-Ban.sh,Ip:"$address"" >> /var/ossec/logs/custom-active-response/Cloudflare-Ban-IP6.log ; done | tee -a /var/ossec/logs/custom-active-response/Cloudflare-Ban-Curl-IP6.log

iptables -S | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}.*DROP' | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read address ; do curl -iv --raw -s -X POST "https://api.cloudflare.com/client/v4/user/firewall/access_rules/rules" -H "X-Auth-Email: <email>" -H "X-Auth-Key: <api>" -H "Content-Type: application/json" --data "{\"mode\":\"block\",\"configuration\":{\"target\":\"ip\",\"value\":\"$address\"},\"notes\":\"Wazuh Active Response - IoC found in Threat Intel\"}" | echo "Cloudflare-Ban.sh,Ip:"$address"" >> /var/ossec/logs/custom-active-response/Cloudflare-Ban-IP4.log ; done | tee -a /var/ossec/logs/custom-active-response/Cloudflare-Ban-Curl-IP4.log
