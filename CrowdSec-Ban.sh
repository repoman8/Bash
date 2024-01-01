#!/bin/bash

## Truncates log files ##

truncate -s 0 /var/ossec/logs/custom-active-response/CrowdSec-Ban-IP6.log
truncate -s 0 /var/ossec/logs/custom-active-response/CrowdSec-Ban-IP4.log
truncate -s 0 /var/ossec/logs/custom-active-response/CrowdSec-Ban.log

## Parses out ipv6 and ipv4 addresses then runs the decisions add command while reading each address ##

ip6tables -S | egrep -o '(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]).){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]).){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))' | while read address ; do sudo cscli decisions add --ip "$address" --duration 240h --reason 'Wazuh Active Response - IoC found in Threat Intel' ; done | tee -a /var/ossec/logs/custom-active-response/CrowdSec-Ban-IP6.log

iptables -S | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}.*DROP' | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read address ;  do sudo cscli decisions add --ip "$address" --duration 240h --reason 'Wazuh Active Response - IoC found in Threat Intel' ; done | tee -a /var/ossec/logs/custom-active-response/CrowdSec-Ban-IP4.log

sudo cscli decisions list -o raw | tee -a /var/ossec/logs/custom-active-response/CrowdSec-Ban.log
