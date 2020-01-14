#!/bin/bash
#

cat http.log | jq '.[] | select([.uri, .user_agent, .username, .host] | add | match("\\.[\\|]?\\./|<script|() {|'\'' |/etc/")) | {ip: .["id.orig_h"], user_agent: .user_agent}' > malicious_hosts.json

(
    IFS=$'\n'
    for i in `cat malicious_hosts.json | jq '.user_agent'` ; do
	ip_list=$(cat http.log | jq ".[] | select(.user_agent==${i}) | .[\"id.orig_h\"]")
	[ `echo "${ip_list}" | wc -l` -lt 8 ] && echo "${ip_list}"
    done

    cat malicious_hosts.json | jq '.ip'
) | tr -d '"' | sort -uV | tee malicious_ip_extended.txt

