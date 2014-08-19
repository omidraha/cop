#! /usr/bin/python
# @todo: change to command line arguments
from pprint import pprint
import settings
from net import check_host_is_up, host_port_discovery, host_os_detect, host_dns_reverse, \
    host_services_detect, host_whois
from utility import check_tools


print("+ Call Of Penetration Tool version 0.1")
tools_404 = check_tools()
if tools_404:
    print('|- Some tools, not found. at first call them !')
    print('|- Here is an list of them: {}'.format(",".join(tools_404)))
    exit()

ip = raw_input("|- Enter ip(s)/domain(s) to kick off: ")

ips = check_host_is_up(ip, fast=False)

db = {}

for ip in ips:
    db[ip] = {}

if ips:
    print('|- IPs are alive({}):'.format(len(ips)))
    print('|\t\t\t{}'.format("\n|\t\t\t".join(ips)))
else:
    print('|- Nothing to do !')
    exit()

print('|')

for ip in db:
    dns_r = host_dns_reverse(ip)
    db[ip]['dns'] = dns_r
    print('|- IP: {:15} Dns reverse: {}'.format(ip, dns_r or '-'))

print('|')

for ip in db:
    # @todo adding seen whois list, according to net range
    whois = host_whois(ip)
    db[ip]['whois'] = whois
    print('|- IP: {:15} whois:'.format(ip))
    print('|\t\t\t\t' + '\n|\t\t\t\t'.join(['{}: {}'.format(k, v \
        if type(v) == str else "-".join(v)) for k, v in whois.iteritems()]))

print('|')

for ip in db:
    ports = host_port_discovery(ip, fast=False)
    db[ip]['ports'] = ports
    print('|- IP: {:15} Open Ports: {}'.format(ip, ", ".join(ports or ['-'])))

print('|')

for ip in db:
    os = host_os_detect(ip, db[ip]['ports'])
    db[ip]['os'] = os
    print('|- IP: {:15} Os: {}'.format(ip, ", ".join(os or ['-'])))

print('|')

for ip in db:
    services = host_services_detect(ip, db[ip]['ports'])
    db[ip]['services'] = services
    print('|- IP: {:15} services: {}'.format(ip, services or ['-']))

print('|\n|\n|\n|- Here is a dump of db:')
pprint(db)
print("|\n|\n|- That's it.")

