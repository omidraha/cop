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

host = raw_input("|- Enter ip(s)/domain(s) to kick off: ")

hosts = check_host_is_up(host, fast=False)

db = {}

for host in hosts:
    db[host] = {}

if hosts:
    print('|- Hosts are alive({}):'.format(len(hosts)))
    print('|\t\t\t{}'.format("\n|\t\t\t".join(hosts)))
else:
    print('|- Nothing to do !')
    exit()

print('|')

for host in db:
    dns_r = host_dns_reverse(host)
    db[host]['dns'] = dns_r
    print('|- Host: {:15} Dns reverse: {}'.format(host, dns_r or '-'))

print('|')

for host in db:
    # @todo adding seen whois list, according to net range
    whois = host_whois(host)
    db[host]['whois'] = whois
    print('|- Host: {:15} whois:'.format(host))
    print('|\t\t\t\t' + '\n|\t\t\t\t'.join(['{}: {}'.format(k, v \
        if type(v) == str else "-".join(v)) for k, v in whois.iteritems()]))

print('|')

for host in db:
    ports = host_port_discovery(host, fast=False)
    db[host]['ports'] = ports
    print('|- Host: {:15} Open Ports: {}'.format(host, ", ".join(ports or ['-'])))

print('|')

for host in db:
    os = host_os_detect(host, db[host]['ports'])
    db[host]['os'] = os
    print('|- Host: {:15} Os: {}'.format(host, ", ".join(os or ['-'])))

print('|')

for host in db:
    services = host_services_detect(host, db[host]['ports'])
    db[host]['services'] = services
    print('|- Host: {:15} services: {}'.format(host, services or ['-']))

print('|\n|\n|\n|- Here is a dump of db:')
pprint(db)
print("|\n|\n|- That's it.")

