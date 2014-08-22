#! /usr/bin/python
# @todo: change to command line arguments
from pprint import pprint
import settings
from net import check_host_is_up, host_port_discovery, host_os_detect, host_reverse_dns_lookup, \
    host_services_detect, host_whois, host_name_server, host_dns_lookup, host_dns_zone_transfer, host_list
from utility import check_tools


print("+ Call Of Penetration Tool version 0.1")
tools_404 = check_tools()
if tools_404:
    print('|- Some tools, not found. at first call them !')
    print('|- Here is an list of them: {}'.format(",".join(tools_404)))
    exit()

input_host = raw_input("|- Enter ip(s)/domain(s) to kick off: ")

ips, domains = host_list(input_host)

hosts = ips + domains

db = {'ips': {}, 'domains': {}}


def get_domain(ip):
    for domain in db['domains']:
        for each_ip in db['domains'][domain]['dns_lookup']:
            if each_ip == ip:
                return domain


if domains:
    print('|* Performing DNS Lookup ...')
    for domain in domains:
        dns_lookup = host_dns_lookup(domain)
        if dns_lookup:
            db['domains'][domain] = {'dns_lookup': dns_lookup}
            print('|-   {:20}  {}'.format(domain, " ".join(dns_lookup) or '-'))

print('|* Host alive checking ...')
alive_ips = check_host_is_up(hosts, fast=False)
if alive_ips:
    len_host = len(alive_ips)
    for ip in alive_ips:
        db['ips'][ip] = {}
        print('|-   {:20}'.format(get_domain(ip) or ip))
    print('|-   {} Host{} up.'.format(len_host, 's' if len_host > 1 else ''))
else:
    print('|- Nothing to do !')
    exit()

print('|')
print('|* Performing Reverse DNS Lookup ...')
for ip in db['ips']:
    dns_r = host_reverse_dns_lookup(ip)
    if dns_r:
        db['ips'][ip]['reverse_dns_lookup'] = dns_r
        print('|-   {:20}  {}'.format(ip, dns_r or '-'))

print('|')
print('|* Getting Name Server records ...')
for domain in db['domains']:
    ns = host_name_server(domain)
    db['domains'][domain]['ns'] = ns
    print('|-   {:20}  {}'.format(domain, ", ".join(ns or ['-'])))

print('|')
print('|* DNS Zone Transfer  Checking ...')
for domain in db['domains']:
    dtz = host_dns_zone_transfer(domain)
    db['domains'][domain]['dtz'] = dtz
    if dtz:
        print('|-   {:20}'.format(domain))
        for ns, t, v in dtz:
            print('|-     \t{:30}\t{}\t{}'.format(ns, t, v))

print('|')
print('|* Whois IP ...')
for ip in db['ips']:
    # @todo adding seen whois list, according to net range
    whois = host_whois(ip)
    db['ips'][ip]['whois'] = whois
    print('|-   {:20} '.format(ip))
    print('|  \t\t\t\t' + '\n|\t\t\t\t'.join(['{}: {}'.format(k, v \
        if type(v) == str else "-".join(v)) for k, v in whois.iteritems()]))

print('|')
print('|* Discover open ports ...')
for ip in db['ips']:
    ports = host_port_discovery(ip, fast=False)
    db['ips'][ip]['ports'] = ports
    print('|-   {:20}  {}'.format(ip, ", ".join(ports or ['-'])))

print('|')
print('|* Detect os ...')
for ip in db['ips']:
    os = host_os_detect(ip, db['ips'][ip]['ports'])
    db['ips'][ip]['os'] = os
    print('|-   {:20}  {}'.format(ip, ", ".join(os or ['-'])))

print('|')
print('|* Detect services ...')
for ip in db['ips']:
    services = host_services_detect(ip, db['ips'][ip]['ports'])
    db['ips'][ip]['services'] = services
    print('|  - {:20}  {}'.format(ip, services or ['-']))

print('|\n|\n|\n|- Here is a dump of db:')
pprint(db)
print("|\n|\n|- That's it.")

