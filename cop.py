#! /usr/bin/python
# @todo: change to command line arguments
import os
from pprint import pprint
from apps.dns import host_dns_lookup, host_name_server, host_dns_zone_transfer, host_reverse_dns_lookup, \
    host_dns_wildcard, host_dns_any_query, host_dnssec
from apps.info import host_whois

from apps.net import check_host_is_up, host_port_discovery, host_os_detect, \
    host_services_detect, host_list
from apps.utility import check_tools


def print_header(text):
    print('\033[1;34m|*\033[1;m {}'.format(text))


print("\033[1;32m|+\033[1;m Call Of Penetration Tool version 0.1")
tools_404 = check_tools()
if tools_404:
    print('|- Some tools, not found. at first call them !')
    print('|- Here is an list of them: {}'.format(",".join(tools_404)))
    exit()
if os.geteuid() != 0:
    print('|- You need power of root permissions to do this !')
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
    for each_ip in db['ips']:
        if each_ip == ip:
            return db['ips'][each_ip].get('reverse_dns_lookup')


print_header('Host alive checking ...')
alive_ips = check_host_is_up(input_host, fast=False)
if alive_ips:
    len_host = len(alive_ips)
    for ip in alive_ips:
        db['ips'][ip] = {}
        print('|-   {:20}'.format(get_domain(ip) or ip))
    print('|-   {} Host{} up.'.format(len_host, 's' if len_host > 1 else ''))
else:
    print('|- Nothing to do !')
    exit()

if domains:
    print_header('Performing DNS Lookup ...')
    for domain in domains:
        dns_lookup = host_dns_lookup(domain)
        if dns_lookup:
            db['domains'][domain] = {'dns_lookup': dns_lookup}
            print('|-   {:20}  {}'.format(domain, " ".join(dns_lookup) or '-'))

print('|')
print_header('Reverse DNS Lookup ...')
for ip in db['ips']:
    dns_r = host_reverse_dns_lookup(ip)
    if dns_r:
        db['ips'][ip]['reverse_dns_lookup'] = dns_r
        print('|-   {:16}  {}'.format(ip, dns_r or '-'))

print('|')
print_header('Getting Name Server records ...')
for domain in db['domains']:
    ns = host_name_server(domain)
    db['domains'][domain]['ns'] = ns
    if ns:
        print('|-   {:20}  {}'.format(domain, ", ".join(ns or ['-'])))

print('|')
print_header('Getting any type of ns record information ...')
for domain in db['domains']:
    dns_any_r = host_dns_any_query(domain)
    db['domains'][domain]['dns_any_records'] = dns_any_r
    if dns_any_r:
        for ns, t, v in dns_any_r:
            print('|-     \t{:35}\t{}\t{}'.format(ns, t, v))

print('|')
print_header('Checking DNSSEC ...')
for domain in db['domains']:
    dnssec = host_dnssec(domain)
    db['domains'][domain]['dnssec'] = dnssec
    if dnssec:
        for ns, t, v in dnssec:
            print('|-     \t{:35}\t{}\t{}'.format(ns, t, v))

print('|')
print_header('Checking Wildcard DNS ...')
for domain in db['domains']:
    wildcard_dns = host_dns_wildcard(domain)
    db['domains'][domain]['wildcard_dns'] = wildcard_dns
    if wildcard_dns:
        for ns, t, v in wildcard_dns:
            print('|-     \t{:35}\t{}\t{}'.format(ns, t, v))

print('|')
print_header('DNS Zone Transfer Checking ...')
for domain in db['domains']:
    dtz = host_dns_zone_transfer(domain)
    db['domains'][domain]['dtz'] = dtz
    if dtz:
        print('|- {:20}'.format(domain))
        for ns, t, v in dtz:
            print('|- \t{:30}\t{}\t{}'.format(ns, t, v))

print('|')
print_header('Whois IP ...')
for ip in db['ips']:
    # @todo adding seen whois list, according to net range
    whois = host_whois(ip)
    db['ips'][ip]['whois'] = whois
    d = get_domain(ip)
    print('|-   {:16}{}\n|'.format(ip, '({})'.format(d) if d else ''))
    print('|  \t\t\t\t' + '\n|\t\t\t\t'.join(['{}: {}'.format(k, v \
        if type(v) == str else "-".join(v)) for k, v in whois.iteritems()]) + '\n|')

print('|')
print_header('Discover open ports ...')
for ip in db['ips']:
    ports = host_port_discovery(ip, fast=True)
    db['ips'][ip]['ports'] = ports
    d = get_domain(ip)
    print('|-   {:16}{}  TCP:{}   UDP:{}'.format(ip, '({})'.format(d) if d else '', ", ".join(ports['tcp'] or ['-']),
                                                 ", ".join(ports['udp'] or ['-'])))

print('|')
print_header('Detect os ...')
for ip in db['ips']:
    os = host_os_detect(ip, db['ips'][ip]['ports'])
    db['ips'][ip]['os'] = os
    d = get_domain(ip)
    print('|-   {:16}{}  {}'.format(ip, '({})'.format(d) if d else '', ", ".join(os or ['-'])))

print('|')
print_header('Detect services ...')
for ip in db['ips']:
    services = host_services_detect(ip, db['ips'][ip]['ports'])
    db['ips'][ip]['services'] = services
    d = get_domain(ip)
    print('|  - {:16}{}  {}'.format(ip, '({})'.format(d) if d else '', services or ['-']))

print('|\n|\n|\n|- Here is a dump of db:')
pprint(db)
print("|\n|\n|- That's it.")

