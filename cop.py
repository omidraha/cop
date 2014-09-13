#! /usr/bin/python
# -*- coding: utf8
# @todo: change to command line arguments
import os
from pprint import pprint
from apps.bf import bf_sub_domains
from apps.dns import host_dns_lookup, host_name_server, host_dns_zone_transfer, host_reverse_dns_lookup, \
    host_dns_wildcard, host_dns_any_query, host_dnssec, host_dns_check_allow_recursion, get_name_server_bind_version
from apps.info import host_whois

from apps.net import check_host_is_up, host_port_discovery, host_os_detect, \
    host_services_detect, host_list, get_ports, get_ports_count
from apps.utility import check_tools, print_line
import settings


def cop_logo():
    print_line("""
|  ╔═╗╔═╗╔═╗  ┬
|  ║  ║ ║╠═╝  │
|  ╚═╝╚═╝╩    o
|  Call Of Penetration Tool version 0.1
|   """, pre='', tail=False)


if settings.SHOW_LOGO:
    cop_logo()
else:
    print_line('Call Of Penetration Tool version 0.1')

tools_404 = check_tools()

if tools_404:
    print_line('Some tools, not found. at first call them !', pre='|-')
    print_line('Here is an list of them: {}'.format(",".join(tools_404)), pre='|-')
    exit()
if os.geteuid() != 0:
    print_line('You need power of root permissions to do this !', pre='|-')
    exit()

print_line('Enter ip(s)/domain(s) to kick off: ', pre='|+', end='', wrap=False)
input_host = raw_input()

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


print_line('Host alive checking ...', pre='|*')
alive_ips = check_host_is_up(input_host, fast=False)

if alive_ips:
    len_host = len(alive_ips)
    for ip in alive_ips:
        db['ips'][ip] = {}
        print_line('{}'.format(get_domain(ip) or ip), color_code=195, tab=1)
    print_line('{} Host{} up.'.format(len_host, 's' if len_host > 1 else ''), color_code=195, tab=1)
else:
    print_line(' Nothing to do !')
    exit()

if domains:
    print_line('Performing DNS lookup ...', pre='|*')
    for domain in domains:
        dns_lookup = host_dns_lookup(domain)
        if dns_lookup:
            db['domains'][domain] = {'dns_lookup': dns_lookup}
            print_line(domain, color_code=87, tab=1)
            print_line(dns_lookup, color_code=195, tab=2)

print_line('Reverse DNS lookup ...', pre='|*')
for ip in db['ips']:
    dns_r = host_reverse_dns_lookup(ip)
    if dns_r:
        db['ips'][ip]['reverse_dns_lookup'] = dns_r
        print_line(ip, color_code=87, tab=1)
        print_line(dns_r, color_code=195, tab=2)

print_line('Getting name server records ...', pre='|*')
for domain in db['domains']:
    ns = host_name_server(domain)
    if ns:
        db['domains'][domain]['name_servers'] = ns
        print_line(domain, color_code=87, tab=1)
        print_line(ns, color_code=195, tab=2)

print_line('Getting name servers bind version ...', pre='|*')
for domain in db['domains']:
    for ns in db['domains'][domain].get('name_servers', []):
        bind_version = get_name_server_bind_version(ns)
        if bind_version:
            db['domains'][domain].setdefault('name_servers_version', {})[ns] = bind_version
    ns_version = db['domains'][domain].get('name_servers_version')
    if ns_version:
        print_line(domain, color_code=87, tab=1)
        print_line(ns_version, color_code=195, tab=2)

print_line('Getting any type of ns record information ...', pre='|*')
for domain in db['domains']:
    dns_any_r = host_dns_any_query(domain)
    if dns_any_r:
        db['domains'][domain]['dns_any_records'] = dns_any_r
        print_line(domain, color_code=87, tab=1)
        print_line(dns_any_r, color_code=195, tab=2)

print_line('Checking DNS allow recursion ...', pre='|*')
for domain in db['domains']:
    ns = db['domains'][domain].get('name_servers')
    dr = host_dns_check_allow_recursion(domain, ns)
    if dr:
        db['domains'][domain]['dr'] = dr
        print_line(domain, color_code=87, tab=1)
        print_line(dr, color_code=195, tab=2)

print_line('Checking DNSSEC ...', pre='|*')
for domain in db['domains']:
    dnssec = host_dnssec(domain)
    if dnssec:
        db['domains'][domain]['dnssec'] = dnssec
        print_line(domain, color_code=87, tab=1)
        print_line(dnssec, color_code=195, tab=2)

print_line('Checking wildcard DNS ...', pre='|*')
for domain in db['domains']:
    wc_dns = host_dns_wildcard(domain)
    if wc_dns:
        db['domains'][domain]['wc_dns'] = wc_dns
        print_line(domain, color_code=87, tab=1)
        print_line(wc_dns, color_code=195, tab=2)

print_line('DNS zone transfer checking ...', pre='|*')
for domain in db['domains']:
    ns = db['domains'][domain].get('name_servers')
    dtz = host_dns_zone_transfer(domain, ns)
    if dtz:
        db['domains'][domain]['dtz'] = dtz
        print_line(domain, color_code=87, tab=1)
        print_line(dtz, color_code=195, tab=2)

print_line('Whois IP ...', pre='|*')
for ip in db['ips']:
    whois = host_whois(ip)
    if whois:
        db['ips'][ip]['whois'] = whois
        d = get_domain(ip)
        print_line('{} {}'.format(ip, '({})'.format(d) if d else ''), color_code=87, tab=1)
        print_line(whois, color_code=195, tab=2)

print_line('Discover open ports ...', pre='|*')
for ip in db['ips']:
    ports = host_port_discovery(ip, fast=True)
    if ports:
        db['ips'][ip]['ports'] = ports
        open_ports = get_ports(ports, 'open')
        if open_ports:
            d = get_domain(ip)
            print_line('{} {}'.format(ip, '({})'.format(d) if d else ''), color_code=87, tab=1)
            print_line(open_ports, color_code=195, tab=2)
        print_line(get_ports_count(ports), color_code=195, tab=3)

print_line('Detect os ...', pre='|*')
for ip in db['ips']:
    ports = db['ips'][ip].get('ports')
    if ports:
        os = host_os_detect(ip, ports)
        if os:
            db['ips'][ip]['os'] = os
            d = get_domain(ip)
            print_line('{} {}'.format(ip, '({})'.format(d) if d else ''), color_code=87, tab=1)
            print_line(os, color_code=195, tab=2)

print_line('Detect services ...', pre='|*')
for ip in db['ips']:
    ports = db['ips'][ip].get('ports')
    if ports:
        services = host_services_detect(ip, ports).get(ip)
        if services:
            db['ips'][ip]['services'] = services
            d = get_domain(ip)
            print_line('{}  {}'.format(ip, '({})'.format(d) if d else ''), color_code=87, tab=1)
            print_line(services, color_code=195, tab=2)

print_line('Brute force sub domains ...', pre='|*')
for domain in db['domains']:
    wc_dns = db['domains'][domain].get('wc_dns') or []
    bf_sub_d = bf_sub_domains(domain, wc_dns)
    if bf_sub_domains:
        db['domains'][domain]['bf_sub_domains'] = bf_sub_d
        print_line(domain, color_code=87, tab=1)
        print_line(bf_sub_d, color_code=195, tab=2)

print_line("That's it.", pre='|.')

if raw_input('\n\nDump of db? (y/N):').lower() in ['y', 'yes']:
    pprint(db)

