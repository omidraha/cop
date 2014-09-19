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
from apps.srv import ftp_anonymous_access_check, ssh_authentication_types_available_check, open_ssh_time_attack, \
    rpc_info
from apps.utility import check_tools, print_line
import settings
from settings import ROOT_PATH


def cop_logo():
    print_line("""
|  ╔═╗╔═╗╔═╗  ┬
|  ║  ║ ║╠═╝  │
|  ╚═╝╚═╝╩    o
|  Call Of Penetration Tool version 0.1
|   """.strip(), pre='', color_code=51)


if settings.SHOW_LOGO:
    cop_logo()
else:
    print_line('Call Of Penetration Tool version 0.1')

tools_404 = check_tools()

if tools_404:
    print_line('Some tools, not found. at first call them !', pre='|- ')
    print_line('Here is an list of them: {}'.format(", ".join(tools_404)), pre='|- ')
    exit()
if os.geteuid() != 0:
    print_line('You need power of root permissions to do this !', pre='|- ')
    exit()

print_line('Enter ip(s)/domain(s) to kick off: ', pre='|+ ', end='', wrap=False)
input_host = raw_input()

ips, domains = host_list(input_host)

hosts = ips + domains

db = {'ips': {}, 'domains': {}}


def get_domains(ip):
    domains = []
    for domain in db['domains']:
        for each_ip in db['domains'][domain]['dns_lookup']:
            if each_ip == ip:
                domains.append(domain)
    if domains:
        return domains
    for each_ip in db['ips']:
        if each_ip == ip:
            r_DNS = db['ips'][each_ip].get('reverse_dns_lookup')
            if r_DNS and r_DNS not in domains:
                domains.append(r_DNS)
    return domains


print_line('Host alive checking ...', pre='|* ')
alive_ips = check_host_is_up(input_host, fast=False)

if alive_ips:
    len_host = len(alive_ips)
    for ip in alive_ips:
        db['ips'][ip] = {}
        d = ', '.join(get_domains(ip))
        print_line('{}'.format(d or ip), color_code=195, tab=1)
    print_line('{} Host{} up.'.format(len_host, 's' if len_host > 1 else ''), color_code=195, tab=1)
else:
    print_line(' Nothing to do !')
    exit()

if domains:
    print_line('Performing DNS lookup ...', pre='|* ')
    for domain in domains:
        dns_lookup = host_dns_lookup(domain)
        if dns_lookup:
            db['domains'][domain] = {'dns_lookup': dns_lookup}
            print_line(domain, color_code=87, tab=1)
            print_line(dns_lookup, color_code=195, tab=2)

print_line('Reverse DNS lookup ...', pre='|* ')
for ip in db['ips']:
    dns_r = host_reverse_dns_lookup(ip)
    if dns_r:
        db['ips'][ip]['reverse_dns_lookup'] = dns_r
        print_line(ip, color_code=87, tab=1)
        print_line(dns_r, color_code=195, tab=2)

print_line('Getting name server records ...', pre='|* ')
for domain in db['domains']:
    ns = host_name_server(domain)
    if ns:
        db['domains'][domain]['name_servers'] = ns
        print_line(domain, color_code=87, tab=1)
        print_line(ns, color_code=195, tab=2)

print_line('Getting name servers bind version ...', pre='|* ')
for domain in db['domains']:
    for ns in db['domains'][domain].get('name_servers', []):
        bind_version = get_name_server_bind_version(ns)
        if bind_version:
            db['domains'][domain].setdefault('name_servers_version', {})[ns] = bind_version
    ns_version = db['domains'][domain].get('name_servers_version')
    if ns_version:
        print_line(domain, color_code=87, tab=1)
        print_line(ns_version, color_code=195, tab=2)

print_line('Getting any type of ns record information ...', pre='|* ')
for domain in db['domains']:
    dns_any_r = host_dns_any_query(domain)
    if dns_any_r:
        db['domains'][domain]['dns_any_records'] = dns_any_r
        print_line(domain, color_code=87, tab=1)
        print_line(dns_any_r, color_code=195, tab=2)

print_line('Checking DNS allow recursion ...', pre='|* ')
for domain in db['domains']:
    ns = db['domains'][domain].get('name_servers')
    dr = host_dns_check_allow_recursion(domain, ns)
    if dr:
        db['domains'][domain]['dr'] = dr
        print_line(domain, color_code=87, tab=1)
        print_line(dr, color_code=195, tab=2)

print_line('Checking DNSSEC ...', pre='|* ')
for domain in db['domains']:
    dnssec = host_dnssec(domain)
    if dnssec:
        db['domains'][domain]['dnssec'] = dnssec
        print_line(domain, color_code=87, tab=1)
        print_line(dnssec, color_code=195, tab=2)

print_line('Checking wildcard DNS ...', pre='|* ')
for domain in db['domains']:
    wc_dns = host_dns_wildcard(domain)
    if wc_dns:
        db['domains'][domain]['wc_dns'] = wc_dns
        print_line(domain, color_code=87, tab=1)
        print_line(wc_dns, color_code=195, tab=2)

print_line('DNS zone transfer checking ...', pre='|* ')
for domain in db['domains']:
    ns = db['domains'][domain].get('name_servers')
    dtz = host_dns_zone_transfer(domain, ns)
    if dtz:
        db['domains'][domain]['dtz'] = dtz
        print_line(domain, color_code=87, tab=1)
        print_line(dtz, color_code=195, tab=2)

print_line('Whois IP ...', pre='|* ')
for ip in db['ips']:
    whois = host_whois(ip)
    if whois:
        db['ips'][ip]['whois'] = whois
        d = ', '.join(get_domains(ip))
        print_line('{} {}'.format(ip, '({})'.format(d) if d else ''), color_code=87, tab=1)
        print_line(whois, color_code=195, tab=2)

print_line('Discover open ports (scan 100 top tcp/udp ports) ...', pre='|* ')
for ip in db['ips']:
    ports = host_port_discovery(ip)
    if ports:
        db['ips'][ip]['ports'] = ports
        open_ports = get_ports(ports, 'open')
        if open_ports:
            d = ', '.join(get_domains(ip))
            print_line('{} {}'.format(ip, '({})'.format(d) if d else ''), color_code=87, tab=1)
            print_line(open_ports, color_code=195, tab=2)
        print_line(get_ports_count(ports), color_code=195, tab=3)

print_line('Discover open ports (scan all tcp/udp 0-65535 ports) ...', pre='|* ')
for ip in db['ips']:
    ports = host_port_discovery(ip, scan_all=True)
    if ports:
        if ports.get('tcp'):
            new_p = list(set(ports['tcp']['open']) - set(db['ips'][ip].get('ports', {}).get('tcp', {}).get('open', [])))
            db['ips'][ip].setdefault('ports', {}).setdefault('tcp', {}).setdefault('open', []).extend(new_p)
        if ports.get('udp'):
            new_p = list(set(ports['udp']['open']) - set(db['ips'][ip].get('ports', {}).get('udp', {}).get('open', [])))
            db['ips'][ip].setdefault('ports', {}).setdefault('udp', {}).setdefault('open', []).extend(new_p)
        open_ports = get_ports(ports, 'open')
        d = ', '.join(get_domains(ip))
        print_line('{} {}'.format(ip, '({})'.format(d) if d else ''), color_code=87, tab=1)
        print_line(open_ports, color_code=195, tab=2)
        print_line(get_ports_count(ports), color_code=195, tab=3)

print_line('Detect os ...', pre='|* ')
for ip in db['ips']:
    ports = db['ips'][ip].get('ports')
    open_ports = get_ports(ports, 'open')
    if open_ports:
        os = host_os_detect(ip, ports)
        if os:
            db['ips'][ip]['os'] = os
            d = ', '.join(get_domains(ip))
            print_line('{} {}'.format(ip, '({})'.format(d) if d else ''), color_code=87, tab=1)
            print_line(os, color_code=195, tab=2)

print_line('Detect services ...', pre='|* ')
for ip in db['ips']:
    ports = db['ips'][ip].get('ports')
    open_ports = get_ports(ports, 'open')
    if open_ports:
        services = host_services_detect(ip, ports).get(ip)
        if services:
            db['ips'][ip]['services'] = services
            d = ', '.join(get_domains(ip))
            print_line('{}  {}'.format(ip, '({})'.format(d) if d else ''), color_code=87, tab=1)
            print_line(services, color_code=195, tab=2)

print_line('Services probing ...', pre='|* ')
for ip in db['ips']:
    services = db['ips'][ip].get('services')
    if services:
        ', '.join(get_domains(ip))
        print_line('{}  {}'.format(ip, '({})'.format(d) if d else ''), color_code=87, tab=1)
        for port, protocol, name, version in services:
            if name == 'ftp':
                print_line('{}:{} FTP anonymous access  check ...'.format(port, protocol), tab=2)
                res = ftp_anonymous_access_check(ip, port)
                if res[0]:
                    db['ips'][ip]['ftp_anonymous'] = res
                    print_line(res[1], color_code=195, tab=2)
            elif name == 'ssh':
                print_line('{}:{} SSH authentication types available check ...'.format(port, protocol), tab=2)
                auth_types = ssh_authentication_types_available_check(ip, port)
                if auth_types:
                    db['ips'][ip]['ssh_auth_types'] = auth_types
                    print_line('SSH authentication available types:', color_code=195, tab=3)
                    print_line(auth_types, color_code=195, tab=4)
                if 'password' in db['ips'][ip]['ssh_auth_types'] and 'openssh' in version.lower():
                    fp = open(ROOT_PATH + '/lst/user_common_14')
                    user_list = fp.read().strip().split()
                    print_line('{}:{} OpenSSH username enumeration time-based attack ...'.format(port, protocol), tab=2)
                    users = open_ssh_time_attack(ip, port, user_list)
                    if users:
                        print_line('SSH username enumeration:', color_code=195, tab=3)
                        print_line(users, color_code=195, tab=4)
            elif name == 'rpcbind':
                print_line('{}:{} Connect to PortMapper and fetches registered programs ...'.format(port, protocol),
                           tab=2)
                res = rpc_info(ip)
                if res:
                    db['ips'][ip].setdefault('rpc_info', {})[protocol] = res
                    print_line('PROGRAM VERSION PROTOCOL PORT  SERVICE', color_code=195, tab=3)
                    print_line(res[0], color_code=195, tab=3)

print_line('Brute force sub domains ...', pre='|* ')
for domain in db['domains']:
    wc_dns = db['domains'][domain].get('wc_dns') or []
    bf_sub_d = bf_sub_domains(domain, wc_dns)
    if bf_sub_domains:
        db['domains'][domain]['bf_sub_domains'] = bf_sub_d
        print_line(domain, color_code=87, tab=1)
        print_line(bf_sub_d, color_code=195, tab=2)

print_line("That's it.", pre='|. ')

if raw_input('\n\nDump of db? (y/N):').lower() in ['y', 'yes']:
    pprint(db)

