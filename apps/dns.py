import random
import string
from apps.utility import run_process, is_ip, reverse_ip, generate_chars


def host_dns_lookup(host):
    cmd = 'dig +short {}'
    ips = []
    if is_ip(host):
        return ips
    output = run_process(cmd.format(host))
    for line in output:
        sep = line.strip()
        if sep.startswith(';'):
            continue
        if is_ip(sep):
            ips.append(sep)
    return ips


def host_reverse_dns_lookup(host, use_dig=True):
    cmd_nmap = 'nmap -Pn  -sL -oG - {}'
    cmd_dig = 'dig +short {}.in-addr.arpa. PTR'
    dns = ''
    if not is_ip(host):
        return dns
    # using dig
    if use_dig:
        output = run_process(cmd_dig.format(reverse_ip(host)))
        if output:
            sep = output[0].strip().strip('.')
            if sep and not sep.startswith(';'):
                dns = sep
        return dns
    # using nmap
    output = run_process(cmd_nmap.format(host))
    for line in output:
        sep = line.split()
        if len(sep) != 5 or sep[0].strip().lower() != 'host:':
            continue
        sep = sep[2].strip('()')
        if sep and not sep.startswith(';'):
            dns = sep
            break
    return dns


def host_name_server(host):
    cmd = 'dig +short NS {}'
    ns = []
    if is_ip(host):
        return ns
    output = run_process(cmd.format(host))
    for line in output:
        if line.startswith(';'):
            continue
        sp = line.strip().strip('.')
        if sp:
            ns.append(sp)
    return ns


def host_dns_any_query(host):
    cmd = 'dig +nocomments +nostats +nocmd +noquestion  any {}'
    dns_any_r = []
    if is_ip(host):
        return dns_any_r
    output = run_process(cmd.format(host))
    for line in output:
        if line.startswith(';') or line.startswith('dig:'):
            continue
        sep = line.strip().split()
        if len(sep) < 4:
            continue
        dns_any_r.append((sep[0], sep[3], " ".join(sep[4:])))
    return dns_any_r


def host_dnssec(host):
    cmd = 'dig +nocomments +nostats +nocmd +noquestion -t dnskey {}'
    dnssec = []
    if is_ip(host):
        return dnssec
    output = run_process(cmd.format(host))
    for line in output:
        if line.startswith(';') or line.startswith('dig:'):
            continue
        sep = line.strip().split()
        if len(sep) < 4:
            continue
        if sep[3].lower() == 'dnskey':
            dnssec.append((sep[0], sep[3], " ".join(sep[4:])))
    return dnssec


def host_dns_wildcard(host):
    cmd_w = 'dig +noall +answer *.{}'
    cmd_r = 'dig +noall +answer {}.{}'
    wildcard_dns = []
    if is_ip(host):
        return wildcard_dns
    random_sub_domain = 'never_exist_{}'.format(generate_chars(4))
    output_1 = run_process(cmd_w.format(host))
    output_2 = run_process(cmd_r.format(random_sub_domain, host))
    outputs = [output_1, output_2]
    for output in outputs:
        for line in output:
            if line.startswith(';') or line.startswith('dig:'):
                continue
            sep = line.strip().split()
            if len(sep) < 4:
                continue
            wildcard_dns.append((sep[0], sep[3], " ".join(sep[4:])))
    return wildcard_dns


def host_dns_zone_transfer(host, ns=None):
    cmd = 'dig @{} {} axfr'
    dzt = []
    if not ns:
        ns = host_name_server(host)
    for each_ns in ns:
        c = cmd.format(each_ns, host)
        output = run_process(c)
        for line in output:
            if line.startswith(';') or line.startswith('dig:'):
                continue
            sep = line.strip().split()
            if len(sep) < 4:
                continue
            dzt.append((sep[0], sep[3], " ".join(sep[4:])))

    return dzt


def host_dns_check_allow_recursion(host, ns=None):
    cmd = 'dig any @{}'
    dr = []
    if not ns:
        ns = host_name_server(host)
    for each_ns in ns:
        c = cmd.format(each_ns)
        output = run_process(c)
        for line in output:
            if not line.startswith(';; flags:'):
                continue
            if 'ra' in line.split(';')[2].strip('  flags:').split():
                dr.append(each_ns)
    return dr
