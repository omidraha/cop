from utility import run_process, is_ip, reverse_ip, is_ip_range

"""
Network Rules:
    Whois IP
    Performing DNS Lookup
    Performing Reverse DNS Lookup
    Getting Name Server records
    DNS Zone Transfer Checking
    Check host is up
    Discover open ports
    Detect os
    Detect services
"""


def host_whois(host):
    cmd = 'whois {}'
    output = run_process(cmd.format(host))
    address = ''
    whois = {}
    for line in output:
        line = line.lower()
        if line.startswith('inetnum:') or line.startswith('netrange:'):
            sep = line.split()
            whois['net_range'] = sep[1], sep[-1]
        elif line.startswith('netname:'):
            sep = line.split()
            whois['net_name'] = " ".join(sep[1:])
        elif line.startswith('descr:'):
            sep = line.split()
            whois['description'] = " ".join(sep[1:])
        elif line.startswith('person:'):
            sep = line.split()
            whois['person'] = " ".join(sep[1:])
        elif line.startswith('address:'):
            sep = line.split()
            address = address + ' ' + " ".join(sep[1:])
        elif line.startswith('fax-no:'):
            sep = line.split()
            whois['fax_number'] = " ".join(sep[1:])
        elif line.startswith('phone:'):
            sep = line.split()
            whois['phone'] = " ".join(sep[1:])
        elif line.startswith('country:'):
            sep = line.split()
            whois['country'] = " ".join(sep[1:])
        elif line.startswith('city:'):
            sep = line.split()
            whois['city'] = " ".join(sep[1:])

    if address:
        whois['address'] = address

    return whois


def host_list(host):
    # @todo, don't use nmap, move to utility
    cmd = 'nmap -Pn -sn -n  -sL -oG - -vvvvv --packet-trace {}'
    hosts = []
    sep_ips = []
    single_ips = []
    domains = []
    for each_host in host.split():
        if is_ip(each_host) or is_ip_range(each_host):
            sep_ips.append(each_host)
        else:
            domains.append(each_host)
    output = run_process(cmd.format(" ".join(sep_ips)))
    for line in output:
        if line.lower().startswith('host:'):
            sep = line.split()
            single_ips.append(sep[1])

    return single_ips, domains


def check_host_is_up(host, fast=True):
    cmd_f = 'nmap -n -sn -oG - -vvvvv --packet-trace {}'
    cmd_s = 'nmap -n -sn -PU161,162,40125 -PE -PS21-25,80,113,1050,35000,8000,8080,8081,3389,2323,2222,666,1336 ' \
            '-PA21-25,80,113,1050,35000,8000,8080,8081,3389,2323,2222,666,1336 -PY22,80,179,5060 ' \
            '-oG - -vvvvv --packet-trace {}'

    if isinstance(host, list):
        host = " ".join(host)
    hosts = []
    if fast:
        cmd = cmd_f.format(host)
    else:
        cmd = cmd_s.format(host)
    output = run_process(cmd)
    for line in output:
        sp = line.split()
        if len(sp) != 5:
            continue
        if sp[-1].lower() == 'up':
            hosts.append(sp[1])
    return hosts


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
            if len(sep) < 5:
                continue
            dzt.append((sep[0], sep[3], " ".join(sep[4:])))

    return dzt


def host_port_discovery(host, fast=True):
    cmd_f = 'nmap -n -Pn --top-ports 100 -oG - --open -vvvvv --packet-trace {}'
    cmd_s = 'nmap -n -Pn --top-ports 1000 -oG - --open -vvvvv --packet-trace {}'
    ports = []
    if fast:
        cmd = cmd_f.format(host)
    else:
        cmd = cmd_s.format(host)
    output = run_process(cmd)
    for line in output:
        sp = line.split('Ports: ')
        if len(sp) != 2:
            continue
        sp = sp[1].split('///')
        for line_2 in sp:
            line_2 = line_2.strip(', ')
            sp_2 = line_2.split('/')
            if len(sp_2) < 2:
                continue
            ports.append(sp_2[0])
    return ports


def host_os_detect(host, ports):
    cmd_port = 'nmap -n -Pn -p{} -O -oG - -vvvvv --packet-trace {}'
    cmd_empty = 'nmap -n -Pn -O -oG - -vvvvv --packet-trace {}'
    if ports:
        cmd = cmd_port.format(', '.join(ports), host)
    else:
        cmd = cmd_empty.format(host)
    output = run_process(cmd)
    os = []
    for line in output:
        sp = line.split('OS:')
        if len(sp) < 2:
            continue
        sp = sp[1].strip().split(',')
        for line_2 in sp:
            line_2 = line_2.strip().strip(' or ').split('\t')[0]
            if '|' in line_2:
                os.extend(line_2.split('|'))
            else:
                os.append(line_2)
    return os


def host_services_detect(host, ports):
    if not ports:
        return []
    cmd_port = 'nmap -n -Pn -p{} -sV -oG - -vvvvv --packet-trace {}'
    cmd = cmd_port.format(','.join(ports), host)
    output = run_process(cmd)
    services = []
    for line in output:
        sp = line.split('Ports: ')
        if len(sp) != 2:
            continue
        sp = sp[1]
        for port_info in sp.split(','):
            if port_info.split('/')[1] == 'open':
                port = port_info.split('/')[0]
                service = port_info.split('/')[4].strip('?')
                services.append((port, service))
    return services


