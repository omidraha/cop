from utility import run_process

"""
Network Rules:
    1. Whois
    2. Check host is up
    3. Do reverse dns
    4. Discover open ports
    5. Detect os
    6. Detect services
"""


def host_whois(ip):
    cmd = 'whois {}'
    output = run_process(cmd.format(ip))
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


def check_host_is_up(ip, fast=True):
    cmd_f = 'nmap -n -sn -oG - -vvvvv --packet-trace {}'
    cmd_s = 'nmap -n -sn -PU161,162,40125 -PE -PS21-25,80,113,1050,35000,8000,8080,8081,3389,2323,2222,666,1336 ' \
            '-PA21-25,80,113,1050,35000,8000,8080,8081,3389,2323,2222,666,1336 -PY22,80,179,5060 ' \
            '-oG - -vvvvv --packet-trace {}'

    ips = []
    if fast:
        cmd = cmd_f.format(ip)
    else:
        cmd = cmd_s.format(ip)
    output = run_process(cmd)
    for line in output:
        sp = line.split()
        if len(sp) != 5:
            continue
        if sp[-1].lower() == 'up':
            ips.append(sp[1])
    return ips


def host_dns_reverse(ip):
    cmd = 'nmap -Pn  -sL -oG - {}'
    output = run_process(cmd.format(ip))
    dns = ''
    for line in output:
        sep = line.split()
        if len(sep) != 5 or sep[0].strip().lower() != 'host:':
            continue
        sep = sep[2].strip('()')
        if sep:
            dns = sep
            break
    return dns


def host_port_discovery(ip, fast=True):
    cmd_f = 'nmap -n -Pn --top-ports 100 -oG - --open -vvvvv --packet-trace {}'
    cmd_s = 'nmap -n -Pn --top-ports 1000 -oG - --open -vvvvv --packet-trace {}'
    ports = []
    if fast:
        cmd = cmd_f.format(ip)
    else:
        cmd = cmd_s.format(ip)
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


def host_os_detect(ip, ports):
    cmd_port = 'nmap -n -Pn -p{} -O -oG - -vvvvv --packet-trace {}'
    cmd_empty = 'nmap -n -Pn -O -oG - -vvvvv --packet-trace {}'
    if ports:
        cmd = cmd_port.format(', '.join(ports), ip)
    else:
        cmd = cmd_empty.format(ip)
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


def host_services_detect(ip, ports):
    if not ports:
        return []
    cmd_port = 'nmap -n -Pn -p{} -sV -oG - -vvvvv --packet-trace {}'
    cmd = cmd_port.format(','.join(ports), ip)
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



