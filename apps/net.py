from apps.utility import run_process, is_ip, is_ip_range

"""
Network Rules:
    Whois IP
    Check host is up
    Discover open ports
    Detect os
    Detect services
"""


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
    cmd_s = 'nmap -n -sn -PU53,161,162,40125 -PE -PS21-25,80,113,1050,35000,8000,8080,8081,3389,2323,2222,666,1336 ' \
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


def host_port_discovery(host, fast=True):
    cmd_f = 'nmap -n -Pn  -sTU --top-ports 100 -oG - --open -vvvvv --packet-trace {}'
    cmd_s = 'nmap -n -Pn  -sTU --top-ports 1000 -oG - --open -vvvvv --packet-trace {}'
    ports = {'tcp': [], 'udp': []}
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
            if len(sp_2) != 5:
                continue
            if sp_2[2].lower() == 'udp' and sp_2[1].lower() == 'open':
                ports['udp'].append(sp_2[0])
            elif sp_2[2].lower() == 'tcp' and sp_2[1].lower() == 'open':
                ports['tcp'].append(sp_2[0])
    return ports


def host_os_detect(host, ports):
    cmd_port_tu = 'nmap -n -Pn -sTU -p T:{},U:{} -O -oG - -vvvvv --packet-trace {}'
    cmd_port_t = 'nmap -n -Pn -sT -p T:{} -O -oG - -vvvvv --packet-trace {}'
    cmd_port_u = 'nmap -n -Pn -sU -p U:{} -O -oG - -vvvvv --packet-trace {}'
    cmd_empty = 'nmap -n -Pn -O -oG - -vvvvv --packet-trace {}'
    if ports['tcp'] and ports['udp']:
        cmd = cmd_port_tu.format(','.join(ports['tcp']), ','.join(ports['udp']), host)
    elif ports['tcp']:
        cmd = cmd_port_t.format(','.join(ports['tcp']), host)
    elif ports['udp']:
        cmd = cmd_port_u.format(','.join(ports['udp']), host)
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
    cmd_port_tu = 'nmap -n -Pn  -sTU -p T:{},U:{} -sV -oG - -vvvvv --packet-trace {}'
    cmd_port_t = 'nmap -n -Pn  -sT -p T:{} -sV -oG - -vvvvv --packet-trace {}'
    cmd_port_u = 'nmap -n -Pn  -sU -p U:{} -sV -oG - -vvvvv --packet-trace {}'
    cmd_empty = 'nmap -n -Pn  -sV -oG - -vvvvv --packet-trace {}'
    if ports['tcp'] and ports['udp']:
        cmd = cmd_port_tu.format(','.join(ports['tcp']), ','.join(ports['udp']), host)
    elif ports['tcp']:
        cmd = cmd_port_t.format(','.join(ports['tcp']), host)
    elif ports['udp']:
        cmd = cmd_port_u.format(','.join(ports['udp']), host)
    else:
        cmd = cmd_empty.format(host)
    output = run_process(cmd)
    services = []
    for line in output:
        sp = line.split('Ports: ')
        if len(sp) != 2:
            continue
        sp = sp[1]
        for port_info in sp.split(','):
            if port_info.split('/')[1].lower() == 'open':
                port = port_info.split('/')[0]
                service = port_info.split('/')[4].strip('?')
                version = port_info.split('/')[6].strip('?')
                services.append((port, service, version))
    return services


