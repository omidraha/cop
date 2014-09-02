from apps.utility import run_process, is_ip, is_ip_range


def host_list(host):
    # @todo, don't use nmap, move to utility
    cmd = 'nmap -Pn -sn -n  -sL -oG - -oN - -vvvvv --packet-trace {}'
    hosts = []
    sep_ips = []
    single_ips = []
    domains = []
    for each_host in host.split():
        if is_ip(each_host) or is_ip_range(each_host):
            sep_ips.append(each_host)
        else:
            domains.append(each_host)
    output = run_process(cmd.format(" ".join(sep_ips)), console=False)
    for line in output:
        if line.lower().startswith('host:'):
            sep = line.split()
            single_ips.append(sep[1])

    return single_ips, domains


def check_host_is_up(host, fast=True):
    cmd_f = 'nmap -n -sn -oG - -oN - -vvvvv --packet-trace {}'
    cmd_s = 'nmap -n -sn -PU53,161,162,40125 -PE -PS21-25,80,113,1050,35000,8000,8080,8081,3389,2323,2222,666,1336 ' \
            '-PA21-25,80,113,1050,35000,8000,8080,8081,3389,2323,2222,666,1336 -PY22,80,179,5060 ' \
            '-oG - -oN - -vvvvv --packet-trace {}'

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
    cmd_f = 'nmap -n -Pn  -sTU --top-ports 100 -oG - -oN - -vvvvv --packet-trace {}'
    cmd_s = 'nmap -n -Pn  -sTU --top-ports 1000 -oG - -oN - -vvvvv --packet-trace {}'
    ports = {}
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
            port_num = sp_2[0]
            port_status = sp_2[1].lower()
            port_type = sp_2[2].lower()
            if port_type not in ['tcp', 'udp']:
                continue
            if port_status not in ['open', 'closed', 'filtered', 'open|filtered', 'closed|filtered', 'unfiltered']:
                continue
            ports.setdefault(port_type, {}).setdefault(port_status, []).append(port_num)
    return ports


def host_os_detect(host, ports):
    cmd_port_tu = 'nmap -n -Pn -sTU -p T:{},U:{} -O -oG - -oN - -vvvvv --packet-trace {}'
    cmd_port_t = 'nmap -n -Pn -sT -p T:{} -O -oG - -oN - -vvvvv --packet-trace {}'
    cmd_port_u = 'nmap -n -Pn -sU -p U:{} -O -oG - -oN - -vvvvv --packet-trace {}'
    cmd_empty = 'nmap -n -Pn -O -oG - -vvvvv --packet-trace {}'
    open_tcp_ports = get_ports(ports, 'open', 'tcp')
    open_udp_ports = get_ports(ports, 'open', 'udp')
    close_tcp_ports = get_ports(ports, 'closed', 'tcp')
    close_udp_ports = get_ports(ports, 'closed', 'udp')
    tcp_ports = (open_tcp_ports or []) + close_tcp_ports[:5]
    udp_ports = (open_udp_ports or []) + close_udp_ports[:5]
    if tcp_ports and udp_ports:
        cmd = cmd_port_tu.format(','.join(tcp_ports), ','.join(udp_ports), host)
    elif tcp_ports:
        cmd = cmd_port_t.format(','.join(tcp_ports), host)
    elif udp_ports:
        cmd = cmd_port_u.format(','.join(udp_ports), host)
    else:
        cmd = cmd_empty.format(host)
    output = run_process(cmd)
    os = []
    for line in output:
        sp = line.split('OS: ')
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
    cmd_port_tu = 'nmap -n -Pn  -sTU -p T:{},U:{} -sV -oG - -oN - -vvvvv --packet-trace {}'
    cmd_port_t = 'nmap -n -Pn  -sT -p T:{} -sV -oG - -oN - -vvvvv --packet-trace {}'
    cmd_port_u = 'nmap -n -Pn  -sU -p U:{} -sV -oG - -oN - -vvvvv --packet-trace {}'
    cmd_empty = 'nmap -n -Pn  -sV -oG - -oN - -vvvvv --packet-trace {}'
    open_tcp_ports = get_ports(ports, 'open', 'tcp')
    open_udp_ports = get_ports(ports, 'open', 'udp')
    if open_tcp_ports and open_udp_ports:
        cmd = cmd_port_tu.format(','.join(open_tcp_ports), ','.join(open_udp_ports), host)
    elif open_tcp_ports:
        cmd = cmd_port_t.format(','.join(open_tcp_ports), host)
    elif open_udp_ports:
        cmd = cmd_port_u.format(','.join(open_udp_ports), host)
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
                port = port_info.split('/')[0].strip()
                service = port_info.split('/')[4].strip('?').strip()
                version = port_info.split('/')[6].strip('?').strip()
                services.append((port, service, version))
    return services


def get_ports(ports, p_status, p_type=None):
    """
    sample ports params:
        ports = {'tcp': {'open':[80, 443], 'closed':[8080], 'open|filtered':[79]},
                'udp': {'open':[53], 'closed':[161], 'open|filtered':[5050]}
                }
    :returns list, dict
    """
    if p_type:
        return ports.get(p_type, {}).get(p_status, [])
    tcp_ports = ports.get('tcp', {}).get(p_status)
    udp_ports = ports.get('udp', {}).get(p_status)
    p = {}
    if tcp_ports:
        p.update({'tcp': tcp_ports})
    if udp_ports:
        p.update({'udp': udp_ports})
    return p

