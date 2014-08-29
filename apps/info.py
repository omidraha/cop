from apps.utility import run_process

"""
Information Gathering Rules:
    Whois IP
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
        whois['address'] = address.strip()

    return whois

