import Queue
import random
import threading
from time import sleep
from apps.dns import host_dns_wildcard
from apps.utility import run_process, get_from_recursive_dict
from settings import ROOT_PATH, MAX_THREAD_BF_SUB_DOMAINS


def bf_sub_domains(domain, wc_dns=None, fast=True):
    # @todo: threading section be a function in utility
    cmd = 'dig +nocomments +nostats +nocmd +noquestion @{} {}.{}'
    if fast:
        sub_domain_file = ROOT_PATH + '/lst/sd_fierce_2888'
    else:
        sub_domain_file = ROOT_PATH + '/lst/sd_subbrute_31290'
    ns = ['8.8.8.8', '8.8.4.4', '4.2.2.1', '4.2.2.2', '4.2.2.3',
          '4.2.2.4', '4.2.2.5', '4.2.2.6', '209.244.0.3',
          '209.244.0.4']
    ips = set()
    sub_domains = []
    if wc_dns is None:
        wc_dns = host_dns_wildcard(domain)
    for ns_name, ns_type, ns_value in wc_dns:
        if ns_name.startswith('never_exist_'):
            ips.add(ns_value)
    fp = open(sub_domain_file)
    out_q = Queue.Queue()
    tds = []
    for ns_name in fp.readlines():
        ns_name = ns_name.strip()
        if not ns_name:
            continue
        t = threading.Thread(target=run_process,
                             args=(cmd.format(random.choice(ns), ns_name, domain), False, True, out_q))
        tds.append((t, ns_name))
    i = 0
    tt = 0
    max_thread = MAX_THREAD_BF_SUB_DOMAINS
    while 1:
        if tt < max_thread and i < len(tds):
            t = tds[i][0]
            t.start()
            i += 1
            tt += 1
        elif tt >= max_thread:
            while out_q.empty():
                sleep(0.1)
            if not out_q.empty():
                output = out_q.get()
                cname_db = {}
                for line in output:
                    if line.startswith(';') or line.startswith('dig:'):
                        continue
                    sep = line.strip().split()
                    if len(sep) < 4:
                        continue
                    if sep[3] == 'CNAME':
                        cname_db[sep[4]] = sep[0]
                    if sep[3] != 'A':
                        continue
                    if sep[0] in cname_db:
                        sep[0] = get_from_recursive_dict(cname_db, sep[0])
                    if sep[4] not in ips:
                        s = '{}'.format(sep[0].strip('.'))
                        if s not in sub_domains:
                            sub_domains.append(s)
                tt -= 1
        else:
            break

    for t, _ in tds:
        t.join()

    return sub_domains
