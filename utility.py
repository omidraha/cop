import subprocess
import logging

logger = logging.getLogger('cop.run_process')


def run_process(cmd, log=True):
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
    output = []
    while True:
        ret_code = p.poll()
        for line in p.stdout.readlines():
            out = line.strip()
            if out:
                output.append(out)
                if log:
                    logger.info(out)
        if ret_code is not None:
            break
    return output


def check_tools():
    tools = ['nmap', 'whois', 'dig']
    tools_404 = []
    for tool in tools:
        output = run_process('which {}'.format(tool))[0]
        if not output:
            tools_404.append(tool)
    return tools_404


def is_ip(host):
    # @todo: improved
    return host.replace('.', '').isdigit()


def is_ip_range(host):
    # @todo: improved
    return host.replace('.', '').replace('-', '').replace('/', '').isdigit()


def reverse_ip(ip):
    return '.'.join(ip.split('.')[::-1])

