import os
import random
import string
import subprocess
import logging
import sys
import textwrap
import fcntl

logger = logging.getLogger('cop.run_process')


def run_process(cmd, log=True, console=True, out_queue=None):
    if console:
        print_line(cmd, end='\r', color_code='243')
    p = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
    output = []
    while True:
        ret_code = p.poll()
        while True:
            lines = (non_block_read(p.stdout) + non_block_read(p.stderr)).strip()
            if lines:
                lines = lines.split('\n')
                output.extend(lines)
                if log:
                    logger.debug("\n".join(lines))
                if console:
                    print_line(lines, end='\r', color_code='243')
            if not lines:
                break
        if ret_code is not None:
            break
    if out_queue:
        out_queue.put(output)
        out_queue.task_done()
    return output


def check_tools():
    tools = ['nmap', 'whois', 'dig', 'ssh', 'masscan', 'rpcinfo']
    tools_404 = []
    for tool in tools:
        output = run_process('which {}'.format(tool), console=False)
        if not output:
            tools_404.append(tool)
    return tools_404


def is_ip(host):
    # @todo: needs to be improved
    return host.replace('.', '').isdigit()


def is_ip_range(host):
    # @todo: needs to be improved
    return host.replace('.', '').replace('-', '').replace('/', '').isdigit()


def reverse_ip(ip):
    return '.'.join(ip.split('.')[::-1])


def generate_chars(length=8, lower=True):
    chars = string.ascii_lowercase if lower else string.ascii_letters
    return "".join(random.choice(chars) for _ in range(length))


def print_line(text, pre='|', end='\n', wrap=False, color_code=45, clear=True, tail=True, tab=0):
    from settings import STD_COLS

    blink_chars = ['.', 'o', 'O', '0', '@']
    tab_char = '  '
    tab_chars = tab_char * tab
    if isinstance(text, dict):
        for key, value in text.iteritems():
            print_line('{}{}{}'.format(key, tab_char, value), pre, end, wrap, color_code, clear, tail, tab)
    elif isinstance(text, list):
        for item in text:
            if isinstance(item, tuple) or isinstance(item, list):
                item = tab_char.join(item)
            print_line('{}'.format(item), pre, end, wrap, color_code, clear, tail, tab)
    else:
        text = text.replace('\t', tab_chars)
        len_text = len(text) + len(tab_chars)
        if clear:
            sys.stdout.write('\r{}\r'.format(STD_COLS * ' '))
            sys.stdout.flush()
        if not wrap and tail and len_text > STD_COLS:
            text = text[:STD_COLS - STD_COLS / 4] + ' ...'
        if wrap:
            cols = STD_COLS - 3
            for line in textwrap.wrap(text, cols):
                len_line = len(line)
                if len_line <= cols:
                    line += (cols - len_line) * ' '
                sys.stdout.write(
                    '\033[38;05;{}m{} {}{}\033[1;m{}'.format(color_code, pre + random.choice(blink_chars), tab_chars,
                                                             line, end))
        else:
            sys.stdout.write('\033[38;05;{}m{}{}{}\033[1;m{}'.format(color_code, pre, tab_chars, text, end))
        sys.stdout.flush()


def get_from_recursive_dict(d, r):
    v = d.get(r)
    if v:
        return get_from_recursive_dict(d, v)
    return r


def non_block_read(stream):
    fd = stream.fileno()
    fl = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
    try:
        return stream.read()
    except IOError:
        return ''
