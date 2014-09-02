import random
import string
import subprocess
import logging
import sys
import textwrap
import struct
import fcntl
import termios
from settings import USE_IOCTL

logger = logging.getLogger('cop.run_process')

if USE_IOCTL:
    std_lines, std_cols = struct.unpack('hh', fcntl.ioctl(sys.stdout, termios.TIOCGWINSZ, '1234'))
else:
    std_cols = 80


def run_process(cmd, log=True, console=True):
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
    output = []
    while True:
        ret_code = p.poll()
        while True:
            line = p.stdout.readline()
            out = line.strip()
            if out:
                output.append(out)
                if log:
                    logger.info(out)
                if console:
                    print_line(out, end='\r', color_code='243', wrap=True)
            if not line:
                break
        if ret_code is not None:
            break
    return output


def check_tools():
    tools = ['nmap', 'whois', 'dig']
    tools_404 = []
    for tool in tools:
        output = run_process('which {}'.format(tool), console=False)[0]
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


def generate_chars(length=8, lower=True):
    chars = string.ascii_lowercase if lower else string.ascii_letters
    return "".join(random.choice(chars) for _ in range(length))


def print_line(text, pre='|', end='\n', wrap=False, color_code=45, clear=True, tail=True, tab=0):
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
            sys.stdout.write('\r{}\r'.format(std_cols * ' '))
        if not wrap and tail and len_text > std_cols:
            text = text[:std_cols - std_cols / 4] + ' ...'
        if wrap:
            cols = std_cols - 3
            for line in textwrap.wrap(text, cols):
                len_line = len(line)
                if len_line <= cols:
                    line += (cols - len_line) * ' '
                sys.stdout.write(
                    '\033[38;05;{}m{} {}{}\033[1;m{}'.format(color_code, pre + random.choice(blink_chars), tab_chars,
                                                             line, end))
        else:
            sys.stdout.write('\033[38;05;{}m{} {}{}\033[1;m{}'.format(color_code, pre, tab_chars, text, end))


