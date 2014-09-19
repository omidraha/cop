import logging
from logging.handlers import WatchedFileHandler
from logging import StreamHandler
import os
import struct
import fcntl
import sys
import termios
from apps.utility import print_line

ROOT_PATH = os.path.abspath(os.path.dirname(__file__))


# log setup
class PrintLogger(object):
    def write(self, data):
        print_line(data.strip(), end='\r', color_code='243')


DEBUG_LOG_PATH = os.path.join(ROOT_PATH, 'cop')
LOGGING_FORMAT_COL = '\033[1;30m>>>>>>>>>>>%(levelname)s %(asctime)s %(message)s\033[1;0m\r'
LOGGING_FORMAT_SIMPLE = '%(levelname)s %(asctime)s %(message)s'
logging.basicConfig(format=LOGGING_FORMAT_SIMPLE)
LOG_To_FILE = False
if LOG_To_FILE:
    try:
        log_handler = WatchedFileHandler(filename=DEBUG_LOG_PATH, encoding='utf-8')
        logging.getLogger().addHandler(log_handler)
        log_handler.setFormatter(logging.Formatter(LOGGING_FORMAT_SIMPLE))
    except IOError:
        pass
logging.getLogger("cop.run_process").setLevel(logging.INFO)
# stdout output
USE_IOCTL = True
if USE_IOCTL:
    STD_LINES, STD_COLS = struct.unpack('hh', fcntl.ioctl(sys.stdout, termios.TIOCGWINSZ, '1234'))
else:
    STD_COLS = 80
# thread
MAX_THREAD_BF_SUB_DOMAINS = 20
# cop logo
SHOW_LOGO = True
# paramiko log
paramiko = logging.getLogger('paramiko')
paramiko.setLevel(logging.INFO)
paramiko.addHandler(StreamHandler(PrintLogger()))
paramiko.propagate = False
