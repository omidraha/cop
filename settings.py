import logging
from logging.handlers import WatchedFileHandler
import os

ROOT_PATH = os.path.abspath(os.path.dirname(__file__))

# log setup
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
# thread
MAX_THREAD_BF_SUB_DOMAINS = 20
# cop logo
SHOW_LOGO = True
