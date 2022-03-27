import random
from datetime import datetime
from os import mkdir

from rich.pretty import pprint
from rich.console import Console

console = Console()
log = Console(style="bold green")

beacon = ''
IP = ''
PORT = ''
SSL = ''
cert = ''
key = ''
date = ''
Dount = ''
name = ''

def campaign_name():
    global name
    name = console.input('\n[cyan][-] Enter Campaign name:[/cyan] ')


def initiate_url():
    identifiers = ["raw_payload", "b52_payload", "b64_stager", "b52_stager", "hjf_payload", "b64_payload",
                   "hjfs_payload", "sct_payload", "hta_payload", "register_url", "download_url", "upload_url",
                   "image_url", "command_url", "result_url", "modules_url"]
    global urls
    urls = {}
    # list_full=['path','pdf','perl','perl5','personal','personals','pgsql','phone','php','phpmyadmin','phpMyAdmin','pics','ping','pix','pl','pls','plx','pol','policy','poll','pop','portal','portlet','portlets','post','postgres','power','press','preview','print','printenv','priv','private','privs','process','processform','prod','production','products','professor','profile','program','project','proof','properties','protect','protected','proxy','ps','pub','public','publish','publisher','purchase','purchases','put','pw','pwd','python','queries','query','queue','quote','ramon','random','rank','rcs','readme','redir','redirect','reference','references','reg','reginternal','regional','register','registered','release','remind','reminder','remote','removed','report','reports','requisite','research','reseller','resource','resources','responder','restricted','retail','right','robot','robotics','root','route','router','rpc','rss','rules','run','sales','sample','samples','save','saved','schema','scr','scratc','script','scripts','sdk','search','secret','secrets','section','sections','secure','secured','security','select','sell','send','sendmail','sensepost','sensor','sent','server','servers','server_stats','service','services','servlet','Servlet','servlets','Servlets','session','sessions','set','setting','settings','setup','share','shared','shell','shit','shop','shopper','show','showcode','shtml','sign','signature','signin','simple','single','site','sitemap','sites','SiteServer','small','snoop','soap','soapdocs','software','solaris','solutions','somebody','source','sources','Sources','spain','spanish','sql','sqladmin','src','srchad','srv','ssi','ssl','staff','start','startpage','stat','statistic','statistics','Statistics','stats','Stats','status','stop','store','story','string','student','stuff','style','stylesheet','stylesheets','submit','submitter','sun','super','support','supported','survey','svc','svn','svr','sw','sys','sysadmin','system','table','tag','tape','tar','target','tech','temp','template','templates','temporal','temps','terminal','test','testing','tests','text','texts','ticket','tmp','today','tool','toolbar','tools','top','topics','tour','tpv','trace','traffic','transaction','transactions','transfer','transport','trap','trash','tree','trees','tutorial','uddi','uninstall','unix','up','update','updates','upload','uploader','uploads','usage','user','users','usr','ustats','util','utilities','utility','utils','validation','validatior','vap','var','vb','vbs','vbscript','vbscripts','vfs','view','viewer','views','virtual','visitor','vpn','w','w3','w3c','W3SVC','W3SVC1','W3SVC2','W3SVC3','warez','wdav','web','webaccess','webadmin','webapp','webboard','webcart','webdata','webdav','webdist','webhits','WEB-INF','weblog','weblogic','weblogs','webmail','webmaster','websearch','webservice','webservices','website','webstat','webstats','webvpn','welcome','wellcome','whatever','whatnot','whois','will','win','windows','word','work','workplace','workshop','ws','wstats','wusage','www','wwwboard','wwwjoin','wwwlog','wwwstats','xcache','xfer','xml','xmlrpc','xsl','xsql','xyz','zap','zip','zipfiles','zips']
    f = open("utils/links.txt")
    links = f.read()
    list_full = links.strip().replace("\r", "").split("\n")  # replace("\0","").replace("\n",",").split(",")

    for i in identifiers:
        uri = random.choice(list_full)
        urls[i] = "/" + uri
        list_full.remove(uri)

    log.log(f"[+] Urls will be used in this campaign:\n")
    pprint(urls)


def get_ip():
    global IP, PORT
    while True:
        try:
            CC = console.input('[cyan][-] Enter a DN/IP:Port for this campaign:[/cyan] ')
            CC = CC.split(':')
            IP = CC[0]
            PORT = CC[1]
            break
        except IndexError:
            console.print("[-] Please enter a valid DN/IP:Port", style="red")
            continue
    log.log(f"[+] You chose: {IP}:{PORT}")


def get_beacon():
    global beacon
    CC = ''
    while len(CC) == 0:
        CC = console.input(
            '[cyan][-] Enter the default beacon period (connect back) for this campaign in seconds:[cyan] ')
    beacon = CC


def log_campaign():
    try:
        mkdir("logs")
    except FileExistsError:
        pass
    global beacon, IP, PORT, date, url, name
    current_date = datetime.now()
    Log = "=================================================================================\n"
    Log += "==========================New Campaign==========================================\n"
    Log += f"[*] Campaign started at: {current_date.strftime('[%H:%M:%S]-[%d/%m/%Y]')}\n\n"
    Log += "[+] Campaign Name:\n" + name
    Log += "[+] Urls for this campaign:\n" + url
    Log += "\n[+] IP/Domain:Port for this Campaign : " + IP + ":" + PORT + "\n"
    Log += "[+] Beacon period for this campaign : " + beacon + "\n\n\n"
    Log += "[+] kill date for this campaign : " + date + "\n\n\n"
    file = open("logs/c2-logs.txt", "a+")
    file.write(Log)
    file.close()


def kill_date():
    global date
    CC = ''
    while len(CC) == 0:
        CC = console.input(
            '[cyan][-] Please enter kill date for this campaign ([green]format dd/MM/yyyy[/green]): [/cyan]')
        if len(CC.split("/")) > 2:
            try:
                date = datetime.strptime(CC, '%d/%m/%Y')
            except:
                console.print("[!] Please enter a valid date", style="red")
                CC = ''
                continue
            date = CC
            break
        else:
            continue


def get_ssl():
    global SSL, key, cert
    CC = ''
    while len(CC) == 0:
        CC = console.input('[cyan][-] Do you want to use SSL?[cyan] [green](yes/no)[/green]: ')
        if CC == "yes":
            SSL = "True"
            break
        if CC == "no":
            SSL = "False"
            return
        else:
            continue
    CC = ''
    while len(CC) == 0:
        CC = console.input(
            '[cyan][-] Do you want to use default self signed SSL certificate?[/cyan] [green](yes/no)[/green]: ')
        if CC == "yes":
            cert = 'utils/Certificate/ninja.crt'
            key = 'utils/Certificate/ninja.key'
            return
        if CC == "no":
            break
        else:
            continue
    CC = ''
    while len(CC) == 0:
        CC = console.input(
            '[cyan][-] Enter the full path for certificate[/cyan] [green]( ex : /root/certificate.crt )[/green]: ')
    cert = CC
    CC = ''
    while len(CC) == 0:
        CC = console.input(
            '[cyan][-] Enter the full path for private key[/cyan] [green]( ex : /root/private.key )[/green]: ')
    key = CC


def Disable_Donut():
    global Donut
    CC = ''
    while len(CC) == 0:
        CC = console.input(
            '[cyan][-] Some users reported issues with donut, so if you have startup crash then disable it.\n[-] Do you want to disable donut shellcodes? ([green]this will disable migrate command in the agents[/green]) [green](yes/no)[/green]: ')
        CC = CC.split(':')
        Choice = CC[0]
        if Choice.lower() != "yes" and Choice.lower() != "no":
            CC = ''
    if Choice.lower() == "yes":
        Donut = 'False'
        log.log("[+] Donut will be disabled", style="bold green")
    if Choice.lower() == "no":
        Donut = 'True'
        log.log("[+] Donut will be Enabled", style="bold green")


def update_template():
    global beacon, IP, PORT, date, Donut, url, name
    name = name + "-campaign"
    url = ''
    for k, v in urls.items():
        url += f'{k}="{v}"\n'
    template = open("core/config.template", "r")
    config = open("core/config.py", "w")
    mkdir(name)
    campaign_config = open(name + "/" + "config.py", "w")

    data = template.read()
    data = data.replace('{IP}', IP).replace('{beacon_time}', beacon).replace('{PORT}', PORT).replace('{URL}',
                                                                                                     url).replace(
        '{SSL}', SSL).replace('{CERT}', cert).replace('{KEY}', key).replace('{KDATE}', date).replace('{DONUT}',
                                                                                                     Donut).replace(
        '{NAME}', str(name))
    config.write(data)
    campaign_config.write(data)
    campaign_config.close()
    config.close()
    template.close()

def banner():
    console.print("""
 ████     ██ ██             ██                      ████
░██░██   ░██░░             ░░                      █░░░ █
░██░░██  ░██ ██ ███████     ██  ██████      █████ ░    ░█
░██ ░░██ ░██░██░░██░░░██   ░██ ░░░░░░██    ██░░░██   ███
░██  ░░██░██░██ ░██  ░██   ░██  ███████   ░██  ░░   █░░
░██   ░░████░██ ░██  ░██ ██░██ ██░░░░██   ░██   ██ █
░██    ░░███░██ ███  ░██░░███ ░░████████  ░░█████ ░██████
░░      ░░░ ░░ ░░░   ░░  ░░░   ░░░░░░░░    ░░░░░  ░░░░░░
                                                        [bold cyan]By: Ahmad khlief
                                                        ----------------[/bold cyan]
\n\n""", style="red")


if __name__ == '__main__':
    try:
        banner()
        initiate_url()
        campaign_name()
        get_ip()
        get_beacon()
        kill_date()
        get_ssl()
        Disable_Donut()
        update_template()
        log_campaign()
        console.print("\t\t\t\t\t[++] Done, you can now run ninja by: python3 Ninja.py", style="bold italic green")
    except KeyboardInterrupt:
        console.print("\n[!] Ctrl+C detected", style="bold red")
