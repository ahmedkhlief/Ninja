
import random
from datetime import datetime


beacon=''
IP=''
PORT=''
SSL=''
cert=''
key=''
date=''
Dount=''
def initiate_url():
    global Urls
    #list_full=['path','pdf','perl','perl5','personal','personals','pgsql','phone','php','phpmyadmin','phpMyAdmin','pics','ping','pix','pl','pls','plx','pol','policy','poll','pop','portal','portlet','portlets','post','postgres','power','press','preview','print','printenv','priv','private','privs','process','processform','prod','production','products','professor','profile','program','project','proof','properties','protect','protected','proxy','ps','pub','public','publish','publisher','purchase','purchases','put','pw','pwd','python','queries','query','queue','quote','ramon','random','rank','rcs','readme','redir','redirect','reference','references','reg','reginternal','regional','register','registered','release','remind','reminder','remote','removed','report','reports','requisite','research','reseller','resource','resources','responder','restricted','retail','right','robot','robotics','root','route','router','rpc','rss','rules','run','sales','sample','samples','save','saved','schema','scr','scratc','script','scripts','sdk','search','secret','secrets','section','sections','secure','secured','security','select','sell','send','sendmail','sensepost','sensor','sent','server','servers','server_stats','service','services','servlet','Servlet','servlets','Servlets','session','sessions','set','setting','settings','setup','share','shared','shell','shit','shop','shopper','show','showcode','shtml','sign','signature','signin','simple','single','site','sitemap','sites','SiteServer','small','snoop','soap','soapdocs','software','solaris','solutions','somebody','source','sources','Sources','spain','spanish','sql','sqladmin','src','srchad','srv','ssi','ssl','staff','start','startpage','stat','statistic','statistics','Statistics','stats','Stats','status','stop','store','story','string','student','stuff','style','stylesheet','stylesheets','submit','submitter','sun','super','support','supported','survey','svc','svn','svr','sw','sys','sysadmin','system','table','tag','tape','tar','target','tech','temp','template','templates','temporal','temps','terminal','test','testing','tests','text','texts','ticket','tmp','today','tool','toolbar','tools','top','topics','tour','tpv','trace','traffic','transaction','transactions','transfer','transport','trap','trash','tree','trees','tutorial','uddi','uninstall','unix','up','update','updates','upload','uploader','uploads','usage','user','users','usr','ustats','util','utilities','utility','utils','validation','validatior','vap','var','vb','vbs','vbscript','vbscripts','vfs','view','viewer','views','virtual','visitor','vpn','w','w3','w3c','W3SVC','W3SVC1','W3SVC2','W3SVC3','warez','wdav','web','webaccess','webadmin','webapp','webboard','webcart','webdata','webdav','webdist','webhits','WEB-INF','weblog','weblogic','weblogs','webmail','webmaster','websearch','webservice','webservices','website','webstat','webstats','webvpn','welcome','wellcome','whatever','whatnot','whois','will','win','windows','word','work','workplace','workshop','ws','wstats','wusage','www','wwwboard','wwwjoin','wwwlog','wwwstats','xcache','xfer','xml','xmlrpc','xsl','xsql','xyz','zap','zip','zipfiles','zips']
    f=open("links.txt")
    links=f.read()
    list_full=links.strip().replace("\r","").split("\n")#replace("\0","").replace("\n",",").split(",")

    raw_payload='/'+random.choice(list_full)
    list_full.remove(raw_payload.replace("/",""))
    b52_payload='/'+random.choice(list_full)
    list_full.remove(b52_payload.replace("/",""))
    b64_stager='/'+random.choice(list_full)
    list_full.remove(b64_stager.replace("/",""))
    b52_stager='/'+random.choice(list_full)
    list_full.remove(b52_stager.replace("/",""))
    hjf_payload='/'+random.choice(list_full)
    list_full.remove(hjf_payload.replace("/",""))
    b64_payload='/'+random.choice(list_full)
    list_full.remove(b64_payload.replace("/",""))
    hjfs_payload='/'+random.choice(list_full)
    list_full.remove(hjfs_payload.replace("/",""))
    sct_payload='/'+random.choice(list_full)
    list_full.remove(sct_payload.replace("/",""))
    hta_payload='/'+random.choice(list_full)
    list_full.remove(hta_payload.replace("/",""))
    register_url='/'+random.choice(list_full)
    list_full.remove(register_url.replace("/",""))
    download_url='/'+random.choice(list_full)
    list_full.remove(download_url.replace("/",""))
    upload_url='/'+random.choice(list_full)
    list_full.remove(upload_url.replace("/",""))
    image_url='/'+random.choice(list_full)
    list_full.remove(image_url.replace("/",""))
    command_url='/'+random.choice(list_full)
    list_full.remove(command_url.replace("/",""))
    result_url='/'+random.choice(list_full)
    list_full.remove(result_url.replace("/",""))
    modules_url='/'+random.choice(list_full)
    list_full.remove(modules_url.replace("/",""))

    #print ("raw_payload="+raw_payload,b52_payload,b64_stager,b52_payload,hjf_payload,b64_payload,hjfs_payload,sct_payload,hta_payload,register_url,download_url,upload_url,image_url,command_url,result_url,modules_url
    #print ("raw_payload="+raw_payload+"\nb52_payload="+b52_payload+"\nb64_stager="+b64_stager+"\nb52_payload="+b52_payload+"\nhjf_payload="+hjf_payload+"\nb64_payload="+b64_payload+"\nhjfs_payload="+hjfs_payload+"\nsct_payload="+sct_payload+"\nhta_payload="+hta_payload+"\nregister_url="+register_url+"\ndownload_url="+download_url+"\nupload_url="+upload_url+"\nimage_url="+image_url+"\ncommand_url="+command_url+"\nresult_url="+result_url+"\nmodules_url="+modules_url
    Urls="raw_payload=\'"+raw_payload+"\'\nb52_payload=\'"+b52_payload+"\'\nb64_stager=\'"+b64_stager+"\'\nb52_stager=\'"+b52_stager+"\'\nhjf_payload=\'"+hjf_payload+"\'\nb64_payload=\'"+b64_payload+"\'\nhjfs_payload=\'"+hjfs_payload+"\'\nsct_payload=\'"+sct_payload+"\'\nhta_payload=\'"+hta_payload+"\'\nregister_url=\'"+register_url+"\'\ndownload_url=\'"+download_url+"\'\nupload_url=\'"+upload_url+"\'\nimage_url=\'"+image_url+"\'\ncommand_url=\'"+command_url+"\'\nresult_url=\'"+result_url+"\'\nmodules_url=\'"+modules_url+"\'"

    print ("Urls will be used in this campaign\n"+Urls)

def get_ip():
    global IP,PORT
    CC=''
    while len(CC) == 0:
        CC = input('Enter a DN/IP:port for this campaign ')
    CC = CC.split(':')
    IP = CC[0]
    PORT=CC[1]
    print ("You chosed IP: "+IP+"and port: "+PORT+"\n")


def get_beacon():
    global beacon
    CC=''
    while len(CC) == 0:
        CC = input('Enter the default beacon period ( connect back) for this campaign in seconds ')
    beacon=CC

def update_template():
    global beacon,IP,PORT,Urls,date,Donut
    template=open("core/config.template","r")
    config=open("core/config.py","w")
    data=template.read()
    data=data.replace('{IP}', IP).replace('{beacon_time}', beacon).replace('{PORT}', PORT).replace('{URL}', Urls).replace('{SSL}', SSL).replace('{CERT}', cert).replace('{KEY}', key).replace('{KDATE}', date).replace('{DONUT}', Donut)
    config.write(data)
    config.close()
    template.close()
    print ("Everything Done you can run ninja by : python3 Ninja.py")

def log_campaign():
    global beacon,IP,PORT,Urls,date
    Log="=================================================================================\n"
    Log+="==========================New Campaign==========================================\n"
    Log+="Urls for this campaign  :\n"+Urls
    Log+="IP/Domain:Port for this Campaign : \n"+IP+":"+PORT+"\n"
    Log+="Beacon period for this campaign : "+beacon+"\n\n\n"
    Log+="kill date for this campaign : "+date+"\n\n\n"
    file=open("c2-logs.txt","a+")
    file.write(Log)
    file.close()

def kill_date():
    global date
    CC=''
    while len(CC) == 0:
        CC = input('please enter kill date for this campaign ( format dd/MM/yyyy ) ? ')
        if len(CC.split("/"))>2:
            try:
                date = datetime.strptime(CC, '%d/%m/%Y')
            except:
                print ("you entered wrong date")
                CC=''
                continue
            date=CC
            break
        else:
            continue

def get_ssl():
    global SSL,key,cert
    CC=''
    while len(CC) == 0:
        CC = input('Do you want to use SSL ? (yes/no) ')
        if CC=="yes":
            SSL="True"
            break
        if CC=="no":
            SSL="False"
            return
        else:
            continue
    CC=''
    while len(CC) == 0:
        CC = input('Do you want to use default self signed SSL certificate  ? (yes/no) ')
        if CC=="yes":
            cert='ninja.crt'
            key='ninja.key'
            return
        if CC=="no":
            break
        else:
            continue
    CC=''
    while len(CC) == 0:
        CC = input('Enter the full path for certificate ( ex : /root/certificate.crt ) ')
    cert=CC
    CC=''
    while len(CC) == 0:
        CC = input('Enter the full path for private key ( ex : /root/private.key ) ')
    key=CC

def Disable_Donut():
    global Donut
    CC=''
    while len(CC) == 0:
        CC = input('Do you want to disable donut shellcodes ( this will disable migrate command in the agents ) ? ( yes/no )\nsome users reported issues with donut if you have startup crash then disable it . ')
        CC = CC.split(':')
        Choice = CC[0]
        if Choice.lower()!="yes" and Choice.lower()!="no":
            CC=''
    if Choice.lower()=="yes" :
        Donut='False'
        print ("Donut will be disabled")
    if Choice.lower()=="no" :
        Donut='True'
        print ("Donut will be Enabled")



if __name__ == '__main__':
    #try :
    initiate_url()
    get_ip()
    get_beacon()
    kill_date()
    get_ssl()
    Disable_Donut()
    update_template()
    log_campaign()
    #except Exception as e:
    #    print ('[-] ERROR(main): %s' % str(e))
