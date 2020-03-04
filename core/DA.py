import re
#from core.color import bcolors
from color import bcolors
AV_list = {
    "Kaspersky":    ["avp", "avpui", "klif", "KAVFS", "kavfsslp","prunsrv"],
    "Malwarebytes":["mbcloudea","mbamservice"],
    "Symantec":    ["SmcGui", "SISIPSService","SemSvc","snac64","sesmcontinst"],
    "Bitdefender": ["vsserv"],
    "TrendMicro": ["tmntsrv","PwmTower"],
    "Windows Defender": ["MsMpEng"],
    "Avast":    ["aswBcc", "bcc"],
    "Cylance": ["CylanceSvc", "CylanceUi"],
    "ESET": ["epfw", "epfwlwf", "epfwwfp"],
    "FireEye Endpoint Agent": ["xagt"],
    "F-Secure": ["fsdevcon", "FSORSPClient"],
    "MacAfee": ["enterceptagent", "McAfeeEngineService", "McAfeeFramework"],
    "SentinelOne": ["SentinelAgent", "SentinelOne"],
    "Sophos": ["sophosssp", "sophossps"],
    "ZoneALarm": ["zlclient"],
    "Panda AntiVirus": ["AVENGINE"],
    "AVG": ["avgemc"],
    "Avira" : ["avscan"],
    "G data" : ["AVKProxy"],


}


AV_score={
    "Kaspersky":  8,
    "Malwarebytes":5,
    "Symantec":    5,
    "Bitdefender": 5,
    "TrendMicro": 6,
    "Windows Defender": 5,
    "Avast":    4,
    "Cylance": 4,
    "ESET": 4,
    "FireEye Endpoint Agent": 6,
    "F-Secure": 5,
    "MacAfee": 3,
    "SentinelOne": 5,
    "Sophos": 4,
    "ZoneALarm": 3,
    "Panda AntiVirus": 3,
    "AVG": 4,
    "Avira" : 3,
    "G data" : 3,


}

Sandbox_IOC={
    "wireshark":  6,
    "vboxservice":7,
    "vboxtray":7,
    "autorun":7,
    "procexp":7,
    "procmon":7,
    "tcpview":7,
    "powershell_ise":4,
    "sysmon":7,
    }

SIEM = {

    "Splunk":["splunk-admon","splunkd","splunk-winevtlog","splunk-netmon"],
    "Sysmon":["sysmon"],
    "Elastic Search / Gray Log":["winlogbeat"]


}


score=[]
sandbox=[]

def detect_SIEM(ps):
    global SIEM,score,sandbox
    siem=[]
    for i in ps.split():
        for t,s in SIEM.items():
            for pc in s:
                if i.split(".")[0]==pc.lower() and not (t in siem):
                    siem.append(t)
                    score.append(9)
                    sandbox.append(6)
    l=len(siem)
    if l>0:
        print bcolors.FAIL +"SIEM detected using process list : "+ bcolors.ENDC,siem
        print "###################################"
    else:
        print bcolors.OKGREEN+"No SIEM Detected "+ bcolors.ENDC
        print "###################################"


def detect_AV(ps,av):
    global AV_list,score,sandbox,AV_score
    AV=[]
    AVP=[]
    for i in av.split("\n"):
        fields=i.split(":")
        if fields[0].strip()=="displayName":
            AV.append(fields[1])
    l=len(AV)
    if  l>0:
        print bcolors.FAIL +"AV detected using powershell API : "+ bcolors.ENDC,AV

    for i in ps.split():
        for t,s in AV_list.items():
            for pc in s:
                if i.split(".")[0]==pc.lower() and not (t in AVP):
                    AVP.append(t)
                    score.append(AV_score[t])
    l=len(AVP)
    if l>0:
        print bcolors.FAIL +"AV detected using process list : "+ bcolors.ENDC,AVP
        print "###################################"
    else:
        print bcolors.OKGREEN+"No AV Detected "+ bcolors.ENDC
        print "###################################"
def AD_enum(adusers,adgroups,ADPC):
    print "\n\nDomain Users :\n"
    for i in adusers.split("\n"):
        fields=i.split(": ")
        #print fields[0]
        if fields[0].strip()=="Name":
            print fields[1].strip(),",",

    print "\n\n############\nDomain Groups :\n"
    for i in adgroups.split("\n")[4:]:
        print i.strip(),",",

    print "\n\n############\nDomain Computers :\n"
    #print ADPC.split("\n\n")[1].split("\n")

    for i in ADPC.split("\n\n"):
        for d in i.split("\n"):
            fields=d.split(": ")
            if fields[0].strip()=="name":
                print fields[1].strip(),",",
    print "\n\n###################################"
def detect_sandbox(ps):
    global Sandbox_IOC
    for i in ps.split():
        for t,s in Sandbox_IOC.items():
            if i.split(".")[0]==t.lower():
                sandbox.append(s)

def PCinfo(pcinfo):
    global score,sandbox
    pclist={}
    """for i in pcinfo.split("\n"):
        fields=i.split(": ")
        #if fields[0].strip()=="OsVersion":
        if len(fields)>1:
            pclist[fields[0].strip()]=fields[1]
    print "PC Report : \nHost Name: %s \nUser Name: %s \nOS : %s \nOS Version : %s \nLocal Time : %s \nTime Zone : %s \nUP Time : %s \nBios Manufacturer : %s \n" % (pclist["CsDNSHostName"],pclist["CsUserName"],pclist["OsName"],pclist["OsVersion"],pclist["OsLocalDateTime"],pclist["TimeZone"],pclist["OsUptime"],pclist["BiosManufacturer"])
    """
    for i in pcinfo.split("\n"):
        fields=i.split(": ")
        #if fields[0].strip()=="OsVersion":
        if len(fields)>1:
            pclist[fields[0].strip()]=fields[1]
    print "PC Report : \n  Host Name: %s \n  OS : %s \n  Build Number : %s \n  Local Time : %s \n  Time Zone : %s \n  Last Boot Time : %s \n " % (pclist["CSName"],pclist["Caption"],pclist["BuildNumber"],pclist["LocalDateTime"],pclist["CurrentTimeZone"],pclist["LastBootUpTime"]),"Bios Manufacturer : "+pclist["Manufacturer"].strip()+" , "+pclist["SMBIOSBIOSVersion"].strip()+" \n###################################"

    if pclist["Manufacturer"].strip().lower().find("innotek")>-1 or pclist["SMBIOSBIOSVersion"].strip().lower().find("virtualbox")>-1:
        sandbox.append(9)

    if pclist["Caption"].strip().lower().find("windows 10")>-1:
        score.append(8)
    if pclist["Caption"].strip().lower().find("windows 7")>-1:
        score.append(4)
    if pclist["Caption"].strip().lower().find("windows 8")>-1:
        score.append(5)
    if pclist["Caption"].strip().lower().find("windows server 2012")>-1:
        score.append(5)
    if pclist["Caption"].strip().lower().find("windows server 2016")>-1:
        score.append(8)

def gethotfix(hotfixes):
    result = re.findall(r"KB\d{7}", hotfixes)
    print  "Installed Updates : ",
    for i in result:
        print i,
    print "\n###################################"
def getpwl(pwl):
    global score,sandbox
    if pwl.find("Windows PowerShell")>=0:
        print bcolors.FAIL +"powershell logging enabled"+ bcolors.ENDC
        score.append(2)
        sandbox.append(8)
    else:
        score.append(8)
        sandbox.append(1)
    print "###################################"

def getadmin(isadmin):
    global score,sandbox
    if isadmin.strip()=="True":
        print "you have admin privileges"+ bcolors.ENDC
        score.append(3)
        sandbox.append(7)
    else:
        print bcolors.FAIL +"you don't have admin privileges"+ bcolors.ENDC
        score.append(9)
        sandbox.append(1)
    print "###################################"

def getjoined(isjoined):
    global score,sandbox
    if isjoined.strip().replace("\n","").split(",")[0].strip()=="True":
        print bcolors.OKGREEN +"this device part of the domain "+isjoined.strip("\n").split(",")[1]+ bcolors.ENDC
        score.append(8)
        sandbox.append(1)
        print "###################################"
        return True
    else:
        print bcolors.FAIL +"this device is not part of domain"+ bcolors.ENDC
        score.append(3)
        sandbox.append(5)
        print "###################################"
        return False


def  getscore():
    global score,sandbox
    sum=0
    for i in score:
        #print i,
        sum=sum+i
    avg=(sum/len(score))
    if avg<=4:
        print bcolors.OKGREEN +"Hardness score ("+str(avg)+"/10"+") : Easy , you can pwn the system easily"+ bcolors.ENDC
    if avg>=5 and avg<=7:
        print bcolors.WARNING +"Hardness score ("+str(avg)+"/10"+") : Medium , you can pwn the system with good enumeration and availble local exploit "+ bcolors.ENDC
    if avg>7:
        print bcolors.FAIL +"Hardness score ("+str(avg)+"/10"+") : Hard , be careful from the AV and the security updates installed"+ bcolors.ENDC
    sum=0
    for i in sandbox:
        #print i,
        sum=sum+i
    avg=(sum/len(sandbox))
    if avg<=4:
        print bcolors.OKGREEN +"Sandbox Score ("+str(avg)+"/10"+") : you are probably in real live system"+ bcolors.ENDC
    if avg>=5 and avg<=7:
        print bcolors.WARNING +"Sandbox Score ("+str(avg)+"/10"+") : check and confirm as you probably in a security analyst device"+ bcolors.ENDC
    if avg>7:
        print bcolors.FAIL +"Sandbox Score ("+str(avg)+"/10"+") : you are in a sandbox"+ bcolors.ENDC
    print "###################################"



def main(fname="DA/ahmedkl@deadsec.comDA_out.txt"):
    try:
        file=open(fname)
        data=file.read()
        data=data.split("###############")
        av=data[1]                       # AV data
        ps=data[2]                       #  process list
        pwl=data[3]                      # powershell winevent logging
        isadmin=data[4]                  # is the user admin ( true or flase)
        isjoined=data[5]                      # is the device joined to domain ( true or flase)
        pcinfo=data[6]                      # system info
        hotfixes=data[7]                      # HOT FIXES Updates
        adusers=data[8]                      # active directory user list
        adgroups=data[9]                      # active directory groups
        #loggedin=data[10]
        ADPC=data[10]                           # active directory PCs
        shares=data[11]                         # network shares
        #print av,ps,pwl,isadmin,isjoined,pcinfo,hotfixes
        detect_SIEM(ps)
        detect_AV(ps,av)
        detect_sandbox(ps)
        getpwl(pwl)
        getadmin(isadmin)
        joined=getjoined(isjoined)
        PCinfo(pcinfo)
        getscore()
        gethotfix(hotfixes)
        if joined:
            AD_enum(adusers,adgroups,ADPC)
        print "\nShares :\n",shares

    except Exception as e:
        print '[-] ERROR(webserver->main): %s' % str(e)
