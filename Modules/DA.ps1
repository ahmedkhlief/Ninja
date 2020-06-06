$joined=if ($env:computername -eq $env:userdomain)
{
echo " no AD domain"
$AV1=Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Out-String
$PS=CimInstance Win32_Process | select ProcessID,Name,CommandLine  | Format-Table -Wrap -AutoSize | Out-String
$PWL=Get-WinEvent -ListLog "Windows PowerShell" | where {$_.RecordCount -gt 0} | Out-String
$admin=(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) | Out-String
$Joined2=(gwmi win32_computersystem).partofdomain | Out-String
$domain=(Get-WmiObject Win32_ComputerSystem).Domain | Out-String
$Joined2="$Joined2,$domain"
$pc=Get-CimInstance Win32_OperatingSystem | Select-Object  Caption, InstallDate, ServicePackMajorVersion, OSArchitecture,  BuildNumber, CSName,LastBootUpTime,CurrentTimeZone,LocalDateTime | FL | Out-String
$bios= Get-CimInstance -Class Win32_BIOS | Out-String
$pc="$pc$bios"
$hotfixes=get-wmiobject -class win32_quickfixengineering | Out-String
$loggedin=Get-WMIObject -class Win32_ComputerSystem | select username | Out-String
$shares=Get-SMBShare | Out-String
}
else
{

echo "must be in AD"

$AV1=Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Out-String
$PS=CimInstance Win32_Process | select ProcessID,Name,CommandLine  | Format-Table -Wrap -AutoSize | Out-String
$PWL=Get-WinEvent -ListLog "Windows PowerShell" | where {$_.RecordCount -gt 0} | Out-String
$admin=(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) | Out-String
$Joined2=(gwmi win32_computersystem).partofdomain | Out-String
$domain=(Get-WmiObject Win32_ComputerSystem).Domain | Out-String
$Joined2="$Joined2,$domain"
$pc=Get-CimInstance Win32_OperatingSystem | Select-Object  Caption, InstallDate, ServicePackMajorVersion, OSArchitecture,  BuildNumber, CSName,LastBootUpTime,CurrentTimeZone,LocalDateTime | FL | Out-String
$bios= Get-CimInstance -Class Win32_BIOS | Out-String
$pc="$pc$bios"
$hotfixes=get-wmiobject -class win32_quickfixengineering | Out-String
$loggedin=Get-WMIObject -class Win32_ComputerSystem | select username | Out-String
$shares=Get-SMBShare | Out-String

$ADPC=Get-DomainComputer | Out-String
$ADUsers=Get-WmiObject -Class Win32_UserAccount -Filter  "LocalAccount='False'" | Out-String
$ADgroups=Get-WmiObject -Class Win32_Group -Filter  "LocalAccount='False'" | Select Name | Out-String
}

$output="Defense_Ananylsis_Module`n`n###############`n$AV1 `n`n###############`n$PS `n`n###############`n$PWL `n`n###############`n$admin `n`n###############`n$joined2 `n`n###############`n$pc `n`n###############`n$hotfixes `n`n###############`n$ADUsers `n`n###############`n$ADgroups `n`n###############`n$ADPC `n`n###############`n$shares"
echo $output
