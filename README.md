# Penetration Testing

Overview
---------
1. - [Enumeration](#1---enumeration)
2. - [Exploitation](#2---exploitation)
3. - [Lateral Movement](#3---lateral-movement)
4. - [Privilege Escalation](#4---privilege-escalation)
5. - [Miscellaneous](#5---Miscellaneous)

     
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

#2. - Exploitation
-----------------------------------------

#3. - Lateral Movement
-----------------------------------------

#4. - Privilege Escalation
-----------------------------------------

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
