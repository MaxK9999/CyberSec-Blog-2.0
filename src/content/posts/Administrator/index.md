---
title: 'HTB-Administrator'
published: 2025-09-15
draft: false
toc: true
---


```
Scope:
10.10.11.42

Credentials:
Olivia
ichliebedich
```

# Recon
## Nmap

```bash
sudo nmap -sV -sC -sT -p- 10.10.11.42 -T5 --min-rate=5000 -vvvv -Pn

PORT      STATE SERVICE       REASON  VERSION
21/tcp    open  ftp           syn-ack Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp    open  domain        syn-ack Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2025-09-15 16:40:38Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack .NET Message Framing
47001/tcp open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49392/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
49397/tcp open  msrpc         syn-ack Microsoft Windows RPC
49404/tcp open  msrpc         syn-ack Microsoft Windows RPC
49422/tcp open  msrpc         syn-ack Microsoft Windows RPC
49664/tcp open  msrpc         syn-ack Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack Microsoft Windows RPC
63997/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows
```

## enum4linux

```bash
enum4linux-ng -U 10.10.11.42 
```

![](attachments/43d7547bbdc0e8c880591365427d0821.png)

# Foothold
## evil-winrm - Olivia

I did some other enum as well before ultimately logging in via `evil-winrm` using the provided creds for *Olivia*:

![](attachments/56a345dfc3c8a25a5656a7c9c114d4a6.png)

Here I started doing some recon on the target:

![](attachments/3071ed5eac92b77e22e447f2081b6ccc.png)

## BloodHound

In order to map the domain I used `bloodhound-ce-python`:

![](attachments/ceec1fed2ff98f2ea6bbee3cb58870d5.png)

I uploaded the resulting files to `bloodhound-ce` and checked it out.

![](attachments/febebeffc43a6d9d9de6441b341954aa.png)

I had a clear path written out to follow:

![](attachments/1a8436e362a80d02c4aa84415f349a76.png)

### GenericAll

First things first I had to take over *michael*'s user by abusing the **GenericAll** GPO.

![](attachments/5b002dd1d2e39fb333434791e8f274f5.png)

I used the following command for a targeted kerberoast:

![](attachments/fea2fd4b49b411519e70c1c0ba00c5b5.png)

Unfortunately the hash could not be cracked by `john`:

![](attachments/2c1a399489bab3ae1030877b2850326a.png)

Instead I successfully changed *michael*'s password using `bloodyAD`:

![](attachments/0a454925fe1eed563c9c2c538a4bca96.png)

```
Michael
P@ssword123!
```

### ForceChangePassword

I could now do the exact same but for the *Benjamin* user:

![](attachments/6d48ea38279e5fd03e1cf61b9fd79594.png)

```
Benjamin
P@ssword123!
```

## 445/TCP - SMB

I used the `spider_plus` extension on `nxc` to quickly spider the shares:

![](attachments/01b2eaf06948badcf25e2aac8146873c.png)

![](attachments/61666e0581d2c7783cd9e471712e4810.png)

And this one looked interesting as well:

![](attachments/8d2fc1e62244ec0a29d90e7c80d5e734.png)

I logged into `\SYSVOL`:

![](attachments/e65da1e9867a88a82dc8123270a435ce.png)

I downloaded the files that I deemed were of interest:

![](attachments/dc6748f612d9d1d6f08d919f9f27faff.png)

These however didn't look promising at all:

![](attachments/02138abdc6cb497047e5ddc62e6baa85.png)

This seemed like a rabbit hole, time to explore different routes.

## 21/TCP - FTP

I logged in with the creds for *Benjamin* into `ftp`:

![](attachments/738d147edd19eb91d477c03c0669b65e.png)

Here I found an interesting `Backup.psafe3` file which I downloaded to my Kali:

![](attachments/4ab201df1b54917088ba0ba477ce96f8.png)

### john 

I easily cracked the password:

![](attachments/efe804adbd07aaa71f531010f277d86b.png)

```
tekieromucho
```

## Psafe3 

I download the following binary in order to view the password manager:

![](attachments/97c353ba3f28fbddf1a776ece3cad8e2.png)

I then used the cracked password to log in:

![](attachments/050ccba0bef11c8f0127d3fdf93ecab0.png)

### creds

```
alexander
UrkIbagoxMyUGw0aPlj9B0AXSea4Sw
```

```
emily
UXLCI5iETUsIBoFVTj8yQFKoHjXmb
```

```
emma
WwANQWnmJnGV07WQN8bMS7FMAbjNur
```

I then went ahead and password sprayed these creds to see which one would stick:

![](attachments/7622697a090f57107decb45051ab536b.png)

Looks like we can use *Emily* to log in.

### user.txt

I logged in with the credentials for *Emily* and got the flag.

![](attachments/b3eff3d8778ed226e4d23a0b5b0feb37.png)

## GenericWrite

I didn't hold any interesting privs but I still checked my GPO's in `bloodhound` where I found that I had `GenericWrite` privs over *Ethan*:

![](attachments/0bdbe0152aff13600c20f12bf5481ac6.png)

I can use a targeted kerberoast to get the `krb5tgs` hash for *Ethan*.

![](attachments/9d4494a55336c72d77bf0a7ac0b74702.png)

![](attachments/9d5e07733786fab60ea5b62b789483fa.png)

```
Ethan
limpbizkit
```

# Privilege Escalation
## DCSync

Now that I had *Ethan*'s creds I could easily abuse the `DCSync` privileges in combination with `impacket-secretsdump`:

![](attachments/b88f4ece8208297ba7b8bb53c89560a6.png)

And then use `impacket-psexec` to log in using the Admin hash:

![](attachments/646ef1542a943b1e5d9ab393b800f197.png)

### root.txt

![](attachments/e0fcb5f0957379d9e42f2be056a76654.png)

![](attachments/0c76bd6514777da8e48ef139cd68797a.png)

---