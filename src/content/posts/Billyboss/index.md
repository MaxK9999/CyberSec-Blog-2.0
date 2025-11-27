---
title: PG-Billyboss
published: 2025-05-16
toc: true
draft: false
tags:
  - "CVE"
  - "SeImpersonatePrivilege"
  - "OSCP Prep"
---

```
Scope:
192.168.128.61
```

# Recon
## Nmap

```bash
sudo nmap -sC -sV billyboss -sT -vvvv -p- -Pn -T5 --min-rate=5000 

PORT      STATE    SERVICE         REASON      VERSION
21/tcp    open     ftp             syn-ack     Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp    open     http            syn-ack     Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-favicon: Unknown favicon MD5: 8D9ADDAFA993A4318E476ED8EB0C8061
|_http-cors: HEAD GET POST PUT DELETE TRACE OPTIONS CONNECT PATCH
|_http-title: BaGet
| http-methods: 
|_  Supported Methods: GET HEAD
135/tcp   open     msrpc           syn-ack     Microsoft Windows RPC
139/tcp   open     netbios-ssn     syn-ack     Microsoft Windows netbios-ssn
445/tcp   open     microsoft-ds?   syn-ack
5040/tcp  open     unknown         syn-ack
7680/tcp  open     pando-pub?      syn-ack
8081/tcp  open     http            syn-ack     Jetty 9.4.18.v20190429
| http-robots.txt: 2 disallowed entries 
|_/repository/ /service/
|_http-title: Nexus Repository Manager
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-favicon: Unknown favicon MD5: 9A008BECDE9C5F250EDAD4F00E567721
|_http-server-header: Nexus/3.21.0-05 (OSS)
49664/tcp open     msrpc           syn-ack     Microsoft Windows RPC
49665/tcp open     msrpc           syn-ack     Microsoft Windows RPC
49666/tcp open     msrpc           syn-ack     Microsoft Windows RPC
49667/tcp open     msrpc           syn-ack     Microsoft Windows RPC
49668/tcp open     msrpc           syn-ack     Microsoft Windows RPC
49669/tcp open     msrpc           syn-ack     Microsoft Windows RPC
```

## 21/TCP - FTP

![](attachments/25db639d3ca6cef5f7cd32ca28439ef5.png)

I then tried out the secure version `lftp`:

![](attachments/174d83a85b92966982cb609cfd9d7dc9.png)

Didn't work either.

## 8081/TCP - HTTP

![](attachments/e1cc9d07b4c63d3851712f276c538836.png)

![](attachments/951d0fd9113f8a9477d9b9a1af534191.png)

![](attachments/d9403c1ef65bf3bf978f449afc0e3a45.png)

![](attachments/7a92cba26a624cb2fbcec57287b2db24.png)

However this exploit still requires a set of valid creds which we do not have.

Other than that I can only find the following according to `nmap`:

![](attachments/aa9b94861ac7df002e119563fcd0a3b2.png)

### Access

Alright so I guess we will need to guess credentials?

![](attachments/bad7b3da0710c195d519e7a50423ae95.png)

![](attachments/b86ab07af0e06caaf196c0e6f9bb7663.png)

`nexus - nexus` worked!

So what can we actually do here?

![](attachments/6550327087187a35e95d2cdf9c548f43.png)

![](attachments/41c737cddf612bf70f09bd91969e3e75.png)

Doesn't seem interesting, but we found the PoC so let's check it out.

### PoC

![](attachments/dbc4249be183a6cc076f17c264f9a0c9.png)

We modify it to suit our needs:

![](attachments/e09cdf84e6a8e05ee697c1b56691a32e.png)

# Foothold
## Shell as Nathan

I execute the PoC

![](attachments/7fc800e623f102cf62fee10bffafe61a.png)

![](attachments/9070b4f02b1650a5dde9e829fb246147.png)

We get a shell back.

:::note
Interestingly we land inside the Nexus directory which is in *nathan*'s `Users` folder.
:::

Since this is the case we must have interesting privileges, as Windows users running the web server usually have the `SeImpersonatePrivilege` enabled:

![](attachments/5d9e804f3071efebfb0e50a7eeb3ba39.png)

Indeed! We can try to escalate privs right away.

# Privilege Escalation
## SeImpersonatePrivilege

![](attachments/9cec68c2b49cf1d13c1b8b08dc370f77.png)

:::fail
PrintSpoofer failed, let's see if GodPotato will work
:::

![](attachments/088f14e8d28c641f9df7effee1c1fd81.png)

![](attachments/bfa38d2746c0a7a93d978ac2663d8e80.png)

We got a reverse shell although it is unclear whether we are actually *SYSTEM*.

### flags

![](attachments/4319bcc5c467162e8d397fb4c5181886.png)

---