---
title: 'HTB-Editor'
published: 2025-09-16
draft: false
toc: true
---

---
```
Scope:
10.10.11.80
```

# Recon
## Nmap

```bash
sudo nmap -sV -sC -sT -p- 10.10.11.80 -T5 --min-rate=5000 -vvvv -Pn

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    syn-ack nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://editor.htb/
8080/tcp open  http    syn-ack Jetty 10.0.20
|_http-server-header: Jetty(10.0.20)
| http-methods: 
|   Supported Methods: OPTIONS GET HEAD PROPFIND LOCK UNLOCK
|_  Potentially risky methods: PROPFIND LOCK UNLOCK
| http-cookie-flags: 
|   /: 
|     JSESSIONID: 
|_      httponly flag not set
| http-webdav-scan: 
|   WebDAV type: Unknown
|   Server Type: Jetty(10.0.20)
|_  Allowed Methods: OPTIONS, GET, HEAD, PROPFIND, LOCK, UNLOCK
| http-title: XWiki - Main - Intro
|_Requested resource was http://10.10.11.80:8080/xwiki/bin/view/Main/
| http-robots.txt: 50 disallowed entries (40 shown)
| /xwiki/bin/viewattachrev/ /xwiki/bin/viewrev/ 
| /xwiki/bin/pdf/ /xwiki/bin/edit/ /xwiki/bin/create/ 
| /xwiki/bin/inline/ /xwiki/bin/preview/ /xwiki/bin/save/ 
| /xwiki/bin/saveandcontinue/ /xwiki/bin/rollback/ /xwiki/bin/deleteversions/ 
| /xwiki/bin/cancel/ /xwiki/bin/delete/ /xwiki/bin/deletespace/ 
| /xwiki/bin/undelete/ /xwiki/bin/reset/ /xwiki/bin/register/ 
| /xwiki/bin/propupdate/ /xwiki/bin/propadd/ /xwiki/bin/propdisable/ 
| /xwiki/bin/propenable/ /xwiki/bin/propdelete/ /xwiki/bin/objectadd/ 
| /xwiki/bin/commentadd/ /xwiki/bin/commentsave/ /xwiki/bin/objectsync/ 
| /xwiki/bin/objectremove/ /xwiki/bin/attach/ /xwiki/bin/upload/ 
| /xwiki/bin/temp/ /xwiki/bin/downloadrev/ /xwiki/bin/dot/ 
| /xwiki/bin/delattachment/ /xwiki/bin/skin/ /xwiki/bin/jsx/ /xwiki/bin/ssx/ 
| /xwiki/bin/login/ /xwiki/bin/loginsubmit/ /xwiki/bin/loginerror/ 
|_/xwiki/bin/logout/
|_http-open-proxy: Proxy might be redirecting requests
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## 80/TCP - HTTP

![](attachments/d3c33e8e5c265caee966fcc9d0f574d3.png)

Down at the bottom I noticed a **Documentation** tab which when clicked showed the following:

![](attachments/ef072262550182348d3290ad56b1afb1.png)

I had to edit this entry to my `/etc/hosts` list.

![](attachments/cae649ba6ed6b4895b5c6052ced26c0b.png)

I then ran `ffuf` to see whether I could find more vhosts but it appears this was  the only one:

![](attachments/97706eda411111457eaa9946180cf396.png)

Moving onto `wiki.`

![](attachments/86697e84601b16bd4320f9e97c3d845e.png)

I noticed the user *Neal Bagwell*, might need this later on to log in.

Furthermore I noticed a version number:

![](attachments/25cfffb134487ec7630562fd626278a3.png)

Apparently there are plenty of CVE's for this version:

![](attachments/38c56025c2a023d4499a8138b1b57168.png)

I settled for [this one](https://github.com/D3Ext/CVE-2025-24893):

![](attachments/da793daaa12c52d80a0c5d328f88670e.png)

# Foothold
## Shell as xwiki

I used the `busybox` reverse shell command to get in:

![](attachments/15ecd41326631fe4f8271c9306bb37d0.png)

I noticed a plethora of open ports:

![](attachments/82407cce8c667fcb5c1ceba409037313.png)

## Enumeration

I then downloaded and ran `linpeas.sh`:

![](attachments/c9bcf8cc436bb826ba0c08dfd1abc3f9.png)

![](attachments/ff7b04430daa7e608497dcee4e8f1507.png)

This one seemed interesting as well if we can get access to a user who's in the *netdata* group:

![](attachments/afe513589c735e6afce6e84429fed337.png)

I didn't really find anything else interesting so decided to look up the docs.

I headed on over to the following directory where I landed in initially to enumerate it further.

![](attachments/a805f61922a436ef9727e2021cb68ef2.png)

Here I found this file which I then proceded to check out:

![](attachments/d68d7eba380532096fe2ae69266fead4.png)

Inside the `hibernate.cfg.xml` file I found juicy cleartext creds:

![](attachments/0b99599fd3fb4076c67687f60cdb1339.png)

```
xwiki
theEd1t0rTeam99
```

## MySQL

Using the found creds I was able to access `mysql` and enumerate it:

![](attachments/0d971262833a1c87436f539158c26b0e.png)

However I didn't find anything of use here so instead sprayed the password against the found *oliver* user.

## Lateral Movement - oliver

The credentials matched and I was able to move laterally:

![](attachments/b960ae35d7c078fec6ec9d696e7fc7d8.png)

### user.txt

![](attachments/79b80d3f742b62b18b946cdc61eb8323.png)

# Privilege Escalation
## netdata - ndsudo

This user was part of the *netdata* group:

![](attachments/394e8f4ccb03434fe913cb5e5e13de47.png)

I can use the previously found binaries that are non-default.

![](attachments/fc1591a4fd7f97b7b2b7e0d80531723c.png)

![](attachments/6e53951264a1a1e3b67461aa1645c098.png)

![](attachments/039e156fd02c9412bc0a000adbd4b489.png)

I then transfered it over and executed it after adding `/tmp` to my `$PATH`:

![](attachments/85852af18b72139d129f12c28f651dd1.png)

![](attachments/792a74e5c9451823602470471f4e4d88.png)

### root.txt

![](attachments/fd021e5455469b5f0d7ebb7fb582557e.png)

![](attachments/5a3460909914a8312b15c9e85ccb046a.png)

---