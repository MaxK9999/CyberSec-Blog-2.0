---
title: 'HTB-Delivery'
published: 2025-09-16
draft: false
toc: true
tags: ['WeakCredentials', 'TicketTrick']
---

---
```
Scope:
10.10.10.222
```

# Recon
## Nmap

```bash
sudo nmap -sV -sC -sT -p- 10.10.10.222 -T5 --min-rate=5000 -vvvv -Pn

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
80/tcp   open  http    syn-ack nginx 1.14.2
|_http-title: Welcome
|_http-server-header: nginx/1.14.2
| http-methods: 
|_  Supported Methods: GET HEAD
8065/tcp open  http    syn-ack Golang net/http server
| http-methods: 
|_  Supported Methods: GET
|_http-favicon: Unknown favicon MD5: 6B215BD4A98C6722601D4F8A985BF370
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Mattermost
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 200 OK
|     Accept-Ranges: bytes
|     Cache-Control: no-cache, max-age=31556926, public
|     Content-Length: 3108
|     Content-Security-Policy: frame-ancestors 'self'; script-src 'self' cdn.rudderlabs.com
|     Content-Type: text/html; charset=utf-8
|     Last-Modified: Tue, 16 Sep 2025 06:22:01 GMT
|     X-Frame-Options: SAMEORIGIN
|     X-Request-Id: zoepm6m5st8zpydro6dgggprch
|     X-Version-Id: 5.30.0.5.30.1.57fb31b889bf81d99d8af8176d4bbaaa.false
|     Date: Tue, 16 Sep 2025 07:10:40 GMT
|     <!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=0"><meta name="robots" content="noindex, nofollow"><meta name="referrer" content="no-referrer"><title>Mattermost</title><meta name="mobile-web-app-capable" content="yes"><meta name="application-name" content="Mattermost"><meta name="format-detection" content="telephone=no"><link re
|   GenericLines, Help, RTSPRequest, SSLSessionReq: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Accept-Ranges: bytes
|     Cache-Control: no-cache, max-age=31556926, public
|     Content-Length: 3108
|     Content-Security-Policy: frame-ancestors 'self'; script-src 'self' cdn.rudderlabs.com
|     Content-Type: text/html; charset=utf-8
|     Last-Modified: Tue, 16 Sep 2025 06:22:01 GMT
|     X-Frame-Options: SAMEORIGIN
|     X-Request-Id: 3qwkqzys5fnx9p7x5c44z3pbje
|     X-Version-Id: 5.30.0.5.30.1.57fb31b889bf81d99d8af8176d4bbaaa.false
|     Date: Tue, 16 Sep 2025 07:10:24 GMT
|     <!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=0"><meta name="robots" content="noindex, nofollow"><meta name="referrer" content="no-referrer"><title>Mattermost</title><meta name="mobile-web-app-capable" content="yes"><meta name="application-name" content="Mattermost"><meta name="format-detection" content="telephone=no"><link re
|   HTTPOptions: 
|     HTTP/1.0 405 Method Not Allowed
|     Date: Tue, 16 Sep 2025 07:10:25 GMT
|_    Content-Length: 0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## 80/TCP - HTTP

I went on over to the website and found this:

![](attachments/207bd4bdc61f3c53b6d609b8744905c0.png)

When clicking on it it takes us to `helpdesk.delivery.htb`, which means that I have to add a vhost to my `/etc/hosts` list.

![](attachments/dbbbeac303476d34de71cc231be5fd4c.png)

Now when I run `gobuster` I find some interesting endpoints:

![](attachments/331cf41d4abf21b89eacc6075b5837b0.png)

Heading on over to the vhost I find the following:

![](attachments/210d5f69eaef8e3f0d6b63281aef0098.png)

### burpsuite

In **Check Ticket Status** there's a mention of registering an account so I try it out.

![](attachments/bc33d5d1fbf6db63d73473d486698462.png)

Clicking on it I see this URL:

![](attachments/cbcde79cca6594b0987d96d3da02291e.png)

>[!note]
>It might be vulnerable to IDOR, SQLi or LFI in the best case.

I registered for a sample account and checked `burp`:

![](attachments/694b819e2d7b77f105528eb79e95e0e2.png)

But this tells us that we need to verify the email, nonetheless we can continue on as the *Guest* user.

I could then create and submit a ticket:

![](attachments/401bf67429a0000540112384dd9c3cc1.png)

![](attachments/1b19dcb1e26ee5c811f5c6fcbf1e65b5.png)

![](attachments/a12ca2cabf7a63a22e6c0dbeb80a3c2c.png)

I could then view the ticket:

![](attachments/108b1998bcc207ffa132baf5039d7c56.png)

## 8065/TCP - HTTP

I then went on over to the **Mattermost** instance on port `8065` where I could register using the provided email address when I created the ticket:

![](attachments/0b015ed3fea95bab4e5013acf504bb96.png)

Back on port `80` I can now refresh the page and see the following content appear:

![](attachments/e6d2a1cc3ae4a9f6afe382979bf361bb.png)

I copy and paste the link and see this:

![](attachments/d952ec399d3602b66bfdd61cfdb72c18.png)

I was able to join the **Internal** team server where I found the following conversations:

![](attachments/af65868d809a2629ce365dacdd32ee13.png)

```
maildeliverer
Youve_G0t_Mail!
```

# Foothold
## SSH as maildeliverer

I log in with the found credentials.

![](attachments/8d8d4548e6e0f5fea9daf561249bb561.png)

### user.txt

![](attachments/767c47743b0cc14ae2fa903de78a12c2.png)

Inside the `/opt` directory I find the `mattermost` folder.

![](attachments/9045e3a1178b46b04f7015d7da22987a.png)

![](attachments/920ffa08969ce3254f5c90fde2b404cf.png)

![](attachments/10256b779778887cd48536aa49fd23cc.png)

```
mmuser
Crack_The_MM_Admin_PW
```

## 3306/TCP - MySQL

Using the found creds I logged in:

![](attachments/b6625ac40f012f7734b7087742319a80.png)

![](attachments/49cda019c6d11cef5bec602364e02ff2.png)

This gave an absolute boatload of output.

Amongst all the noise however I was also able to find *root*:

![](attachments/1e7b50dc2a3390f5fed185f236d36a0e.png)

# Privilege Escalation
## hashcat - rule based

I used hashcat with the `best64.rule` to crack the hash:

![](attachments/1b176d81ab0522118d0258bc6b5442d4.png)

![](attachments/c864a09d00778a400e7ea232276707c4.png)

It was simply a variation on the cleartext password that we've already found previously in the **Internal** channel. Let's log in.

![](attachments/afc9bc0d57ac2dae23ad42b7adc11452.png)

### root.txt

![](attachments/042bb1538a4b9a1f4cbb066fc34d9a49.png)

>[!note]
>![](attachments/0f0bbd6459104ee9dd65b3f71182e836.png)
>
>Here is the [link to the post](https://medium.com/intigriti/how-i-hacked-hundreds-of-companies-through-their-helpdesk-b7680ddc2d4c)

![](attachments/893eefc5e98562d5b1038b118ee4bfdb.png)

---