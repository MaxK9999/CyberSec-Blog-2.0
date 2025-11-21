---
title: 'HTB-Driver'
published: 2025-09-24
draft: false
toc: true
tags: ['CVE-2021-1675', 'PrintNightmare', 'SCF-file-attack']
---

---
```
Scope:
10.10.11.106
```

# Recon
## Nmap

```bash
sudo nmap -sV -sC -sT -p- driver.htb -T5 --min-rate=5000 -vvvv -Pn

PORT     STATE SERVICE      REASON  VERSION
80/tcp   open  http         syn-ack Microsoft IIS httpd 10.0
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=MFP Firmware Update Center. Please enter password for admin
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: Site doesnt have a title (text/html; charset=UTF-8).
135/tcp  open  msrpc        syn-ack Microsoft Windows RPC
445/tcp  open  microsoft-ds syn-ack Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
5985/tcp open  http         syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DRIVER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
```

From the `nmap` scan it seems like there's an account on port `80` called *admin*.

## 80/TCP - HTTP

![](attachments/13d2ebd9301400394077fa4d987d3a2c.png)

It seems like we're dealing with **HTTP Basic Authentication**. Since we already know the username we will only need to identify the password.

Using `hydra` I can quickly find out the credential combination:

![](attachments/c471449b2c8741b543d195662debf2cc.png)

Logging in brings me to the following page:

![](attachments/0ad1aa2f1a01ad89f1f32b45335ce70a.png)

Clicking on **Firmware Updates** shows us this page:

![](attachments/fffd443244b094ac93299be32d26e123.png)

I tried uploading a `webshell.php`:

![](attachments/3d38010e28052196a39e8d429d296a06.png)

The URL told us that it worked:

![](attachments/eadc4acdda527e68d5f45f2059cd2dfb.png)

However I wasn't able to access the webshell since I didn't know where it got uploaded, `burp` didn't tell me either so there's probably a different route here.

## 445/TCP - SMB

![](attachments/00aacbae4c608ef2359318bc70135300.png)

I wasn't able to create a NULL session here, but this port is still open.

I started digging around when I found the following:

![](attachments/7d4c9cf158da3bd38b1f801f39be4e66.png)

![](attachments/eea6f8d2746b5c464d85610fa099db0d.png)

We can upload this file to the `smb` share through the webserver, and catch the hashes through responder.

## PoC

![](attachments/8513e7c626806f1b09ad455fd0f669c0.png)

![](attachments/ba8defe7c16ef672da934fbefd0cc07b.png)

By running `sudo responder -I tun0` I then catch the hash for *tony*:

![](attachments/634f0cfe4a80b4c09011839354f305b5.png)

By using `john` we can easily crack the password.

![](attachments/5a65385ec25b1d92b8d02fb7e4c2368c.png)

```
tony
liltony
```

# Foothold
## 5985/TCP - WinRM

Using the previously found creds we get easy access.

![](attachments/b3ec1b4b597b09aee9143eba49e7b060.png)

### user.txt

Here we can get the `user.txt` right away:

![](attachments/42d7a28b585d218df44f047d1aa13a15.png)

## Enumeration

![](attachments/111e50e562a03c9bca23a284c447074b.png)

After scrolling through it I found a scheduled task:

![](attachments/cc24dd8c1ad614a922bdb4a4342a6175.png)

Before diving deeper into those files I enumerated further:

![](attachments/cf4c10db49b0a075744d8e3fbc8f7947.png)

The above tells us that the Spooler service is running. We can use `PrintNightmare.ps1` to easily get *admin* rights.

# Privilege Escalation
## CVE-2021-1675 - PrintNightmare

I downloaded over the script and added the *tester* user as follows:

![](attachments/9900ca5fc17dc379762051df5762f2d0.png)

I can now easily log in as this user:

![](attachments/5ebc47908d30989e5f87e5edd1eadf45.png)

### root.txt

![](attachments/66bb9eea3b10db30b7a2d085a62c098f.png)

## Cleaning Up

As part of the clean up we can now delete all files from the system and delete the created user:

![](attachments/c8a94f597d0001c803db0032ec5fbf96.png)

![](attachments/5d8f394a83dfad9401e1e5fbd4d14b7c.png)

---