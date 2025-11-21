---
title: 'HTB-Outbound'
published: 2025-09-18
draft: false
toc: true
---
**Start 08:50 14-07-2025**

---
```
Scope:
10.10.11.77

Creds:
tyler / LhKL1o9Nm3X2
```
# Recon
## Nmap

```bash
sudo nmap -sC -sV -sT -vvvv -p- -T5 --min-rate=5000 -Pn outbound.htb                                                              [0]

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 9.6p1 Ubuntu 3ubuntu13.12 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack nginx 1.24.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://mail.outbound.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

![](attachments/f7f61c8afcb67cd14190fa737ef8a022.png)

I checked for other subdomains but no hits:

![](attachments/50a67abfc3459560b91c69699790ab6d.png)

## 80/TCP - HTTP

![](attachments/a4d565f1c47fa32c2cab0638e8712ccd.png)

Here we can easily log in with the provided creds:

![](attachments/87c431879c4f7c0a8398c3a642233de4.png)

![](attachments/1757a92a890ef9590128545caf8d1c35.png)

Scrolling around I manage to find the version:

![](attachments/4747c4e96ba43b631bce066919a87528.png)

### CVE-2025-49113 - Authenticated RCE

![](attachments/64393584d450f3f10111c67be44e7fe5.png)

![](attachments/09cfa2f2ea5bfaa984f55f57bf75a8bf.png)

Apparently the exploit lies in this piece of code:


![](attachments/08fbb709dca9df7dda1c7fee557fee41.png)

Scrolling further down we can find the PoC:

![](attachments/2405a6ccda1d12b4e6dda82740d09396.png)

We can't just get traditional reverse shell right away, instead it's limited RCE:

![](attachments/ecf7381e7c9385480fa09d0e27b4fb3c.png)

# Foothold
## Shell as www-data

I was able to get a full-on reverse shell using the following method:

![](attachments/58bd6182e02594e65139ea4f947a4c0e.png)

![](attachments/3a278e5bd53c4a4e404ae8f3573ee349.png)

Time for some enum:

![](attachments/0257fc0f162894dfa98b9bf2c50e90f4.png)

I downloaded over `linpeas.sh` to speed up my enum.

![](attachments/953e6c11eab9e04a4f09cd5949e2db6b.png)

![](attachments/28dc9afef7ab5fe8e9663e88ba8d2def.png)

`mysql` is open and running.

![](attachments/23870465a85d1cfb154a462558ba1f25.png)

![](attachments/16cff22984cd05a983d91c2ac3ca89db.png)

```
roundcube
RCDBPass2025
```

![](attachments/134a093a11570d41ba4056d370244c38.png)

## MySQL

![](attachments/92353364456d4b4aab06b0d7a3cf562e.png)

![](attachments/5a3f9f9ac8491f1529586f38e9ba5820.png)

![](attachments/d27c3ab4a16af2e0cac90ec4e25f7ec0.png)

## Lateral Movement - Tyler

Eventually I figured to respray the password and got access as *tyler* using `su`:

![](attachments/5f7b4c705ec1ae530d6bab297240cac2.png)

>[!note]
>After being stuck for a while I returned to `mysql` and found that I needed to decypher the session:

### Return to MySQL

![](attachments/f83775265bd70f0d256a6b3a7df7db16.png)

![](attachments/335dae5080bbc140ba41013838078cde.png)

From here we can decipher the text:

![](attachments/fc5b9bfb12e278aa59d726bd45b2fbc5.png)

And now I can use the `/var/www/html/roundcube/decrypt.sh` script to decipher that one:

![](attachments/b323c2c6aceeda2eaa3c8331c5c0e30a.png)

## Lateral Movement - Jacob

We can now return back to the web service again to log in there:

![](attachments/f4f17a364dcb0d948ff09ab935eea146.png)

![](attachments/f03995c3aeb2d45538e939364c097d90.png)

![](attachments/c6f9b68dd6e10c83cea61118c49d39cf.png)

```
jacob
gY4Wr3a1evp4
```

We can use these creds to login to `ssh` for real this time:

![](attachments/cfb15bd64335c539f74bc3b75269756b.png)

### user.txt

![](attachments/afe2c91a73e6145700487bd5e51696a5.png)

# Privilege Escalation
## CVE-2025-27591 - Below

So we have `sudo -l` privs for the following:

![](attachments/caf55c7905625fe10202a7591cdacb1d.png)

Luckily for us someone's already made a PoC for getting *root* -> https://github.com/BridgerAlderson/CVE-2025-27591-PoC?tab=readme-ov-file

![](attachments/89700107f74238251d1a0fde9553419c.png)

![](attachments/b515e1a0694c25b886c42ee7c57a1fb4.png)

Super duper easy!

### root.txt

![](attachments/4d00fd2c9b6e38aa7e8f9fc025a3c67a.png)

![](attachments/30518a9b739424aa84d02cce3db75e7d.png)

---

**Finished 23:15 14-07-2025**

[^Links]: [[Hack The Box]]

#CVE-2025-49113 #CVE-2025-27591 
