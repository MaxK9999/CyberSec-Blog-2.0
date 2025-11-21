---
title: 'HTB-Horizontall'
published: 2025-09-18
draft: false
toc: true
---
**Start 12:17 25-10-2025**

---
```
Scope:
10.10.11.105
```
# Recon
## Nmap

```bash
sudo nmap -sC -sV -sT -p- -vvvv -T5 --min-rate=5000 -Pn horizontall.htb

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack nginx 1.14.0 (Ubuntu)
|_http-title: horizontall
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-favicon: Unknown favicon MD5: 1BA2AE710D927F13D483FD5D1E548C9B
| http-methods: 
|_  Supported Methods: GET HEAD
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## 80/TCP - HTTP

![](attachments/fb698446ddcc1a65f4229493ff0953c2.png)

![](attachments/5e18d5fdb8e9da8cef324265a38d4b11.png)

It looks like a static site.

I ran a `gobuster` scan but found nothing useful:

![](attachments/7b6829fb18ed997791d1d6145a2ef901.png)

I did find some obfuscated `js` code in the source code that I ran in [prettier.io](https://prettier.io/playground):

![](attachments/d613a324fb87898229082841a18e1a19.png)

Going all the way down I noticed the following which looked like a vhost:

![](attachments/77bed367eb56772ade85e8d9ff10efbe.png)

## api-prod

I added the `vhost` and started enumerating the host:

![](attachments/f2d7be2c4e28da2b5d46f693a8d2de41.png)

![](attachments/a0596360f4bf9eb4c646410477f0e82b.png)

I checked the response in `caido` since the page was empty:

![](attachments/23940f245dd550f025ff3727b90a3167.png)

I headed over to the endpoint that I'd found earlier:

![](attachments/7ed164fb51d8bfc9e8600592ea7a7e91.png)

I then used `gobuster` to enumerate the endpoints:

![](attachments/b68011db1fe6a4725a6072c15893cdfd.png)

# Exploitation
## CVE-2019-19609

I searched for relevant exploits and found an **Unauthenticated RCE** which could be big.

![](attachments/6a6e583cd92ae3288178e793eb3be415.png)

I downloaded the exploit from exploit-db and tried it out:

![](attachments/cf6e26c420e576269c98f6497c5014e2.png)

Once I had achieved RCE I ran the following payload to achieve a foothold:

![](attachments/ddd744879ea91afb35bf8b4e19d04f91.png)

# Foothold
## Shell as strapi

![](attachments/488a7ec928ff20ddbd55f4fb42673196.png)

I noticed one other user present on the target:

![](attachments/6ed1476aacbf936dcbac6cda219cc1d2.png)

I went ahead and read the user flag right away.

### user.txt

![](attachments/eb2827f1e6035136d81160ab00622e23.png)

Other than that I had no permissions over any files or directories in *developer*'s `/home` directory. 

## Enumeration

I transferred over `linpeas.sh` and got to work:

![](attachments/cf6faf88ebbb270a6fe917772831c9ba.png)

![](attachments/bc872329ba53a2d7a6f6ac09f69dafbc.png)

![](attachments/07231dcfd157b5996a254bccea842684.png)

Other than that I also found the credentials for *developer*:

![](attachments/46aba36ad9fe314cb9f5b37f2ec1f03b.png)

```
developer
#J!:F9Zt2u
```

While we couldn't use these creds to `su`, we couldn't access `mysql` with them either.

![](attachments/e2517be7eb0927534e51de3919d61b10.png)

# Privilege Escalation
## pwnkit

The priv esc was actually rather simple, we indeed just had to run `pwnkit.py`:

![](attachments/9ceeff94ca7718af8119d94857a09454.png)

### root.txt

![](attachments/a93ca71424951738d88abb50c9c8c5d9.png)

![](attachments/730951e8a082375f91e4b4787b9f8b35.png)

---

**Finished 13:25 25-10-2025**

[^Links]: [[Hack The Box]]

#pwnkit #CVE-2019-19609 #vhosts 
