---
title: PG-BullyBox
published: 2025-01-03
toc: true
draft: false
tags:
  - "git"
  - "git-dumper"
  - "OSCP Prep"
---

```
Scope:
192.168.196.27
```

# Recon
## Nmap

```bash
sudo nmap -sC -sV -oN nmap bully -T5 -vvvv --min-rate=5000 -sT -p-

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 b9:bc:8f:01:3f:85:5d:f9:5c:d9:fb:b6:15:a0:1e:74 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBYESg2KmNLhFh1KJaN2UFCVAEv6MWr58pqp2fIpCSBEK2wDJ5ap2XVBVGLk9Po4eKBbqTo96yttfVUvXWXoN3M=
|   256 53:d9:7f:3d:22:8a:fd:57:98:fe:6b:1a:4c:ac:79:67 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBdIs4PWZ8yY2OQ6Jlk84Ihd5+15Nb3l0qvpf1ls3wfa
80/tcp open  http    syn-ack Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

It appears this box only has 2 open ports. Let's start with enumerating port 80.

:::note
In the meantime I will run gobuster in order to enumerate sub directories.
:::

## Gobuster

```bash
gobuster dir -u http://bullybox.local -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -x txt,pdf,config
```

This gave a huge output of a bunch of numbers endpoints, but I did find one that could help my further search:

![](attachments/565fcaf0935699abfb86dda0bddc7731.png)

I reran gobuster again using a different list:

![](attachments/b6539bfceccf33f2624e2231f7de938b.png)

Found something!

![](attachments/1fa60113fadcf80e1d7370801e425e20.png)

We'll first enumerate the website, then perhaps come back to this.


## 80/TCP - HTTP

![](attachments/82fe5a8d111808e0723b5ff1e97579a0.png)

![](attachments/b38abefed1274281917893eb61c44081.png)

Here I registered for an account and logged in:

![](attachments/dc6e1630db5419be6d9f864d2709d66b.png)

From the page source we find the HIGHLY LIKELY version of **BoxBilling** running:

![](attachments/8acbe09f2b5974fd1b8b28a07229d7c5.png)

Looking up this version online yields the following:

![](attachments/b46b7605a8c1be84aa28de1f9704c898.png)

![](attachments/ebbc93fb220ea24a2713ac447f41f295.png)

Unfortunately we do not have *admin* access yet. I checked how to acquire it:

![](attachments/ec693a2524fd030235922a485430bc7b.png)

![](attachments/7dc024ed67fd7af11ad26f43418114ba.png)

We've now found the admin log in area.

Whenever I enter some sort of creds I get this popup:

![](attachments/9272897a252a19602ed0257555e903c1.png)

I went and inspected the POST request using burp.


### git-dumper

We still really need the admin creds to modify the request.

Let's check out that `.git` directory again using a tool called `git-dumper`.

```bash
pipx install git-dumper
```

![](attachments/b72526b0b8410d5d9cf986ab89eb4307.png)

This resulted in an absolute massive output.

![](attachments/402b2f5ca3744170ab1ac7e120b2446f.png)

Here I found the config file at the top which was LIKELY to contain a password in this case:

![](attachments/48ed9393951b0fde9a35d08e592ca358.png)

Awesome, we got the admin creds. Let's move forwards

```creds
admin
Playing-Unstylish7-Provided
```

Now we still need the email in order to log in.

![](attachments/e84a53ab4c515a3a831ddb870b6641dd.png)

![](attachments/2d1962fb717df4f2de724dfe913a5ce0.png)

We have succesfully logged in as admin.

### RCE

To make our life easier there's a ready-made GitHub PoC available for us:

![](attachments/b43ab85ae66438fb7d3506b0d249e9c2.png)

:::warning
The script failed on me at the start because of some dependency issues but was solved by using `sudo apt install python3-pwntools`.
:::

We then make sure the last modifications are done:

![](attachments/dadd9ec5a5d979ccb8270dcadf0c06d9.png)

![](attachments/4b7aaebcd453b9a2df28a2cf5ba3b0dd.png)

Nice we got our shell, time to get the flag:

![](attachments/58b8ed67e84d5ccdd3c5bbbddfb52331.png)

Well shit. Let's do some enumeration.

![](attachments/26f23b1ee3a77e59653f7e2fd3ad1ddf.png)

Oh well that saves some time.

### proof.txt

![](attachments/c6d7082c49898991d68f91fd82e7e497.png)

Ez pz.

---