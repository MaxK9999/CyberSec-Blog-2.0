---
title: 'HTB-Paper'
published: 2025-04-22
draft: false
toc: true
tags: ["LFI", "polkit", "OSCP Prep"]
---

```
10.10.11.143
```

# Recon
## Nmap

```bash
┌──(kali㉿kali)-[~]
└─$ nmap -sC -sV -sT -T5 -vvvv -p- 10.10.11.143

PORT    STATE SERVICE  REASON  VERSION
22/tcp  open  ssh      syn-ack OpenSSH 8.0 (protocol 2.0)
80/tcp  open  http     syn-ack Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1k mod_fcgid/2.3.9)
| http-methods: 
|   Supported Methods: GET POST OPTIONS HEAD TRACE
|_  Potentially risky methods: TRACE
|_http-generator: HTML Tidy for HTML5 for Linux version 5.7.28
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
|_http-title: HTTP Server Test Page powered by CentOS
443/tcp open  ssl/http syn-ack Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1k mod_fcgid/2.3.9)
|_ssl-date: TLS randomness does not represent time
| http-methods: 
|   Supported Methods: GET POST OPTIONS HEAD TRACE
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
commonName=localhost.localdomain/organizationName=Unspecified/countryName=US/emailAddress=root@localhost.localdomain/organizationalUnitName
```


## 80/TCP - HTTP

![](attachments/dcb71800b6041537de7d77575076afec.png)

There really is nothing here, time for `feroxbuster` to do its thing.

Unfortunately apart from a bunch of `/manual/` endpoints we don't find anything useful, let's check `443`:

![](attachments/e9f59c61f5a6d2a6e326fca62b48cd46.png)

Since this didn't tell us anything I decided to check the response headers:

![](attachments/e7a40cc18dbe0da280c9f29c5f760c68.png)

I found an `X-Backend-Server` header with the `office.paper` variable. I decided to add it to my `/etc/hosts` list as this was HIGHLY LIKELY a subdomain.

![](attachments/7354acc2b243a41cc7720faaf19610fa.png)

Correct indeed! Let's check the tech stack:

![](attachments/f1dd59808670e7be8d35b5ad8e2f7eef.png)

It's running **WordPress 5.2.3**, let's see if it's vulnerable.

![](attachments/337d659e7261b2a5a79504602a1ade20.png)

It is vulnerable, let's see if this is what we need to find.

![](attachments/9367ff69807fc0f3020254539ffe4653.png)

According to above comment it looks like it is the correct CVE, let's exploit it.

![](attachments/403d80b97bc011c8456aebf5b77476ae.png)

![](attachments/cd3c1e07191e9f0f3c1ed0db93756617.png)

I went ahead and registered a new account via the found URL:

![](attachments/d2e1465154a41488f4d4096d93d13c79.png)


## LFI

This was all fun and games but I had no access to the admin panel, so I decided to check what I could get from the bot:

![](attachments/a7de56ea1f3776d5da80306c62752bad.png)

I was able to list files from the `/sales/` directory.

However I was *also* able to get the contents from the `/` directory.

![](attachments/42d3a99ea97d2bc9feaeb9564b7bef91.png)

Even better news:

![](attachments/35250b22d62f22c7fa2787f0484eae33.png)
![](attachments/c6ed095b74b8f074f6298e66f487ce27.png)

Let's check out *dwight*'s `/home` directory.

![](attachments/cb9c69f1b85822a8a5142e078fb7d91c.png)

Even though I had access, I unfortunately did *not* find a `.ssh` key here nor could I read the `user.txt` file yet.

However I noticed the `/hubot` directory, and checked it out:

![](attachments/a4f7caddc85e11e352ca7eeceab3ef00.png)

In here I found the `.env` file which usually contains stuff developers want to hide from the rest.

![](attachments/88d069be579e224db946408481e6685e.png)

Hell yeah.

```
recyclops
Queenofblad3s!23
```

![](attachments/22ccc6457bc5728b4b08e16a57109486.png)

When I try to log in I get the above message, but I am still able to log in:

![](attachments/2ee2ecad24d72681e05c02939d19d811.png)


# Foothold

Let's see if *dwight* uses the same password for SSH:

![](attachments/da39677e6180c4f7346a41cfa71bb94d.png)

EZ PZ access.

## user.txt

![](attachments/bd6f36934052c0d02dd53a04505503b7.png)

Other than that I have no `sudo` privs:

![](attachments/a623427f9c05f4bd3006b29bdd79b6ae.png)


# Privilege Escalation

I decide to download over `linpeas.sh` and run it.

![](attachments/c71a83c7b47976fd0560d7a18e454f0e.png)

I noticed this one which I haven't seen before amongst the suggestions, let's check it out.

Let's verify the version of `polkit` running:

![](attachments/5cc87753423a8f2c4694d7a9d310cbb1.png)

I found a script that should automatically do this:

![](attachments/6fb1810d9b2899d79ccfb1053cec398c.png)

![](attachments/637e464bc39d6a3837acdd02f2681a17.png)

![](attachments/5336b673d05e1976e88d8dc35f61d6d6.png)

Hell yeah.

## root.txt

![](attachments/084177e5792807ccfc2249ca0dd52b77.png)

![](attachments/1e6bc93647697874854f7edf6a726b62.png)

---