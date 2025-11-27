---
title: PG-Boolean
published: 2025-01-04
toc: true
draft: false
tags:
  - "LFI"
  - "gobuster"
  - "persistence"
  - "burpsuite"
  - "OSCP Prep"
---

```
Scope:
192.168.188.231
```

# Recon
## Nmap

```bash
sudo nmap -sC -sV -oN nmap 192.168.188.231 -T5 -vvvv --min-rate=5000 -sT -p-

PORT      STATE  SERVICE REASON       VERSION
22/tcp    open   ssh     syn-ack      OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
80/tcp    open   http    syn-ack
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GenericLines, Help, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns: 
|     HTTP/1.1 400 Bad Request
|   FourOhFourRequest, GetRequest, HTTPOptions: 
|     HTTP/1.0 403 Forbidden
|     Content-Type: text/html; charset=UTF-8
|_    Content-Length: 0
3000/tcp  closed ppp     conn-refused
33017/tcp open   http    syn-ack      Apache httpd 2.4.38 ((Debian))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Development
|_http-server-header: Apache/2.4.38 (Debian)
```

That's weird, we get 3 ports of which `3000` seems to be closed but still shown, and `80` is open but has a `403` code. I decided to check it using `curl`:

![](attachments/a9400f41dad9d53d6416d098b9c8e69f.png)

However port `33017` gave us some other output:

![](attachments/d0041c4e512cc626e8d4e91d3d3844de.png)

It seems this port is still in development, could be a potential attack vector. We'll note it down for now.

## Gobuster

Let's do some directory enumeration.

![](attachments/40daab2e580108522d7f41524c262145.png)

We get some `filemanager*` pages, including a `.config` file which could be potentially interesting. Problem is that we need login creds in order to access it.

![](attachments/d3d3a54ebb7b78609a22a280f81969d3.png)

Funnily enough when we check the page source we notice something interesting:

![](attachments/b7ae17245eafb397820e262e5bc1444c.png)

I registered for an account using fake creds but couldn't get access.

![](attachments/c38529623aead9e3de5ec7e1094f3965.png)

![](attachments/e11ca1ddaf7d6bcbd7f6229c91542a24.png)

I then checked the other port:

![](attachments/5cba528d1f74158e976eb6956b545ac6.png)

This yet again showed us a bunch of interesting extensions but we couldn't access them:

![](attachments/55003cf1387aad436f6f1e7ed1186a4c.png)


# Initial Foothold 

## 80/TCP - HTTP

Using **WappAlyzer** I found out that the webpage was using **Ruby on Rails**.

![](attachments/c698ec8b2d7b035650deede7e74b5fc4.png)

Since the exact version was not known nor found I had to do some digging.

I booted up burpsuite and analyzed the POST request.

:::note
It turns out that when a user creates an account, they need to verify the email first.
Via burp I found out that the response told the server whether the `confirmed` state was either `true` or `false`, e.g. a Boolean value.
:::

![](attachments/7a9a1075dd975c0bf8fafd5ff870a60a.png)

We needed to zoom in on this part:

![](attachments/0181260f7fa6cdcf2785e5d35e164004.png)

This response meant that we could manipulate our request by adding the `confirmed=true` value.

Let's test it out.

```bash
# Change ONLY the following parameter
user%5Bemail%5D=test1%40gmail.com

# Into
user%5Bconfirmed%5D=True
```

![](attachments/73cda4143495732ed9802359021e6f87.png)

By modifying the request we were able to verify our email address and account, now let's login.

Upon refreshing the page we got a new dashboard:

![](attachments/39aa6d89a09f110df3177ff40fc010c0.png)

I tested the upload function to better understand it:

![](attachments/f3d736a80cb5346c519a0fa7ba028fdd.png)

I then right clicked the file to check where it was uploaded:

![](attachments/5f2b2f9944ff5132ea5db1284f0399ad.png)

This is the link that would execute every time I tried to download the file again.

Let's try something out.

![](attachments/9fadf9f5f70ce46b6b1485d92a0ffa63.png)

We were able to get the `/etc/passwd` file.

:::note
We were able to get the `/etc/passwd` file by exploiting a **Directory Traversal** vulnerability.
:::

Inside the `/etc/passwd` we found the following user:

![](attachments/29c9180df86d73935ae17d6a75cdc8b8.png)

Let's try to insert a `ssh` key in their `.ssh` directory in order to simplify logging in to their system.

![](attachments/77e2f0a6ed1d0a947bb495a56a36b822.png)


## SSH Keygen

To drop our ssh key in there we can follow [this guide](https://mqt.gitbook.io/oscp-notes/ssh-keys?source=post_page-----9c7f5b963559--------------------------------):

![](attachments/f71eb41da4f55c6a18508ea15774ac88.png)

![](attachments/8a9855fb19cd362aa502a114f976f56e.png)

![](attachments/05838d840146b23f224ee216472ca12c.png)

We have successfully copied it over, let's log in now.

![](attachments/dcb56c72a68ced83da9dca52cac1083b.png)

### local.txt

![](attachments/0a8671a4daf526c56c435f60b78540f7.png)


# Privilege Escalation

I noticed the `boolean` directory in remi's `/home` directory. I went in and started snooping around, after some searching I found the following:

![](attachments/e74e688332d3027a241ef6c9f27f2719.png)

We could try and log into **MySQL** and check for some interesting stuff.

![](attachments/2b81822ebcb0facfa1e8dcb29fcaf64f.png)

Nothing interesting came up.

:::note
I got a bit stuck then realized that the `root` key was inside remi's `/.ssh/keys` directory, meaning I could just log in using that key.
:::

![](attachments/b7f96f5b62c6d598f3ebcc45fb281fd1.png)

:::warning
Using normal `ssh -i root root@127.0.0.1` kept resulting in an error so this was the only way to get it working.
:::

---


