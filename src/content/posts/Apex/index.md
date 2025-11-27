---
title: PG-Apex
published: 2025-05-10
toc: true
draft: false
tags:
  - "CVE"
  - "LFI"
  - "OSCP Prep"
---

```
Scope:
192.168.231.145
```

# Recon
## Nmap

```bash
sudo nmap -sC -sV apex -T5 -vvvv --min-rate=5000 -sT -p-

PORT     STATE SERVICE     REASON  VERSION
80/tcp   open  http        syn-ack Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-title: APEX Hospital
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-favicon: Unknown favicon MD5: FED84E16B6CCFE88EE7FFAAE5DFEFD34
445/tcp  open  netbios-ssn syn-ack Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
3306/tcp open  mysql       syn-ack MariaDB 5.5.5-10.1.48
| mysql-info: 
|   Protocol: 10
|   Version: 5.5.5-10.1.48-MariaDB-0ubuntu0.18.04.1
|   Thread ID: 52
|   Capabilities flags: 63487
|   Some Capabilities: SupportsCompression, LongPassword, Support41Auth, Speaks41ProtocolOld, ConnectWithDatabase, InteractiveClient, IgnoreSigpipes, SupportsLoadDataLocal, SupportsTransactions, DontAllowDatabaseTableColumn, LongColumnFlag, Speaks41ProtocolNew, IgnoreSpaceBeforeParenthesis, ODBCClient, FoundRows, SupportsMultipleStatments, SupportsMultipleResults, SupportsAuthPlugins
|   Status: Autocommit
|   Salt: =_I0R/2Ja(BQT/.:xm;~
|_  Auth Plugin Name: mysql_native_password
```

## 445/TCP - SMB
### Enum4linux-ng

![](attachments/d743cecb07e216ebbf1704b7405b3cf8.png)

![](attachments/de52b1f92442935de596de5e299e8da6.png)

![](attachments/22fc396c637ddedc5708c93e928e415c.png)

Time to check out the `docs` directory.

### Smbclient

![](attachments/4d158dcd17bd0108e782fd95acf65470.png)

I checked out the `.pdf` files and they contained a few pages of medical records and such.

![](attachments/a1358f670c18265d55a421cc31d5755d.png)

### Exiftool

Just in case I used `exiftool` to view the metadata of the files.

![](attachments/1fc9444e1b07e1f4764f820f7f1bb240.png)

## 80/TCP - HTTP

I opened up my browser and expected to see some sort of hospital website:

![](attachments/69b9003464e386ad871584eac0e6f775.png)

Indeed it is.

Here I find a few possible usernames:

![](attachments/dd439b5bb73b0aebb6f21dc8503445e5.png)

The contact form didn't seem vulnerable:

![](attachments/1d364792e43fda06d2221a8ffa5ad16e.png)

I clicked on **Scheduler** and this took me to a login page:

![](attachments/afcd74f0226bf16e4f9cf6ecb6c7eaf3.png)

I tried out `admin - admin` but this didn't work:

![](attachments/e906167f71da908b0045ba0778f946fa.png)

### Gobuster

I launched `gobuster` to enumerate the directories and endpoints:

![](attachments/87808248ec2eae8562dc25288a9e8c2b.png)

I found a `admin.php` page which I checked out:

![](attachments/76f93ed5850c514add3bbd2a08223858.png)

Awesome we found the version, let's look for an exploit!

![](attachments/7ef6eae4282aaba166894901cb264815.png)

We need to be authenticated though, we have potential usernames but not the passwords.

I started searching further and found the following directory:

![](attachments/0e57d50189d52e98d376ebebd1abe727.png)

![](attachments/b08876ead8b902187f6707dc02f47447.png)

In here I could apparently upload files!

### LFI - Responsive Filemanager 9.13.4

I tried uploading a webshell but it wasn't allowed:

![](attachments/191c270fac5568460553116c8cbc319d.png)

We could now brute force filetypes and check whether any would be allowed but I decided to enumerate further first.

I noticed a little question mark in the top right corner:

![](attachments/9af1a352bb678ad7b6d5f4778b2eef3d.png)

![](attachments/5de7701de9b1658e2419e421fa22a29f.png)

Ah yes... We now got another version.

![](attachments/4ebc966f71db831c62206f7af9610355.png)

![](attachments/8f83e9ce38ff1b89f3c647cda25b3d36.png)

![](attachments/9c2a6c9bc0de79cb1c8a3d48877398c7.png)

Pretty straightforward 

![](attachments/9acad1df37b8b12db11234b62c0cb3dc.png)

![](attachments/99e39302b1c13b598121aab5ddfea531.png)

Unfortunate

We need to find another way to get RCE.

# Foothold
## Checking Source Code 

I checked out GitHub where I found the source code to `openemr` where they had the following `sqlconf.php` file:

![](attachments/5b019e2762c57af207e7462ae01ae420.png)

I checked whether this existed here, perhaps it could contain credentials:

![](attachments/3560b23b8e66f7522a8605b9765e3bc4.png)

No error, meaning it HIGHLY LIKELY exists, let's try reading it using the LFI exploit.

:::important
Before doing this however we need to make slight changes to the PoC, we'll have to change the `read_file` `url_path` so we can get the file via `smb`, namely because the file won't be read on the client side as it is a `.php` file:
![](attachments/f4119bb19089a3e59f0b3ae5d72aa9e0.png)
:::

![](attachments/427a231cb3186921679c754c5884e070.png)

Now we can grab it and check the contents.

![](attachments/bc422cae6d824370df4aec8115cb71bf.png)

## 3306/TCP - MySQL

:::warning
I had to issue the `skip_ssl` option otherwise it *WOULD NOT WORK*!!!!
[](attachments/3af0dcb5bcd57c1f2885763575c4b2fb.png)
:::

![](attachments/b1314ac3613d4cb51b7d3e777cf8625c.png)

We gain access with the found password.

![](attachments/d831258a8e7b0d3988e5a11e5bd1cc02.png)

![](attachments/f067e42ebf832b8835a00287cf174875.png)

This was obviously not the pass?

I checked the tables again:

![](attachments/71bc7fb23e202117c42ecee4f8e6a8a2.png)

![](attachments/5116df9911b66c3bec735caeb424a6a8.png)

```
$2a$05$bJcIfCBjN5Fuh0K9qfoe0eRJqMdM49sWvuSGqv84VMMAkLgkK8XnC
$2a$05$bJcIfCBjN5Fuh0K9qfoe0n$
```

## Hashcat

I threw the hash into `hashcat`:

![](attachments/a26b1b6e787f22c099588bccd20289ab.png)

![](attachments/518cfdcb9616d3dcb961613f37a16c3c.png)

I could now use these creds to log in to the portal.

```
admin
thedoctor
```

## RCE - OpenEMR 5.0.1

I then followed the previously found github RCE steps:

![](attachments/81c2608bf22b3c1b5c0a10b892cdb5ba.png)

![](attachments/8fb247217bd2960019f8ae661d857622.png)

![](attachments/255a6b484d9f7535191b668589b370fb.png)

Yeah this didn't work, let's check alternative scripts.

![](attachments/788ce098e3c26d5d644e93504930a0bf.png)

I went ahead and launched the following one:

![](attachments/44ae8840b52d00f744206d4f1408f2d2.png)

![](attachments/b66c9c48540488f570136313ee7f25bc.png)

### local.txt

![](attachments/03cd70f52e6fff8a8c72b3f01685a900.png)

# Privilege Escalation
## Shell as root

Since the password was for the *admin* user, we can try and password spray before doing any further enum:

![](attachments/9d303ad1343071e45377b9a69cc089f6.png)

Easiest privesc ever.

### proof.txt

![](attachments/39f224acee6da69742ee753766388507.png)

---
