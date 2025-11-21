---
title: 'HTB-Nineveh'
published: 2025-04-23
draft: false
toc: true
tags: ["LFI", "hydra", "pspy", "OSCP Prep"]
---

```
Scope:
10.10.10.43
```

# Recon
## Nmap

```bash
sudo nmap -sC -sV nineveh -sT -T5 --min-rate=5000 -Pn -vvvv

PORT    STATE SERVICE  REASON  VERSION
80/tcp  open  http     syn-ack Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
443/tcp open  ssl/http syn-ack Apache httpd 2.4.18
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html).
```

## 443/TCP - HTTPS

![](attachments/a3ba6fc80a527ce88522019694418a5c.png)

I decided to launch `feroxbuster` and brute force directories.

![](attachments/95766d09e5f9238a90f142da9ced318a.png)

![](attachments/09442246af25ff49fff1ebddebac0d2a.png)

![](attachments/f7181d456a73faf90e868f9936b046ff.png)

I found a `phpLiteAdmin` page with version **1.9** running. This version has multiple vulnerabilities but let's first narrow it down. I decided to launch `gobuster` as well to do some more recon.

![](attachments/04ce843d22c294e8977d3fb66b0c651c.png)

I found another interesting endpoint, let's check it out.

### Strings

![](attachments/148b307f86c9808e69c843d04ac02ae2.png)

Interesting, I saved the pictures and ran `exiftool` but didn't get anything useful:

![](attachments/750395313f0e0da12654f759b2f781a5.png)

Let's check it out using `strings`.

![](attachments/07e2e803030bdf79779244fddab510cf.png)

Unfortunately for us the SSH port is closed thus we have no way of accessing it.

### Hydra 

Time to brute force our way into the `/db` endpoint:

![](attachments/c0e6f37729a539cef551fa7c29e2efb5.png)

I easily found the password and tried it out on the target:

![](attachments/24f75aada5173ca763f50b4000e55351.png)

We got access!

## PoC

I then found a PoC on how to get **PHP Code Injection**:

![](attachments/484e84db0d58bd103b477acbf362d4ed.png)

![](attachments/3407135b36d06b9f173849fed247203c.png)

### Reproducing steps

![](attachments/96ecf857bfc905bca4da71024fbe64b2.png)

![](attachments/70dff1cd04ea1c5df981e0ee761a3bc0.png)

Then we go ahead and fill in the field:

![](attachments/9152dfc6ee2b151b08b1a7681f72f252.png)

![](attachments/dd11cfef9589320556452dc6e471023e.png)

## 80/TCP - HTTP

We return to port `80`. 

![](attachments/3ca87ff7eb9f306c9e52d7cb6e6acfee.png)

![](attachments/64289f09a67fc19d62a00ece903e019c.png)

![](attachments/f7bea25b62ce980dda5fde17aa6c01e8.png)

Here we find out that there are 2 error messages, if I enter a different username than *admin* I get the following message:

![](attachments/d8a1874251336406238f8e690096bb1b.png)

### More Hydra

Thus I yet again launched `hydra` to brute force myself in again:

![](attachments/ef634061177b7442f414f31e36ab497f.png)

![](attachments/6b7adb6176c3af4efe7da765970d589a.png)

And I was inside.

![](attachments/50ab05c1c12e4ea3c0745fc43d1c4377.png)

### LFI

Judging from the URL my senses started tingling and pointing towards some sort of **File Inclusion** vulnerability:

![](attachments/cdc4d2cece84cf6fbdca4061e01cdbb8.png)

Let's see whether this param indeed is vulnerable.

I tried a bunch of combinations but in the end I found this one to work:

```
/manage.php?notes=files/ninevehNotes/../../../../../../etc/passwd
```

![](attachments/4a8aa324efcaf9c5029fb6c63ef983e9.png)

:::success
This is HIGHLY LIKELY because it still needs to read the note, when I input it without the `ninevehNotes` file it gives me this error:
![](attachments/0a2491fc8025ee950cf18d69e7a511be.png)
:::


# Foothold
## RCE via Webshell

We should now be able to use the LFI exploit on the shell that we previously made.

![](attachments/6738b6b4bcacd0c05302058658eec303.png)

It worked!!!

## Reverse shell

Time to get out of this restricted webshell and get a full reverse shell.

![](attachments/259e09fa253b8324b95676a65b5cb38d.png)

![](attachments/ab4c633d5f12ff0ced72e6e175358e6c.png)

![](attachments/566415c071212487007687923a9bf881.png)

Awesome! We got access as *www-data* now.

I then wanted to enable `ssh` so I could use the found `id_rsa` key to log in, but I had no `sudo` privs:

![](attachments/0b8aa9c5e147c92fda0d29b63c40cc8e.png)

## Automatic Enum

I downloaded over `linpeas.sh` and started doing some enum.

While I found some possibly interesting PE vectors I also found this `knockd` binary:

![](attachments/f066c4aaab42ff824fbcdb66aa676e77.png)

This should be responsible for opening up the SSH port, which will let us get access with the *amrois* `id_rsa` key we found earlier.

![](attachments/0f288efcfcdbdfb97e95f02de9c04059.png)

Inside the `knockd.conf` file we found the sequence needed to open up SSH.

## Port Knock

We will be using `nmap` to port knock, however since the sequence must be precise, we will write a `bash` one-liner for it:

```bash
for i in 571 290 911; do
for> nmap -Pn --host-timeout 100 --max-retries 0 nineveh.htb -p $i        
for> done;
```

![](attachments/682f8582279ce892eb484bbd6d3c49c7.png)

Now we can go ahead and SSH into the system.

## Shell as Amrois

![](attachments/019a99f7d0df4d9fd8a2b9ad90918bcc.png)

### user.txt

![](attachments/e6eb1d10abcdf6fb40b5ca0246c18e36.png)


# Privilege Escalation
## pspy64

I transferred over `pspy64` in order to check out the running PID's and found some interesting ones running under *root*:

![](attachments/468c16c9827a1a90c4efabdecbc5ee23.png)

Apparently there's a binary checking for rootkits.

I'll go ahead and look up whether there's some sort of exploit for this binary:

![](attachments/01c900cb9ee3aedc16b2f05b91e2f92a.png)

Indeed there is, a pretty old one at that as well, let's grab it.

:::note
There's also a `msfconsole` version of it, but I want to do it manually.
![](attachments/25ce392348e864f5e49a0e15c3049525.png)
:::

![](attachments/5aad1c74c6f9ca867762c07d5fac86f9.png)

I then went ahead and put a reverse shell inside a `/tmp/update` file:

![](attachments/cd8ee609d8dbe0738990be77f909a7c5.png)

Now it's sit and wait for the shell to fire.

![](attachments/8c26deeb58beaa2db2d6ab09326a3d24.png)

### root.txt

![](attachments/039fab6a3bda3465d0bd784e4362a756.png)


![](attachments/4773f6a9ec920d5e0b628b2e2cea189e.png)

---