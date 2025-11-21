---
title: 'HTB-Trick'
published: 2025-09-18
draft: false
toc: true
---
**Start 09:30 25-09-2025**

---
```
Scope:
10.10.11.166
```
# Recon
## Nmap

```bash
sudo nmap -sV -sC -sT -p- trick.htb -T5 --min-rate=5000 -vvvv -Pn 

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
25/tcp open  smtp    syn-ack Postfix smtpd
|_smtp-commands: debian.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
53/tcp open  domain  syn-ack ISC BIND 9.11.5-P4-5.1+deb10u7 (Debian Linux)
| dns-nsid: 
|_  bind.version: 9.11.5-P4-5.1+deb10u7-Debian
80/tcp open  http    syn-ack nginx 1.14.2
|_http-server-header: nginx/1.14.2
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-favicon: Unknown favicon MD5: 556F31ACD686989B1AFCF382C05846AA
|_http-title: Coming Soon - Start Bootstrap Theme
Service Info: Host:  debian.localdomain; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

I noticed the `53` port first which I used to zone transfer:

![](attachments/58276f790acfb22373702c67181edc11.png)

I found a subdomain called `preprod-payroll`.

## 80/TCP - HTTP
### preprod-payroll

![](attachments/ca0468abe25bd0edb0d12bcb7ca74141.png)

I used `gobuster` to enumerate the endpoints. Since this is a *pre-production* subdomain, it's LIKELY to still contain debug functionalities of some sorts.

![](attachments/82d580c7508f76dede2bec86213046d0.png)

`/users.php` sounds interesting!

![](attachments/506c344079c9d2caa1710f984fb30b8c.png)

I then checked out the other endpoints:

![](attachments/04e48f17da723164f1813f82fe3725ab.png)

But I couldn't do anything in either of them. I know that there's a `/database` however, meaning some sort of SQL commands get used. Maybe there's a SQLi here?

### SQLi testing

I copied the initial request and used it with `sqlmap` to bruteforce the db:

![](attachments/5775c1afe2def035ac2c01b396b98257.png)

![](attachments/cb35771b1a8cbd6ab9d5ac373035c937.png)

It worked!

![](attachments/36e1e2485ebe3b1fd69016d8b9efb944.png)

I found the creds down below:

![](attachments/3a42e888fac6c60acaac1a9b6b6efdf3.png)

```
Administrator
SuperGucciRainbowCake
```

I could now use these creds to login:

![](attachments/e05db0a133eab3660853779037fe2698.png)

### LFI 

I tried out reading `/etc/passwd` using the URL but that didn't work:

![](attachments/ddfe9cf164c84983892c0650779b79eb.png)

This didn't seem to work so I tried my next trick to get the PHP page source:

```url
php://filter/read=convert.base64-encode/resource=users
```

![](attachments/7f6b5936c0688aff013f4a5c0fceae19.png)

I then used the following to decode the `base64` encoding:

![](attachments/e34099f9b83032b5419af685fd9436d5.png)

![](attachments/917216dbf2a0f65aacd4bc21b566ef16.png)

The above gave us the file that we should look into, so I went ahead and read and decoded it:

![](attachments/272687f6dc85ba2228978f95963c86e8.png)

![](attachments/c2a05ce547c8d8424d13456a09a90f76.png)

This gave us a set of creds.

```
remo
TrulyImpossiblePasswordLmao123
```

However this would not give us access to `ssh`:

![](attachments/01c40011517b96c11a1e5c90ca62cd9a.png)

I tried out port `25` but got nowhere either. 

### ffuf - discovering preprod-marketing

Instead I used `ffuf` to discover yet another subdomain called `preprod-marketing` as follows:

![](attachments/6025a02369b6274a9720c9b85916dfc1.png)

### preprod-marketing

I head on over to the webpage and am greeted with this landing page.

![](attachments/aa5220a307e83594018dc9fa2e666b0f.png)

Here we find yet again a possible **LFI** vulnerability:

![](attachments/4b646d1a852b26508f046c272d2925a7.png)

### Even More LFI

I was able to retrieve the `/etc/passwd` file contents as follows:

![](attachments/026b2bf2225c455681792a8e3a715f06.png)

Here we find the user *michael*. It is possible that the passwords are reused.

![](attachments/b0165a676126d6d15f0c01772dcb660b.png)

Unfortunately they aren't. However we can easily grab *michael*'s `id_rsa`:

![](attachments/2fe4f5fe3e38b525ff08a592792568c9.png)

# Foothold
## SSH as michael

![](attachments/29dd0e20aee1a1f9fef7a8747ad4dcdf.png)

### user.txt

![](attachments/bde97b9454e9875965fd049cc4d15f97.png)

# Privilege Escalation
## fail2ban

Checking `sudo -l` we notice the following:

![](attachments/445ab9ebf50fd2f1921a04b592f926bd.png)

![](attachments/38eda0b835e4c24bccf07954e03dccb5.png)

>[!quote]+
>In Linux, fail2ban is mostly used to protect the SSH service. If the daemon detects several unsuccessful ssh login attempts, it executes a command that blocks the IP address. So misconfigurations can lead to privilege escalation.

I used the `github` link and read the instructions:

![](attachments/1e05139e2727446c89e47a32db20b5a9.png)

![](attachments/7ff2067191e98df14a16d8f8841e56a5.png)

![](attachments/d3e46555fc07ff25979c40add2c40293.png)

I then started up the exploit:

![](attachments/aead5388e784f41a44ab7e2e83c077d4.png)

After waiting for roughly 100 seconds we become *root*:

![](attachments/de896d103e3babd77e67262b1cf7947c.png)

### root.txt

![](attachments/8af7c8d7a349df2d63630541b7ad80ea.png)

![](attachments/1180093833ed71bcdba796118467e570.png)

---

**Finished 10:27 25-09-2025**

[^Links]: [[Hack The Box]]

#fail2ban #LFI #SQLi #sqlmap #ffuf 
