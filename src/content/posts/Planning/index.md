---
title: 'HTB-Planning'
published: 2025-10-07
draft: false
toc: true
---

```
Scope:
10.10.11.68

Creds:
admin / 0D5oT70Fq13EvB5r
```

# Recon
## Nmap

```bash
sudo nmap -sC -sV -sT -vvvv -p- -T5 --min-rate=5000 -Pn planning.htb

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack nginx 1.24.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-title: Edukate - Online Education Website
|_http-server-header: nginx/1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

![](attachments/a3292080c924251189a24c38e89d0015.png)

No easy win.

## 80/TCP - HTTP

![](attachments/1ce880ec85419cc0507b12dc7040be5a.png)

![](attachments/3ce91641e55ac8f4b70c3a76fd53aa09.png)

I ran a `gobuster` scan:

![](attachments/90af2bae5d93a6f8ba78a772cc159a41.png)

I then tried creating wordlists out of the found instructors, hoping that I could brute force it with the provided password.

![](attachments/d2dcf5c9364fa0e52dc5ba643a6880b9.png)

None of these matched however:

![](attachments/97dd3f3d55ce0d81714f557d1972f9a0.png)

### Vhost 

I then started enumerating `vhosts` using `ffuf`:

![](attachments/ffc9e8fffa0137f38c7ae42f1ab76699.png)

I went ahead and added it to my `/etc/hosts`:

![](attachments/6b6c193a26da1edf047a7146302f9b7f.png)

![](attachments/f35a6305188f60d7cbcc603c8520e98d.png)

I went ahead and input the creds and got in:

![](attachments/8130c01b819e5a36acf16989029c6f4a.png)

## PoC

I then searched up whether there was any RCE exploit for the **Grafana v11.0** version:

![](attachments/bc990446ab2488117d15eefc48ab7620.png)

![](attachments/a2271c93f76f33cb394fe9d010546997.png)

![](attachments/0720881070e282e7c7b18d1b3bcf9448.png)

While this looked promising, I was not done yet.

![](attachments/5039f833176cb49fd434d7774b165ce6.png)

By using the `env` command however I was able to find some juicy creds:

![](attachments/7e35dd84c843a87998b943315d4123f2.png)

![](attachments/daa519b1fc19f0b374e8399ff06bc787.png)

```
enzo
RioTecRANDEntANT!
```

Success!

# Foothold
## Shell as enzo

![](attachments/b392a6de4ccd845c497d912403872c40.png)

Time to get `user.txt`

### user.txt

![](attachments/14ae62fa69d9b66af4257850cc017f6e.png)

I then tried an easy win but unfortunately it didn't work:

![](attachments/155219e61294727d9bf5682b17539d1d.png)

# Privilege Escalation
## Enumeration

I downloaded over `linpeas.sh` and started enumerating:

![](attachments/aa3740c345b3b728b276dd238ec9e83f.png)

Well that sucks.

![](attachments/775a4de90723fe260dfdf299dacc7a3d.png)

![](attachments/1e395e36be51d7ce3fc36cbfad13ac64.png)

Let's check the last one out.

![](attachments/edb91de01fcbf33f701333f3c60c0e6c.png)

## Local Port Forward

I use the following command on `ssh` to port forward so I can access the `8000` port.

![](attachments/85d2155f443c9c003451a93e95dc3341.png)

I use the found creds:

![](attachments/5b2f8d347bca4a849a6c9a81fdc4b460.png)

![](attachments/59375c831dabea4aca1a9ec14eacfdd0.png)

And I'm in.

I create a new cron job:

![](attachments/265d95c8cca22b0d368b3777b01eada3.png)

I start a listener and click on **Run now**:

![](attachments/24c570335bb0bd6af1a1242c5407cd13.png)

### root.txt

![](attachments/c5be32b6a5cdb1f349ab68d3e40e9989.png)

![](attachments/87e994d8548453d0b9086a3178120d0b.png)

---