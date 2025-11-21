---
title: 'HTB-Usage'
published: 2025-09-18
draft: false
toc: true
---
**Start 09:49 27-10-2025**

---
```
Scope:
10.10.11.18
```
# Recon
## Nmap

```bash
sudo nmap -sC -sV -sT -p- -vvvv -T5 --min-rate=5000 -Pn usage.htb

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
|_http-title: Daily Blogs
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
| http-methods: 
|_  Supported Methods: GET HEAD
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## 80/TCP - HTTP

![](attachments/0721bd610838ee3248cb0b3531f550db.png)

I analyse the request right away in `burp`:

![](attachments/d09ae9a8edd4399a75f4d6a920a163a9.png)

I take note of the `laravel_session` inside the `Cookie` header.

Clicking on **Admin** redirects us to the `admin.usage.htb` vhost.

![](attachments/cd9a95f2fc9adc6af30de4d84385ecfe.png)

![](attachments/adc10e4d35cde3d5d9b40460056044df.png)

![](attachments/7559c219e64ffbcf4da80a0c144b8436.png)

Here I tried to login using default creds:

![](attachments/0475e6911abd5bfc5b248131a11f325d.png)

I went back to the original site and registered for an account:

![](attachments/375afba5ae74661048fe4931584ba364.png)

And logged in:

![](attachments/1a225bd92f11ebf1c4d2df32c285f541.png)

Other than that there's nothing here apart from some blogs. 

### SQLi

I tried some more functionalities as well as the **Reset Password**:

![](attachments/304af7207cb39e862c8c4731327c9d24.png)

I tried adding a `'` here and noticed the `500` error, meaning it was probably susceptible to **SQLi**:

![](attachments/ffd3dcafade0d0461cb56825f435df15.png)

![](attachments/4c73e499b2bbe41c9b50499918e04e29.png)

I confirmed this by adding `-- -`:

![](attachments/28d67da48878742c196253408898e29e.png)

I copied the request and did some automated testing using `sqlmap`:

![](attachments/f4c66545f94d81d5c36c8ab3c6ee587a.png)

![](attachments/169c68d913d7902a368bb65d25d78535.png)

It started dumping info extremely slow since it went with the **time-based blind** payloads so I instead reran it:

```bash
sqlmap -r req.txt --batch --level 5 --risk 3 --threads 10 --dbms=mysql -D usage_blog -T admin_users --dump  --skip _token
```

![](attachments/c1202d38587e9b5d3aacb110c6708485.png)
### Hash cracking

I went ahead and cracked the hash

![](attachments/983d4e6c6ffceb1b1d4d3699f6718ce3.png)

![](attachments/92a2599749988f5628e888d721085389.png)

```
admin
whatever1
```

### admin.usage.htb

We can now log in with the creds:

![](attachments/09a31a9b1b253818f574ebf58fbb9708.png)

I started looking for exploits:

![](attachments/18ea4724083c52fb31e57a04ded7aab5.png)

![](attachments/e3b5ec2f311d4ad44231384ec9bd24da.png)

I found the exploit [here](https://sploitus.com/exploit?id=2566E785-0AA3-54BD-994A-D636B5656220):

![](attachments/9fe64175e57572782fb643b7a6000261.png)

# Foothold
## Shell as dash

I followed the instructions and got a shell:

![](attachments/f6d2e709143c25a2ecab439656b1199f.png)

![](attachments/ab331a7dde1abb698b889e855226733d.png)

![](attachments/d2eb61cf7e985da9aec674aa4062a549.png)

### Enumeration

I noticed one other user called *xander*:

![](attachments/89ab3a7b95a5f243d97c4bbe91428ee3.png)

I started looking around:

![](attachments/433ede3debb1c0867c330f7d9aa1b52c.png)

![](attachments/c96305a3cd99daa7b40467e389f39088.png)

```
staff
s3cr3t_c0d3d_1uth
```

I checked out whether `mysql` was running:

![](attachments/2e5c2413a84232202ed49738b115f67f.png)

But first I went ahead and enumerated my `/home` directory:

![](attachments/f7c55ceca561c814c486f3f092578f1d.png)

I copied over the `id_rsa` and logged in via `ssh`:

![](attachments/0b6388f3abeda9541743d1bb6cc0a3ce.png)

### user.txt

![](attachments/60887b7a631651b746ec765b123b0fd3.png)

I started checking further and found another set of creds:

![](attachments/25f3eaa13b8f3454754c8d2050faac09.png)

```
admin
3nc0d3d_pa$$w0rd
```

However in order to access this instance we need to create a port forward since it's only running on `localhost`.

## Port Forward

![](attachments/2668b1b379447750cb217e2cefc3f0a7.png)

![](attachments/1723e2df83fcf2069c2ad6bc9b331c22.png)

![](attachments/e1039209ec342b018e5dff8583e7376c.png)

I can now use the found creds to log in:

![](attachments/76a0dedf322987dccecc4b14be85c377.png)

![](attachments/e5de070a763f3cfa7e040d40e2994c46.png)

# Privilege Escalation
## Monit

![](attachments/5e9ea9b5c5c3f9ea12b56a20d041b009.png)

![](attachments/ec1db2545289d9e9f1d8f9ff53fd173b.png)

I was looking around to see whether this might be the path:

![](attachments/1c89e49c3124000dec2471833b76ea7f.png)

But it looks like a completely different scenario so I skipped it. 

## usage_management

Instead I sprayed the password and it turns out the password is reused by *xander*:

![](attachments/d501d21321008e9c2758663450a2e359.png)

It turns out *xander* can run the `usage_management` binary as *root*:

![](attachments/09f8b0376fb2387258a014c4b690d72b.png)

The binary had 3 options:

![](attachments/7303c7bd43518049f971c53f77ed2ef2.png)

![](attachments/8044a541b8537f48c304329f031d24b2.png)

Since this is a custom binary we need to understand what's happening underneath, what better place to start than with `strings`:

![](attachments/a363cc57c21cc920b68602d5abad5d93.png)

![](attachments/c107210fe203492029b788b59f670be9.png)

We notice that it zips the `/var/www/html` directory up using `7z`. However we also notice the **Wildcard** `*` option at the end!

## Wildcard Exploitation

From the `/var/www/html` directory we can create the following linked file:

```bash
touch @tester; ln -fs /root/.ssh/id_rsa tester
```

![](attachments/5a5f9c6ba95a79cdbb20d273b5d82871.png)

Upon execution we see the `id_rsa` for *root* being dumped:

![](attachments/7bf98358f8e39d59659632eca31eb556.png)

We can copy the output and remove the `No more files` lines and log in via `ssh`:

![](attachments/a080755edf795822814e9bc412584cbc.png)

### root.txt

![](attachments/04537e568e91c6aa4f3fbd78416b5134.png)

![](attachments/c2f03d2fe129810c2e5ad118aa177e45.png)

---

**Finished 14:55 27-10-2025**

[^Links]: [[Hack The Box]]


#SQLi #sqlmap #wildcard 
