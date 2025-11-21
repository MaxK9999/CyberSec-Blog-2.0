---
title: 'HTB-TwoMillion'
published: 2025-09-18
draft: false
toc: true
---
**Start 10:11 25-10-2025**

---
```
Scope:
10.10.11.221
```
# Recon
## Nmap

```bash
sudo nmap -sC -sV -sT -p- -vvvv -T5 --min-rate=5000 -Pn 2million.htb

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack nginx
| http-methods: 
|_  Supported Methods: GET
|_http-favicon: Unknown favicon MD5: 20E95ACF205EBFDCB6D634B7440B0CEE
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Hack The Box :: Penetration Testing Labs
|_http-trane-info: Problem with XML parsing of /evox/about
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## 80/TCP - HTTP

![](attachments/953c66c1bf24f8cc848469c24f97da64.png)

I checked out `wappalyzer` to learn more about the tech stack:

![](attachments/a7bc65bc35550247d22bdef502c8cbb9.png)

### gobuster

Time for some directory enum.

![](attachments/cc96f1cb391d77ee1ee758ae6faa7346.png)

I noticed an `/api` endpoint but it gave a `401` code so I couldn't access it (yet). Instead I checked out the `/invite` endpoint.

![](attachments/1e6f422ce4909b9fed40f2be13f54c00.png)

I checked out the source code and noticed the following:

![](attachments/f898238105f5f275fb3ad723ba37609f.png)

I checked out the `inviteapi.min.js` code:

![](attachments/d1e24d40c55c78722d5c7da3f4df77c1.png)

This looked like obfuscated `js` code, let's unpack it.

# Exploitation
## JavaScript Deobfuscation

For this I used [unPacker](https://matthewfl.com/unPacker.html):

![](attachments/8df7c838f15f6c9d728d07c273935d2f.png)

```js
function verifyInviteCode(code)
	{
	var formData=
		{
		"code":code
	};
	$.ajax(
		{
		type:"POST",dataType:"json",data:formData,url:'/api/v1/invite/verify',success:function(response)
			{
			console.log(response)
		}
		,error:function(response)
			{
			console.log(response)
		}
	}
	)
}
function makeInviteCode()
	{
	$.ajax(
		{
		type:"POST",dataType:"json",url:'/api/v1/invite/how/to/generate',success:function(response)
			{
			console.log(response)
		}
		,error:function(response)
			{
			console.log(response)
		}
	}
	)
}
```
 
This looks interesting, we can analyse the `api` call through `caido`:

![](attachments/43f706675787f373575605a1e570955e.png)

It says the encryption type is `ROT13` which is easily decoded.

![](attachments/fd8a32b3a60996cb4194faa4a9489c66.png)

We follow the instructions:

![](attachments/58c4d969897b704df7059cab4f7fe087.png)

This time we get no hint but can clearly see that it's `base64` encoded.

![](attachments/02dc0fcb3591a4283e6de2eda4216502.png)

By entering this code we can access the `/register` endpoint:

![](attachments/63c3a178094e6c73ba0e13e9f71eda37.png)

I then registered and tried logging in:

![](attachments/00e9287af4630377566eb544d05d28d2.png)

![](attachments/76ff53ee46498485b8d2e87b6c58ac4f.png)

Most of the tabs are static but some are still interactive:

![](attachments/fc8b673afa3dfeb2eb62a1b278e06872.png)

I didn't find anything useful here for now.

## API testing

Now that I had access I went on to test if I could access the `/api` endpoint:

![](attachments/90c99533ba5a80ebab2247128637ccc7.png)

Especially this setting looks promising:

![](attachments/4708a19818881d34aa6ce24a12abfa0f.png)

We might be able to use this in order to escalate privileges.

![](attachments/0624087e6dd1238141dc1f3a2fc45ca4.png)

I received an error about the content type so let's add the `application/json` in the headers.

![](attachments/43e7be7bbc4f0391d6c2eb18a04d2faf.png)

We need to add the email.

![](attachments/ad8c96c199c8f4b6762fe3123478ff8e.png)

Now it tells us to add `is_admin` so I added a `1` which indicates `true`:

![](attachments/22a4b47baef9612a5b648cf1a3437fd6.png)

It returns a `200` which means it worked!

![](attachments/8e0b98a99cd786c30a09d6258171d9a5.png)

Checking the `GET` request returns `true` meaning we successfully changed the user to an admin.

Next up I tried playing around with the `POST` request:

![](attachments/65d636f3c019c219fbdcd84bdbf51f8f.png)

![](attachments/7e2ce59301101f2031db7d5afa48087a.png)

This request directly interacts with the backend and generates a vpn pack, we can try to inject commands here.

## Command Injection

![](attachments/1373d2fc19337eab9e3a32b31a48388c.png)

No response but it did give us a `200`, let's test it further. In case the backend is executing a `bash` command we can try commenting out other options and/or commands by using `#`:

![](attachments/6a0a70b3d13cd7dd1b70502cf64106c5.png)

![](attachments/5b1749134e0757b843e0b681fb909aef.png)

# Foothold
## Shell as www-data

Using the found **Command Injection** vulnerability we can get a reverse shell:

![](attachments/bf4ecf924c1fa0007f92332eca8f412a.png)

![](attachments/3e7fd8c0c426aa7fae6eeacd0b602752.png)

I then enumerated the current directory where I found cleartext credentials in the `.env` file:

![](attachments/197c16943bbaecb7f1ff4b748877988f.png)

```
admin
SuperDuperPass123
```

## MySQL

Using the found creds we can log into `mysql`:

![](attachments/d7eacede57165dd55efa143626bc2513.png)

![](attachments/b4eabaeedd305a243a6b1ccca4d6d9be.png)

I tried cracking these but neither worked. Time for some enum.

## Lateral Movement to admin

I enumerated the users:

![](attachments/aa4904aa93ea4e30693bc760dd5a8074.png)

I then tried the found password for password reuse:

![](attachments/6e7d55d2d3789302658c65a93d260978.png)

I then started checking the environment:

![](attachments/04ab66eaf53054af65de1542611eb0a3.png)

### user.txt

![](attachments/dcb2356aa0d58059aed804c50a398566.png)

## Enumeration

I download over `linpeas` and during enum found this:

![](attachments/e7d310d2432168348313ccbf8a5d27a4.png)

I found this content inside:

```
From: ch4p <ch4p@2million.htb>
To: admin <admin@2million.htb>
Cc: g0blin <g0blin@2million.htb>
Subject: Urgent: Patch System OS
Date: Tue, 1 June 2023 10:45:22 -0700
Message-ID: <9876543210@2million.htb>
X-Mailer: ThunderMail Pro 5.2

Hey admin,

I'm know you're working as fast as you can to do the DB migration. While we're partially down, can you also upgrade the OS on our web host? There have been a few serious Linux kernel CVEs already this year. That one in OverlayFS / FUSE looks nasty. We can't get popped by that.

HTB Godfather
```

I did some searching and found a CVE:

![](attachments/07af7d114681a3944e07f10f087a92d0.png)

# Privilege Escalation
## CVE-2023-0386

I did some digging on github:

![](attachments/9632521facea3ecfe2f9a94b32462df2.png)

![](attachments/67327313eac2a76a511000f3f90067fe.png)

I transferred the files to the target and executed the commands:

![](attachments/2f62629fc58bab73a72483efb27e20d5.png)

![](attachments/3154194b0cb889398e0f961a50059ca5.png)

We can then easily exploit it:

![](attachments/e402ae65298274a5873fccf1a35fd285.png)

### root.txt

![](attachments/2701b28b5dd91600aff5483384a9312a.png)

![](attachments/ae293f6de4dfc2d1759d19b438545fe3.png)

---

**Finished 11:58 25-10-2025**

[^Links]: [[Hack The Box]]

#JavaScriptDeobfuscation #API-Attacks #command-injection #CVE-2023-0386 
