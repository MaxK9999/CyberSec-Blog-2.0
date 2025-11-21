---
title: 'HTB-Shoppy'
published: 2025-09-18
draft: false
toc: true
---
**Start 10:33 25-09-2025**

---
```
Scope:
10.10.11.180
```
# Recon
## Nmap

```bash
sudo nmap -sV -sC -sT -p- shoppy.htb -T5 --min-rate=5000 -vvvv -Pn 

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
80/tcp   open  http    syn-ack nginx 1.23.1
|_http-title:             Shoppy Wait Page        
|_http-server-header: nginx/1.23.1
|_http-favicon: Unknown favicon MD5: D5F0A0ADD0BFBB2BC51607F78ECE2F57
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
9093/tcp open  http    syn-ack Golang net/http server
|_http-trane-info: Problem with XML parsing of /evox/about
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Unknown favicon MD5: DEAA4EF1DE78FC2D7744B12A667FA28C
|_http-title: Site doesnt have a title (text/plain; version=0.0.4; charset=utf-8).
| fingerprint-strings: 
|   GenericLines: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Content-Type: text/plain; version=0.0.4; charset=utf-8
|     Date: Thu, 25 Sep 2025 08:35:12 GMT
```

## 80/TCP - HTTP

![](attachments/2fe593d068f18d9a53a74f4fd3ee6e46.png)

The site did not have anything on the surface so I went ahead and used `gobuster` to enumerate it:

![](attachments/377f5d931362b9d348d7d28f0c3184d7.png)

I then headed over to the `/login` page:

![](attachments/567d253d0ee79b06dceac73b00b380db.png)

I then tried to submit default creds and viewed the output:

![](attachments/d71b7be11dca9baf8b937bd183fdf9d3.png)

I tried manipulating it to achieve SQLi:

![](attachments/70d1665c06e1dfc0d78c76703740dc32.png)

This isn't really helpful for now. Checking `wappalyzer` yields nothing interesting either:

![](attachments/119c5cdd3836cc6e835c290d74bda098.png)

### NoSQL Injection

Since the `'` was messing up the query and giving a timeout response it's still worth looking into **NoSQL Injection** in case the server is running something like **MongoDB**.

I searched for some payloads and found the following list:

![](attachments/a83a5eb38870537f964fcb1d2affa4d0.png)

I tried my luck and found a payload that actually worked!

```
username=admin' || '1'=='1&password=admin
```

![](attachments/6d24647f941839b41f5e7d294ff6de02.png)

I went ahead and entered it on the website:

![](attachments/31ab732a97c0bd44bda327176a9fc836.png)

![](attachments/402ca02dbc72c31e69c2c5f3fd3d4b42.png)

Clicking on **Search for users** lets me search for any users and give me their data:

![](attachments/43af6e7479aff5614e179b191dd67866.png)

![](attachments/b729a847c8cb9c616ed6f25b33e6624d.png)

### Burpsuite Intruder

I then analyzed the request and found that if the user exists, then the response would be a `304`:

![](attachments/a06321cade5643c30d8f0f08412fb326.png)

Otherwise it's a `200`:

![](attachments/b133b54b49df3d6da6e854c165c8cd90.png)

Using this knowledge we can initiate a `burp Intruder` attack where we use a list with usernames to fuzz for existing users.

![](attachments/57c78b9c9c5cb8362ee5a057cdc6640a.png)

Using an extensive list such as `john.txt` from the `statistically-likely-usernames` repo yields us the following result:

![](attachments/5825f1bb019e7d74dc124ad7bfd2de91.png)

It appears that there's a user called *josh*!

![](attachments/5380886a8493b98abb468184c9584a5b.png)

![](attachments/1e1fe029e475dac70d92c4ceab1fd5fb.png)

Let's try cracking the MD5 hash.

![](attachments/164e91a07156473c98e65f602fca83f4.png)

```
josh
remembermethisway
```

### NoSQLi Alternative

Since we already know that there's a NoSQLi vulnerability we can leverage it to find all present users:

![](attachments/becdc1ae836721f2f99a7a640663ca4e.png)

![](attachments/10a5d9e080502d17522f9fe53dbfdbd8.png)

Now that we've found creds we should be able to login, but where? SSH did not work so let's look further.

### Subdomain fuzzing 

I tried out port `9093` but that did not seem helpful in any way so I ran `ffuf` to enumerate further:

![](attachments/7731070da46818c79a1a193bb1ab0e61.png)

And I was able to find the `mattermost` subdomain!

![](attachments/1211094d41c4541e8655a347b1f7f2a9.png)

### mattermost

After adding the domain to my `/etc/hosts` I went ahead and visited the website:

![](attachments/b1364402aa25848c00650f75bff55233.png)

I used the previously found creds to login:

![](attachments/06bbbf467829c39cf566b6b3d3857262.png)

![](attachments/51b964571d4518d2e0d53a6a190712cd.png)

Scrolling through the channels we find cleartext credentials posted:

![](attachments/73636dda0b84ec7bba10c15dce0df535.png)

```
jaeger
Sh0ppyBest@pp!
```

# Foothold
## SSH as jaeger

Using the found creds we get access to the target:

![](attachments/f950ab13265ec08dd4a8527f366c0931.png)

### user.txt

We can grab the first flag right away:

![](attachments/3751d2e95fccee143d4aecec41205487.png)

### Strings

I perform some surface level enum of the user:

![](attachments/d1093373ae96aafebecdf9cdc2a2e8c1.png)

This is the program *josh* was talking about in the chat:

![](attachments/d8e7cd97568a5df2c2f6732b337f6f75.png)

Apparently it's written in `C++`, not sure whether that's useful for us right now.

![](attachments/3a4634e3d567d5fb984267895bde55be.png)

I tested it out:

![](attachments/026d4488036aa0d72908591f3a864e57.png)

I tried the other password but that didn't work either:

![](attachments/906aea979375bf65ab1e270e46b81311.png)

I read the binary using `strings` to understand how it works underneath:

![](attachments/f85183de1c18fb46bd3e944ed7ebb2c6.png)

Furthermore we can use the `-e` option on `strings` in order to select character endianness:

![](attachments/7629ddb0a62fc86bf15ca0c0716d3a50.png)

![](attachments/e45c1aa6cacaa2f03ca8dadcab47a356.png)

Using the hardcoded credentials we can get access to `creds.txt`:

![](attachments/061d4dfede53009f711542d569524652.png)

```
deploy
Deploying@pp!
```

This gives us the ability to move laterally.

## Lateral Movement

![](attachments/b3ac891b955433cdd9eeea9988483ba2.png)

Eventhough we weren't able to run `sudo -l` we still find that we're part of the `docker` group.

![](attachments/63ff017feac208946b0dbd790cfb37da.png)

# Privilege Escalation
## Docker

This is an amazing position to be in since we can easily exploit the binary using [GTFObins](https://gtfobins.github.io/gtfobins/docker/):

![](attachments/ab42476702dac3764d7bf0fe33db2531.png)

![](attachments/8de08039ff23bae82afd55f560e8494a.png)

### root.txt

![](attachments/ca21c34870e1f86b4e8bfb54126a6cd4.png)

![](attachments/27cdd06b869fa45a22ce4f5ff9a270ab.png)

---

**Finished 12:05 25-09-2025**

[^Links]: [[Hack The Box]]

#NoSQL #Intruder #ffuf #strings #docker 
