---
title: 'HTB-Forge'
published: 2025-09-18
draft: false
toc: true
---
**Start 17:36 27-10-2025**

---
```
Scope:
10.10.11.111
```
# Recon
## Nmap

```bash
sudo nmap -sC -sV -sT -p- -vvvv -T5 --min-rate=5000 -Pn forge.htb

PORT   STATE    SERVICE REASON      VERSION
22/tcp open     ssh     syn-ack     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open     http    syn-ack     Apache httpd 2.4.41
|_http-title: Gallery
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD
Service Info: Host: 10.10.11.111; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## 80/TCP - HTTP

![](attachments/aaafdef1a75125bf12d03bcdf39bf94a.png)

We can directly upload an image:

![](attachments/bc72ac2725b43f5120afb6930bed321f.png)

![](attachments/15ffd99ae14160edd7674e4f7e168b35.png)

![](attachments/9b14e5c4713d2ef4849226f71a4fcfbd.png)

![](attachments/30ec040fe40e47f8b3387c7a194a6d2d.png)

I tried to include the `/etc/passwd` file but got this response:

![](attachments/6593c14582774aff09efbd19954e9bfd.png)

This appears to be a **SSRF** vulnerability rather than a **File Upload** one, let's test it out.

### SSRF

![](attachments/6b805619a28ed73fb56c8e1f671265c1.png)

![](attachments/bc4129274897fcf6802c95e5d354a61b.png)

I notice that it shows `python` as the `User-Agent` meaning it's probably either **Flask** or **Django** running the application.

I analysed the request further:

![](attachments/4ae70fd4623370f1c5eaccbe43cb73b8.png)

I tried reading files but it's not supported:

![](attachments/2e571cab9198176abfe6db28e748990d.png)

I then tested the following method:

![](attachments/ae3bcb4f83384d7e7da0475a3f68af76.png)

![](attachments/afb94d6c8b567e21b070969fa9c4564a.png)

However when I tested this one I got a different response:

![](attachments/165f5eec60c28181bb4534c131f09da7.png)

![](attachments/b77d38e9f593ea9718f5fe9ae9890b88.png)

I tried to enumerate open ports this way to see whether there were any other open ones but got none other than `80`:

```bash
ffuf -w ./ports.txt -u http://forge.htb/upload -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "url=http://0:FUZZ&remote=1" -fr 'An error occured!'
```

![](attachments/7520799604b4a6cacbdccf3aa5891117.png)

Anyhow, instead I used the following technique to bypass the `localhost` checker:

![](attachments/72c4d249f3d4c05fd6f8c13228e6ae6e.png)

By simply adding one uppercase letter we were able to successfully bypass it:

![](attachments/98a76b583803978471f45ebabfabf4bc.png)

![](attachments/60a098cd33e606cbf8083bdb16f5068c.png)

We are able to retrieve the `index` page that the webserver is hosting. Problem is though that I still am unable to fetch any other files, so it's time to continue our enumeration.

### admin.forge.htb

Using `ffuf` I found the `admin` vhost:

![](attachments/063a2533274dce1af8334443fe2cd66f.png)

![](attachments/5816de31d3ec980714474b528529f73c.png)

![](attachments/acfce6db80ca2eb0ccc3978933c2b45c.png)

And now I understand where the **SSRF** part comes in.

![](attachments/4b158dd7c3e439e130d9ffe46fe2bc5d.png)

![](attachments/51e00ace33776246a46c33231b2a1576.png)

![](attachments/48d97ea4806cc829e17110ea8a705906.png)

I then checked the `/announcements` endpoint using the same technique:

![](attachments/e98cc4c7cb18f484e6a11492611bf488.png)

```
user
heightofsecurity123!
```

We get a set of creds, as well as more info about the `/upload` endpoint.

Combining the information we've gathered we can go ahead fetch everything that's inside the `ftp` server:

![](attachments/89c3747848a4df3fac7d41f69fde814a.png)

![](attachments/73da0e04b0aa9765ed625b521b4f8e31.png)

### user.txt

![](attachments/490ca1f8bbc3ae412cbe5b913ccb0292.png)

![](attachments/006ec96710e2348ce1d2df6bf7b62f8c.png)

# Foothold
## Shell as user
### Fetching id_rsa

Since we were able to read the `user.txt` file it's *HIGHLY LIKELY* that the `ftp` directory is inside the user's `/home` directory. Let's try to fetch the `ssh` `id_rsa` key.

![](attachments/1489e36c4b2f5b1cf35539d1b8619193.png)

![](attachments/114b311b934151ed495b2c201ff96bb3.png)

In order to understand whom the key belonged to I read the `/etc/passwd` file:

![](attachments/4a478aa0cf852345436b2ca7c89f57ac.png)

![](attachments/b968ec094d869d45a4da6334c4dfba08.png)

I thus captured the `id_rsa` and logged in with it:

![](attachments/9af74584427e0511a0c4dec4dff5563f.png)

![](attachments/6d744f43bb0a1b1e351090f40987ceba.png)

# Privilege Escalation
## remote-manage

Using `sudo -l` I found out that I could run the following binary as *root*:

![](attachments/e72d57a7fc4e8c9bad3eda3c87424128.png)

![](attachments/bb5ff564f9ae7f7463247119b2a23e49.png)

### Exploitation

I went ahead and tried it out:

![](attachments/b0913689c08fe1427b2cf5ff6f2f5ed3.png)

From another terminal I was able to execute some commands:

![](attachments/0a5a710c5ec7afb24629309eb8d84c4a.png)

The way to exploit this is by sending *any* input that isn't an `int`:

![](attachments/38e25d38749f895f74b9b9640b7ffef3.png)

Back in the first terminal we notice:

![](attachments/d368035f222b247ed1d9cbee6e40d816.png)

We can then use the following command to spawn a *root* shell:

![](attachments/59787c3a8d64ce97f686b5fd7d71fcbd.png)

>[!TLDR]
>When the exception is caught, the code explicitly calls `pdb.post_mortem(e.__traceback__)`. `post_mortem()` receives the traceback object (`e.__traceback__`) and starts `pdb` positioned at the point of the exception. That gives you an interactive `(Pdb)` prompt in the terminal where the root process was started (the terminal running `sudo /usr/bin/python3 /opt/remote-manage.py`).

### root.txt

![](attachments/0358d276ee18dc14a4982b961e223477.png)

![](attachments/bbd0f5c43b41ba80fe737fc218b252ae.png)

---

**Finished 18:45 27-10-2025**

[^Links]: [[Hack The Box]]

#SSRF 
