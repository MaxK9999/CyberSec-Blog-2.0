---
title: 'HTB-Soulmate'
published: 2025-11-24
draft: false
toc: true
tags: ["erlang", "CrushFTP", "CVE-2025-31161"]
---

```
Scope:
10.10.11.86
```

# Recon
## Nmap

```bash
sudo nmap -sC -sV -sT -Pn -T5 -vvvv --min-rate=5000 10.10.11.86

PORT      STATE    SERVICE              REASON      VERSION
22/tcp    open     ssh                  syn-ack     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp    open     http                 syn-ack     nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Soulmate - Find Your Perfect Match
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
```

## 80/TCP - HTTP

![](../attachments/586cb0833ff4c7c63e2ba9f209ddb2de.png)

I checked the site out but found nothing useful.

### ftp.soulmate.htb

I did a `vhost` scan using `ffuf`:

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt:FUZZ -u http://soulmate.htb -H "Host:FUZZ.soulmate.htb" -fs 154
```

![](../attachments/ead10920fe29a6070a2f4a183576cb8f.png)

I headed over to the vhost and found that it was a **CrushFTP** web UI:

![](../attachments/f458fb99e31179dc89b6186af8d16850.png)

I tried to log in using `admin - admin` and got this `xml` error:

![](../attachments/e36b0f550707c64d75a574ce1fd312ea.png)

I checked out the request in `burp`:

![](../attachments/d0aa7917f3624e3f07d0efc0a07c4b8c.png)

I didn't find anything that could be exploited in the request right away so searched for PoC's:

![](../attachments/1f4718e209b05178c638b9d833f2baef.png)

Since I didn't know the version this was more or less guess work.

# Exploitation
## CVE-2025-31161

The following article seemed interesting:

![](../attachments/7cece646b8e192d47c3486214ec5dca3.png)

![](../attachments/ccb23adc9b19f96c17f59382b51b5b00.png)

The PoC is pretty straightforward:

![](../attachments/1af1b201b6c78b8143eb30f60bd22ebe.png)

![](../attachments/c036e45d0f5c17f665b4114b15c0157a.png)

![](../attachments/f7e064a55ac9a3913d065058f58c8a42.png)

Let's exploit it.

```bash
python3 cve-2025-31161.py --target_host ftp.soulmate.htb --port 80 --target_user admin --new_user tester --password 'P@ssword123'
```

![](../attachments/680a335796c9f5c3ba284bc9ff854a91.png)

We now get valid access:

![](../attachments/7c10d9ffa54d39e0ca965e94e772a1a2.png)

I clicked on the **Admin** tab and got redirected:

![](../attachments/ed4529394c4a17f81f816d642bded89f.png)

Amongst the **Recent Logins** I notice the *crushadmin* user as well as the `172.19.0.1` IP address. This IP makes me think that the `ftp` web UI is running inside of a `docker` container, I'll see later on whether my assumptions are right.

## Logging in as ben

I headed over to the **User Manager** tab where I found the user *ben* which had access to some interesting directories including `webProd`.

![](../attachments/bc97df75d14b0bbb3697a24bb39096bf.png)

I went ahead and changed the password for the user and logged in with their creds.

![](../attachments/701b0975b1e662654f206f068f2849a4.png)
![](../attachments/2c6726c5388646e743f5dd96dc1ef21d.png)

![](../attachments/c6c4c891de4f563d42183ee15c269454.png)

![](../attachments/5ba56c6941e40b6c8f004c9164695547.png)

Since all the files inside are with the `.php` extension I went ahead and dropped in a webshell:

![](../attachments/974ec750f1b3fae39a018c6216d5c24d.png)

![](../attachments/ef11e2c39eba778968ee2b3dd327e001.png)

![](../attachments/579271d150116bace8dfb565d17073a9.png)

I could now go ahead and access it by heading over to `http://soulmate.htb/webshell.php`.

![](../attachments/c2aed0360cd23b1308372c1c34a60bb6.png)

As we see from the `ip a` output the `CrushFTP` instance was indeed running from inside of a `docker` container:

![](../attachments/2f6ba9e871b65e25de2092097d2dcaf9.png)

# Foothold
## Shell as www-data

Using the following reverse shell payload I got myself a shell:

![](../attachments/0fd24c97b36566cd8dad7772d0b90879.png)

![](../attachments/c4fd23e2a91e2d63566927927e6f9d9c.png)

What's funny is that the file that we've uploaded was actually owned by *root*:

![](../attachments/23bbd60f64fe1c9f797f5faa009dbdd2.png)

I then found the config file:

![](../attachments/8ee345a6d556f5b466a6ed217521e45d.png)

Inside the file I found the admin password:

![](../attachments/759d5b00d129a36b125994509d9128d6.png)

```
Crush4dmin990
```

Unfortunately this password was not reused anywhere.

## SSH as ben

During my further enumeration of the machine I uploaded `pspy32` and checked out the running processes:

![](../attachments/27961d984a203e5b16ac90cdfa936be1.png)

Inside the script the credentials for *ben* were found:

![](../attachments/8be9fcb57fb81e52b725c4514fd5d6fb.png)

![](../attachments/1392d804076caf20212835e4ddcc245d.png)

```
ben
HouseH0ldings998
```

Using these creds I was able to log in via `ssh`:

![](../attachments/b2a16729e386a38b13ddc7e71c3daead.png)

### user.txt

![](../attachments/660a67bea18c315558d4a15c0972507e.png)

# Privilege Escalation
## 2222/TCP - SSH

I quickly found out that I was unable to run `sudo`:

![](../attachments/e7fac435a5b9cba093b9591a30da5e7d.png)

I wasn't part of any good groups either:

![](../attachments/4b09c590c88f1d30ce2210fd8469afcf.png)

I then remembered the script that we found mentioned port `2222` on localhost:

![](../attachments/2411e65fbda76758378528cec738019b.png)

I logged into the service via `ssh`:

![](../attachments/7d96bb34090a7da5a7e79b9492b756b3.png)

Since this was an `erlang_shell` instead of a regular one we needed to execute commands differently:

![](../attachments/b10c87e974e18d7ffeefc1783074d6f8.png)

Thus I gave myself a *root* reverse shell:

![](../attachments/905264545cba9bf3d3ab9111a7627b98.png)

![](../attachments/5722ed22f744be4d959530ccdf5a9d35.png)

### root.txt

![](../attachments/78a9db99e809fff3b3380796601e39b6.png)

![](../attachments/689ccfdc3daf3b5ae3d2db3b4221ffeb.png)

---