---
title: PG-Authby
published: 2025-02-21
toc: true
draft: false
tags:
  - "Windows"
  - "docroot"
  - "FTP"
  - "OSCP Prep"
---

```
Scope:
192.168.198.46
```

# Recon
## Nmap

```bash
sudo nmap -sT authby -sV -sC -vvvv -T5 -p- -T5 --min-rate=5000

PORT     STATE SERVICE       REASON  VERSION
21/tcp   open  ftp           syn-ack zFTPServer 6.0 build 2011-10-17
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| total 9680
| ----------   1 root     root      5610496 Oct 18  2011 zFTPServer.exe
| ----------   1 root     root           25 Feb 10  2011 UninstallService.bat
| ----------   1 root     root      4284928 Oct 18  2011 Uninstall.exe
| ----------   1 root     root           17 Aug 13  2011 StopService.bat
| ----------   1 root     root           18 Aug 13  2011 StartService.bat
| ----------   1 root     root         8736 Nov 09  2011 Settings.ini
| dr-xr-xr-x   1 root     root          512 Feb 21 18:23 log
| ----------   1 root     root         2275 Aug 09  2011 LICENSE.htm
| ----------   1 root     root           23 Feb 10  2011 InstallService.bat
| dr-xr-xr-x   1 root     root          512 Nov 08  2011 extensions
| dr-xr-xr-x   1 root     root          512 Nov 08  2011 certificates
|_dr-xr-xr-x   1 root     root          512 Aug 03  2024 accounts
242/tcp  open  http          syn-ack Apache httpd 2.2.21 ((Win32) PHP/5.3.8)
|_http-server-header: Apache/2.2.21 (Win32) PHP/5.3.8
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: 401 Authorization Required
| http-auth: 
| HTTP/1.1 401 Authorization Required\x0D
|_  Basic realm=Qui e nuce nuculeum esse volt, frangit nucem!
3145/tcp open  zftp-admin    syn-ack zFTPServer admin
3389/tcp open  ms-wbt-server syn-ack Microsoft Terminal Service
|_ssl-date: 2025-02-21T10:24:30+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: LIVDA
|   NetBIOS_Domain_Name: LIVDA
|   NetBIOS_Computer_Name: LIVDA
|   DNS_Domain_Name: LIVDA
|   DNS_Computer_Name: LIVDA
|   Product_Version: 6.0.6001
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

## 21/TCP - FTP

There's a boatload of files here, but I can't transfer them since they're owned by root:

![](attachments/7a9fcb419814102542207f8a94a88639.png)

Luckily for us it seems that all we have to do is *omit* the `-a` option and try logging in with default creds.

I first tried the other port to no avail

![](attachments/cd005275f79c02c3e6999290db2c431b.png)

And then I tried 21 again

![](attachments/9756ad71325cc41320e8d47b7449b2e4.png)

We get in using default `admin - admin` creds!

The directory looks a whole lot different now as well.

![](attachments/c9843fc77194e5924c086769b1b9d42e.png)

Let's check them out.

![](attachments/622e0e98b9635fc814b142bc58d4a214.png)

:::info
Little side note:
![](attachments/183790beaa25a5b4cefec4f186fd564e.png)
:::


![](attachments/57e57ff2682b21603d6a9c823c084e89.png)


## Hashcat

Let's go ahead and crack it.

![](attachments/0cd735747dc1430d7bc47e3fd820bb2d.png)

![](attachments/c82b6f6f557d0dfbb26b5c2d5f8eb546.png)

![](attachments/eba2f0a5ec70d8e865d3484f77240e0c.png)


## 242/TCP - HTTP

![](attachments/721bd90fdabf7b4c7f3c3768bc9564b2.png)

![](attachments/f0543807b0653033284e3f96af98e3e0.png)

![](attachments/2d35259150cc4dee0b1160d96b8f7c1e.png)

I then checked whether the creds could be the ones for RDP but it seems they're invalid:

![](attachments/e58aaf8cf5c33919d011626d8a5abd26.png)

However we can try **Remote File Upload** via FTP! 

![](attachments/5d18637be61391f216e79d58ab3dd375.png)

![](attachments/dcd5c7c344faff5356a3664544af5563.png)

Since we have access as *admin* on FTP we can easily upload any sort of file. Let's see if this reflects on the website.

![](attachments/a83b45a2880c09ce344113c750fdab55.png)

Awesome, this proves that the FTP server is indeed the docroot, let's go ahead and make a webshell payload that we will `put` onto the FTP server.

![](attachments/ceb7f3c200c4d8b9f769089dcab3d473.png)

![](attachments/a973038dc6b0c92ab28782bac98fd021.png)

![](attachments/0f90c35a7f1942856ab861ad32ef1512.png)

Let's check out what else we can do:

![](attachments/cb9ad14dd3d9bcd39aa856f0d253f2df.png)

Hell yeah, let's upload one of the potatoes to the docroot, and execute it to get ourselves a *SYSTEM* shell right away.

![](attachments/b69163d1cc0536df6f0daa6caa54967a.png)

![](attachments/4f7f0f2062b656cba2aa802ade24f2de.png)

![](attachments/a8ced10148eb420eeb055a4fbb698175.png)

Unfortunately this did not seem to work.

I decided to ping my own IP to see whether there was an issue of some sorts

![](attachments/3a8fb3c11d45c63e0479623a52b649d5.png)

![](attachments/65e45487d7ed38edb8a11b6db719b237.png)

This seemed to work however.


# Foothold

I then proceeded to simply initiate a reverse shell via the `nc.exe` binary I'd uploaded.

![](attachments/dccd68c60a0d35a08cd4213502011ec4.png)

![](attachments/fa34e2e399f245d2b547a4867d95f76f.png)

:::warning
Well this explains why the `powershell` reverse shell wouldn't kick in.
:::

## local.txt

![](attachments/4e7dbe95d8b2d9cab643b839c72b9b79.png)


# Privilege Escalation

## Abusing privileges

![](attachments/a9e673689601da4497e098d6b19a57ae.png)

I guess this won't fire since we have the 64-bit version.

![](attachments/862456c66599e212952a2c60e329ea02.png)

Well this wouldn't work either, what now?

Looks like none of the other potatoes worked either, let's do some more enumeration.


## Enum

![](attachments/15ab6dfe42a8fd0d36a95d7a42ef112b.png)

It appears to be a clean install of **Windows Server 2008**, there *MUST* be some exploits for it.

![](attachments/0f057a884dbdd9f2df9657918ad6efe1.png)

Perfect, let's check out the PoC

![](attachments/069786c39a98759b235a990ceb0718b2.png)

Alrighty then, pretty straightforward. Let's compile it.

![](attachments/2c88826071ff4cdc3d0ffc113ba10d58.png)

We transfer it over and *instantly* become **SYSTEM**

![](attachments/7e8f9812c34603ef51a16f8b8f7efc59.png)


## proof.txt

![](attachments/a2247f5bc3c2d42bac1f33554886b5f3.png)

---


